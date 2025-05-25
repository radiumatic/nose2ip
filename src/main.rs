use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use notify::{EventKind, Watcher};
use regex::Regex;
use serde::Deserialize;
use ini::Ini;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader, SeekFrom};
use tokio::process::Command;
use tokio::sync::{Mutex, Notify};

mod state;
use state::WatcherState;

const STATE_FILE: &str = "watcher_state.json";

#[derive(Debug, Deserialize)]
struct Config {
    services_dir: String,
    #[serde(default)]
    enabled_services: Option<Vec<String>>,
    #[serde(default)]
    fail2ban_config: Option<String>,
    #[serde(default)]
    fail2ban_filter_dir: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct ServiceConfig {
    name: String,
    log_path: String,
    pattern: String,
    failures_threshold: u32,
    ban_time_secs: u64,
    backoff_factor: Option<f64>,
}

type SharedNotifyMap = Arc<Mutex<HashMap<String, Arc<Notify>>>>;

#[derive(Clone)]
struct IpBanManager {
    inner: Arc<Mutex<IpBanInner>>,
}

struct IpBanInner {
    ban_counts: HashMap<String, u32>,
    banned_ips: HashSet<String>,
}

impl IpBanManager {
    pub fn new() -> Self {
        IpBanManager {
            inner: Arc::new(Mutex::new(IpBanInner {
                ban_counts: HashMap::new(),
                banned_ips: HashSet::new(),
            })),
        }
    }

    pub async fn ban_ip(self: Arc<Self>, service: &ServiceConfig, ip: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut inner = self.inner.lock().await;
        let count = inner.ban_counts.get(ip).cloned().unwrap_or(0);
        let backoff = service.backoff_factor.unwrap_or(2.0);
        let duration_secs = ((service.ban_time_secs as f64) * backoff.powi(count as i32)).round() as u64;
        inner.ban_counts.insert(ip.to_string(), count + 1);

        if inner.banned_ips.insert(ip.to_string()) {
            drop(inner);
            // Ban via iptables
            let status = Command::new("iptables")
                .args(&["-I", "INPUT", "-s", ip, "-j", "DROP"])
                .status()
                .await?;
            if status.success() {
                println!("Banned IP {} for {} seconds (service {})", ip, duration_secs, service.name);
            } else {
                eprintln!("Failed to ban IP {}: iptables returned {}", ip, status);
            }

            let manager = self.clone();
            let ip_clone = ip.to_string();
            let service_name = service.name.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(duration_secs)).await;
                let mut inner = manager.inner.lock().await;
                if inner.banned_ips.remove(&ip_clone) {
                    drop(inner);
                    let status = Command::new("iptables")
                        .args(&["-D", "INPUT", "-s", &ip_clone, "-j", "DROP"])
                        .status()
                        .await;
                    match status {
                        Ok(s) if s.success() => println!("Unbanned IP {} (service {})", &ip_clone, service_name),
                        Ok(s) => eprintln!("Failed to unban IP {}: iptables returned {}", &ip_clone, s),
                        Err(e) => eprintln!("Failed to unban IP {}: {}", &ip_clone, e),
                    }
                }
            });
        }

        Ok(())
    }
}

fn load_config<P: AsRef<Path>>(path: P) -> Result<Config, Box<dyn std::error::Error>> {
    let data = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&data)?)
}

fn load_services(dir: &str) -> Result<Vec<ServiceConfig>, Box<dyn std::error::Error>> {
    let mut services = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
            let data = fs::read_to_string(&path)?;
            let svc: ServiceConfig = serde_json::from_str(&data)?;
            services.push(svc);
        }
    }
    Ok(services)
}

fn load_fail2ban_services(jail_config: &str, filter_dir: &str) -> Result<Vec<ServiceConfig>, Box<dyn std::error::Error>> {
    let conf = Ini::load_from_file(jail_config)?;
    let mut services = Vec::new();
    for (sec, prop) in &conf {
        if let Some(section_name) = sec {
            let enabled = prop.get("enabled").unwrap_or("false") == "true";
            if !enabled {
                continue;
            }
            let filter = prop.get("filter").ok_or("filter not specified")?;
            let logpath = prop.get("logpath").ok_or("logpath not specified")?;
            let maxretry: u32 = prop.get("maxretry").ok_or("maxretry not specified")?.parse()?;
            let bantime: u64 = prop.get("bantime").ok_or("bantime not specified")?.parse()?;
            let filter_path = Path::new(filter_dir).join(format!("{}.conf", filter));
            let filter_content = std::fs::read_to_string(&filter_path)?;
            let regex = filter_content
                .lines()
                .filter_map(|l| {
                    if l.trim_start().starts_with("failregex") {
                        l.splitn(2, '=').nth(1).map(str::trim)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
                .join("|");
            let pattern = format!(r"<HOST> {}", regex);
            services.push(ServiceConfig {
                name: section_name.to_string(),
                log_path: logpath.to_string(),
                pattern,
                failures_threshold: maxretry,
                ban_time_secs: bantime,
                backoff_factor: None,
            });
        }
    }
    Ok(services)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load config and service definitions
    let config = load_config("config.json")?;
    // Load JSON-based service definitions
    let mut services = Vec::new();
    let mut json_services = load_services(&config.services_dir)?;
    services.extend(json_services);

    // Optionally load fail2ban-style service definitions
    if let Some(fb_conf) = &config.fail2ban_config {
        // allow custom filter directory, default to /etc/fail2ban/filter.d
        let filter_dir = config.fail2ban_filter_dir.as_deref().unwrap_or("/etc/fail2ban/filter.d");
        let mut fb_services = load_fail2ban_services(fb_conf, filter_dir)?;
        services.extend(fb_services);
    }

    // Filter services based on enabled list, if provided
    if let Some(enabled) = &config.enabled_services {
        services.retain(|svc| enabled.contains(&svc.name));
    }

    // Abort if no services remain
    if services.is_empty() {
        println!("No services configured in {}", config.services_dir);
        return Ok(());
    }

    // Load persistent state
    let state = WatcherState::load(STATE_FILE)?;
    let state_mutex = Arc::new(Mutex::new(state));

    // Prepare notifiers
    let notifiers: SharedNotifyMap = Arc::new(Mutex::new(HashMap::new()));
    for svc in &services {
        notifiers.lock().await.insert(svc.log_path.clone(), Arc::new(Notify::new()));
    }

    // Setup filesystem watcher
    let notifiers_clone = notifiers.clone();
    let mut watcher = notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
        if let Ok(event) = res {
            if let EventKind::Modify(_) = event.kind {
                for path in event.paths {
                    if let Some(p) = path.to_str() {
                        let notifiers = notifiers_clone.clone();
                        let p = p.to_string();
                        tokio::spawn(async move {
                            if let Some(n) = notifiers.lock().await.get(&p) {
                                n.notify_one();
                            }
                        });
                    }
                }
            }
        }
    })?;

    for svc in &services {
        watcher.watch(Path::new(&svc.log_path), notify::RecursiveMode::NonRecursive)?;
    }

    let ip_manager = Arc::new(IpBanManager::new());

    // Spawn monitoring tasks
    for svc in services {
        let svc_name = svc.name.clone();
        let state_mutex = state_mutex.clone();
        let notifiers = notifiers.clone();
        let ip_manager = ip_manager.clone();
        tokio::spawn(async move {
            if let Err(e) = watch_and_process_service(svc, state_mutex, notifiers, ip_manager).await {
                eprintln!(
                    "Error in service {}: {}",
                    svc_name,
                    e
                );
            }
        });
    }

    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;
    println!("Shutting down...");

    // Save state
    let final_state = state_mutex.lock().await;
    final_state.save(STATE_FILE)?;
    println!("State saved.");

    Ok(())
}

async fn watch_and_process_service(
    service: ServiceConfig,
    state_mutex: Arc<Mutex<WatcherState>>,
    notifiers: SharedNotifyMap,
    ip_manager: Arc<IpBanManager>,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(&service.log_path);
    let mut file = File::open(path).await?;
    let regex = Regex::new(&service.pattern)?;
    let mut failure_counts: HashMap<String, u32> = HashMap::new();

    loop {
        let mut state = state_mutex.lock().await;
        let mut pos = state
            .file_progress
            .get(&service.log_path)
            .copied()
            .unwrap_or(0);
        file.seek(SeekFrom::Start(pos as u64)).await?;
        let mut reader = BufReader::new(file);
        let mut line = String::new();
        while reader.read_line(&mut line).await? > 0 {
            if let Some(caps) = regex.captures(&line) {
                let ip = caps
                    .name("ip")
                    .map(|m| m.as_str().to_string())
                    .or_else(|| caps.get(1).map(|m| m.as_str().to_string()))
                    .unwrap_or_default();
                let cnt = failure_counts.entry(ip.clone()).or_insert(0);
                *cnt += 1;
                println!(
                    "Service {}: {} failed attempts from {}",
                    service.name,
                    cnt,
                    ip
                );
                if *cnt >= service.failures_threshold {
                    ip_manager.clone().ban_ip(&service, &ip).await?;
                    *cnt = 0;
                }
            }
            pos += line.len();
            line.clear();
        }
        state.file_progress.insert(service.log_path.clone(), pos);
        drop(state);
        file = reader.into_inner();

        if let Some(n) = notifiers.lock().await.get(&service.log_path) {
            n.notified().await;
        } else {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    use std::os::unix::fs::PermissionsExt;
    use std::fs::Permissions;
    use tokio::time::Duration;
    use std::sync::Arc;

    #[test]
    fn test_load_fail2ban_services() {
        let dir = tempdir().unwrap();
        let filter_dir = dir.path().join("filter.d");
        fs::create_dir_all(&filter_dir).unwrap();
        let jail_path = dir.path().join("jail.conf");
        let jail_content = r#"
[ssh]
enabled = true
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
"#;
        fs::write(&jail_path, jail_content).unwrap();
        let filter_path = filter_dir.join("sshd.conf");
        let filter_content = r#"failregex = ^%(__prefix_line)sAuthentication failure for .* from <HOST>.*$"#;
        fs::write(&filter_path, filter_content).unwrap();

        let services = load_fail2ban_services(
            jail_path.to_str().unwrap(),
            filter_dir.to_str().unwrap(),
        ).unwrap();
        assert_eq!(services.len(), 1);
        let svc = &services[0];
        assert_eq!(svc.name, "ssh");
        assert_eq!(svc.log_path, "/var/log/auth.log");
        assert_eq!(svc.failures_threshold, 5);
        assert_eq!(svc.ban_time_secs, 3600);
        assert!(svc.pattern.contains("<HOST>"));
    }

    #[tokio::test]
    async fn test_ban_ip_invokes_iptables() {
        // Prepare fake iptables binary
        let temp = tempdir().unwrap();
        let bin_dir = temp.path().join("bin");
        fs::create_dir_all(&bin_dir).unwrap();
        let calls_file = temp.path().join("calls.txt");
        let script = format!(r#"#!/bin/sh
echo "$@" >> "{}"
exit 0
+"#, calls_file.display());
        let iptables_path = bin_dir.join("iptables");
        fs::write(&iptables_path, script).unwrap();
        fs::set_permissions(&iptables_path, Permissions::from_mode(0o755)).unwrap();
        // Override PATH to pick up fake iptables
        let orig_path = std::env::var("PATH").unwrap_or_default();
        unsafe { std::env::set_var("PATH", format!("{}:{}", bin_dir.display(), orig_path)); }

        // Configure service for banning
        let service = ServiceConfig {
            name: "test".to_string(),
            log_path: "".to_string(),
            pattern: "".to_string(),
            failures_threshold: 1,
            ban_time_secs: 1,
            backoff_factor: Some(1.0),
        };
        let manager = Arc::new(IpBanManager::new());
        manager.clone().ban_ip(&service, "127.0.0.1").await.unwrap();
        // Wait for unban to execute
        Duration::from_secs(2);
        tokio::time::sleep(Duration::from_secs(2)).await;
        let content = fs::read_to_string(&calls_file).unwrap();
        assert!(content.contains("-I INPUT -s 127.0.0.1 -j DROP"));
        assert!(content.contains("-D INPUT -s 127.0.0.1 -j DROP"));
    }
}
