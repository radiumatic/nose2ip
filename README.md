# nose2ban

It's mostly a clone of fail2ban. 

## Features

- A log‐watcher and IP ban manager written in Rust
- Supports both JSON‐based service definitions and fail2ban‐style INI/Jail configurations (via `rust-ini`)
- Uses asynchronous I/O and file‐watch notifications (`tokio`, `notify`)
- Applies bans with `iptables`, then automatically unbans after the configured duration

## How it works

1. **Load configurations**
   - Reads `config.json` to find:
     - `services_dir` (directory of per-service JSON files)
     - Optional `fail2ban_config` (jail INI file) and `fail2ban_filter_dir`
     - Optional `enabled_services` list
   - Parses each JSON service file (`ServiceConfig`) or fail2ban section (`load_fail2ban_services`).
2. **Initialize state**
   - Restores position in each log file from `watcher_state.json` if present.
3. **Watch logs**
   - Uses `notify` to get file‐modify events
   - Applies a configurable regex pattern to each line to extract the offending IP
4. **Count failures & ban**
   - Maintains in‐memory failure counts per IP
   - When a count reaches `failures_threshold`, invokes `iptables -I INPUT -s <IP> -j DROP`
   - Schedules unban after `ban_time_secs * backoff^n` seconds using `tokio::spawn`
5. **Persist progress**
   - On shutdown (Ctrl+C), saves file offsets back to `watcher_state.json`.

## Setup & Configuration

1. **Prerequisites**
   - Rust toolchain (Rust 1.86+)
   - `iptables` available in `$PATH` and root privileges to execute it
2. **Clone & build**
   ```bash
   git clone https://github.com/radiumatic/nose2ban
   cd nose2ban
   cargo build --release
   ```
3. **Create configuration files**

   a) `config.json` at project root:
   ```json
   {
     "services_dir": "services",
     "enabled_services": ["ssh"],
     "fail2ban_config": "jail.conf",
     "fail2ban_filter_dir": "filter.d"
   }
   ```

   b) Example JSON service (e.g. `services/ssh.json`):
   ```json
   {
     "name": "ssh",
     "log_path": "/var/log/auth.log",
     "pattern": "<HOST> sshd failure",
     "failures_threshold": 5,
     "ban_time_secs": 3600,
     "backoff_factor": 2.0
   }
   ```

   c) Example fail2ban jail (e.g. `jail.conf`):
   ```ini
   [ssh]
   enabled = true
   filter  = sshd
   logpath = /var/log/auth.log
   maxretry = 5
   bantime = 3600
   ```

   d) Matching filter regex (e.g. `filter.d/sshd.conf`):
   ```ini
   failregex = ^%(__prefix_line)sAuthentication failure for .* from <HOST>.*$
   ```

## Running

- **Tests (no real `iptables` calls)**
  ```bash
  cargo test
  ```
- **Production run** (requires root to modify iptables):
  ```bash
  sudo cargo run --release
  ```

Logs will be tailed continuously. Press Ctrl+C to stop and persist state.

