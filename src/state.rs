use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct WatcherState {
    pub file_progress: HashMap<String, usize>,
}

impl WatcherState {
    pub fn load<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let path = path.as_ref();
        if path.exists() {
            let data = fs::read_to_string(path)?;
            let state = serde_json::from_str(&data)?;
            Ok(state)
        } else {
            Ok(Self { file_progress: HashMap::new() })
        }
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let data = serde_json::to_string_pretty(self)?;
        fs::write(path, data)
    }
}
