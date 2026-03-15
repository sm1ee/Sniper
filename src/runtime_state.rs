use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

const RUNTIME_STATE_FILE: &str = "runtime-state.json";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeStateSnapshot {
    pub proxy_addr: String,
    pub ui_addr: String,
    pub updated_at: DateTime<Utc>,
    pub app_version: String,
}

impl RuntimeStateSnapshot {
    pub fn new(proxy_addr: SocketAddr, ui_addr: SocketAddr) -> Self {
        Self {
            proxy_addr: proxy_addr.to_string(),
            ui_addr: ui_addr.to_string(),
            updated_at: Utc::now(),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    pub fn api_base_url(&self) -> String {
        format!("http://{}", self.ui_addr)
    }
}

pub fn runtime_state_path(data_dir: &Path) -> PathBuf {
    data_dir.join(RUNTIME_STATE_FILE)
}

pub fn load_runtime_state(data_dir: &Path) -> Result<Option<RuntimeStateSnapshot>> {
    let path = runtime_state_path(data_dir);
    if !path.exists() {
        return Ok(None);
    }

    let bytes = fs::read(&path)
        .with_context(|| format!("failed to read runtime state at {}", path.display()))?;
    let snapshot = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to decode runtime state at {}", path.display()))?;
    Ok(Some(snapshot))
}

pub fn persist_runtime_state(data_dir: &Path, snapshot: &RuntimeStateSnapshot) -> Result<()> {
    fs::create_dir_all(data_dir)
        .with_context(|| format!("failed to create data dir {}", data_dir.display()))?;
    let path = runtime_state_path(data_dir);
    let json = serde_json::to_vec_pretty(snapshot).context("failed to encode runtime state")?;
    fs::write(&path, json)
        .with_context(|| format!("failed to write runtime state to {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::{fs, net::SocketAddr};

    use super::{
        load_runtime_state, persist_runtime_state, runtime_state_path, RuntimeStateSnapshot,
    };

    #[test]
    fn runtime_state_round_trip() {
        let temp_dir =
            std::env::temp_dir().join(format!("sniper-runtime-state-{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let snapshot = RuntimeStateSnapshot::new(
            "127.0.0.1:18080".parse::<SocketAddr>().unwrap(),
            "127.0.0.1:13000".parse::<SocketAddr>().unwrap(),
        );
        persist_runtime_state(&temp_dir, &snapshot).unwrap();
        let loaded = load_runtime_state(&temp_dir).unwrap().unwrap();

        assert_eq!(loaded.proxy_addr, snapshot.proxy_addr);
        assert_eq!(loaded.ui_addr, snapshot.ui_addr);
        assert!(runtime_state_path(&temp_dir).exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
