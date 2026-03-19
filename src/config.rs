use std::{
    env, fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::certificate::default_data_dir;

const STARTUP_SETTINGS_FILE: &str = "startup-settings.json";

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub proxy_addr: SocketAddr,
    pub ui_addr: SocketAddr,
    pub max_entries: usize,
    pub body_preview_bytes: usize,
    pub data_dir: PathBuf,
}

impl AppConfig {
    pub fn from_env() -> Result<Self> {
        Self::from_env_with_defaults("127.0.0.1:8080", "127.0.0.1:23001")
    }

    pub fn from_env_for_desktop() -> Result<Self> {
        Self::from_env_with_defaults("127.0.0.1:8080", "127.0.0.1:0")
    }

    pub fn from_env_with_defaults(proxy_default: &str, ui_default: &str) -> Result<Self> {
        let data_dir = env::var_os("SNIPER_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(default_data_dir);
        let default_proxy_addr = parse_socket_addr_value("default proxy listener", proxy_default)?;
        let startup = load_startup_settings_snapshot(&data_dir, default_proxy_addr)?;

        Ok(Self {
            proxy_addr: resolve_proxy_addr(&data_dir, &startup)?,
            ui_addr: parse_socket_addr("SNIPER_UI_ADDR", ui_default)?,
            max_entries: parse_usize("SNIPER_MAX_ENTRIES", 500)?,
            body_preview_bytes: parse_usize("SNIPER_BODY_PREVIEW_BYTES", 65_536)?,
            data_dir,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StartupSettingsSnapshot {
    pub proxy_bind_host: String,
    pub proxy_port: u16,
}

impl StartupSettingsSnapshot {
    pub fn from_proxy_addr(addr: SocketAddr) -> Self {
        Self {
            proxy_bind_host: addr.ip().to_string(),
            proxy_port: addr.port(),
        }
    }

    pub fn proxy_addr(&self) -> Result<SocketAddr> {
        parse_bind_socket_addr(&self.proxy_bind_host, self.proxy_port)
    }

    pub fn proxy_addr_string(&self) -> String {
        format!("{}:{}", self.proxy_bind_host, self.proxy_port)
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct StartupSettingsUpdate {
    pub proxy_bind_host: Option<String>,
    pub proxy_port: Option<u16>,
}

#[derive(Clone, Debug, Serialize)]
pub struct StartupSettingsView {
    pub proxy_bind_host: String,
    pub proxy_port: u16,
    pub proxy_addr: String,
    pub active_proxy_addr: String,
    pub restart_required: bool,
    pub file_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rebound: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rebind_error: Option<String>,
}

pub struct StartupSettingsStore {
    path: PathBuf,
    inner: RwLock<StartupSettingsSnapshot>,
}

impl StartupSettingsStore {
    pub fn load_or_create(data_dir: &Path, active_proxy_addr: SocketAddr) -> Result<Self> {
        let snapshot = load_startup_settings_snapshot(data_dir, active_proxy_addr)?;
        Ok(Self {
            path: startup_settings_path(data_dir),
            inner: RwLock::new(snapshot),
        })
    }

    pub async fn view(&self, active_proxy_addr: SocketAddr) -> StartupSettingsView {
        let snapshot = self.snapshot().await;
        StartupSettingsView {
            proxy_bind_host: snapshot.proxy_bind_host.clone(),
            proxy_port: snapshot.proxy_port,
            proxy_addr: snapshot.proxy_addr_string(),
            active_proxy_addr: active_proxy_addr.to_string(),
            restart_required: snapshot
                .proxy_addr()
                .map_or(true, |addr| addr != active_proxy_addr),
            file_path: self.path.display().to_string(),
            rebound: None,
            rebind_error: None,
        }
    }

    pub async fn snapshot(&self) -> StartupSettingsSnapshot {
        self.inner.read().await.clone()
    }

    pub async fn update(&self, update: StartupSettingsUpdate) -> Result<StartupSettingsSnapshot> {
        let mut current = self.inner.write().await;
        let mut next = current.clone();

        if let Some(proxy_bind_host) = update.proxy_bind_host {
            next.proxy_bind_host = normalize_bind_host(&proxy_bind_host)?;
        }

        if let Some(proxy_port) = update.proxy_port {
            next.proxy_port = validate_proxy_port(proxy_port)?;
        }

        next.proxy_addr()?;
        persist_startup_settings(&self.path, &next)?;
        *current = next.clone();
        Ok(next)
    }
}

fn parse_socket_addr(name: &str, default: &str) -> Result<SocketAddr> {
    let value = env::var(name).unwrap_or_else(|_| default.to_string());
    parse_socket_addr_value(name, &value)
}

fn parse_socket_addr_value(name: &str, value: &str) -> Result<SocketAddr> {
    value
        .parse()
        .with_context(|| format!("failed to parse {name}={value} as socket address"))
}

fn parse_usize(name: &str, default: usize) -> Result<usize> {
    let value = env::var(name).unwrap_or_else(|_| default.to_string());
    value
        .parse()
        .with_context(|| format!("failed to parse {name}={value} as usize"))
}

fn resolve_proxy_addr(data_dir: &Path, startup: &StartupSettingsSnapshot) -> Result<SocketAddr> {
    if let Ok(value) = env::var("SNIPER_PROXY_ADDR") {
        return parse_socket_addr_value("SNIPER_PROXY_ADDR", &value);
    }

    load_startup_settings_snapshot(data_dir, startup.proxy_addr()?)?.proxy_addr()
}

fn startup_settings_path(data_dir: &Path) -> PathBuf {
    data_dir.join(STARTUP_SETTINGS_FILE)
}

fn load_startup_settings_snapshot(
    data_dir: &Path,
    default_proxy_addr: SocketAddr,
) -> Result<StartupSettingsSnapshot> {
    fs::create_dir_all(data_dir).with_context(|| {
        format!(
            "failed to create startup settings directory {}",
            data_dir.display()
        )
    })?;
    let path = startup_settings_path(data_dir);
    match fs::read(&path) {
        Ok(bytes) => {
            let snapshot = serde_json::from_slice::<StartupSettingsSnapshot>(&bytes)
                .with_context(|| format!("failed to parse startup settings {}", path.display()))?;
            snapshot.proxy_addr()?;
            Ok(snapshot)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let snapshot = StartupSettingsSnapshot::from_proxy_addr(default_proxy_addr);
            persist_startup_settings(&path, &snapshot)?;
            Ok(snapshot)
        }
        Err(error) => Err(error)
            .with_context(|| format!("failed to read startup settings {}", path.display())),
    }
}

fn persist_startup_settings(path: &Path, snapshot: &StartupSettingsSnapshot) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create startup settings directory {}",
                parent.display()
            )
        })?;
    }
    fs::write(
        path,
        serde_json::to_vec_pretty(snapshot).context("failed to serialize startup settings")?,
    )
    .with_context(|| format!("failed to write startup settings {}", path.display()))
}

fn parse_bind_socket_addr(bind_host: &str, port: u16) -> Result<SocketAddr> {
    let host = normalize_bind_host(bind_host)?;
    let port = validate_proxy_port(port)?;
    let ip = host
        .parse::<IpAddr>()
        .with_context(|| format!("failed to parse bind host {host} as an IP address"))?;
    Ok(SocketAddr::new(ip, port))
}

fn normalize_bind_host(value: &str) -> Result<String> {
    let host = value.trim();
    if host.is_empty() {
        return Err(anyhow::anyhow!("proxy bind host cannot be empty"));
    }
    host.parse::<IpAddr>()
        .with_context(|| format!("failed to parse bind host {host} as an IP address"))?;
    Ok(host.to_string())
}

fn validate_proxy_port(port: u16) -> Result<u16> {
    if port == 0 {
        return Err(anyhow::anyhow!("proxy port must be between 1 and 65535"));
    }
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::{StartupSettingsStore, StartupSettingsUpdate};

    #[tokio::test]
    async fn startup_settings_store_persists_proxy_listener() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-startup-settings-{}", uuid::Uuid::new_v4()));
        let store =
            StartupSettingsStore::load_or_create(&data_dir, "127.0.0.1:18080".parse().unwrap())
                .unwrap();

        let snapshot = store
            .update(StartupSettingsUpdate {
                proxy_bind_host: Some("0.0.0.0".to_string()),
                proxy_port: Some(8081),
            })
            .await
            .unwrap();

        assert_eq!(snapshot.proxy_bind_host, "0.0.0.0");
        assert_eq!(snapshot.proxy_port, 8081);

        let reloaded =
            StartupSettingsStore::load_or_create(&data_dir, "127.0.0.1:18080".parse().unwrap())
                .unwrap();
        let saved = reloaded.snapshot().await;
        assert_eq!(saved.proxy_bind_host, "0.0.0.0");
        assert_eq!(saved.proxy_port, 8081);
    }
}
