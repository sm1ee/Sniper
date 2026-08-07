use std::{
    env, fs,
    io::Write,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::warn;

use crate::certificate::default_data_dir;

const STARTUP_SETTINGS_FILE: &str = "startup-settings.json";
/// Retained websocket sessions, event log entries, scanner findings, fuzzer
/// attacks and sequence runs. These are small next to captured traffic — 5,000
/// findings are 3 MB and 5,000 websockets 13 MB in a real session — so the cap can
/// be generous.
const DEFAULT_MAX_ENTRIES: usize = 20_000;
/// Retained captured transactions. Raised now that they load in parallel from
/// transactions.ndjson: 100,000 records parsed in 2,408 ms inside snapshot.json
/// and parse in 331 ms as their own file, so a larger history costs less to open
/// than the old default did. They stay the bulk of a session on disk — roughly
/// 12 KB per record — so this is the knob to lower if space matters.
const DEFAULT_MAX_TRANSACTION_ENTRIES: usize = 250_000;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub proxy_addr: SocketAddr,
    pub ui_addr: SocketAddr,
    pub max_entries: usize,
    pub max_transaction_entries: usize,
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
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(default_data_dir);
        let default_proxy_addr = parse_socket_addr_value("default proxy listener", proxy_default)?;
        let startup = load_startup_settings_snapshot(&data_dir, default_proxy_addr)?;

        Ok(Self {
            proxy_addr: resolve_proxy_addr(&data_dir, &startup)?,
            ui_addr: parse_ui_socket_addr("SNIPER_UI_ADDR", ui_default)?,
            max_entries: parse_usize_min("SNIPER_MAX_ENTRIES", DEFAULT_MAX_ENTRIES, 1)?,
            max_transaction_entries: parse_usize_min(
                "SNIPER_MAX_TRANSACTION_ENTRIES",
                DEFAULT_MAX_TRANSACTION_ENTRIES,
                1,
            )?,
            body_preview_bytes: parse_usize("SNIPER_BODY_PREVIEW_BYTES", 10_485_760)?,
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
        self.proxy_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| format!("{}:{}", self.proxy_bind_host, self.proxy_port))
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
struct StoredStartupSettingsSnapshot {
    proxy_bind_host: Option<String>,
    proxy_port: Option<u16>,
    proxy_addr: Option<String>,
}

impl StoredStartupSettingsSnapshot {
    fn into_snapshot(self, default_proxy_addr: SocketAddr) -> Result<StartupSettingsSnapshot> {
        let fallback = if self.proxy_bind_host.is_some() && self.proxy_port.is_some() {
            default_proxy_addr
        } else {
            self.proxy_addr
                .as_deref()
                .map(|value| parse_socket_addr_value("startup settings proxy_addr", value))
                .transpose()?
                .unwrap_or(default_proxy_addr)
        };
        let fallback = StartupSettingsSnapshot::from_proxy_addr(fallback);
        let snapshot = StartupSettingsSnapshot {
            proxy_bind_host: self.proxy_bind_host.unwrap_or(fallback.proxy_bind_host),
            proxy_port: self.proxy_port.unwrap_or(fallback.proxy_port),
        };
        snapshot.proxy_addr()?;
        Ok(snapshot)
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct StartupSettingsUpdate {
    #[serde(default)]
    pub expected_active_session_id: Option<uuid::Uuid>,
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

fn parse_ui_socket_addr(name: &str, default: &str) -> Result<SocketAddr> {
    let addr = parse_socket_addr(name, default)?;
    validate_ui_socket_addr(name, addr)?;
    Ok(addr)
}

fn validate_ui_socket_addr(name: &str, addr: SocketAddr) -> Result<()> {
    if !addr.ip().is_loopback() {
        anyhow::bail!(
            "{name} must bind to a loopback address because Sniper's local UI API is unauthenticated"
        );
    }
    Ok(())
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

fn parse_usize_min(name: &str, default: usize, min: usize) -> Result<usize> {
    let parsed = parse_usize(name, default)?;
    if parsed < min {
        anyhow::bail!("{name} must be at least {min}");
    }
    Ok(parsed)
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
            let snapshot = serde_json::from_slice::<StoredStartupSettingsSnapshot>(&bytes)
                .with_context(|| format!("failed to parse startup settings {}", path.display()))
                .and_then(|snapshot| snapshot.into_snapshot(default_proxy_addr));
            match snapshot {
                Ok(snapshot) => Ok(snapshot),
                Err(error) => {
                    warn!(
                        %error,
                        path = %path.display(),
                        "recovering corrupt startup settings"
                    );
                    recover_startup_settings_snapshot(&path, default_proxy_addr)
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let snapshot = StartupSettingsSnapshot::from_proxy_addr(default_proxy_addr);
            persist_startup_settings(&path, &snapshot)?;
            Ok(snapshot)
        }
        Err(error) if path.exists() => {
            warn!(
                %error,
                path = %path.display(),
                "recovering unreadable startup settings"
            );
            recover_startup_settings_snapshot(&path, default_proxy_addr)
        }
        Err(error) => Err(error)
            .with_context(|| format!("failed to read startup settings {}", path.display())),
    }
}

fn recover_startup_settings_snapshot(
    path: &Path,
    default_proxy_addr: SocketAddr,
) -> Result<StartupSettingsSnapshot> {
    if path.exists() {
        let corrupt_path = path.with_file_name(format!(
            ".startup-settings.corrupt-{}.json",
            uuid::Uuid::new_v4()
        ));
        fs::rename(path, &corrupt_path).with_context(|| {
            format!(
                "failed to move corrupt startup settings {} to {}",
                path.display(),
                corrupt_path.display()
            )
        })?;
    }
    let snapshot = StartupSettingsSnapshot::from_proxy_addr(default_proxy_addr);
    persist_startup_settings(path, &snapshot)?;
    Ok(snapshot)
}

fn persist_startup_settings(path: &Path, snapshot: &StartupSettingsSnapshot) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| {
        format!(
            "failed to create startup settings directory {}",
            parent.display()
        )
    })?;
    let tmp_path = parent.join(format!(".startup-settings.{}.tmp", uuid::Uuid::new_v4()));
    let json =
        serde_json::to_vec_pretty(snapshot).context("failed to serialize startup settings")?;
    {
        let mut file = fs::File::create(&tmp_path).with_context(|| {
            format!("failed to write startup settings to {}", tmp_path.display())
        })?;
        file.write_all(&json).with_context(|| {
            format!("failed to write startup settings to {}", tmp_path.display())
        })?;
        file.sync_all()
            .with_context(|| format!("failed to sync startup settings {}", tmp_path.display()))?;
    }
    fs::rename(&tmp_path, path)
        .with_context(|| format!("failed to replace startup settings {}", path.display()))?;
    sync_directory(parent, "startup settings directory")?;
    Ok(())
}

fn sync_directory(path: &Path, label: &str) -> Result<()> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("failed to sync {label} {}", path.display()))
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
    use std::{
        ffi::OsString,
        sync::{Mutex, MutexGuard},
    };

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set<K: Into<OsString>>(key: &'static str, value: K) -> Self {
            let guard = Self {
                key,
                previous: std::env::var_os(key),
            };
            std::env::set_var(key, value.into());
            guard
        }

        fn remove(key: &'static str) -> Self {
            let guard = Self {
                key,
                previous: std::env::var_os(key),
            };
            std::env::remove_var(key);
            guard
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    fn lock_env() -> MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap()
    }

    #[test]
    fn max_entries_env_rejects_zero_retention() {
        const VAR_NAME: &str = "SNIPER_TEST_MAX_ENTRIES_ZERO";
        std::env::set_var(VAR_NAME, "0");
        let result = super::parse_usize_min(VAR_NAME, super::DEFAULT_MAX_ENTRIES, 1);
        std::env::remove_var(VAR_NAME);

        assert!(result.is_err());
    }

    #[test]
    fn ui_addr_rejects_non_loopback_bind() {
        let result =
            super::validate_ui_socket_addr("SNIPER_UI_ADDR", "0.0.0.0:23001".parse().unwrap());

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("loopback address"));
    }

    #[test]
    fn app_config_ignores_empty_sniper_data_dir_env() {
        let _guard = lock_env();
        let home =
            std::env::temp_dir().join(format!("sniper-config-home-{}", uuid::Uuid::new_v4()));
        let _home_guard = EnvVarGuard::set("HOME", home.clone().into_os_string());
        let _data_dir_guard = EnvVarGuard::set("SNIPER_DATA_DIR", "");
        let _proxy_guard = EnvVarGuard::remove("SNIPER_PROXY_ADDR");
        let _ui_guard = EnvVarGuard::remove("SNIPER_UI_ADDR");
        let _max_entries_guard = EnvVarGuard::remove("SNIPER_MAX_ENTRIES");
        let _max_transaction_entries_guard = EnvVarGuard::remove("SNIPER_MAX_TRANSACTION_ENTRIES");
        let _body_preview_guard = EnvVarGuard::remove("SNIPER_BODY_PREVIEW_BYTES");

        let config =
            super::AppConfig::from_env_with_defaults("127.0.0.1:18080", "127.0.0.1:0").unwrap();

        assert_eq!(config.data_dir, home.join(".sniper"));

        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn app_config_defaults_to_separate_http_history_retention() {
        let _guard = lock_env();
        let home =
            std::env::temp_dir().join(format!("sniper-config-retention-{}", uuid::Uuid::new_v4()));
        let _home_guard = EnvVarGuard::set("HOME", home.clone().into_os_string());
        let _data_dir_guard = EnvVarGuard::remove("SNIPER_DATA_DIR");
        let _proxy_guard = EnvVarGuard::remove("SNIPER_PROXY_ADDR");
        let _ui_guard = EnvVarGuard::remove("SNIPER_UI_ADDR");
        let _max_entries_guard = EnvVarGuard::remove("SNIPER_MAX_ENTRIES");
        let _max_transaction_entries_guard = EnvVarGuard::remove("SNIPER_MAX_TRANSACTION_ENTRIES");
        let _body_preview_guard = EnvVarGuard::remove("SNIPER_BODY_PREVIEW_BYTES");

        let config =
            super::AppConfig::from_env_with_defaults("127.0.0.1:18080", "127.0.0.1:0").unwrap();

        assert_eq!(config.max_entries, super::DEFAULT_MAX_ENTRIES);
        assert_eq!(config.max_transaction_entries, super::DEFAULT_MAX_TRANSACTION_ENTRIES);

        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn app_config_allows_transaction_retention_override() {
        let _guard = lock_env();
        let home = std::env::temp_dir().join(format!(
            "sniper-config-transaction-retention-{}",
            uuid::Uuid::new_v4()
        ));
        let _home_guard = EnvVarGuard::set("HOME", home.clone().into_os_string());
        let _data_dir_guard = EnvVarGuard::remove("SNIPER_DATA_DIR");
        let _proxy_guard = EnvVarGuard::remove("SNIPER_PROXY_ADDR");
        let _ui_guard = EnvVarGuard::remove("SNIPER_UI_ADDR");
        let _max_entries_guard = EnvVarGuard::set("SNIPER_MAX_ENTRIES", "123");
        let _max_transaction_entries_guard =
            EnvVarGuard::set("SNIPER_MAX_TRANSACTION_ENTRIES", "456");
        let _body_preview_guard = EnvVarGuard::remove("SNIPER_BODY_PREVIEW_BYTES");

        let config =
            super::AppConfig::from_env_with_defaults("127.0.0.1:18080", "127.0.0.1:0").unwrap();

        assert_eq!(config.max_entries, 123);
        assert_eq!(config.max_transaction_entries, 456);

        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn ui_addr_allows_loopback_ephemeral_bind() {
        super::validate_ui_socket_addr("SNIPER_UI_ADDR", "127.0.0.1:0".parse().unwrap()).unwrap();
        super::validate_ui_socket_addr("SNIPER_UI_ADDR", "[::1]:0".parse().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn startup_settings_store_persists_proxy_listener() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-startup-settings-{}", uuid::Uuid::new_v4()));
        let store =
            StartupSettingsStore::load_or_create(&data_dir, "127.0.0.1:18080".parse().unwrap())
                .unwrap();

        let snapshot = store
            .update(StartupSettingsUpdate {
                expected_active_session_id: None,
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
        let temp_files = std::fs::read_dir(&data_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".startup-settings.")
            })
            .count();
        assert_eq!(temp_files, 0);
    }

    #[tokio::test]
    async fn startup_settings_store_accepts_partial_legacy_snapshot() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-startup-settings-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&data_dir).expect("temp data dir should be created");
        std::fs::write(
            data_dir.join(super::STARTUP_SETTINGS_FILE),
            br#"{"proxy_bind_host":"0.0.0.0"}"#,
        )
        .expect("legacy startup settings should be written");

        let store =
            StartupSettingsStore::load_or_create(&data_dir, "127.0.0.1:18080".parse().unwrap())
                .expect("partial startup settings should load");
        let saved = store.snapshot().await;

        assert_eq!(saved.proxy_bind_host, "0.0.0.0");
        assert_eq!(saved.proxy_port, 18080);

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[tokio::test]
    async fn startup_settings_store_accepts_legacy_proxy_addr_snapshot() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-startup-settings-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&data_dir).expect("temp data dir should be created");
        std::fs::write(
            data_dir.join(super::STARTUP_SETTINGS_FILE),
            br#"{"proxy_addr":"[::1]:19090"}"#,
        )
        .expect("legacy startup settings should be written");

        let store =
            StartupSettingsStore::load_or_create(&data_dir, "127.0.0.1:18080".parse().unwrap())
                .expect("legacy proxy addr startup settings should load");
        let saved = store.snapshot().await;

        assert_eq!(saved.proxy_bind_host, "::1");
        assert_eq!(saved.proxy_port, 19090);

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[tokio::test]
    async fn startup_settings_store_recovers_corrupt_json() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-startup-settings-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&data_dir).expect("temp data dir should be created");
        std::fs::write(data_dir.join(super::STARTUP_SETTINGS_FILE), b"{not-json")
            .expect("corrupt startup settings should be written");

        let store =
            StartupSettingsStore::load_or_create(&data_dir, "127.0.0.1:18080".parse().unwrap())
                .expect("corrupt startup settings should recover");
        let saved = store.snapshot().await;

        assert_eq!(saved.proxy_bind_host, "127.0.0.1");
        assert_eq!(saved.proxy_port, 18080);
        let corrupt_files = std::fs::read_dir(&data_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".startup-settings.corrupt-")
            })
            .count();
        assert_eq!(corrupt_files, 1);

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[tokio::test]
    async fn startup_settings_store_recovers_directory_path() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-startup-settings-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(data_dir.join(super::STARTUP_SETTINGS_FILE))
            .expect("startup settings directory should be created");

        let store =
            StartupSettingsStore::load_or_create(&data_dir, "127.0.0.1:18080".parse().unwrap())
                .expect("directory startup settings should recover");
        let saved = store.snapshot().await;

        assert_eq!(saved.proxy_bind_host, "127.0.0.1");
        assert_eq!(saved.proxy_port, 18080);
        assert!(data_dir.join(super::STARTUP_SETTINGS_FILE).is_file());

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[tokio::test]
    async fn startup_settings_store_recovers_invalid_split_fields() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-startup-settings-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&data_dir).expect("temp data dir should be created");
        std::fs::write(
            data_dir.join(super::STARTUP_SETTINGS_FILE),
            br#"{"proxy_bind_host":"not an ip","proxy_port":0}"#,
        )
        .expect("invalid startup settings should be written");

        let store =
            StartupSettingsStore::load_or_create(&data_dir, "127.0.0.1:18080".parse().unwrap())
                .expect("invalid startup settings should recover");
        let saved = store.snapshot().await;

        assert_eq!(saved.proxy_bind_host, "127.0.0.1");
        assert_eq!(saved.proxy_port, 18080);

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[tokio::test]
    async fn startup_settings_prefers_valid_split_fields_over_bad_legacy_proxy_addr() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-startup-settings-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&data_dir).expect("temp data dir should be created");
        std::fs::write(
            data_dir.join(super::STARTUP_SETTINGS_FILE),
            br#"{"proxy_bind_host":"127.0.0.1","proxy_port":8080,"proxy_addr":"127.0.0.1:not-a-port"}"#,
        )
        .expect("startup settings should be written");

        let store =
            StartupSettingsStore::load_or_create(&data_dir, "127.0.0.1:18080".parse().unwrap())
                .expect("valid split startup settings should load");
        let saved = store.snapshot().await;

        assert_eq!(saved.proxy_bind_host, "127.0.0.1");
        assert_eq!(saved.proxy_port, 8080);

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn startup_settings_view_formats_ipv6_proxy_addr() {
        let snapshot = super::StartupSettingsSnapshot {
            proxy_bind_host: "::1".to_string(),
            proxy_port: 8081,
        };

        assert_eq!(snapshot.proxy_addr_string(), "[::1]:8081");
    }
}
