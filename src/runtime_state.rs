#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::{
    fs,
    io::{ErrorKind, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::warn;
use uuid::Uuid;

const RUNTIME_STATE_FILE: &str = "runtime-state.json";
const RUNTIME_STATE_LOCK_FILE: &str = ".runtime-state.lock";
const RUNTIME_OWNER_LOCK_FILE: &str = ".runtime-owner.lock";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeStateSnapshot {
    #[serde(default = "default_instance_id")]
    pub instance_id: Uuid,
    pub proxy_addr: String,
    pub ui_addr: String,
    #[serde(default)]
    pub proxy_online: bool,
    #[serde(default = "default_updated_at")]
    pub updated_at: DateTime<Utc>,
    #[serde(default = "default_app_version")]
    pub app_version: String,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub process_path: Option<String>,
}

fn default_updated_at() -> DateTime<Utc> {
    DateTime::<Utc>::from(std::time::UNIX_EPOCH)
}

fn default_app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

fn default_instance_id() -> Uuid {
    Uuid::nil()
}

impl RuntimeStateSnapshot {
    pub fn new(proxy_addr: SocketAddr, ui_addr: SocketAddr) -> Self {
        Self::with_proxy_status_and_instance(proxy_addr, ui_addr, true, Uuid::new_v4())
    }

    pub fn with_proxy_status(
        proxy_addr: SocketAddr,
        ui_addr: SocketAddr,
        proxy_online: bool,
    ) -> Self {
        Self::with_proxy_status_and_instance(proxy_addr, ui_addr, proxy_online, Uuid::new_v4())
    }

    pub fn with_proxy_status_and_instance(
        proxy_addr: SocketAddr,
        ui_addr: SocketAddr,
        proxy_online: bool,
        instance_id: Uuid,
    ) -> Self {
        let ui_addr = advertise_local_api_addr(ui_addr);
        Self {
            instance_id,
            proxy_addr: proxy_addr.to_string(),
            ui_addr: ui_addr.to_string(),
            proxy_online,
            updated_at: Utc::now(),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            pid: Some(std::process::id()),
            process_path: std::env::current_exe()
                .ok()
                .map(|path| path.display().to_string()),
        }
    }

    pub fn api_base_url(&self) -> String {
        format!("http://{}", self.ui_addr)
    }
}

pub fn advertise_local_api_addr(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
        }
        IpAddr::V6(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), addr.port())
        }
        _ => addr,
    }
}

pub fn runtime_state_path(data_dir: &Path) -> PathBuf {
    data_dir.join(RUNTIME_STATE_FILE)
}

fn runtime_state_lock_path(data_dir: &Path) -> PathBuf {
    data_dir.join(RUNTIME_STATE_LOCK_FILE)
}

pub fn load_runtime_state(data_dir: &Path) -> Result<Option<RuntimeStateSnapshot>> {
    let path = runtime_state_path(data_dir);
    if !path.exists() && !runtime_state_lock_path(data_dir).exists() {
        return Ok(None);
    }
    let _lock = lock_runtime_state(data_dir)?;
    load_runtime_state_locked(data_dir)
}

fn load_runtime_state_locked(data_dir: &Path) -> Result<Option<RuntimeStateSnapshot>> {
    let path = runtime_state_path(data_dir);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) if path.exists() => {
            warn!(
                ?error,
                path = %path.display(),
                "discarding unreadable runtime state"
            );
            move_invalid_runtime_state_aside(data_dir, &path);
            return Ok(None);
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read runtime state at {}", path.display()));
        }
    };
    let mut snapshot = match serde_json::from_slice(&bytes) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            warn!(
                ?error,
                path = %path.display(),
                "discarding corrupt runtime state"
            );
            move_invalid_runtime_state_aside(data_dir, &path);
            return Ok(None);
        }
    };
    if let Err(error) = sanitize_loaded_runtime_state(&mut snapshot) {
        warn!(
            ?error,
            path = %path.display(),
            "discarding invalid runtime state"
        );
        move_invalid_runtime_state_aside(data_dir, &path);
        return Ok(None);
    }
    Ok(Some(snapshot))
}

fn sanitize_loaded_runtime_state(snapshot: &mut RuntimeStateSnapshot) -> Result<()> {
    let proxy_addr: SocketAddr = snapshot
        .proxy_addr
        .parse()
        .context("runtime-state proxy_addr is not a socket address")?;
    let ui_addr: SocketAddr = snapshot
        .ui_addr
        .parse()
        .context("runtime-state ui_addr is not a socket address")?;
    let advertised_ui_addr = advertise_local_api_addr(ui_addr);
    snapshot.proxy_addr = proxy_addr.to_string();
    snapshot.ui_addr = advertised_ui_addr.to_string();
    Ok(())
}

fn move_invalid_runtime_state_aside(data_dir: &Path, path: &Path) {
    let corrupt_path = data_dir.join(format!(
        ".runtime-state.corrupt-{}.json",
        uuid::Uuid::new_v4()
    ));
    if let Err(rename_error) = fs::rename(path, &corrupt_path) {
        warn!(
            ?rename_error,
            path = %path.display(),
            "failed to move invalid runtime state aside"
        );
        let _ = fs::remove_file(path);
    }
}

pub fn persist_runtime_state(data_dir: &Path, snapshot: &RuntimeStateSnapshot) -> Result<()> {
    let _lock = lock_runtime_state(data_dir)?;
    persist_runtime_state_locked(data_dir, snapshot)
}

fn persist_runtime_state_locked(data_dir: &Path, snapshot: &RuntimeStateSnapshot) -> Result<()> {
    fs::create_dir_all(data_dir)
        .with_context(|| format!("failed to create data dir {}", data_dir.display()))?;
    let path = runtime_state_path(data_dir);
    let tmp_path = data_dir.join(format!(".runtime-state.{}.tmp", uuid::Uuid::new_v4()));
    let json = serde_json::to_vec_pretty(snapshot).context("failed to encode runtime state")?;
    {
        let mut file = fs::File::create(&tmp_path)
            .with_context(|| format!("failed to write runtime state to {}", tmp_path.display()))?;
        file.write_all(&json)
            .with_context(|| format!("failed to write runtime state to {}", tmp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to sync runtime state {}", tmp_path.display()))?;
    }
    if path.is_dir() {
        warn!(
            path = %path.display(),
            "moving directory runtime state aside before replace"
        );
        move_invalid_runtime_state_aside(data_dir, &path);
    }
    fs::rename(&tmp_path, &path)
        .with_context(|| format!("failed to replace runtime state at {}", path.display()))?;
    sync_directory(data_dir, "runtime state directory")?;
    Ok(())
}

pub fn remove_runtime_state(data_dir: &Path) -> Result<()> {
    let _lock = lock_runtime_state(data_dir)?;
    remove_runtime_state_locked(data_dir)
}

fn remove_runtime_state_locked(data_dir: &Path) -> Result<()> {
    let path = runtime_state_path(data_dir);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect runtime state {}", path.display()));
        }
    };
    if metadata.is_dir() {
        warn!(
            path = %path.display(),
            "moving directory runtime state aside before remove"
        );
        move_invalid_runtime_state_aside(data_dir, &path);
        return sync_directory(data_dir, "runtime state directory");
    }
    match fs::remove_file(&path) {
        Ok(()) => sync_directory(data_dir, "runtime state directory"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to remove runtime state {}", path.display()))
        }
    }
}

pub fn remove_runtime_state_if_matches(
    data_dir: &Path,
    expected: &RuntimeStateSnapshot,
) -> Result<bool> {
    let _lock = lock_runtime_state(data_dir)?;
    let Some(current) = load_runtime_state_locked(data_dir)? else {
        return Ok(false);
    };
    if !runtime_state_matches(&current, expected) {
        return Ok(false);
    }
    remove_runtime_state_locked(data_dir)?;
    Ok(true)
}

pub fn remove_runtime_state_if_same_ui_addr(
    data_dir: &Path,
    expected_ui_addr: SocketAddr,
) -> Result<bool> {
    let _lock = lock_runtime_state(data_dir)?;
    let Some(current) = load_runtime_state_locked(data_dir)? else {
        return Ok(false);
    };
    let expected_ui_addr = advertise_local_api_addr(expected_ui_addr).to_string();
    if current.ui_addr != expected_ui_addr {
        return Ok(false);
    }
    remove_runtime_state_locked(data_dir)?;
    Ok(true)
}

pub fn remove_runtime_state_if_owner(data_dir: &Path, expected_instance_id: Uuid) -> Result<bool> {
    let _lock = lock_runtime_state(data_dir)?;
    let Some(current) = load_runtime_state_locked(data_dir)? else {
        return Ok(false);
    };
    if current.instance_id != expected_instance_id {
        return Ok(false);
    }
    remove_runtime_state_locked(data_dir)?;
    Ok(true)
}

fn runtime_state_matches(left: &RuntimeStateSnapshot, right: &RuntimeStateSnapshot) -> bool {
    left.instance_id == right.instance_id
        && left.proxy_addr == right.proxy_addr
        && left.ui_addr == right.ui_addr
        && left.proxy_online == right.proxy_online
        && left.updated_at == right.updated_at
        && left.app_version == right.app_version
        && left.pid == right.pid
        && left.process_path == right.process_path
}

pub struct RuntimeOwnerLock {
    #[allow(dead_code)]
    file: fs::File,
}

pub fn try_acquire_runtime_owner_lock(data_dir: &Path) -> Result<Option<RuntimeOwnerLock>> {
    fs::create_dir_all(data_dir)
        .with_context(|| format!("failed to create data dir {}", data_dir.display()))?;
    let lock_path = data_dir.join(RUNTIME_OWNER_LOCK_FILE);
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| format!("failed to open runtime owner lock {}", lock_path.display()))?;
    if try_lock_runtime_owner_file(&file, &lock_path)? {
        Ok(Some(RuntimeOwnerLock { file }))
    } else {
        Ok(None)
    }
}

#[cfg(unix)]
fn try_lock_runtime_owner_file(file: &fs::File, lock_path: &Path) -> Result<bool> {
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        return Ok(true);
    }

    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN => Ok(false),
        _ => Err(error)
            .with_context(|| format!("failed to lock runtime owner {}", lock_path.display())),
    }
}

#[cfg(not(unix))]
fn try_lock_runtime_owner_file(_file: &fs::File, _lock_path: &Path) -> Result<bool> {
    Ok(true)
}

#[cfg(unix)]
impl Drop for RuntimeOwnerLock {
    fn drop(&mut self) {
        let result = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
        if result != 0 {
            warn!(
                error = ?std::io::Error::last_os_error(),
                "failed to unlock runtime owner"
            );
        }
    }
}

fn sync_directory(path: &Path, label: &str) -> Result<()> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("failed to sync {label} {}", path.display()))
}

struct RuntimeStateLock {
    #[allow(dead_code)]
    file: fs::File,
}

fn lock_runtime_state(data_dir: &Path) -> Result<RuntimeStateLock> {
    fs::create_dir_all(data_dir)
        .with_context(|| format!("failed to create data dir {}", data_dir.display()))?;
    let lock_path = runtime_state_lock_path(data_dir);
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| format!("failed to open runtime state lock {}", lock_path.display()))?;
    lock_runtime_state_file(&file, &lock_path)?;
    Ok(RuntimeStateLock { file })
}

#[cfg(unix)]
fn lock_runtime_state_file(file: &fs::File, lock_path: &Path) -> Result<()> {
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to lock runtime state {}", lock_path.display()))
    }
}

#[cfg(not(unix))]
fn lock_runtime_state_file(_file: &fs::File, _lock_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
impl Drop for RuntimeStateLock {
    fn drop(&mut self) {
        let result = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
        if result != 0 {
            warn!(
                error = ?std::io::Error::last_os_error(),
                "failed to unlock runtime state"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, net::SocketAddr, sync::mpsc, time::Duration};

    use super::{
        advertise_local_api_addr, load_runtime_state, persist_runtime_state, remove_runtime_state,
        remove_runtime_state_if_owner, remove_runtime_state_if_same_ui_addr, runtime_state_path,
        try_acquire_runtime_owner_lock, RuntimeStateSnapshot, RUNTIME_OWNER_LOCK_FILE,
        RUNTIME_STATE_LOCK_FILE,
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

        assert_eq!(loaded.instance_id, snapshot.instance_id);
        assert_eq!(loaded.proxy_addr, snapshot.proxy_addr);
        assert_eq!(loaded.ui_addr, snapshot.ui_addr);
        assert_eq!(loaded.pid, Some(std::process::id()));
        assert_eq!(loaded.process_path, snapshot.process_path);
        assert!(loaded.proxy_online);
        assert!(runtime_state_path(&temp_dir).exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn runtime_owner_lock_rejects_second_owner_until_released() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sniper-runtime-owner-lock-{}",
            uuid::Uuid::new_v4()
        ));
        let _ = fs::remove_dir_all(&temp_dir);

        let first = try_acquire_runtime_owner_lock(&temp_dir).unwrap().unwrap();

        assert!(temp_dir.join(RUNTIME_OWNER_LOCK_FILE).exists());
        assert!(try_acquire_runtime_owner_lock(&temp_dir).unwrap().is_none());

        drop(first);
        assert!(try_acquire_runtime_owner_lock(&temp_dir).unwrap().is_some());

        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn runtime_state_advertises_loopback_for_wildcard_ui_binds() {
        assert_eq!(
            advertise_local_api_addr("0.0.0.0:23001".parse().unwrap()).to_string(),
            "127.0.0.1:23001"
        );
        assert_eq!(
            advertise_local_api_addr("[::]:23001".parse().unwrap()).to_string(),
            "[::1]:23001"
        );

        let snapshot = RuntimeStateSnapshot::with_proxy_status(
            "127.0.0.1:8080".parse().unwrap(),
            "0.0.0.0:23001".parse().unwrap(),
            true,
        );
        assert_eq!(snapshot.api_base_url(), "http://127.0.0.1:23001");
    }

    #[test]
    fn runtime_state_remove_deletes_file_and_accepts_missing_file() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sniper-runtime-state-remove-{}",
            uuid::Uuid::new_v4()
        ));
        let snapshot = RuntimeStateSnapshot::new(
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
            "127.0.0.1:9000".parse::<SocketAddr>().unwrap(),
        );
        persist_runtime_state(&temp_dir, &snapshot).unwrap();
        assert!(runtime_state_path(&temp_dir).exists());

        remove_runtime_state(&temp_dir).unwrap();
        assert!(!runtime_state_path(&temp_dir).exists());
        remove_runtime_state(&temp_dir).unwrap();

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn runtime_state_remove_if_matches_preserves_replaced_snapshot() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sniper-runtime-state-remove-match-{}",
            uuid::Uuid::new_v4()
        ));
        let expected = RuntimeStateSnapshot::new(
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
            "127.0.0.1:9000".parse::<SocketAddr>().unwrap(),
        );
        let replacement = RuntimeStateSnapshot::new(
            "127.0.0.1:8081".parse::<SocketAddr>().unwrap(),
            "127.0.0.1:9001".parse::<SocketAddr>().unwrap(),
        );
        persist_runtime_state(&temp_dir, &expected).unwrap();
        persist_runtime_state(&temp_dir, &replacement).unwrap();

        assert!(!super::remove_runtime_state_if_matches(&temp_dir, &expected).unwrap());
        assert!(runtime_state_path(&temp_dir).exists());
        let loaded = load_runtime_state(&temp_dir).unwrap().unwrap();
        assert_eq!(loaded.ui_addr, replacement.ui_addr);

        assert!(super::remove_runtime_state_if_matches(&temp_dir, &replacement).unwrap());
        assert!(!runtime_state_path(&temp_dir).exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn runtime_state_remove_if_same_ui_addr_deletes_matching_owner() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sniper-runtime-state-remove-ui-match-{}",
            uuid::Uuid::new_v4()
        ));
        let snapshot = RuntimeStateSnapshot::with_proxy_status(
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
            "0.0.0.0:9000".parse::<SocketAddr>().unwrap(),
            false,
        );
        persist_runtime_state(&temp_dir, &snapshot).unwrap();

        assert!(
            remove_runtime_state_if_same_ui_addr(&temp_dir, "127.0.0.1:9000".parse().unwrap())
                .unwrap()
        );
        assert!(!runtime_state_path(&temp_dir).exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn runtime_state_remove_if_same_ui_addr_preserves_other_owner() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sniper-runtime-state-remove-ui-mismatch-{}",
            uuid::Uuid::new_v4()
        ));
        let snapshot = RuntimeStateSnapshot::new(
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
            "127.0.0.1:9001".parse::<SocketAddr>().unwrap(),
        );
        persist_runtime_state(&temp_dir, &snapshot).unwrap();

        assert!(!remove_runtime_state_if_same_ui_addr(
            &temp_dir,
            "127.0.0.1:9000".parse().unwrap()
        )
        .unwrap());
        assert!(runtime_state_path(&temp_dir).exists());
        let loaded = load_runtime_state(&temp_dir).unwrap().unwrap();
        assert_eq!(loaded.ui_addr, snapshot.ui_addr);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn runtime_state_remove_if_owner_deletes_matching_instance() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sniper-runtime-state-remove-owner-match-{}",
            uuid::Uuid::new_v4()
        ));
        let snapshot = RuntimeStateSnapshot::new(
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
            "127.0.0.1:9000".parse::<SocketAddr>().unwrap(),
        );
        persist_runtime_state(&temp_dir, &snapshot).unwrap();

        assert!(remove_runtime_state_if_owner(&temp_dir, snapshot.instance_id).unwrap());
        assert!(!runtime_state_path(&temp_dir).exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn runtime_state_remove_if_owner_preserves_other_instance_on_same_ui_addr() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sniper-runtime-state-remove-owner-mismatch-{}",
            uuid::Uuid::new_v4()
        ));
        let snapshot = RuntimeStateSnapshot::new(
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
            "127.0.0.1:9000".parse::<SocketAddr>().unwrap(),
        );
        persist_runtime_state(&temp_dir, &snapshot).unwrap();

        assert!(!remove_runtime_state_if_owner(&temp_dir, uuid::Uuid::new_v4()).unwrap());
        assert!(runtime_state_path(&temp_dir).exists());
        let loaded = load_runtime_state(&temp_dir).unwrap().unwrap();
        assert_eq!(loaded.instance_id, snapshot.instance_id);
        assert_eq!(loaded.ui_addr, snapshot.ui_addr);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn runtime_state_load_accepts_missing_file() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sniper-runtime-state-missing-{}",
            uuid::Uuid::new_v4()
        ));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let loaded = load_runtime_state(&temp_dir).unwrap();

        assert!(loaded.is_none());
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn runtime_state_load_missing_file_does_not_create_paths() {
        let absent_dir = std::env::temp_dir().join(format!(
            "sniper-runtime-state-absent-dir-{}",
            uuid::Uuid::new_v4()
        ));
        let _ = fs::remove_dir_all(&absent_dir);

        let loaded = load_runtime_state(&absent_dir).unwrap();

        assert!(loaded.is_none());
        assert!(!absent_dir.exists());

        let empty_dir = std::env::temp_dir().join(format!(
            "sniper-runtime-state-empty-dir-{}",
            uuid::Uuid::new_v4()
        ));
        let _ = fs::remove_dir_all(&empty_dir);
        fs::create_dir_all(&empty_dir).unwrap();

        let loaded = load_runtime_state(&empty_dir).unwrap();

        assert!(loaded.is_none());
        assert!(!empty_dir.join(RUNTIME_STATE_LOCK_FILE).exists());
        let _ = fs::remove_dir_all(&empty_dir);
    }

    #[test]
    fn runtime_state_load_waits_on_existing_lock_before_declaring_missing() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sniper-runtime-state-existing-lock-{}",
            uuid::Uuid::new_v4()
        ));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();
        let lock = super::lock_runtime_state(&temp_dir).unwrap();
        let snapshot = RuntimeStateSnapshot::new(
            "127.0.0.1:18080".parse::<SocketAddr>().unwrap(),
            "127.0.0.1:23001".parse::<SocketAddr>().unwrap(),
        );
        let (tx, rx) = mpsc::channel();
        let load_dir = temp_dir.clone();
        let handle = std::thread::spawn(move || {
            tx.send(load_runtime_state(&load_dir).unwrap()).unwrap();
        });

        std::thread::sleep(Duration::from_millis(50));
        assert!(rx.try_recv().is_err());

        fs::write(
            runtime_state_path(&temp_dir),
            serde_json::to_vec_pretty(&snapshot).unwrap(),
        )
        .unwrap();
        drop(lock);

        let loaded = rx.recv_timeout(Duration::from_secs(2)).unwrap().unwrap();
        assert_eq!(loaded.ui_addr, snapshot.ui_addr);
        handle.join().unwrap();
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn runtime_state_accepts_legacy_missing_metadata() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sniper-runtime-state-legacy-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        fs::write(
            runtime_state_path(&temp_dir),
            br#"{"proxy_addr":"127.0.0.1:18080","ui_addr":"127.0.0.1:23001"}"#,
        )
        .unwrap();

        let loaded = load_runtime_state(&temp_dir).unwrap().unwrap();

        assert_eq!(loaded.proxy_addr, "127.0.0.1:18080");
        assert_eq!(loaded.ui_addr, "127.0.0.1:23001");
        assert_eq!(loaded.instance_id, uuid::Uuid::nil());
        assert_eq!(
            loaded.updated_at,
            chrono::DateTime::<chrono::Utc>::from(std::time::UNIX_EPOCH)
        );
        assert!(!loaded.proxy_online);
        assert_eq!(loaded.app_version, env!("CARGO_PKG_VERSION"));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn runtime_state_load_normalizes_wildcard_ui_addr() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sniper-runtime-state-wildcard-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        fs::write(
            runtime_state_path(&temp_dir),
            br#"{"proxy_addr":"127.0.0.1:18080","ui_addr":"0.0.0.0:23001"}"#,
        )
        .unwrap();

        let loaded = load_runtime_state(&temp_dir).unwrap().unwrap();

        assert_eq!(loaded.proxy_addr, "127.0.0.1:18080");
        assert_eq!(loaded.ui_addr, "127.0.0.1:23001");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn runtime_state_load_preserves_specific_non_loopback_ui_addr() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sniper-runtime-state-specific-ui-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        fs::write(
            runtime_state_path(&temp_dir),
            br#"{"proxy_addr":"127.0.0.1:18080","ui_addr":"192.0.2.1:23001"}"#,
        )
        .unwrap();

        let loaded = load_runtime_state(&temp_dir).unwrap().unwrap();

        assert_eq!(loaded.proxy_addr, "127.0.0.1:18080");
        assert_eq!(loaded.ui_addr, "192.0.2.1:23001");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn runtime_state_ignores_and_moves_invalid_socket_addr() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sniper-runtime-state-invalid-{}",
            uuid::Uuid::new_v4()
        ));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();
        fs::write(
            runtime_state_path(&temp_dir),
            br#"{"proxy_addr":"127.0.0.1:18080","ui_addr":"not-an-addr"}"#,
        )
        .unwrap();

        let loaded = load_runtime_state(&temp_dir).unwrap();

        assert!(loaded.is_none());
        assert!(!runtime_state_path(&temp_dir).exists());
        assert!(fs::read_dir(&temp_dir).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".runtime-state.corrupt-")
        }));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn runtime_state_ignores_and_moves_directory_path() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sniper-runtime-state-directory-{}",
            uuid::Uuid::new_v4()
        ));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(runtime_state_path(&temp_dir)).unwrap();

        let loaded = load_runtime_state(&temp_dir).unwrap();

        assert!(loaded.is_none());
        assert!(!runtime_state_path(&temp_dir).exists());
        assert!(fs::read_dir(&temp_dir).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".runtime-state.corrupt-")
        }));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn runtime_state_persist_replaces_directory_path() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sniper-runtime-state-persist-directory-{}",
            uuid::Uuid::new_v4()
        ));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(runtime_state_path(&temp_dir)).unwrap();
        let snapshot = RuntimeStateSnapshot::new(
            "127.0.0.1:18080".parse::<SocketAddr>().unwrap(),
            "127.0.0.1:23001".parse::<SocketAddr>().unwrap(),
        );

        persist_runtime_state(&temp_dir, &snapshot).unwrap();
        let loaded = load_runtime_state(&temp_dir).unwrap().unwrap();

        assert_eq!(loaded.ui_addr, "127.0.0.1:23001");
        assert!(runtime_state_path(&temp_dir).is_file());
        assert!(fs::read_dir(&temp_dir).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".runtime-state.corrupt-")
        }));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn runtime_state_remove_moves_directory_path() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sniper-runtime-state-remove-directory-{}",
            uuid::Uuid::new_v4()
        ));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(runtime_state_path(&temp_dir)).unwrap();

        remove_runtime_state(&temp_dir).unwrap();

        assert!(!runtime_state_path(&temp_dir).exists());
        assert!(fs::read_dir(&temp_dir).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".runtime-state.corrupt-")
        }));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn runtime_state_ignores_and_moves_corrupt_json() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sniper-runtime-state-corrupt-{}",
            uuid::Uuid::new_v4()
        ));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();
        fs::write(runtime_state_path(&temp_dir), b"{not json").unwrap();

        let loaded = load_runtime_state(&temp_dir).unwrap();

        assert!(loaded.is_none());
        assert!(!runtime_state_path(&temp_dir).exists());
        assert!(fs::read_dir(&temp_dir).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".runtime-state.corrupt-")
        }));

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
