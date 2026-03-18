use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use anyhow::Context;
use anyhow::Result;
use reqwest::StatusCode;
use semver::Version;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use crate::{
    certificate::{CertificateAuthority, CertificateExport},
    config::{AppConfig, StartupSettingsStore, StartupSettingsView},
    event_log::EventLevel,
    session::{SessionContext, SessionRegistry, SessionSummary},
    ui_settings::AppUiSettingsStore,
};

const MAX_WEBSOCKET_FRAMES_PER_SESSION: usize = 200;
const APP_RELEASES_URL: &str = "https://github.com/sm1ee/Sniper/releases";
const APP_LATEST_RELEASE_API_URL: &str =
    "https://api.github.com/repos/sm1ee/Sniper/releases/latest";
const APP_VERSION_CACHE_TTL: Duration = Duration::from_secs(30 * 60);
const APP_VERSION_FETCH_TIMEOUT: Duration = Duration::from_millis(1500);

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub certificates: Arc<CertificateAuthority>,
    pub startup: Arc<StartupSettingsStore>,
    pub ui_settings: Arc<AppUiSettingsStore>,
    pub sessions: Arc<SessionRegistry>,
    pub proxy_online: Arc<AtomicBool>,
    active_session: Arc<RwLock<Arc<SessionContext>>>,
    app_version_cache: Arc<RwLock<Option<CachedAppVersionInfo>>>,
    /// The currently active proxy listener address (mutable — updated on rebind).
    pub active_proxy_addr: Arc<RwLock<SocketAddr>>,
    /// Handle for the running proxy task so it can be aborted on rebind.
    proxy_task: Arc<RwLock<Option<JoinHandle<()>>>>,
}

impl AppState {
    pub fn new(config: AppConfig) -> Result<Self> {
        let certificates = Arc::new(CertificateAuthority::load_or_create(&config.data_dir)?);
        let startup = Arc::new(StartupSettingsStore::load_or_create(
            &config.data_dir,
            config.proxy_addr,
        )?);
        let ui_settings = Arc::new(AppUiSettingsStore::load_or_create(&config.data_dir)?);
        let (sessions, active_session) = SessionRegistry::load_or_create(
            &config.data_dir,
            config.max_entries,
            MAX_WEBSOCKET_FRAMES_PER_SESSION,
        )?;

        let active_proxy_addr = config.proxy_addr;
        Ok(Self {
            config,
            certificates,
            startup,
            ui_settings,
            sessions: Arc::new(sessions),
            proxy_online: Arc::new(AtomicBool::new(false)),
            active_session: Arc::new(RwLock::new(active_session)),
            app_version_cache: Arc::new(RwLock::new(None)),
            active_proxy_addr: Arc::new(RwLock::new(active_proxy_addr)),
            proxy_task: Arc::new(RwLock::new(None)),
        })
    }

    pub fn set_proxy_online(&self, online: bool) {
        self.proxy_online.store(online, Ordering::Relaxed);
    }

    pub fn is_proxy_online(&self) -> bool {
        self.proxy_online.load(Ordering::Relaxed)
    }

    pub async fn session(&self) -> Arc<SessionContext> {
        self.active_session.read().await.clone()
    }

    pub fn list_sessions(&self) -> Vec<SessionSummary> {
        self.sessions.summaries()
    }

    pub async fn active_session_summary(&self) -> SessionSummary {
        let active_id = self.sessions.active_session_id();
        self.session()
            .await
            .summary(active_id == self.sessions.active_session_id())
    }

    pub async fn create_session(&self, name: Option<String>) -> Result<SessionSummary> {
        let metadata = self.sessions.create_session(name)?;
        self.activate_session(metadata.id).await
    }

    pub async fn activate_session(&self, id: uuid::Uuid) -> Result<SessionSummary> {
        let current = self.session().await;
        let current_id = current.id();
        if current_id != id {
            self.persist_session_context(&current).await?;
        }

        let metadata = self.sessions.activate_session(id)?;
        let session = self.sessions.load_context(id)?;
        *self.active_session.write().await = session.clone();
        Ok(session.summary(metadata.id == self.sessions.active_session_id()))
    }

    pub async fn persist_active_session(&self) -> Result<SessionSummary> {
        let session = self.session().await;
        self.persist_session_context(&session).await
    }

    pub async fn persist_session_context(
        &self,
        session: &Arc<SessionContext>,
    ) -> Result<SessionSummary> {
        let metadata = session.persist().await?;
        self.sessions.update_metadata(metadata)?;
        Ok(session.summary(session.id() == self.sessions.active_session_id()))
    }

    pub async fn get_active_proxy_addr(&self) -> SocketAddr {
        *self.active_proxy_addr.read().await
    }

    pub async fn set_active_proxy_addr(&self, addr: SocketAddr) {
        *self.active_proxy_addr.write().await = addr;
    }

    pub async fn set_proxy_task(&self, handle: JoinHandle<()>) {
        let mut guard = self.proxy_task.write().await;
        if let Some(old) = guard.take() {
            old.abort();
        }
        *guard = Some(handle);
    }

    pub async fn abort_proxy_task(&self) {
        let mut guard = self.proxy_task.write().await;
        if let Some(old) = guard.take() {
            old.abort();
            // Wait for the task to actually finish so its TcpListener is dropped
            // and the OS releases the socket before we try to rebind.
            let _ = old.await;
        }
    }

    pub async fn runtime_info(&self) -> RuntimeInfo {
        let session = self.session().await;
        let active_addr = self.get_active_proxy_addr().await;
        RuntimeInfo {
            proxy_addr: active_addr.to_string(),
            ui_addr: self.config.ui_addr.to_string(),
            max_entries: self.config.max_entries,
            body_preview_bytes: self.config.body_preview_bytes,
            data_dir: self.config.data_dir.display().to_string(),
            proxy_online: self.is_proxy_online(),
            features: vec![
                "http_capture".to_string(),
                "connect_tunnel".to_string(),
                "https_mitm".to_string(),
                "special_https_host".to_string(),
                "root_ca_export".to_string(),
                "live_history".to_string(),
                "desktop_capture_ui".to_string(),
                "intercept_queue".to_string(),
                "replay".to_string(),
                "websocket_history".to_string(),
                "runtime_settings".to_string(),
                "event_log".to_string(),
                "match_and_replace".to_string(),
                "fuzzer".to_string(),
                "target_site_map".to_string(),
                "session_storage".to_string(),
            ],
            notes: vec![
                "A persistent Sniper root CA is generated locally and reused across restarts."
                    .to_string(),
                "https://sniper and http://sniper expose the root CA download portal.".to_string(),
                "CONNECT tunnels for HTTPS are terminated locally and forwarded through MITM."
                    .to_string(),
                "Intercept can pause requests before forwarding, and websocket sessions are captured separately."
                    .to_string(),
                "Traffic, runtime settings, rules, and logs are stored per session under the local data directory."
                    .to_string(),
                "Bodies are preview-captured in-memory to keep the first version simple."
                    .to_string(),
            ],
            certificate: self.certificates.export().clone(),
            runtime: session.runtime.snapshot().await,
            startup: self.startup.view(active_addr).await,
            active_session: self.active_session_summary().await,
        }
    }

    pub async fn app_version_info(&self) -> AppVersionInfo {
        let cached = self.app_version_cache.read().await.clone();
        if let Some(cached) = cached.as_ref() {
            if cached.checked_at.elapsed() < APP_VERSION_CACHE_TTL {
                return cached.info.clone();
            }
        }

        match tokio::time::timeout(APP_VERSION_FETCH_TIMEOUT, self.fetch_latest_release_info())
            .await
        {
            Ok(Ok(info)) => {
                *self.app_version_cache.write().await =
                    Some(CachedAppVersionInfo::new(info.clone()));
                info
            }
            _ => cached
                .map(|cached| cached.info)
                .unwrap_or_else(AppVersionInfo::current_only),
        }
    }

    async fn fetch_latest_release_info(&self) -> Result<AppVersionInfo> {
        let client = reqwest::Client::builder()
            .user_agent(format!(
                "Sniper/{} (+{})",
                env!("CARGO_PKG_VERSION"),
                APP_RELEASES_URL
            ))
            .build()
            .context("failed to build GitHub releases client")?;

        let response = client
            .get(APP_LATEST_RELEASE_API_URL)
            .send()
            .await
            .context("failed to query GitHub latest release")?;

        if response.status() == StatusCode::NOT_FOUND {
            return Ok(AppVersionInfo::current_only());
        }

        let response = response
            .error_for_status()
            .context("GitHub latest release query failed")?;
        let release = response
            .json::<GitHubRelease>()
            .await
            .context("failed to decode GitHub latest release response")?;

        let mut info = AppVersionInfo::current_only();
        info.latest_version = Some(release.tag_name.clone());
        info.latest_release_url = Some(release.html_url);
        info.update_available = is_newer_version(&info.current_version, &release.tag_name);
        Ok(info)
    }

    /// Download the latest DMG from GitHub releases, mount it, copy the new
    /// app bundle over the current one, then restart the process.
    /// Sends progress events through the provided sender.
    pub async fn self_update(
        &self,
        tx: tokio::sync::mpsc::Sender<UpdateProgress>,
    ) -> Result<()> {
        use std::process::Command;
        use tokio::io::AsyncWriteExt;

        let app_bundle = self.app_bundle_path()?;

        tx.send(UpdateProgress::step("Checking for updates...")).await.ok();

        let client = reqwest::Client::builder()
            .user_agent(format!(
                "Sniper/{} (+{})",
                env!("CARGO_PKG_VERSION"),
                APP_RELEASES_URL
            ))
            .build()
            .context("failed to build HTTP client")?;

        let release: GitHubRelease = client
            .get(APP_LATEST_RELEASE_API_URL)
            .send()
            .await
            .context("failed to query GitHub latest release")?
            .error_for_status()
            .context("GitHub API error")?
            .json()
            .await
            .context("failed to decode release JSON")?;

        let dmg_asset = release
            .assets
            .iter()
            .find(|a| a.name.ends_with(".dmg"))
            .context("no DMG asset found in the latest release")?;

        let total_size = dmg_asset.size;
        tx.send(UpdateProgress::step("Downloading update...")).await.ok();

        // Stream-download DMG with progress
        let tmp_dir = std::env::temp_dir().join("sniper-update");
        tokio::fs::create_dir_all(&tmp_dir).await?;
        let dmg_path = tmp_dir.join(&dmg_asset.name);

        let response = client
            .get(&dmg_asset.browser_download_url)
            .send()
            .await
            .context("failed to download DMG")?
            .error_for_status()
            .context("DMG download failed")?;

        let content_length = response
            .content_length()
            .or(total_size)
            .unwrap_or(0);

        let mut file = tokio::fs::File::create(&dmg_path).await?;
        let mut stream = response.bytes_stream();
        let mut downloaded: u64 = 0;

        use futures_util::StreamExt;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("download interrupted")?;
            file.write_all(&chunk).await?;
            downloaded += chunk.len() as u64;
            if content_length > 0 {
                let pct = ((downloaded as f64 / content_length as f64) * 100.0) as u8;
                tx.send(UpdateProgress::download(pct, downloaded, content_length))
                    .await
                    .ok();
            }
        }
        file.flush().await?;
        drop(file);

        // Mount the DMG (no -quiet so we get stdout with mount point)
        tx.send(UpdateProgress::step("Installing update...")).await.ok();

        let mount_output = Command::new("hdiutil")
            .args(["attach", "-nobrowse"])
            .arg(&dmg_path)
            .output()
            .context("failed to mount DMG")?;

        if !mount_output.status.success() {
            anyhow::bail!(
                "hdiutil attach failed: {}",
                String::from_utf8_lossy(&mount_output.stderr)
            );
        }

        // Find the mount point from stdout
        let stdout = String::from_utf8_lossy(&mount_output.stdout);
        let mount_point = stdout
            .lines()
            .filter_map(|line| {
                let parts: Vec<&str> = line.splitn(3, '\t').collect();
                parts.get(2).map(|s| s.trim().to_string())
            })
            .find(|p| p.starts_with("/Volumes/"))
            .context("could not find DMG mount point")?;

        // Find the .app inside the mounted volume
        let mut new_app_path = None;
        let mut read_dir = tokio::fs::read_dir(&mount_point).await?;
        while let Some(entry) = read_dir.next_entry().await? {
            let name = entry.file_name();
            if name.to_string_lossy().ends_with(".app") {
                new_app_path = Some(entry.path());
                break;
            }
        }
        let new_app_path = new_app_path.context("no .app found in DMG")?;

        // Copy new app over the current bundle
        let cp_output = Command::new("cp")
            .args(["-Rf"])
            .arg(&new_app_path)
            .arg(app_bundle.parent().unwrap_or(std::path::Path::new("/")))
            .output()
            .context("failed to copy new app bundle")?;

        if !cp_output.status.success() {
            let _ = Command::new("hdiutil")
                .args(["detach", "-quiet"])
                .arg(&mount_point)
                .output();
            anyhow::bail!(
                "cp failed: {}",
                String::from_utf8_lossy(&cp_output.stderr)
            );
        }

        // Detach DMG & clean up
        let _ = Command::new("hdiutil")
            .args(["detach", "-quiet"])
            .arg(&mount_point)
            .output();
        let _ = tokio::fs::remove_dir_all(&tmp_dir).await;

        // Re-sign the app bundle so macOS accepts the replaced binary.
        // Without this the system kills the process with SIGKILL
        // (Code Signature Invalid / Taskgated Invalid Signature).
        tx.send(UpdateProgress::step("Signing...")).await.ok();
        let sign_output = Command::new("codesign")
            .args(["--force", "--deep", "--sign", "-"])
            .arg(&app_bundle)
            .output()
            .context("failed to run codesign")?;
        if !sign_output.status.success() {
            tracing::warn!(
                "codesign failed (non-fatal): {}",
                String::from_utf8_lossy(&sign_output.stderr)
            );
        }

        tx.send(UpdateProgress::step("Restarting...")).await.ok();

        // Launch the new app and exit
        let _ = Command::new("open")
            .args(["-n", "-a"])
            .arg(&app_bundle)
            .spawn();

        tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            std::process::exit(0);
        });

        Ok(())
    }

    /// Resolve the `.app` bundle directory from the current executable path.
    /// Expects layout: `Sniper.app/Contents/MacOS/<binary>`.
    fn app_bundle_path(&self) -> Result<std::path::PathBuf> {
        let exe = std::env::current_exe().context("cannot determine executable path")?;
        // exe → Contents/MacOS/<binary>
        let contents = exe
            .parent() // MacOS/
            .and_then(|p| p.parent()) // Contents/
            .and_then(|p| p.parent()) // Sniper.app/
            .context("executable is not inside a .app bundle")?;
        Ok(contents.to_path_buf())
    }

    pub async fn log_info(
        &self,
        source: impl Into<String>,
        title: impl Into<String>,
        message: impl Into<String>,
    ) {
        let session = self.session().await;
        session
            .event_log
            .push(EventLevel::Info, source, title, message)
            .await;
    }

    pub async fn log_warn(
        &self,
        source: impl Into<String>,
        title: impl Into<String>,
        message: impl Into<String>,
    ) {
        let session = self.session().await;
        session
            .event_log
            .push(EventLevel::Warn, source, title, message)
            .await;
    }

    pub async fn log_error(
        &self,
        source: impl Into<String>,
        title: impl Into<String>,
        message: impl Into<String>,
    ) {
        let session = self.session().await;
        session
            .event_log
            .push(EventLevel::Error, source, title, message)
            .await;
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RuntimeInfo {
    pub proxy_addr: String,
    pub ui_addr: String,
    pub max_entries: usize,
    pub body_preview_bytes: usize,
    pub data_dir: String,
    pub proxy_online: bool,
    pub features: Vec<String>,
    pub notes: Vec<String>,
    pub certificate: CertificateExport,
    pub runtime: crate::runtime::RuntimeSettingsSnapshot,
    pub startup: StartupSettingsView,
    pub active_session: SessionSummary,
}

#[derive(Clone, Debug, Serialize)]
pub struct AppVersionInfo {
    pub current_version: String,
    pub latest_version: Option<String>,
    pub update_available: bool,
    pub releases_url: String,
    pub latest_release_url: Option<String>,
}

impl AppVersionInfo {
    fn current_only() -> Self {
        Self {
            current_version: env!("CARGO_PKG_VERSION").to_string(),
            latest_version: None,
            update_available: false,
            releases_url: APP_RELEASES_URL.to_string(),
            latest_release_url: None,
        }
    }
}

#[derive(Clone, Debug)]
struct CachedAppVersionInfo {
    checked_at: Instant,
    info: AppVersionInfo,
}

impl CachedAppVersionInfo {
    fn new(info: AppVersionInfo) -> Self {
        Self {
            checked_at: Instant::now(),
            info,
        }
    }
}

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    assets: Vec<GitHubAsset>,
}

#[derive(Debug, Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
    size: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct UpdateProgress {
    pub step: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percent: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub downloaded: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
}

impl UpdateProgress {
    fn step(msg: &str) -> Self {
        Self { step: msg.to_string(), percent: None, downloaded: None, total: None }
    }
    fn download(pct: u8, downloaded: u64, total: u64) -> Self {
        Self {
            step: "Downloading update...".to_string(),
            percent: Some(pct),
            downloaded: Some(downloaded),
            total: Some(total),
        }
    }
}

fn normalize_version_text(value: &str) -> String {
    value
        .trim()
        .trim_start_matches(|ch| ch == 'v' || ch == 'V')
        .to_string()
}

fn parse_version(value: &str) -> Option<Version> {
    Version::parse(&normalize_version_text(value)).ok()
}

fn is_newer_version(current: &str, latest: &str) -> bool {
    match (parse_version(current), parse_version(latest)) {
        (Some(current), Some(latest)) => latest > current,
        _ => false,
    }
}
