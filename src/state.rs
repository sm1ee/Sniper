use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use anyhow::Result;
use reqwest::StatusCode;
use semver::Version;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

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
    active_session: Arc<RwLock<Arc<SessionContext>>>,
    app_version_cache: Arc<RwLock<Option<CachedAppVersionInfo>>>,
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

        Ok(Self {
            config,
            certificates,
            startup,
            ui_settings,
            sessions: Arc::new(sessions),
            active_session: Arc::new(RwLock::new(active_session)),
            app_version_cache: Arc::new(RwLock::new(None)),
        })
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

    pub async fn runtime_info(&self) -> RuntimeInfo {
        let session = self.session().await;
        RuntimeInfo {
            proxy_addr: self.config.proxy_addr.to_string(),
            ui_addr: self.config.ui_addr.to_string(),
            max_entries: self.config.max_entries,
            body_preview_bytes: self.config.body_preview_bytes,
            data_dir: self.config.data_dir.display().to_string(),
            features: vec![
                "http_capture".to_string(),
                "connect_tunnel".to_string(),
                "https_mitm".to_string(),
                "special_https_host".to_string(),
                "root_ca_export".to_string(),
                "live_history".to_string(),
                "desktop_capture_ui".to_string(),
                "intercept_queue".to_string(),
                "repeater".to_string(),
                "websocket_history".to_string(),
                "runtime_settings".to_string(),
                "event_log".to_string(),
                "match_and_replace".to_string(),
                "intruder".to_string(),
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
            startup: self.startup.view(self.config.proxy_addr).await,
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
        _ => normalize_version_text(current) != normalize_version_text(latest),
    }
}
