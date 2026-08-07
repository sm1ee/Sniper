use std::{
    collections::HashMap,
    env, fs,
    io::Write,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use anyhow::Context;
use anyhow::Result;
use reqwest::StatusCode;
use semver::Version;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex as AsyncMutex, RwLock};
use tokio::task::JoinHandle;

use crate::{
    certificate::{CertificateAuthority, CertificateExport},
    config::{AppConfig, StartupSettingsStore, StartupSettingsView},
    event_log::EventLevel,
    session::{SessionContext, SessionRegistry, SessionSummary},
    ui_settings::AppUiSettingsStore,
    ws_replay::WsReplayStore,
};

const MAX_WEBSOCKET_FRAMES_PER_SESSION: usize = 50_000;
const APP_RELEASES_URL: &str = "https://github.com/sm1ee/Sniper/releases";
const APP_LATEST_RELEASE_API_URL: &str =
    "https://api.github.com/repos/sm1ee/Sniper/releases/latest";
/// How long a session switch waits for in-flight proxy work before giving up. Long
/// enough for a request that is nearly done, short enough not to feel like a hang.
const SESSION_SWITCH_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
/// How long a forced switch waits before and after stopping streamed responses.
const SESSION_SWITCH_FORCE_TIMEOUT: Duration = Duration::from_secs(3);
const APP_VERSION_CACHE_TTL: Duration = Duration::from_secs(30 * 60);
const APP_VERSION_FETCH_TIMEOUT: Duration = Duration::from_secs(8);
const APP_RELEASE_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const APP_RELEASE_READ_TIMEOUT: Duration = Duration::from_secs(30);
const EXPECTED_APP_BUNDLE_IDENTIFIER: &str = "com.sm1ee.sniper";
const EXPECTED_APP_EXECUTABLE: &str = "Sniper";
const EXPECTED_BUNDLED_CLI_EXECUTABLE: &str = "sniper-cli";
const HDIUTIL_PATH: &str = "/usr/bin/hdiutil";
const DITTO_PATH: &str = "/usr/bin/ditto";
const CODESIGN_PATH: &str = "/usr/bin/codesign";
const SPCTL_PATH: &str = "/usr/sbin/spctl";
const PLIST_BUDDY_PATH: &str = "/usr/libexec/PlistBuddy";
const LIPO_PATH: &str = "/usr/bin/lipo";
const SH_PATH: &str = "/bin/sh";
const SELF_UPDATE_INSTALLER_LOG_FILE: &str = "self-update-installer.log";

fn validate_self_update_app_bundle_path(app_bundle: &Path) -> Result<()> {
    if app_bundle.file_name().and_then(|value| value.to_str()) != Some("Sniper.app")
        || app_bundle.extension().and_then(|value| value.to_str()) != Some("app")
        || !app_bundle.join("Contents/MacOS").is_dir()
    {
        anyhow::bail!("self-update is only supported when running from Sniper.app");
    }
    Ok(())
}

fn proxy_listener_status_word(generation: u64, online: bool) -> u64 {
    (generation << 1) | u64::from(online)
}

fn proxy_listener_generation(status: u64) -> u64 {
    status >> 1
}

fn proxy_listener_online(status: u64) -> bool {
    status & 1 == 1
}

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub certificates: Arc<CertificateAuthority>,
    pub startup: Arc<StartupSettingsStore>,
    pub ui_settings: Arc<AppUiSettingsStore>,
    pub sessions: Arc<SessionRegistry>,
    pub proxy_online: Arc<AtomicBool>,
    proxy_listener_status: Arc<AtomicU64>,
    active_session: Arc<RwLock<Arc<SessionContext>>>,
    app_version_cache: Arc<RwLock<Option<CachedAppVersionInfo>>>,
    update_in_progress: Arc<AtomicBool>,
    /// The currently active proxy listener address (mutable — updated on rebind).
    pub active_proxy_addr: Arc<RwLock<SocketAddr>>,
    /// The currently bound UI listener address (mutable because port 0 is resolved at bind time).
    active_ui_addr: Arc<RwLock<SocketAddr>>,
    /// Handle for the running proxy task so it can be aborted on rebind.
    proxy_task: Arc<RwLock<Option<JoinHandle<()>>>>,
    /// Serializes runtime proxy rebinds so reported state cannot race the actual listener.
    pub proxy_rebind_lock: Arc<AsyncMutex<()>>,
    /// Serializes persisted startup settings with the hot-rebound listener state.
    pub startup_settings_lock: Arc<AsyncMutex<()>>,
    /// Serializes session operations so inactive writes and deletion cannot race each other.
    session_operation_locks: Arc<AsyncMutex<HashMap<uuid::Uuid, Arc<AsyncMutex<()>>>>>,
    /// Serializes session activation so old/new session operation locks cannot deadlock.
    session_activation_lock: Arc<AsyncMutex<()>>,
    /// Canonical contexts for inactive sessions loaded through the API.
    session_contexts: Arc<AsyncMutex<HashMap<uuid::Uuid, Arc<SessionContext>>>>,
    /// Cached read-only inactive sessions for repeated pinned history/detail reads.
    read_only_session_contexts: Arc<AsyncMutex<HashMap<uuid::Uuid, Arc<SessionContext>>>>,
    /// WebSocket replay connections.
    pub ws_replay: Arc<WsReplayStore>,
    /// Stable owner token for runtime-state writes from this app process.
    pub runtime_instance_id: uuid::Uuid,
}

#[derive(Clone, Copy, Debug)]
struct LiveSessionCounts {
    request_count: usize,
    websocket_count: usize,
    event_count: usize,
    fuzzer_count: usize,
    rule_count: usize,
}

async fn session_live_counts(session: &Arc<SessionContext>) -> LiveSessionCounts {
    LiveSessionCounts {
        request_count: session.store.len().await,
        websocket_count: session.websockets.len().await,
        event_count: session.event_log.len().await,
        fuzzer_count: session.fuzzer.len().await,
        rule_count: session.match_replace.len().await,
    }
}

fn apply_live_session_counts(summary: &mut SessionSummary, counts: LiveSessionCounts) {
    summary.request_count = counts.request_count;
    summary.websocket_count = counts.websocket_count;
    summary.event_count = counts.event_count;
    summary.fuzzer_count = counts.fuzzer_count;
    summary.rule_count = counts.rule_count;
}

async fn session_summary_with_live_counts(
    session: &Arc<SessionContext>,
    active: bool,
) -> SessionSummary {
    let mut summary = session.summary(active);
    apply_live_session_counts(&mut summary, session_live_counts(session).await);
    summary
}

impl AppState {
    pub fn new(config: AppConfig) -> Result<Self> {
        let certificates = Arc::new(CertificateAuthority::load_or_create(&config.data_dir)?);
        let startup = Arc::new(StartupSettingsStore::load_or_create(
            &config.data_dir,
            config.proxy_addr,
        )?);
        let ui_settings = Arc::new(AppUiSettingsStore::load_or_create(&config.data_dir)?);
        let (sessions, active_session) = SessionRegistry::load_or_create_with_transaction_limit(
            &config.data_dir,
            config.max_entries,
            config.max_transaction_entries,
            MAX_WEBSOCKET_FRAMES_PER_SESSION,
        )?;

        let active_proxy_addr = config.proxy_addr;
        let active_ui_addr = config.ui_addr;
        let runtime_instance_id = uuid::Uuid::new_v4();
        Ok(Self {
            config,
            certificates,
            startup,
            ui_settings,
            sessions: Arc::new(sessions),
            proxy_online: Arc::new(AtomicBool::new(false)),
            proxy_listener_status: Arc::new(AtomicU64::new(proxy_listener_status_word(0, false))),
            active_session: Arc::new(RwLock::new(active_session)),
            app_version_cache: Arc::new(RwLock::new(None)),
            update_in_progress: Arc::new(AtomicBool::new(false)),
            active_proxy_addr: Arc::new(RwLock::new(active_proxy_addr)),
            active_ui_addr: Arc::new(RwLock::new(active_ui_addr)),
            proxy_task: Arc::new(RwLock::new(None)),
            proxy_rebind_lock: Arc::new(AsyncMutex::new(())),
            startup_settings_lock: Arc::new(AsyncMutex::new(())),
            session_operation_locks: Arc::new(AsyncMutex::new(HashMap::new())),
            session_activation_lock: Arc::new(AsyncMutex::new(())),
            session_contexts: Arc::new(AsyncMutex::new(HashMap::new())),
            read_only_session_contexts: Arc::new(AsyncMutex::new(HashMap::new())),
            ws_replay: Arc::new(WsReplayStore::new()),
            runtime_instance_id,
        })
    }

    pub fn set_proxy_online(&self, online: bool) {
        loop {
            let current = self.proxy_listener_status.load(Ordering::Acquire);
            let generation = proxy_listener_generation(current);
            let next = proxy_listener_status_word(generation, online);
            if self
                .proxy_listener_status
                .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
        }
        self.proxy_online.store(online, Ordering::Relaxed);
    }

    pub fn is_proxy_online(&self) -> bool {
        proxy_listener_online(self.proxy_listener_status.load(Ordering::Acquire))
    }

    pub fn mark_proxy_listener_online(&self) -> u64 {
        loop {
            let current = self.proxy_listener_status.load(Ordering::Acquire);
            let next_generation = proxy_listener_generation(current).saturating_add(1);
            let next = proxy_listener_status_word(next_generation, true);
            if self
                .proxy_listener_status
                .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.proxy_online.store(true, Ordering::Relaxed);
                return next_generation;
            }
        }
    }

    pub fn mark_proxy_listener_offline_if_current(&self, expected_generation: u64) -> bool {
        let current_online = proxy_listener_status_word(expected_generation, true);
        let current_offline = proxy_listener_status_word(expected_generation, false);
        if self
            .proxy_listener_status
            .compare_exchange(
                current_online,
                current_offline,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            self.proxy_online.store(false, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    pub async fn session(&self) -> Arc<SessionContext> {
        self.active_session.read().await.clone()
    }

    pub(crate) async fn session_with_proxy_owner(
        &self,
    ) -> (Arc<SessionContext>, crate::proxy::ActiveProxySessionGuard) {
        let active_session = self.active_session.read().await;
        let session = active_session.clone();
        let owner = crate::proxy::remember_active_proxy_session_owner(session.id(), crate::proxy::PROXY_WORK_REPLAY);
        (session, owner)
    }

    pub async fn session_operation_lock(&self, id: uuid::Uuid) -> Arc<AsyncMutex<()>> {
        let mut locks = self.session_operation_locks.lock().await;
        locks
            .entry(id)
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
    }

    pub async fn workspace_update_lock(&self, id: uuid::Uuid) -> Arc<AsyncMutex<()>> {
        self.session_operation_lock(id).await
    }

    #[cfg(test)]
    async fn session_operation_lock_count(&self) -> usize {
        self.session_operation_locks.lock().await.len()
    }

    async fn remove_session_operation_lock(&self, id: uuid::Uuid) {
        self.session_operation_locks.lock().await.remove(&id);
    }

    pub async fn session_context_for_id(&self, id: uuid::Uuid) -> Result<Arc<SessionContext>> {
        let active = self.session().await;
        if id == active.id() {
            return Ok(active);
        }

        if !self.sessions.contains_session(id) {
            anyhow::bail!("session {id} was not found");
        }
        let operation_lock = self.session_operation_lock(id).await;
        let operation_guard = operation_lock.lock().await;
        if !self.sessions.contains_session(id) {
            drop(operation_guard);
            self.remove_session_operation_lock(id).await;
            anyhow::bail!("session {id} was not found");
        }
        self.session_context_for_id_operation_locked(id).await
    }

    pub async fn read_session_context_for_id(&self, id: uuid::Uuid) -> Result<Arc<SessionContext>> {
        let active = self.session().await;
        if id == active.id() {
            return Ok(active);
        }

        if !self.sessions.contains_session(id) {
            anyhow::bail!("session {id} was not found");
        }
        let operation_lock = self.session_operation_lock(id).await;
        let operation_guard = operation_lock.lock().await;
        if !self.sessions.contains_session(id) {
            drop(operation_guard);
            self.remove_session_operation_lock(id).await;
            anyhow::bail!("session {id} was not found");
        }
        {
            let mut contexts = self.session_contexts.lock().await;
            if let Some(session) = contexts.get(&id) {
                if self.sessions.contains_session(id) {
                    return Ok(session.clone());
                }
                contexts.remove(&id);
            }
        }
        if !self.sessions.contains_session(id) {
            anyhow::bail!("session {id} was not found");
        }
        let mut read_only_contexts = self.read_only_session_contexts.lock().await;
        if let Some(session) = read_only_contexts.get(&id) {
            if self.sessions.contains_session(id) {
                return Ok(session.clone());
            }
            read_only_contexts.remove(&id);
        }
        if !self.sessions.contains_session(id) {
            anyhow::bail!("session {id} was not found");
        }
        let session = self.sessions.load_context_read_only(id)?;
        read_only_contexts.insert(id, session.clone());
        Ok(session)
    }

    pub async fn is_current_session_context(&self, session: &Arc<SessionContext>) -> bool {
        let id = session.id();
        let active = self.session().await;
        if id == active.id() {
            return Arc::ptr_eq(&active, session);
        }
        {
            let contexts = self.session_contexts.lock().await;
            if let Some(current) = contexts.get(&id) {
                return Arc::ptr_eq(current, session);
            }
        }
        let read_only_contexts = self.read_only_session_contexts.lock().await;
        read_only_contexts
            .get(&id)
            .is_some_and(|current| Arc::ptr_eq(current, session))
    }

    pub async fn session_context_for_id_operation_locked(
        &self,
        id: uuid::Uuid,
    ) -> Result<Arc<SessionContext>> {
        self.read_only_session_contexts.lock().await.remove(&id);
        let mut contexts = self.session_contexts.lock().await;
        if let Some(session) = contexts.get(&id) {
            if self.sessions.contains_session(id) {
                return Ok(session.clone());
            }
            contexts.remove(&id);
        }
        if !self.sessions.contains_session(id) {
            drop(contexts);
            self.remove_session_operation_lock(id).await;
            anyhow::bail!("session {id} was not found");
        }
        let session = self.sessions.load_context(id)?;
        contexts.insert(id, session.clone());
        Ok(session)
    }

    pub async fn list_sessions(&self) -> Vec<SessionSummary> {
        let mut summaries = self.sessions.summaries();
        let mut live_counts = HashMap::new();

        let active = self.session().await;
        live_counts.insert(active.id(), session_live_counts(&active).await);

        let writable_contexts: Vec<_> = {
            let contexts = self.session_contexts.lock().await;
            contexts.values().cloned().collect()
        };
        for session in writable_contexts {
            if self.sessions.contains_session(session.id()) {
                live_counts.insert(session.id(), session_live_counts(&session).await);
            }
        }

        let read_only_contexts: Vec<_> = {
            let contexts = self.read_only_session_contexts.lock().await;
            contexts.values().cloned().collect()
        };
        for session in read_only_contexts {
            if self.sessions.contains_session(session.id()) {
                live_counts.insert(session.id(), session_live_counts(&session).await);
            }
        }

        for summary in &mut summaries {
            if let Some(counts) = live_counts.get(&summary.id) {
                apply_live_session_counts(summary, *counts);
            }
        }
        summaries
    }

    pub async fn active_session_summary(&self) -> SessionSummary {
        let active_id = self.sessions.active_session_id();
        let session = self.session().await;
        session_summary_with_live_counts(&session, session.id() == active_id).await
    }

    pub async fn create_session(&self, name: Option<String>) -> Result<SessionSummary> {
        let metadata = self.sessions.create_session(name)?;
        match self.activate_session(metadata.id).await {
            Ok(summary) => Ok(summary),
            Err(error) => {
                if let Err(cleanup_error) = self.sessions.delete_session(metadata.id) {
                    tracing::warn!(
                        ?cleanup_error,
                        session_id = %metadata.id,
                        "failed to remove session created before activation failure"
                    );
                }
                self.ws_replay.remove_session(metadata.id).await;
                self.session_operation_locks
                    .lock()
                    .await
                    .remove(&metadata.id);
                self.session_contexts.lock().await.remove(&metadata.id);
                self.read_only_session_contexts
                    .lock()
                    .await
                    .remove(&metadata.id);
                Err(error)
            }
        }
    }

    pub async fn activate_session(&self, id: uuid::Uuid) -> Result<SessionSummary> {
        self.activate_session_with_options(id, false).await
    }

    /// `force` cuts in-flight proxy connections instead of refusing the switch.
    /// Needed because a streamed response — a server-sent event stream, a long
    /// poll, a download — holds its session for as long as it stays open, and a
    /// browser pointed at the proxy keeps one open indefinitely.
    pub async fn activate_session_with_options(
        &self,
        id: uuid::Uuid,
        force: bool,
    ) -> Result<SessionSummary> {
        let _activation_guard = self.session_activation_lock.lock().await;
        if !self.sessions.contains_session(id) {
            anyhow::bail!("session {id} was not found");
        }
        let operation_lock = self.session_operation_lock(id).await;
        let operation_guard = operation_lock.lock().await;
        if !self.sessions.contains_session(id) {
            drop(operation_guard);
            self.remove_session_operation_lock(id).await;
            anyhow::bail!("session {id} was not found");
        }
        let current_id = self.sessions.active_session_id();
        let _current_operation_guard = if current_id != id {
            Some(
                self.session_operation_lock(current_id)
                    .await
                    .lock_owned()
                    .await,
            )
        } else {
            None
        };
        // Give in-flight proxy work a moment to finish rather than refusing on the
        // spot — an ordinary request is done in milliseconds. This runs before the
        // active-session write lock is taken, so the rest of the app keeps serving
        // while we wait.
        if current_id != id {
            for session_id in [current_id, id] {
                if !crate::proxy::session_has_active_proxy_work(session_id) {
                    continue;
                }
                if force {
                    // Stops everything a session can be holding: streamed
                    // responses, and the long-running tasks behind HTTPS tunnels
                    // and WebSocket relays. A browser keeps tunnels open for
                    // minutes, so none of this drains on its own. Whatever they
                    // were carrying is cut and never recorded.
                    crate::proxy::wait_for_session_proxy_work_to_finish(
                        session_id,
                        SESSION_SWITCH_FORCE_TIMEOUT,
                    )
                    .await;
                    if crate::proxy::session_has_active_proxy_work(session_id) {
                        let aborted = crate::proxy::abort_session_tracked_tasks(session_id);
                        tracing::warn!(
                            %session_id,
                            aborted,
                            "cutting long-running proxy tasks for a forced session switch"
                        );
                        let deadline = Instant::now() + SESSION_SWITCH_FORCE_TIMEOUT;
                        while crate::proxy::session_has_active_proxy_work(session_id)
                            && Instant::now() < deadline
                        {
                            tokio::time::sleep(Duration::from_millis(20)).await;
                        }
                    }
                } else {
                    // No cutting: just give work that is about to finish a moment.
                    let deadline = Instant::now() + SESSION_SWITCH_DRAIN_TIMEOUT;
                    while crate::proxy::session_has_active_proxy_work(session_id)
                        && Instant::now() < deadline
                    {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }
            }
        }

        let mut active_session = self.active_session.write().await;
        let current = active_session.clone();
        let current_id = current.id();
        if current_id != id {
            if crate::proxy::session_has_active_proxy_work(current_id)
                || crate::proxy::session_has_active_proxy_work(id)
            {
                let busy = [current_id, id]
                    .into_iter()
                    .map(crate::proxy::describe_session_proxy_work)
                    .find(|description| !description.is_empty())
                    .unwrap_or_else(|| "proxy work".to_string());
                anyhow::bail!(
                    "cannot switch sessions while proxy activity is still running ({busy})"
                );
            }
            self.persist_session_context(&current).await?;
            {
                let mut contexts = self.session_contexts.lock().await;
                contexts.insert(current_id, current.clone());
            }
            self.read_only_session_contexts
                .lock()
                .await
                .remove(&current_id);
            self.read_only_session_contexts.lock().await.remove(&id);
            let session = {
                let mut contexts = self.session_contexts.lock().await;
                if let Some(session) = contexts.get(&id) {
                    session.clone()
                } else {
                    let session = self.sessions.load_context(id)?;
                    contexts.insert(id, session.clone());
                    session
                }
            };
            let metadata = self.sessions.activate_session(id)?;
            session.replace_metadata(metadata.clone());
            let dropped_requests = current.intercepts.drop_all().await;
            let dropped_responses = current.response_intercepts.drop_all().await;
            if dropped_requests > 0 || dropped_responses > 0 {
                tracing::info!(
                    session_id = %current_id,
                    dropped_requests,
                    dropped_responses,
                    "dropped pending intercepts before switching sessions"
                );
            }
            *active_session = session.clone();
            return Ok(session.summary(metadata.id == self.sessions.active_session_id()));
        }

        let metadata = self.sessions.activate_session(id)?;
        current.replace_metadata(metadata.clone());
        Ok(current.summary(metadata.id == self.sessions.active_session_id()))
    }

    pub async fn delete_session(&self, id: uuid::Uuid) -> Result<()> {
        if !self.sessions.contains_session(id) {
            anyhow::bail!("session {id} was not found");
        }
        let operation_lock = self.session_operation_lock(id).await;
        let operation_guard = operation_lock.lock().await;
        if !self.sessions.contains_session(id) {
            drop(operation_guard);
            self.remove_session_operation_lock(id).await;
            anyhow::bail!("session {id} was not found");
        }
        if crate::proxy::session_has_live_websocket_relays(id) {
            anyhow::bail!("cannot delete a session while live captures are active");
        }
        if crate::proxy::session_has_active_proxy_work(id) {
            anyhow::bail!("cannot delete a session while proxy activity is still running");
        }
        if crate::proxy::session_has_pending_persist(id) {
            anyhow::bail!("cannot delete a session while capture persistence is pending");
        }
        let cached_session = {
            let contexts = self.session_contexts.lock().await;
            contexts.get(&id).cloned()
        };
        let _mutation_guard = match cached_session.as_ref() {
            Some(session) => Some(session.mutation_guard().await),
            None => None,
        };
        let result = self.sessions.delete_session(id);
        drop(operation_guard);
        if result.is_ok() {
            self.ws_replay.remove_session(id).await;
            self.session_operation_locks.lock().await.remove(&id);
            self.session_contexts.lock().await.remove(&id);
            self.read_only_session_contexts.lock().await.remove(&id);
        }
        result
    }

    pub fn session_storage_path(&self, id: uuid::Uuid) -> Result<std::path::PathBuf> {
        self.sessions.session_storage_path(id)
    }

    pub async fn persist_active_session(&self) -> Result<SessionSummary> {
        let session = self.session().await;
        self.persist_session_context(&session).await
    }

    pub async fn persist_session_context(
        &self,
        session: &Arc<SessionContext>,
    ) -> Result<SessionSummary> {
        self.read_only_session_contexts
            .lock()
            .await
            .remove(&session.id());
        if !self.sessions.contains_session(session.id()) {
            anyhow::bail!("session {} was deleted", session.id());
        }
        let metadata = session.persist().await?;
        self.finalize_session_persist(session, metadata)
    }

    pub async fn persist_session_context_mutation_locked(
        &self,
        session: &Arc<SessionContext>,
    ) -> Result<SessionSummary> {
        self.read_only_session_contexts
            .lock()
            .await
            .remove(&session.id());
        if !self.sessions.contains_session(session.id()) {
            anyhow::bail!("session {} was deleted", session.id());
        }
        let metadata = session.persist_mutation_locked().await?;
        self.finalize_session_persist(session, metadata)
    }

    pub async fn replace_workspace_state_and_persist(
        &self,
        session: &Arc<SessionContext>,
        snapshot: crate::workspace::WorkspaceStateSnapshot,
    ) -> std::result::Result<
        crate::workspace::WorkspaceStateSnapshot,
        crate::workspace::WorkspaceReplaceError<String>,
    > {
        if !self.sessions.contains_session(session.id()) {
            return Err(crate::workspace::WorkspaceReplaceError::Persist(format!(
                "session {} was deleted",
                session.id()
            )));
        }
        self.read_only_session_contexts
            .lock()
            .await
            .remove(&session.id());
        {
            let mut contexts = self.session_contexts.lock().await;
            if contexts
                .get(&session.id())
                .is_some_and(|current| !Arc::ptr_eq(current, session))
            {
                contexts.remove(&session.id());
            }
        }
        let (snapshot, fallback_metadata) = session
            .replace_workspace_snapshot_checked_and_persist(snapshot)
            .await
            .map_err(|error| match error {
                crate::workspace::WorkspaceReplaceError::Conflict(current) => {
                    crate::workspace::WorkspaceReplaceError::Conflict(current)
                }
                crate::workspace::WorkspaceReplaceError::Persist(error) => {
                    crate::workspace::WorkspaceReplaceError::Persist(error.to_string())
                }
            })?;
        if let Some(metadata) = fallback_metadata {
            self.finalize_session_persist(session, metadata)
                .map_err(|error| {
                    crate::workspace::WorkspaceReplaceError::Persist(error.to_string())
                })?;
        }
        Ok(snapshot)
    }

    fn finalize_session_persist(
        &self,
        session: &Arc<SessionContext>,
        metadata: crate::session::SessionMetadata,
    ) -> Result<SessionSummary> {
        let active = session.id() == self.sessions.active_session_id();
        if let Err(error) = self.sessions.update_metadata(metadata) {
            if !self.sessions.contains_session(session.id()) {
                if let Err(cleanup_error) = std::fs::remove_dir_all(session.storage_dir()) {
                    if cleanup_error.kind() != std::io::ErrorKind::NotFound {
                        tracing::warn!(
                            ?cleanup_error,
                            session_id = %session.id(),
                            "failed to remove deleted session snapshot directory"
                        );
                    }
                }
                return Err(error);
            }
            tracing::warn!(
                ?error,
                session_id = %session.id(),
                "session snapshot persisted but registry metadata update failed"
            );
            return Err(error);
        }
        Ok(session.summary(active))
    }

    pub async fn get_active_proxy_addr(&self) -> SocketAddr {
        *self.active_proxy_addr.read().await
    }

    pub async fn set_active_proxy_addr(&self, addr: SocketAddr) {
        *self.active_proxy_addr.write().await = addr;
    }

    pub async fn get_active_ui_addr(&self) -> SocketAddr {
        *self.active_ui_addr.read().await
    }

    pub async fn set_active_ui_addr(&self, addr: SocketAddr) {
        *self.active_ui_addr.write().await = addr;
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
        let active_session = session_summary_with_live_counts(&session, true).await;
        let active_addr = self.get_active_proxy_addr().await;
        let ui_addr = self.get_active_ui_addr().await;
        RuntimeInfo {
            runtime_instance_id: self.runtime_instance_id,
            proxy_addr: active_addr.to_string(),
            ui_addr: ui_addr.to_string(),
            max_entries: self.config.max_entries,
            max_transaction_entries: self.config.max_transaction_entries,
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
            runtime: session.runtime.snapshot().await.redacted_for_read(),
            startup: self.startup.view(active_addr).await,
            active_session,
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
        let client = app_release_http_client("failed to build GitHub releases client")?;

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
        let update_available = release_update_available(&info.current_version, &release);
        info.latest_version = Some(release.tag_name.clone());
        info.latest_release_url = Some(release.html_url);
        info.update_available = update_available;
        Ok(info)
    }

    /// Download the latest DMG from GitHub releases, mount it, copy the new
    /// app bundle over the current one, then restart the process.
    /// Sends progress events through the provided sender.
    pub async fn self_update(
        self: &Arc<Self>,
        tx: tokio::sync::mpsc::Sender<UpdateProgress>,
    ) -> Result<()> {
        use std::process::Command;
        use tokio::io::AsyncWriteExt;

        let mut update_guard = self.begin_self_update()?;
        let app_bundle = self.app_bundle_path()?;
        verify_app_identity(&app_bundle, env!("CARGO_PKG_VERSION"), "current app")
            .context("current app bundle identity check failed")?;
        ensure_self_update_bundle_is_writable(&app_bundle)?;

        // An ad-hoc-signed install (no Developer ID team) was distributed unsigned,
        // so it cannot enforce Gatekeeper/team pinning on its own updates. Rather
        // than brick self-update, such installs accept ad-hoc updates from the same
        // release line. Developer-ID-signed installs keep the strict checks below.
        // ponytail: only relaxed for already-unsigned installs; sign the app to
        // restore Gatekeeper + team-pin enforcement.
        let allow_adhoc_update = allow_ad_hoc_self_update()
            || app_signing_team_identifier(&app_bundle, "current app")?.is_none();

        tx.send(UpdateProgress::step("Checking for updates..."))
            .await
            .ok();

        let client = app_release_http_client("failed to build HTTP client")?;

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

        ensure_release_is_newer(env!("CARGO_PKG_VERSION"), &release.tag_name)?;

        let dmg_asset = select_release_dmg_asset(&release.assets, &release.tag_name)
            .context("no native-compatible DMG asset found in the latest release")?;

        let total_size = dmg_asset.size;
        tx.send(UpdateProgress::step("Downloading update..."))
            .await
            .ok();

        // Stream-download DMG with progress
        let tmp_dir = std::env::temp_dir().join(format!("sniper-update-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&tmp_dir).await?;
        let mut artifact_guard = UpdateArtifactGuard::new(tmp_dir.clone());
        let dmg_path = tmp_dir.join(&dmg_asset.name);

        let response = client
            .get(&dmg_asset.browser_download_url)
            .send()
            .await
            .context("failed to download DMG")?
            .error_for_status()
            .context("DMG download failed")?;

        let response_content_length = response.content_length();
        let progress_total = response_content_length.or(total_size).unwrap_or(0);

        let mut file = tokio::fs::File::create(&dmg_path).await?;
        let mut stream = response.bytes_stream();
        let mut downloaded: u64 = 0;

        use futures_util::StreamExt;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("download interrupted")?;
            file.write_all(&chunk).await?;
            downloaded += chunk.len() as u64;
            if progress_total > 0 {
                let pct = (((downloaded as f64 / progress_total as f64) * 100.0).round() as u64)
                    .min(100) as u8;
                tx.send(UpdateProgress::download(pct, downloaded, progress_total))
                    .await
                    .ok();
            }
        }
        file.flush().await?;
        drop(file);
        validate_downloaded_update_size(downloaded, response_content_length, total_size)?;

        // Mount the DMG and ask hdiutil for machine-readable output.
        tx.send(UpdateProgress::step("Installing update..."))
            .await
            .ok();

        let mount_output = Command::new(HDIUTIL_PATH)
            .args(["attach", "-nobrowse", "-plist"])
            .arg(&dmg_path)
            .output()
            .context("failed to mount DMG")?;

        if !mount_output.status.success() {
            anyhow::bail!(
                "hdiutil attach failed: {}",
                String::from_utf8_lossy(&mount_output.stderr)
            );
        }

        let attach_info = match parse_hdiutil_attach_output(&mount_output.stdout) {
            Ok(attach_info) => attach_info,
            Err(error) => {
                cleanup_update_artifacts(&[], &tmp_dir).await;
                return Err(error);
            }
        };
        let detach_targets = attach_info.detach_targets.clone();
        artifact_guard.set_detach_targets(detach_targets.clone());

        let new_app_path = match find_update_app_bundle_in_mounts(&attach_info.mount_points) {
            Ok((_mount_point, app_path)) => app_path,
            Err(error) => {
                cleanup_update_artifacts(&detach_targets, &tmp_dir).await;
                return Err(error);
            }
        };
        if !new_app_path.exists() {
            cleanup_update_artifacts(&detach_targets, &tmp_dir).await;
            anyhow::bail!("downloaded app bundle disappeared from mounted DMG");
        }

        tx.send(UpdateProgress::step("Verifying signature..."))
            .await
            .ok();
        if let Err(error) = verify_app_signature(&new_app_path, "downloaded app") {
            cleanup_update_artifacts(&detach_targets, &tmp_dir).await;
            return Err(error);
        }
        if allow_adhoc_update {
            tracing::warn!(
                "skipping Gatekeeper assessment for downloaded app (ad-hoc self-update)"
            );
        } else {
            if let Err(error) = assess_app_gatekeeper(&new_app_path, "downloaded app") {
                cleanup_update_artifacts(&detach_targets, &tmp_dir).await;
                return Err(error);
            }
        }
        if let Err(error) = verify_app_identity(&new_app_path, &release.tag_name, "downloaded app")
        {
            cleanup_update_artifacts(&detach_targets, &tmp_dir).await;
            return Err(error);
        }
        if let Err(error) = verify_app_executable_arch_for_release_asset(
            &new_app_path,
            &dmg_asset.name,
            "downloaded app",
        ) {
            cleanup_update_artifacts(&detach_targets, &tmp_dir).await;
            return Err(error);
        }
        if let Err(error) = verify_app_signing_team_matches(&new_app_path, &app_bundle) {
            cleanup_update_artifacts(&detach_targets, &tmp_dir).await;
            return Err(error);
        }

        let staged_app = tmp_dir.join("staged").join("Sniper.app");
        if let Some(parent) = staged_app.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let stage_output = Command::new(DITTO_PATH)
            .arg(&new_app_path)
            .arg(&staged_app)
            .output()
            .context("failed to stage new app bundle")?;

        if !stage_output.status.success() {
            cleanup_update_artifacts(&detach_targets, &tmp_dir).await;
            anyhow::bail!(
                "staging ditto failed: {}",
                String::from_utf8_lossy(&stage_output.stderr)
            );
        }

        tx.send(UpdateProgress::step("Verifying signature..."))
            .await
            .ok();
        if let Err(error) = verify_app_signature(&staged_app, "staged app") {
            cleanup_update_artifacts(&detach_targets, &tmp_dir).await;
            return Err(error);
        }
        if let Err(error) = verify_app_identity(&staged_app, &release.tag_name, "staged app") {
            cleanup_update_artifacts(&detach_targets, &tmp_dir).await;
            return Err(error);
        }
        if let Err(error) =
            verify_app_executable_arch_for_release_asset(&staged_app, &dmg_asset.name, "staged app")
        {
            cleanup_update_artifacts(&detach_targets, &tmp_dir).await;
            return Err(error);
        }

        let expected_team = match app_signing_team_identifier(&app_bundle, "current app") {
            Ok(team) => team.unwrap_or_default(),
            Err(error) => {
                cleanup_update_artifacts(&detach_targets, &tmp_dir).await;
                return Err(error);
            }
        };
        let installer_log_path = self_update_installer_log_path(&self.config.data_dir);
        let installer_log = match open_self_update_installer_log(&installer_log_path) {
            Ok(file) => file,
            Err(error) => {
                cleanup_update_artifacts(&detach_targets, &tmp_dir).await;
                return Err(error);
            }
        };
        tx.send(UpdateProgress::step(&format!(
            "Installer log: {}",
            installer_log_path.display()
        )))
        .await
        .ok();

        detach_update_targets(&detach_targets).await;
        artifact_guard.clear_detach_targets();

        if let Err(error) = self.prepare_for_self_update_shutdown().await {
            cleanup_update_artifacts(&[], &tmp_dir).await;
            return Err(error);
        }

        if let Err(error) = spawn_update_installer_after_exit(
            std::process::id(),
            &staged_app,
            &app_bundle,
            &tmp_dir,
            &release.tag_name,
            &expected_team,
            installer_log,
        ) {
            cleanup_update_artifacts(&[], &tmp_dir).await;
            self.restore_proxy_after_self_update_prepare_failure().await;
            return Err(error);
        }

        artifact_guard.disarm();
        update_guard.keep_latched();
        tx.send(UpdateProgress::step("Restarting...")).await.ok();
        self.remove_runtime_state_for_self_update_restart();

        tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            std::process::exit(0);
        });

        Ok(())
    }

    fn begin_self_update(&self) -> Result<SelfUpdateGuard> {
        self.update_in_progress
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| anyhow::anyhow!("self-update is already in progress"))?;
        Ok(SelfUpdateGuard {
            in_progress: self.update_in_progress.clone(),
            keep_latched: false,
        })
    }

    async fn prepare_for_self_update_shutdown(&self) -> Result<()> {
        self.ws_replay.disconnect_all().await;
        let relay_result = crate::proxy::close_live_websocket_relays(
            self,
            "Sniper self-update restart closed the live WebSocket relay.",
        )
        .await
        .context("failed to persist closed live WebSocket relays before self-update restart");
        self.abort_proxy_task().await;
        self.set_proxy_online(false);
        crate::proxy::drain_proxy_connections(Duration::from_secs(1)).await;
        crate::proxy::flush_pending_session_persists(self)
            .await
            .context("failed to flush pending session snapshots before self-update restart")?;
        self.persist_active_session()
            .await
            .context("failed to persist active session before self-update restart")?;
        relay_result?;
        Ok(())
    }

    async fn restore_proxy_after_self_update_prepare_failure(self: &Arc<Self>) {
        let proxy_addr = self.get_active_proxy_addr().await;
        match crate::proxy::rebind_proxy(Arc::clone(self), proxy_addr).await {
            Ok(()) => {
                tracing::warn!(
                    %proxy_addr,
                    "restored proxy listener after self-update installer spawn failure"
                );
            }
            Err(error) => {
                self.set_proxy_online(false);
                let ui_addr = self.get_active_ui_addr().await;
                if let Err(persist_error) = crate::runtime_state::persist_runtime_state(
                    &self.config.data_dir,
                    &crate::runtime_state::RuntimeStateSnapshot::with_proxy_status_and_instance(
                        proxy_addr,
                        ui_addr,
                        false,
                        self.runtime_instance_id,
                    ),
                ) {
                    tracing::warn!(
                        ?persist_error,
                        "failed to persist offline runtime state after self-update installer spawn failure"
                    );
                }
                tracing::warn!(
                    %error,
                    %proxy_addr,
                    "failed to restore proxy listener after self-update installer spawn failure"
                );
            }
        }
    }

    fn remove_runtime_state_for_self_update_restart(&self) {
        match crate::runtime_state::remove_runtime_state_if_owner(
            &self.config.data_dir,
            self.runtime_instance_id,
        ) {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!(
                    "runtime state was replaced before self-update restart; leaving it intact"
                );
            }
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "failed to remove runtime state before self-update restart"
                );
            }
        }
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
        validate_self_update_app_bundle_path(contents)?;
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

struct SelfUpdateGuard {
    in_progress: Arc<AtomicBool>,
    keep_latched: bool,
}

impl SelfUpdateGuard {
    fn keep_latched(&mut self) {
        self.keep_latched = true;
    }
}

impl Drop for SelfUpdateGuard {
    fn drop(&mut self) {
        if !self.keep_latched {
            self.in_progress.store(false, Ordering::Release);
        }
    }
}

struct UpdateArtifactGuard {
    tmp_dir: std::path::PathBuf,
    detach_targets: Vec<String>,
    disarmed: bool,
}

impl UpdateArtifactGuard {
    fn new(tmp_dir: std::path::PathBuf) -> Self {
        Self {
            tmp_dir,
            detach_targets: Vec::new(),
            disarmed: false,
        }
    }

    fn set_detach_targets(&mut self, detach_targets: Vec<String>) {
        self.detach_targets = detach_targets;
    }

    fn clear_detach_targets(&mut self) {
        self.detach_targets.clear();
    }

    fn disarm(&mut self) {
        self.disarmed = true;
    }
}

impl Drop for UpdateArtifactGuard {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }
        for target in &self.detach_targets {
            let _ = std::process::Command::new(HDIUTIL_PATH)
                .args(["detach", "-quiet", target])
                .status();
        }
        let _ = std::fs::remove_dir_all(&self.tmp_dir);
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RuntimeInfo {
    pub runtime_instance_id: uuid::Uuid,
    pub proxy_addr: String,
    pub ui_addr: String,
    pub max_entries: usize,
    pub max_transaction_entries: usize,
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

#[derive(Debug, Deserialize)]
struct HdiutilAttachOutput {
    #[serde(rename = "system-entities", default)]
    system_entities: Vec<HdiutilSystemEntity>,
}

#[derive(Debug, Deserialize)]
struct HdiutilSystemEntity {
    #[serde(rename = "dev-entry")]
    dev_entry: Option<String>,
    #[serde(rename = "mount-point")]
    mount_point: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HdiutilAttachInfo {
    mount_points: Vec<String>,
    detach_targets: Vec<String>,
}

fn parse_hdiutil_attach_output(output: &[u8]) -> Result<HdiutilAttachInfo> {
    let attach_output: HdiutilAttachOutput =
        plist::from_bytes(output).context("failed to parse hdiutil attach plist output")?;

    let mut mount_points = Vec::new();
    let mut detach_targets = Vec::new();
    for entity in attach_output.system_entities {
        if let Some(mount_point) = entity
            .mount_point
            .filter(|mount_point| mount_point.starts_with("/Volumes/"))
        {
            push_unique(&mut detach_targets, mount_point.clone());
            mount_points.push(mount_point);
        }
        if let Some(dev_entry) = entity
            .dev_entry
            .filter(|dev_entry| dev_entry.starts_with("/dev/"))
        {
            push_unique(&mut detach_targets, dev_entry);
        }
    }

    Ok(HdiutilAttachInfo {
        mount_points,
        detach_targets,
    })
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

fn select_release_dmg_asset<'a>(
    assets: &'a [GitHubAsset],
    release_tag: &str,
) -> Option<&'a GitHubAsset> {
    let native_arch = native_release_asset_arch();
    assets
        .iter()
        .filter(|asset| is_dmg_asset(&asset.name))
        .filter(|asset| release_asset_version_matches(&asset.name, release_tag))
        .find(|asset| release_asset_matches_arch(&asset.name, native_arch))
        .or_else(|| {
            assets
                .iter()
                .filter(|asset| is_dmg_asset(&asset.name))
                .filter(|asset| release_asset_version_matches(&asset.name, release_tag))
                .find(|asset| is_universal_dmg(&asset.name))
        })
}

fn release_update_available(current_version: &str, release: &GitHubRelease) -> bool {
    is_newer_version(current_version, &release.tag_name)
        && select_release_dmg_asset(&release.assets, &release.tag_name).is_some()
}

fn validate_downloaded_update_size(
    downloaded: u64,
    response_content_length: Option<u64>,
    asset_size: Option<u64>,
) -> Result<()> {
    if let Some(expected) = response_content_length {
        if downloaded != expected {
            anyhow::bail!(
                "downloaded DMG size mismatch: expected {expected} bytes from Content-Length, got {downloaded}"
            );
        }
    }
    if let Some(expected) = asset_size {
        if downloaded != expected {
            anyhow::bail!(
                "downloaded DMG size mismatch: expected {expected} bytes from release metadata, got {downloaded}"
            );
        }
    }
    Ok(())
}

fn find_update_app_bundle_in_mounts(mount_points: &[String]) -> Result<(String, PathBuf)> {
    if mount_points.is_empty() {
        anyhow::bail!("could not find DMG mount point");
    }

    let mut errors = Vec::new();
    for mount_point in mount_points {
        match find_update_app_bundle(Path::new(mount_point)) {
            Ok(app_path) => return Ok((mount_point.clone(), app_path)),
            Err(error) => errors.push(format!("{mount_point}: {error}")),
        }
    }

    anyhow::bail!(
        "could not find Sniper.app in mounted DMG volume(s): {}",
        errors.join("; ")
    )
}

fn find_update_app_bundle(mount_point: &Path) -> Result<PathBuf> {
    let mut app_entries = Vec::new();
    for entry in std::fs::read_dir(mount_point).context("failed to read mounted DMG")? {
        let entry = entry.context("failed to inspect mounted DMG")?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.ends_with(".app") {
            app_entries.push((name.into_owned(), entry.path()));
        }
    }

    if app_entries.len() != 1 || app_entries[0].0 != "Sniper.app" {
        anyhow::bail!("DMG must contain exactly one top-level app named Sniper.app");
    }

    let app_path = app_entries.remove(0).1;
    let metadata = std::fs::symlink_metadata(&app_path)
        .with_context(|| format!("failed to inspect downloaded app {}", app_path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!(
            "downloaded app must be a real app directory: {}",
            app_path.display()
        );
    }
    Ok(app_path)
}

fn native_release_asset_arch() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x86_64",
        other => other,
    }
}

fn is_dmg_asset(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with(".dmg")
}

fn release_asset_matches_arch(name: &str, arch: &str) -> bool {
    match (
        release_asset_arch_tag(name),
        release_asset_arch_tag_from_alias(arch),
    ) {
        (Some(asset_arch), Some(native_arch)) => asset_arch == native_arch,
        _ => false,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReleaseAssetArchTag {
    Arm64,
    X86_64,
    Universal,
}

fn release_asset_arch_tag(name: &str) -> Option<ReleaseAssetArchTag> {
    let lower = name.to_ascii_lowercase();
    let stem = lower.strip_suffix(".dmg")?;
    let (prefix, arch_tag) = stem.rsplit_once('-')?;
    let version = prefix.strip_prefix("sniper-")?;
    if !is_stable_release_version_tag(version) {
        return None;
    }
    release_asset_arch_tag_from_alias(arch_tag)
}

fn release_asset_version_matches(name: &str, release_tag: &str) -> bool {
    let Some(asset_version) = release_asset_version(name) else {
        return false;
    };
    let Some(release_version) = parse_version(release_tag) else {
        return false;
    };
    asset_version == release_version
}

fn release_asset_version(name: &str) -> Option<Version> {
    let lower = name.to_ascii_lowercase();
    let stem = lower.strip_suffix(".dmg")?;
    let (prefix, _arch_tag) = stem.rsplit_once('-')?;
    let version = prefix.strip_prefix("sniper-")?;
    if !is_stable_release_version_tag(version) {
        return None;
    }
    parse_version(version)
}

fn ensure_self_update_bundle_is_writable(app_bundle: &Path) -> Result<()> {
    if !self_update_bundle_is_writable(app_bundle) {
        anyhow::bail!(
            "move Sniper.app to /Applications or another writable folder before updating"
        );
    }
    Ok(())
}

fn self_update_bundle_is_writable(app_bundle: &Path) -> bool {
    if app_bundle.starts_with("/Volumes") {
        return false;
    }
    if app_bundle
        .components()
        .any(|component| component.as_os_str() == "AppTranslocation")
    {
        return false;
    }
    let Some(parent) = app_bundle.parent() else {
        return false;
    };
    std::fs::metadata(parent)
        .map(|metadata| !metadata.permissions().readonly())
        .unwrap_or(false)
        && self_update_parent_write_preflight(parent).is_ok()
}

fn self_update_parent_write_preflight(parent: &Path) -> std::io::Result<()> {
    let nonce = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default()
    );
    let probe = parent.join(format!(".sniper-update-write-test-{nonce}"));
    let renamed = parent.join(format!(".sniper-update-write-test-{nonce}.renamed"));
    let _ = std::fs::remove_dir_all(&probe);
    let _ = std::fs::remove_dir_all(&renamed);
    std::fs::create_dir(&probe)?;
    match std::fs::rename(&probe, &renamed) {
        Ok(()) => {
            std::fs::remove_dir(&renamed)?;
            Ok(())
        }
        Err(error) => {
            let _ = std::fs::remove_dir_all(&probe);
            let _ = std::fs::remove_dir_all(&renamed);
            Err(error)
        }
    }
}

fn release_asset_arch_tag_from_alias(arch: &str) -> Option<ReleaseAssetArchTag> {
    match arch.to_ascii_lowercase().as_str() {
        "arm64" | "aarch64" => Some(ReleaseAssetArchTag::Arm64),
        "x86_64" | "x64" | "amd64" => Some(ReleaseAssetArchTag::X86_64),
        "universal" => Some(ReleaseAssetArchTag::Universal),
        _ => None,
    }
}

fn is_stable_release_version_tag(value: &str) -> bool {
    match parse_version(value) {
        Some(version) => version.pre.is_empty() && version.build.is_empty(),
        None => false,
    }
}

fn is_universal_dmg(name: &str) -> bool {
    release_asset_arch_tag(name) == Some(ReleaseAssetArchTag::Universal)
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
        Self {
            step: msg.to_string(),
            percent: None,
            downloaded: None,
            total: None,
        }
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

async fn cleanup_update_artifacts(detach_targets: &[String], tmp_dir: &Path) {
    detach_update_targets(detach_targets).await;
    let _ = tokio::fs::remove_dir_all(tmp_dir).await;
}

async fn detach_update_targets(detach_targets: &[String]) {
    for target in detach_targets {
        detach_update_dmg(target).await;
    }
}

async fn detach_update_dmg(target: &str) {
    let _ = tokio::process::Command::new(HDIUTIL_PATH)
        .args(["detach", "-quiet"])
        .arg(target)
        .output()
        .await;
}

fn self_update_installer_log_path(data_dir: &Path) -> PathBuf {
    data_dir.join(SELF_UPDATE_INSTALLER_LOG_FILE)
}

fn open_self_update_installer_log(path: &Path) -> Result<fs::File> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create self-update installer log directory {}",
                parent.display()
            )
        })?;
    }
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
        options.mode(0o600);
    }
    let mut file = options.open(path).with_context(|| {
        format!(
            "failed to open self-update installer log {}",
            path.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).with_context(|| {
            format!(
                "failed to set private permissions on self-update installer log {}",
                path.display()
            )
        })?;
    }
    writeln!(
        file,
        "--- Sniper self-update installer {} ---",
        chrono::Utc::now().to_rfc3339()
    )
    .with_context(|| {
        format!(
            "failed to write self-update installer log marker {}",
            path.display()
        )
    })?;
    file.flush().with_context(|| {
        format!(
            "failed to flush self-update installer log marker {}",
            path.display()
        )
    })?;
    Ok(file)
}

fn spawn_update_installer_after_exit(
    pid: u32,
    staged_app: &Path,
    app_bundle: &Path,
    tmp_dir: &Path,
    expected_version: &str,
    expected_team: &str,
    installer_log: fs::File,
) -> Result<()> {
    let installer_err_log = installer_log
        .try_clone()
        .context("failed to clone self-update installer log handle")?;
    std::process::Command::new(SH_PATH)
        .args([
            "-c",
            update_installer_script(),
            "sniper-installer",
            &pid.to_string(),
            &staged_app.display().to_string(),
            &app_bundle.display().to_string(),
            &tmp_dir.display().to_string(),
            expected_version,
            expected_team,
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(installer_log))
        .stderr(std::process::Stdio::from(installer_err_log))
        .spawn()
        .context("failed to spawn self-update installer")?;
    Ok(())
}

fn update_installer_script() -> &'static str {
    r#"pid="$1"
staged="$2"
bundle="$3"
tmp="$4"
expected_version="$5"
case "$expected_version" in
  v*|V*) expected_version="${expected_version#?}" ;;
esac
expected_team="$6"
backup="${bundle}.previous.$$"
bundle_parent="$(/usr/bin/dirname "$bundle")"
backup_name="$(/usr/bin/basename "$backup")"
log_installer() {
  echo "sniper-installer: $1"
}
sniper_app_path_shape_ok() {
  candidate="$1"
  candidate_name="$(/usr/bin/basename "$candidate")"
  candidate_parent="$(/usr/bin/dirname "$candidate")"
  [ -d "$candidate" ] && \
    [ ! -L "$candidate" ] && \
    [ "$candidate_name" = "Sniper.app" ] && \
    [ "$candidate_parent" = "$bundle_parent" ]
}
sniper_app_identity_ok_if_present() {
  candidate="$1"
  info_plist="$candidate/Contents/Info.plist"
  if [ ! -f "$info_plist" ]; then
    return 0
  fi
  candidate_bundle_id="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$info_plist" 2>/dev/null || true)"
  candidate_executable="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$info_plist" 2>/dev/null || true)"
  [ "$candidate_bundle_id" = "com.sm1ee.sniper" ] && [ "$candidate_executable" = "Sniper" ]
}
sniper_backup_path_ok() {
  candidate="$1"
  candidate_name="$(/usr/bin/basename "$candidate")"
  candidate_parent="$(/usr/bin/dirname "$candidate")"
  [ -d "$candidate" ] && \
    [ ! -L "$candidate" ] && \
    [ "$candidate_name" = "$backup_name" ] && \
    [ "$candidate_parent" = "$bundle_parent" ] && \
    sniper_app_identity_ok_if_present "$candidate"
}
remove_sniper_app_dir() {
  candidate="$1"
  if sniper_app_path_shape_ok "$candidate" && sniper_app_identity_ok_if_present "$candidate"; then
    rm -rf "$candidate"
    return $?
  fi
  log_installer "refusing to remove unexpected app path $candidate"
  return 1
}
remove_sniper_backup_dir() {
  candidate="$1"
  if sniper_backup_path_ok "$candidate"; then
    rm -rf "$candidate"
    return $?
  fi
  log_installer "refusing to remove unexpected backup path $candidate"
  return 1
}
matching_sniper_pids() {
  sniper_executable="$bundle/Contents/MacOS/Sniper"
  /bin/ps -axww -o pid= -o command= | /usr/bin/awk -v exe="$sniper_executable" '
    {
      pid=$1
      sub(/^[[:space:]]*[0-9]+[[:space:]]+/, "", $0)
      if (pid ~ /^[0-9]+$/ && index($0, exe) == 1) print pid
    }
  '
}
launch_health_check() {
  before_pids="$(matching_sniper_pids)"
  if ! /usr/bin/open -n "$bundle"; then
    return 1
  fi
  launch_attempts=0
  while [ "$launch_attempts" -lt 50 ]; do
    after_pids="$(matching_sniper_pids)"
    for candidate_pid in $after_pids; do
      found_before=0
      for before_pid in $before_pids; do
        if [ "$candidate_pid" = "$before_pid" ]; then
          found_before=1
          break
        fi
      done
      if [ "$found_before" -eq 0 ]; then
        sleep 2
        matching_sniper_pids | /usr/bin/grep -qx "$candidate_pid"
        return $?
      fi
    done
    launch_attempts=$((launch_attempts + 1))
    sleep 0.2
  done
  log_installer "launch health check timed out"
  return 1
}
log_installer "waiting for old process $pid to exit"
wait_attempts=0
while kill -0 "$pid" 2>/dev/null; do
  wait_attempts=$((wait_attempts + 1))
  if [ "$wait_attempts" -ge 150 ]; then
    log_installer "timed out waiting for old process $pid"
    rm -rf "$tmp"
    exit 1
  fi
  sleep 0.2
done
sleep 0.5
if [ -e "$backup" ]; then
  if ! remove_sniper_backup_dir "$backup"; then
    rm -rf "$tmp"
    exit 1
  fi
fi
if [ -e "$bundle" ]; then
  if ! mv "$bundle" "$backup"; then
    log_installer "failed to move existing app bundle to backup"
    rm -rf "$tmp"
    exit 1
  fi
fi
log_installer "installing staged app"
if /usr/bin/ditto "$staged" "$bundle" && /usr/bin/codesign --verify --deep --strict "$bundle"; then
  installed_bundle_id="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$bundle/Contents/Info.plist" 2>/dev/null || true)"
  installed_executable="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$bundle/Contents/Info.plist" 2>/dev/null || true)"
  installed_version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$bundle/Contents/Info.plist" 2>/dev/null || true)"
  case "$installed_version" in
    v*|V*) installed_version="${installed_version#?}" ;;
  esac
  installed_team=""
  if [ -n "$expected_team" ]; then
    installed_team="$(/usr/bin/codesign -dv --verbose=4 "$bundle" 2>&1 | /usr/bin/awk -F= '/^TeamIdentifier=/{print $2; exit}')"
  fi
  if [ "$installed_bundle_id" = "com.sm1ee.sniper" ] && \
    [ "$installed_executable" = "Sniper" ] && \
    [ "$installed_version" = "$expected_version" ] && \
    { [ -z "$expected_team" ] || [ "$installed_team" = "$expected_team" ]; } && \
    { [ -z "$expected_team" ] || /usr/sbin/spctl --assess --type execute "$bundle"; }; then
    if launch_health_check; then
      log_installer "update installed and launched successfully"
      remove_sniper_backup_dir "$backup" || log_installer "leaving previous app backup at $backup"
      rm -rf "$tmp"
      exit 0
    fi
    log_installer "launch health check failed"
  else
    log_installer "installed app validation failed"
  fi
else
  log_installer "failed to copy or verify staged app"
fi
if [ -e "$bundle" ]; then
  if ! remove_sniper_app_dir "$bundle"; then
    rm -rf "$tmp"
    exit 1
  fi
fi
if [ -e "$backup" ]; then
  if mv "$backup" "$bundle"; then
    log_installer "restored previous app bundle after update failure"
    /usr/bin/codesign --verify --deep --strict "$bundle" && /usr/bin/open "$bundle" || true
  else
    log_installer "failed to restore previous app bundle"
    rm -rf "$tmp"
    exit 1
  fi
fi
rm -rf "$tmp"
log_installer "self-update installer failed"
exit 1
"#
}

fn verify_app_signature(app_path: &Path, label: &str) -> Result<()> {
    let output = std::process::Command::new(CODESIGN_PATH)
        .args(["--verify", "--deep", "--strict"])
        .arg(app_path)
        .output()
        .with_context(|| format!("failed to verify {label} signature"))?;
    if output.status.success() {
        return Ok(());
    }
    anyhow::bail!(
        "{label} signature verification failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assess_app_gatekeeper(app_path: &Path, label: &str) -> Result<()> {
    let output = std::process::Command::new(SPCTL_PATH)
        .args(["--assess", "--type", "execute"])
        .arg(app_path)
        .output()
        .with_context(|| format!("failed to assess {label} with Gatekeeper"))?;
    if output.status.success() {
        return Ok(());
    }
    anyhow::bail!(
        "{label} Gatekeeper assessment failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn verify_app_identity(app_path: &Path, expected_version: &str, label: &str) -> Result<()> {
    let plist_path = app_path.join("Contents/Info.plist");
    let bundle_id = read_info_plist_value(&plist_path, "CFBundleIdentifier")?;
    if bundle_id != EXPECTED_APP_BUNDLE_IDENTIFIER {
        anyhow::bail!(
            "{label} bundle identifier mismatch: expected {}, got {}",
            EXPECTED_APP_BUNDLE_IDENTIFIER,
            bundle_id
        );
    }

    let executable = read_info_plist_value(&plist_path, "CFBundleExecutable")?;
    if executable != EXPECTED_APP_EXECUTABLE {
        anyhow::bail!(
            "{label} executable mismatch: expected {}, got {}",
            EXPECTED_APP_EXECUTABLE,
            executable
        );
    }

    let version = normalize_version_text(&read_info_plist_value(
        &plist_path,
        "CFBundleShortVersionString",
    )?);
    let expected_version = normalize_version_text(expected_version);
    if version != expected_version {
        anyhow::bail!(
            "{label} version mismatch: expected {}, got {}",
            expected_version,
            version
        );
    }

    Ok(())
}

fn verify_app_executable_arch_for_release_asset(
    app_path: &Path,
    asset_name: &str,
    label: &str,
) -> Result<()> {
    for executable in [EXPECTED_APP_EXECUTABLE, EXPECTED_BUNDLED_CLI_EXECUTABLE] {
        let executable_path = app_path.join("Contents/MacOS").join(executable);
        let output = std::process::Command::new(LIPO_PATH)
            .args(["-archs"])
            .arg(&executable_path)
            .output()
            .with_context(|| {
                format!(
                    "failed to inspect {label} {executable} architecture at {}",
                    executable_path.display()
                )
            })?;
        if !output.status.success() {
            anyhow::bail!(
                "failed to inspect {label} {executable} architecture: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let archs = String::from_utf8_lossy(&output.stdout);
        let archs: Vec<&str> = archs.split_whitespace().collect();
        if !release_asset_archs_match_binary_archs(asset_name, &archs) {
            anyhow::bail!(
                "{label} {executable} architecture {:?} does not match release asset {}",
                archs,
                asset_name
            );
        }
    }
    Ok(())
}

fn release_asset_archs_match_binary_archs(asset_name: &str, binary_archs: &[&str]) -> bool {
    let Some(asset_arch) = release_asset_arch_tag(asset_name) else {
        return false;
    };
    let has_arm64 = binary_archs
        .iter()
        .any(|arch| release_asset_arch_tag_from_alias(arch) == Some(ReleaseAssetArchTag::Arm64));
    let has_x86_64 = binary_archs
        .iter()
        .any(|arch| release_asset_arch_tag_from_alias(arch) == Some(ReleaseAssetArchTag::X86_64));
    match asset_arch {
        ReleaseAssetArchTag::Arm64 => has_arm64,
        ReleaseAssetArchTag::X86_64 => has_x86_64,
        ReleaseAssetArchTag::Universal => has_arm64 && has_x86_64,
    }
}

fn verify_app_signing_team_matches(downloaded_app: &Path, current_app: &Path) -> Result<()> {
    let current_team = app_signing_team_identifier(current_app, "current app")?;
    let downloaded_team = app_signing_team_identifier(downloaded_app, "downloaded app")?;
    signing_team_update_verdict(current_team, downloaded_team)
}

/// Decide whether a self-update is allowed based on the current and downloaded
/// app signing teams. A Developer-ID install (Some team) must receive a matching
/// signed update. An ad-hoc install (None team) cannot pin a team on its updates,
/// so it accepts ad-hoc updates instead of bricking self-update.
fn signing_team_update_verdict(
    current_team: Option<String>,
    downloaded_team: Option<String>,
) -> Result<()> {
    match (current_team, downloaded_team) {
        (Some(current), Some(downloaded)) if current == downloaded => Ok(()),
        (Some(current), Some(downloaded)) => {
            anyhow::bail!(
                "downloaded app signing team mismatch: expected {current}, got {downloaded}"
            )
        }
        (Some(current), None) => {
            anyhow::bail!("downloaded app is missing signing team identifier {current}")
        }
        (None, _) => {
            tracing::warn!(
                "current app has no signing team identifier (ad-hoc install); accepting ad-hoc self-update"
            );
            Ok(())
        }
    }
}

fn allow_ad_hoc_self_update() -> bool {
    std::env::var("SNIPER_ALLOW_ADHOC_SELF_UPDATE").as_deref() == Ok("1")
}

fn app_signing_team_identifier(app_path: &Path, label: &str) -> Result<Option<String>> {
    let output = std::process::Command::new(CODESIGN_PATH)
        .args(["-dv", "--verbose=4"])
        .arg(app_path)
        .output()
        .with_context(|| format!("failed to inspect {label} signature"))?;
    if !output.status.success() {
        anyhow::bail!(
            "failed to inspect {label} signature: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(parse_codesign_team_identifier(&String::from_utf8_lossy(
        &output.stderr,
    )))
}

fn parse_codesign_team_identifier(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        line.strip_prefix("TeamIdentifier=")
            .map(str::trim)
            .filter(|value| !value.is_empty() && *value != "not set")
            .map(ToOwned::to_owned)
    })
}

fn read_info_plist_value(plist_path: &Path, key: &str) -> Result<String> {
    let command = format!("Print :{key}");
    let output = std::process::Command::new(PLIST_BUDDY_PATH)
        .args(["-c", command.as_str()])
        .arg(plist_path)
        .output()
        .with_context(|| format!("failed to read {key} from {}", plist_path.display()))?;
    if !output.status.success() {
        anyhow::bail!(
            "failed to read {key} from {}: {}",
            plist_path.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn normalize_version_text(value: &str) -> String {
    value.trim().trim_start_matches(['v', 'V']).to_string()
}

fn parse_version(value: &str) -> Option<Version> {
    Version::parse(&normalize_version_text(value)).ok()
}

fn ensure_release_is_newer(current: &str, latest: &str) -> Result<()> {
    if is_newer_version(current, latest) {
        return Ok(());
    }
    anyhow::bail!("latest release {latest} is not newer than current version {current}");
}

fn is_newer_version(current: &str, latest: &str) -> bool {
    match (parse_version(current), parse_version(latest)) {
        (Some(current), Some(latest)) => latest > current,
        _ => false,
    }
}

fn app_release_http_client(error_context: &'static str) -> Result<reqwest::Client> {
    let builder = reqwest::Client::builder()
        .connect_timeout(APP_RELEASE_CONNECT_TIMEOUT)
        .read_timeout(APP_RELEASE_READ_TIMEOUT)
        .user_agent(format!(
            "Sniper/{} (+{})",
            env!("CARGO_PKG_VERSION"),
            APP_RELEASES_URL
        ));
    let builder = if release_proxy_env_targets_loopback() {
        builder.no_proxy()
    } else {
        builder
    };
    builder.build().context(error_context)
}

fn release_proxy_env_targets_loopback() -> bool {
    ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]
        .iter()
        .filter_map(|key| env::var(key).ok())
        .any(|value| proxy_url_targets_loopback(&value))
}

fn proxy_url_targets_loopback(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() {
        return false;
    }
    let parsed = if value.contains("://") {
        url::Url::parse(value)
    } else {
        url::Url::parse(&format!("http://{value}"))
    };
    let Ok(parsed) = parsed else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .map(|addr| addr.is_loopback())
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::{
        ensure_release_is_newer, find_update_app_bundle, find_update_app_bundle_in_mounts,
        native_release_asset_arch, open_self_update_installer_log, parse_codesign_team_identifier,
        parse_hdiutil_attach_output, proxy_url_targets_loopback,
        release_asset_archs_match_binary_archs, release_asset_matches_arch,
        release_proxy_env_targets_loopback, release_update_available, select_release_dmg_asset,
        self_update_bundle_is_writable, self_update_installer_log_path, signing_team_update_verdict,
        update_installer_script,
        validate_downloaded_update_size, validate_self_update_app_bundle_path, verify_app_identity,
        AppState, GitHubAsset, GitHubRelease, UpdateArtifactGuard, CODESIGN_PATH, DITTO_PATH,
        EXPECTED_APP_BUNDLE_IDENTIFIER, EXPECTED_APP_EXECUTABLE, HDIUTIL_PATH, LIPO_PATH,
        PLIST_BUDDY_PATH, SH_PATH, SPCTL_PATH,
    };
    use crate::config::AppConfig;
    use crate::event_log::EventLevel;
    use crate::fuzzer::{FuzzerAttackRecord, FuzzerAttackStatus};
    use crate::match_replace::{MatchReplaceRule, MatchReplaceScope, MatchReplaceTarget};
    use crate::model::WebSocketSessionRecord;
    use crate::model::{BodyEncoding, EditableRequest, MessageRecord, TransactionRecord};
    use crate::workspace::{
        ReplayTabState, ReplayWorkspaceState, WorkspaceReplaceError, WorkspaceStateSnapshot,
    };
    use std::fs;
    use std::path::Path;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn asset(name: &str) -> GitHubAsset {
        GitHubAsset {
            name: name.to_string(),
            browser_download_url: format!("https://example.test/{name}"),
            size: Some(1),
        }
    }

    fn release(tag_name: &str, assets: Vec<GitHubAsset>) -> GitHubRelease {
        GitHubRelease {
            tag_name: tag_name.to_string(),
            html_url: format!("https://example.test/releases/{tag_name}"),
            assets,
        }
    }

    #[test]
    fn update_asset_selection_prefers_native_arch_dmg() {
        let native = native_release_asset_arch();
        let other = if native == "arm64" { "x86_64" } else { "arm64" };
        let assets = vec![
            asset(&format!("Sniper-0.2.4-{other}.dmg")),
            asset(&format!("Sniper-0.2.4-{native}.dmg")),
        ];

        let selected = select_release_dmg_asset(&assets, "v0.2.4").unwrap();

        assert!(selected.name.contains(native));
    }

    #[test]
    fn release_asset_arch_matching_accepts_common_aliases() {
        assert!(release_asset_matches_arch("Sniper-0.2.4-x64.dmg", "x86_64"));
        assert!(release_asset_matches_arch(
            "Sniper-0.2.4-amd64.dmg",
            "x86_64"
        ));
        assert!(release_asset_matches_arch(
            "Sniper-0.2.4-aarch64.dmg",
            "arm64"
        ));
        assert!(!release_asset_matches_arch(
            "Sniper-0.2.4-arm64.dmg",
            "x86_64"
        ));
    }

    #[test]
    fn release_asset_arch_matching_rejects_misleading_tokens() {
        assert!(!release_asset_matches_arch(
            "Sniper-0.2.4-not-arm64.dmg",
            "arm64"
        ));
        assert!(!release_asset_matches_arch(
            "Sniper-0.2.4-arm64-copy.dmg",
            "arm64"
        ));
        assert!(!release_asset_matches_arch(
            "Other-0.2.4-arm64.dmg",
            "arm64"
        ));
        assert!(!release_asset_matches_arch(
            "Sniper-0.2.4+build-arm64.dmg",
            "arm64"
        ));
    }

    #[test]
    fn self_update_system_tool_paths_are_absolute() {
        for path in [
            HDIUTIL_PATH,
            DITTO_PATH,
            CODESIGN_PATH,
            SPCTL_PATH,
            PLIST_BUDDY_PATH,
            LIPO_PATH,
            SH_PATH,
        ] {
            assert!(path.starts_with('/'), "{path} should be absolute");
        }
    }

    #[test]
    fn self_update_parses_hdiutil_attach_plist_mounts_and_detach_targets() {
        let output = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>system-entities</key>
  <array>
    <dict>
      <key>dev-entry</key>
      <string>/dev/disk4</string>
    </dict>
    <dict>
      <key>dev-entry</key>
      <string>/dev/disk4s1</string>
      <key>mount-point</key>
      <string>/Volumes/Sniper 0.2.5</string>
    </dict>
  </array>
</dict>
</plist>
"#;

        let info = parse_hdiutil_attach_output(output).unwrap();

        assert_eq!(info.mount_points, vec!["/Volumes/Sniper 0.2.5"]);
        assert_eq!(
            info.detach_targets,
            vec!["/dev/disk4", "/Volumes/Sniper 0.2.5", "/dev/disk4s1"]
        );
    }

    #[test]
    fn self_update_tracks_detach_targets_without_mount_point() {
        let output = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>system-entities</key>
  <array>
    <dict>
      <key>dev-entry</key>
      <string>/dev/disk4s1</string>
    </dict>
  </array>
</dict>
</plist>
"#;

        let info = parse_hdiutil_attach_output(output).unwrap();

        assert!(info.mount_points.is_empty());
        assert_eq!(info.detach_targets, vec!["/dev/disk4s1"]);
        assert!(find_update_app_bundle_in_mounts(&info.mount_points)
            .unwrap_err()
            .to_string()
            .contains("could not find DMG mount point"));
    }

    #[test]
    fn release_asset_arch_matching_requires_binary_arch_compatibility() {
        assert!(release_asset_archs_match_binary_archs(
            "Sniper-0.2.5-arm64.dmg",
            &["arm64"]
        ));
        assert!(release_asset_archs_match_binary_archs(
            "Sniper-0.2.5-arm64.dmg",
            &["x86_64", "arm64"]
        ));
        assert!(!release_asset_archs_match_binary_archs(
            "Sniper-0.2.5-arm64.dmg",
            &["x86_64"]
        ));
        assert!(release_asset_archs_match_binary_archs(
            "Sniper-0.2.5-universal.dmg",
            &["x86_64", "arm64"]
        ));
        assert!(!release_asset_archs_match_binary_archs(
            "Sniper-0.2.5-universal.dmg",
            &["arm64"]
        ));
        assert!(!release_asset_archs_match_binary_archs(
            "Sniper-0.2.5.dmg",
            &["x86_64", "arm64"]
        ));
    }

    #[test]
    fn update_asset_selection_falls_back_to_universal_dmg() {
        let assets = vec![
            asset("Sniper-0.2.4.zip"),
            asset("Sniper-0.2.4-universal.dmg"),
        ];

        let selected = select_release_dmg_asset(&assets, "v0.2.4").unwrap();

        assert_eq!(selected.name, "Sniper-0.2.4-universal.dmg");
    }

    #[test]
    fn update_asset_selection_ignores_stale_native_asset_for_latest_tag() {
        let native = native_release_asset_arch();
        let assets = vec![
            asset(&format!("Sniper-0.2.4-{native}.dmg")),
            asset("Sniper-0.2.5-universal.dmg"),
        ];

        let selected = select_release_dmg_asset(&assets, "v0.2.5").unwrap();

        assert_eq!(selected.name, "Sniper-0.2.5-universal.dmg");
    }

    #[test]
    fn update_asset_selection_prefers_current_native_over_current_universal() {
        let native = native_release_asset_arch();
        let assets = vec![
            asset("Sniper-0.2.5-universal.dmg"),
            asset(&format!("Sniper-0.2.5-{native}.dmg")),
        ];

        let selected = select_release_dmg_asset(&assets, "v0.2.5").unwrap();

        assert_eq!(selected.name, format!("Sniper-0.2.5-{native}.dmg"));
    }

    #[test]
    fn update_asset_selection_rejects_misleading_universal_dmg() {
        let assets = vec![
            asset("Sniper-0.2.4.zip"),
            asset("Sniper-0.2.4-not-universal.dmg"),
        ];

        assert!(select_release_dmg_asset(&assets, "v0.2.4").is_none());
    }

    #[test]
    fn self_update_bundle_eligibility_rejects_dmg_and_translocation_paths() {
        assert!(!self_update_bundle_is_writable(Path::new(
            "/Volumes/Sniper/Sniper.app"
        )));
        assert!(!self_update_bundle_is_writable(Path::new(
            "/private/var/folders/xx/AppTranslocation/123/Sniper.app"
        )));
    }

    #[test]
    fn self_update_bundle_eligibility_accepts_writable_parent() {
        let root = std::env::temp_dir().join(format!(
            "sniper-self-update-eligibility-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let app = root.join("Sniper.app");

        assert!(self_update_bundle_is_writable(&app));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn update_asset_selection_rejects_explicit_non_native_arch_dmg() {
        let native = native_release_asset_arch();
        let other = if native == "arm64" { "x86_64" } else { "arm64" };
        let assets = vec![
            asset("Sniper-0.2.4.zip"),
            asset(&format!("Sniper-0.2.4-{other}.dmg")),
        ];

        assert!(select_release_dmg_asset(&assets, "v0.2.4").is_none());
    }

    #[test]
    fn update_asset_selection_rejects_unsuffixed_dmg_fallback() {
        let native = native_release_asset_arch();
        let other = if native == "arm64" { "x86_64" } else { "arm64" };
        let assets = vec![
            asset("Sniper-0.2.4.dmg"),
            asset(&format!("Sniper-0.2.4-{other}.dmg")),
        ];

        assert!(select_release_dmg_asset(&assets, "v0.2.4").is_none());
    }

    #[test]
    fn self_update_release_gate_requires_newer_version() {
        assert!(ensure_release_is_newer("0.2.4", "v0.2.5").is_ok());
        assert!(ensure_release_is_newer("0.2.4", "0.2.4").is_err());
        assert!(ensure_release_is_newer("0.2.4", "v0.2.3").is_err());
    }

    #[test]
    fn signing_team_verdict_allows_adhoc_and_pins_developer_id() {
        let team = |s: &str| Some(s.to_string());
        // Developer-ID install: update must carry the same team.
        assert!(signing_team_update_verdict(team("ABC123"), team("ABC123")).is_ok());
        assert!(signing_team_update_verdict(team("ABC123"), team("XYZ789")).is_err());
        assert!(signing_team_update_verdict(team("ABC123"), None).is_err());
        // Ad-hoc install (no team): accepts ad-hoc updates so self-update is not bricked.
        assert!(signing_team_update_verdict(None, None).is_ok());
        assert!(signing_team_update_verdict(None, team("ABC123")).is_ok());
    }

    #[test]
    fn update_available_requires_newer_native_compatible_dmg() {
        let native = native_release_asset_arch();
        let other = if native == "arm64" { "x86_64" } else { "arm64" };

        assert!(!release_update_available(
            "0.2.4",
            &release("v0.2.5", vec![asset(&format!("Sniper-0.2.5-{other}.dmg"))])
        ));
        assert!(!release_update_available(
            "0.2.4",
            &release("v0.2.5", vec![asset("Sniper-0.2.5.zip")])
        ));
        assert!(!release_update_available(
            "0.2.4",
            &release("v0.2.4", vec![asset(&format!("Sniper-0.2.4-{native}.dmg"))])
        ));
        assert!(release_update_available(
            "0.2.4",
            &release("v0.2.5", vec![asset(&format!("Sniper-0.2.5-{native}.dmg"))])
        ));
        assert!(release_update_available(
            "0.2.4",
            &release("v0.2.5", vec![asset("Sniper-0.2.5-universal.dmg")])
        ));
    }

    #[test]
    fn self_update_download_size_validation_rejects_mismatches() {
        validate_downloaded_update_size(100, Some(100), Some(100)).unwrap();
        validate_downloaded_update_size(100, None, Some(100)).unwrap();

        assert!(validate_downloaded_update_size(99, Some(100), Some(99))
            .unwrap_err()
            .to_string()
            .contains("Content-Length"));
        assert!(validate_downloaded_update_size(101, Some(100), Some(101))
            .unwrap_err()
            .to_string()
            .contains("Content-Length"));
        assert!(validate_downloaded_update_size(100, None, Some(101))
            .unwrap_err()
            .to_string()
            .contains("release metadata"));
    }

    #[test]
    fn self_update_app_discovery_requires_exactly_one_sniper_app() {
        let root = std::env::temp_dir().join(format!(
            "sniper-update-app-discovery-{}",
            uuid::Uuid::new_v4()
        ));
        let sniper_app = root.join("Sniper.app");
        fs::create_dir_all(&sniper_app).unwrap();

        assert_eq!(find_update_app_bundle(&root).unwrap(), sniper_app);

        fs::create_dir_all(root.join("Other.app")).unwrap();
        assert!(find_update_app_bundle(&root)
            .unwrap_err()
            .to_string()
            .contains("exactly one"));

        fs::remove_dir_all(root.join("Other.app")).unwrap();
        fs::rename(&sniper_app, root.join("Other.app")).unwrap();
        assert!(find_update_app_bundle(&root)
            .unwrap_err()
            .to_string()
            .contains("Sniper.app"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn self_update_requires_current_app_bundle_named_sniper_app() {
        let root = std::env::temp_dir().join(format!(
            "sniper-current-app-bundle-{}",
            uuid::Uuid::new_v4()
        ));
        let sniper_app = root.join("Sniper.app");
        let renamed_app = root.join("Sniper Beta.app");
        fs::create_dir_all(sniper_app.join("Contents/MacOS")).unwrap();
        fs::create_dir_all(renamed_app.join("Contents/MacOS")).unwrap();

        validate_self_update_app_bundle_path(&sniper_app).unwrap();
        assert!(validate_self_update_app_bundle_path(&renamed_app)
            .unwrap_err()
            .to_string()
            .contains("Sniper.app"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn updater_proxy_loopback_detection_accepts_common_local_forms() {
        assert!(proxy_url_targets_loopback("http://127.0.0.1:8080"));
        assert!(proxy_url_targets_loopback("localhost:8080"));
        assert!(proxy_url_targets_loopback("http://[::1]:8080"));
        assert!(!proxy_url_targets_loopback(
            "http://proxy.example.test:8080"
        ));
        assert!(!proxy_url_targets_loopback(""));
    }

    #[test]
    fn release_proxy_loopback_detection_uses_https_relevant_proxy_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        let keys = [
            "HTTPS_PROXY",
            "https_proxy",
            "HTTP_PROXY",
            "http_proxy",
            "ALL_PROXY",
            "all_proxy",
        ];
        let previous = keys
            .iter()
            .map(|key| (*key, std::env::var_os(key)))
            .collect::<Vec<_>>();
        for key in keys {
            std::env::remove_var(key);
        }

        std::env::set_var("HTTP_PROXY", "http://127.0.0.1:8080");
        std::env::set_var("HTTPS_PROXY", "http://corp.proxy.example:3128");
        assert!(!release_proxy_env_targets_loopback());

        std::env::set_var("HTTPS_PROXY", "http://127.0.0.1:8443");
        assert!(release_proxy_env_targets_loopback());

        std::env::remove_var("HTTPS_PROXY");
        std::env::set_var("ALL_PROXY", "localhost:9000");
        assert!(release_proxy_env_targets_loopback());

        for (key, value) in previous {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }

    #[test]
    fn self_update_guard_rejects_concurrent_updates() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-update-guard-{}", uuid::Uuid::new_v4()));
        let state = AppState::new(AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        })
        .unwrap();

        let first = state.begin_self_update().unwrap();
        assert!(state.begin_self_update().is_err());
        drop(first);
        assert!(state.begin_self_update().is_ok());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn self_update_guard_stays_latched_after_restart_is_pending() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-update-latched-{}", uuid::Uuid::new_v4()));
        let state = AppState::new(AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        })
        .unwrap();

        let mut first = state.begin_self_update().unwrap();
        first.keep_latched();
        drop(first);

        assert!(state.begin_self_update().is_err());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn self_update_prepare_failure_restore_restarts_proxy_listener() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-update-restore-proxy-{}",
            uuid::Uuid::new_v4()
        ));
        let state = std::sync::Arc::new(
            AppState::new(AppConfig {
                proxy_addr: "127.0.0.1:0".parse().unwrap(),
                ui_addr: "127.0.0.1:0".parse().unwrap(),
                max_entries: 100,
                max_transaction_entries: 100,
                body_preview_bytes: 4096,
                data_dir: data_dir.clone(),
            })
            .unwrap(),
        );

        crate::proxy::rebind_proxy(
            std::sync::Arc::clone(&state),
            state.get_active_proxy_addr().await,
        )
        .await
        .unwrap();
        let proxy_addr = state.get_active_proxy_addr().await;
        assert!(state.is_proxy_online());

        state.prepare_for_self_update_shutdown().await.unwrap();
        assert!(!state.is_proxy_online());

        state
            .restore_proxy_after_self_update_prepare_failure()
            .await;
        assert!(state.is_proxy_online());
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::net::TcpStream::connect(proxy_addr),
        )
        .await
        .expect("proxy listener should accept connections after restore")
        .expect("proxy listener should be reachable after restore");

        state.abort_proxy_task().await;
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn activating_session_updates_active_context_metadata_before_persist() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-activate-session-{}", uuid::Uuid::new_v4()));
        let state = AppState::new(AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        })
        .unwrap();
        let created = state
            .create_session(Some("Review".to_string()))
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;

        let activated = state.activate_session(created.id).await.unwrap();
        let touched_last_opened_at = activated.last_opened_at;
        state.persist_active_session().await.unwrap();
        let summary = state
            .list_sessions()
            .await
            .into_iter()
            .find(|session| session.id == created.id)
            .unwrap();

        assert_eq!(summary.last_opened_at, touched_last_opened_at);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn workspace_snapshot_fallback_updates_registry_metadata() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-workspace-fallback-registry-{}",
            uuid::Uuid::new_v4()
        ));
        let state = AppState::new(AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        })
        .unwrap();
        let session = state.session().await;
        session
            .store
            .insert(TransactionRecord::http(
                chrono::Utc::now(),
                "GET".to_string(),
                "https".to_string(),
                "registry.example".to_string(),
                "/fallback".to_string(),
                Some(200),
                1,
                MessageRecord {
                    headers: Vec::new(),
                    body_preview: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    body_size: 0,
                    decoded_body_size: None,
                    preview_truncated: false,
                    content_type: None,
                    content_decoded: false,
                },
                None,
                Vec::new(),
                None,
                None,
            ))
            .await;
        let snapshot_path = session.storage_dir().join("snapshot.json");
        std::fs::remove_file(&snapshot_path).unwrap();

        let mut workspace = session.workspace.snapshot().await;
        workspace.replay = ReplayWorkspaceState {
            active_tab_id: Some("fallback-tab".to_string()),
            tabs: vec![ReplayTabState {
                id: "fallback-tab".to_string(),
                sequence: 1,
                ..ReplayTabState::default()
            }],
            ..ReplayWorkspaceState::default()
        };

        let committed = state
            .replace_workspace_state_and_persist(&session, workspace)
            .await
            .unwrap();

        assert_eq!(
            committed.replay.active_tab_id.as_deref(),
            Some("fallback-tab")
        );
        let summary = state
            .list_sessions()
            .await
            .into_iter()
            .find(|summary| summary.id == session.id())
            .unwrap();
        assert_eq!(summary.request_count, 1);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn workspace_persist_rejects_invalid_snapshot_without_clobbering_current() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-workspace-invalid-persist-{}",
            uuid::Uuid::new_v4()
        ));
        let state = AppState::new(AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        })
        .unwrap();
        let session = state.session().await;

        let mut workspace = session.workspace.snapshot().await;
        workspace.replay = ReplayWorkspaceState {
            active_tab_id: Some("valid-tab".to_string()),
            tabs: vec![ReplayTabState {
                id: "valid-tab".to_string(),
                sequence: 1,
                ..ReplayTabState::default()
            }],
            ..ReplayWorkspaceState::default()
        };
        state
            .replace_workspace_state_and_persist(&session, workspace)
            .await
            .unwrap();

        let mut invalid = session.workspace.snapshot().await;
        invalid.replay.active_tab_id = Some("missing-tab".to_string());
        let error = state
            .replace_workspace_state_and_persist(&session, invalid)
            .await
            .unwrap_err();
        match error {
            WorkspaceReplaceError::Persist(message) => {
                assert!(message.contains("workspace snapshot is invalid"));
            }
            WorkspaceReplaceError::Conflict(_) => panic!("invalid snapshot should fail validation"),
        }

        let current = session.workspace.snapshot().await;
        assert_eq!(current.replay.active_tab_id.as_deref(), Some("valid-tab"));
        let reloaded = state.sessions.load_context(session.id()).unwrap();
        let durable = reloaded.workspace.snapshot().await;
        assert_eq!(durable.replay.active_tab_id.as_deref(), Some("valid-tab"));

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn session_list_uses_live_retained_counts() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-list-live-count-{}",
            uuid::Uuid::new_v4()
        ));
        let state = AppState::new(AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 2,
            max_transaction_entries: 2,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        })
        .unwrap();
        let session = state.session().await;

        for path in ["/first", "/second", "/third"] {
            session
                .store
                .insert(TransactionRecord::http(
                    chrono::Utc::now(),
                    "GET".to_string(),
                    "https".to_string(),
                    "live-count.example".to_string(),
                    path.to_string(),
                    Some(200),
                    1,
                    MessageRecord {
                        headers: Vec::new(),
                        body_preview: String::new(),
                        body_encoding: BodyEncoding::Utf8,
                        body_size: 0,
                        decoded_body_size: None,
                        preview_truncated: false,
                        content_type: None,
                        content_decoded: false,
                    },
                    None,
                    Vec::new(),
                    None,
                    None,
                ))
                .await;
        }
        session
            .websockets
            .open(WebSocketSessionRecord {
                id: uuid::Uuid::new_v4(),
                sequence: 0,
                started_at: chrono::Utc::now(),
                closed_at: None,
                duration_ms: None,
                scheme: "wss".to_string(),
                host: "live-count.example".to_string(),
                path: "/ws".to_string(),
                status: Some(101),
                request: MessageRecord {
                    headers: Vec::new(),
                    body_preview: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    body_size: 0,
                    decoded_body_size: None,
                    preview_truncated: false,
                    content_type: None,
                    content_decoded: false,
                },
                response: None,
                frames: Vec::new(),
                notes: Vec::new(),
            })
            .await;
        session
            .event_log
            .push(
                EventLevel::Info,
                "test",
                "Live event",
                "Event count should be live",
            )
            .await;
        session
            .fuzzer
            .insert(FuzzerAttackRecord {
                id: uuid::Uuid::new_v4(),
                started_at: chrono::Utc::now(),
                completed_at: chrono::Utc::now(),
                status: FuzzerAttackStatus::Completed,
                template: EditableRequest {
                    scheme: "https".to_string(),
                    host: "live-count.example".to_string(),
                    method: "GET".to_string(),
                    path: "/FUZZ".to_string(),
                    headers: Vec::new(),
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                payload_count: 1,
                marker_count: 1,
                results: Vec::new(),
                notes: Vec::new(),
            })
            .await;
        session
            .match_replace
            .replace_all(vec![MatchReplaceRule {
                id: uuid::Uuid::new_v4(),
                enabled: true,
                description: "count me".to_string(),
                scope: MatchReplaceScope::Request,
                target: MatchReplaceTarget::Path,
                search: "/old".to_string(),
                replace: "/new".to_string(),
                regex: false,
                case_sensitive: false,
            }])
            .await;

        let summary = state
            .list_sessions()
            .await
            .into_iter()
            .find(|summary| summary.id == session.id())
            .unwrap();
        assert_eq!(summary.request_count, 2);
        assert_eq!(summary.websocket_count, 1);
        assert_eq!(summary.event_count, 1);
        assert_eq!(summary.fuzzer_count, 1);
        assert_eq!(summary.rule_count, 1);

        let active_summary = state.active_session_summary().await;
        assert_eq!(active_summary.request_count, 2);
        assert_eq!(active_summary.websocket_count, 1);
        assert_eq!(active_summary.event_count, 1);
        assert_eq!(active_summary.fuzzer_count, 1);
        assert_eq!(active_summary.rule_count, 1);

        let runtime_info = state.runtime_info().await;
        assert_eq!(runtime_info.active_session.request_count, 2);
        assert_eq!(runtime_info.active_session.websocket_count, 1);
        assert_eq!(runtime_info.active_session.event_count, 1);
        assert_eq!(runtime_info.active_session.fuzzer_count, 1);
        assert_eq!(runtime_info.active_session.rule_count, 1);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn inactive_session_contexts_are_canonical_until_activation() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-canonical-session-{}", uuid::Uuid::new_v4()));
        let state = AppState::new(AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        })
        .unwrap();
        let original_id = state.active_session_summary().await.id;
        state
            .create_session(Some("Second".to_string()))
            .await
            .unwrap();

        let first = state.session_context_for_id(original_id).await.unwrap();
        let second = state.session_context_for_id(original_id).await.unwrap();
        assert!(std::sync::Arc::ptr_eq(&first, &second));

        state.activate_session(original_id).await.unwrap();
        let active = state.session().await;
        assert!(std::sync::Arc::ptr_eq(&first, &active));

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn inactive_read_only_session_contexts_are_cached_until_write_path_loads() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-read-only-session-cache-{}",
            uuid::Uuid::new_v4()
        ));
        let state = AppState::new(AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        })
        .unwrap();
        let original_id = state.active_session_summary().await.id;
        state
            .create_session(Some("Second".to_string()))
            .await
            .unwrap();
        state.session_contexts.lock().await.remove(&original_id);
        state
            .read_only_session_contexts
            .lock()
            .await
            .remove(&original_id);

        let first_read = state
            .read_session_context_for_id(original_id)
            .await
            .unwrap();
        let second_read = state
            .read_session_context_for_id(original_id)
            .await
            .unwrap();
        assert!(std::sync::Arc::ptr_eq(&first_read, &second_read));
        assert!(state.is_current_session_context(&first_read).await);
        assert!(state
            .read_only_session_contexts
            .lock()
            .await
            .contains_key(&original_id));

        let writable = state.session_context_for_id(original_id).await.unwrap();
        assert!(!state.is_current_session_context(&first_read).await);
        assert!(state.is_current_session_context(&writable).await);
        assert!(state
            .session_contexts
            .lock()
            .await
            .contains_key(&original_id));
        assert!(!state
            .read_only_session_contexts
            .lock()
            .await
            .contains_key(&original_id));
        let read_after_write_load = state
            .read_session_context_for_id(original_id)
            .await
            .unwrap();
        assert!(std::sync::Arc::ptr_eq(&writable, &read_after_write_load));

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn workspace_persist_invalidates_stale_read_only_session_context() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-workspace-read-only-cache-{}",
            uuid::Uuid::new_v4()
        ));
        let state = AppState::new(AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        })
        .unwrap();
        let original = state.session().await;
        let original_id = original.id();
        state
            .create_session(Some("Second".to_string()))
            .await
            .unwrap();
        state.session_contexts.lock().await.remove(&original_id);
        state
            .read_only_session_contexts
            .lock()
            .await
            .remove(&original_id);

        let cached_read = state
            .read_session_context_for_id(original_id)
            .await
            .unwrap();
        assert!(state
            .read_only_session_contexts
            .lock()
            .await
            .contains_key(&original_id));

        let mut workspace = WorkspaceStateSnapshot {
            session_id: Some(original_id),
            client_id: Some("test-ui".to_string()),
            client_version: 1,
            ..WorkspaceStateSnapshot::default()
        };
        workspace.replay.active_tab_id = Some("fresh-workspace".to_string());
        workspace.replay.tabs.push(ReplayTabState {
            id: "fresh-workspace".to_string(),
            sequence: 1,
            ..ReplayTabState::default()
        });

        state
            .replace_workspace_state_and_persist(&original, workspace)
            .await
            .unwrap();

        let read_after_write = state
            .read_session_context_for_id(original_id)
            .await
            .unwrap();
        assert!(!std::sync::Arc::ptr_eq(&cached_read, &read_after_write));
        assert_eq!(
            read_after_write
                .workspace
                .snapshot()
                .await
                .replay
                .active_tab_id
                .as_deref(),
            Some("fresh-workspace")
        );

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn activating_session_preserves_unrelated_session_ws_replay_state() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-activate-preserve-ws-replay-{}",
            uuid::Uuid::new_v4()
        ));
        let state = AppState::new(AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        })
        .unwrap();
        let original_id = state.active_session_summary().await.id;
        state
            .create_session(Some("Second".to_string()))
            .await
            .unwrap();
        let ws_id = uuid::Uuid::new_v4();
        state
            .ws_replay
            .remember_disconnected_connection_for_test(ws_id, original_id)
            .await;

        state
            .create_session(Some("Third".to_string()))
            .await
            .unwrap();

        assert_eq!(
            state.ws_replay.belongs_to_session(ws_id, original_id).await,
            Some(true)
        );
        assert!(state.ws_replay.snapshot(ws_id).await.is_some());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn session_operation_lock_blocks_delete_until_released() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-session-op-lock-{}", uuid::Uuid::new_v4()));
        let state = AppState::new(AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        })
        .unwrap();
        let original_id = state.active_session_summary().await.id;
        state
            .create_session(Some("Second".to_string()))
            .await
            .unwrap();
        let operation_lock = state.session_operation_lock(original_id).await;
        let operation_guard = operation_lock.lock().await;

        let delete_result = tokio::time::timeout(
            std::time::Duration::from_millis(30),
            state.delete_session(original_id),
        )
        .await;
        assert!(delete_result.is_err());

        drop(operation_guard);
        state.delete_session(original_id).await.unwrap();

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn delete_missing_session_does_not_create_operation_lock() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-missing-delete-lock-{}",
            uuid::Uuid::new_v4()
        ));
        let state = AppState::new(AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        })
        .unwrap();
        let before = state.session_operation_lock_count().await;

        let error = state
            .delete_session(uuid::Uuid::new_v4())
            .await
            .unwrap_err();

        assert!(error.to_string().contains("was not found"));
        assert_eq!(state.session_operation_lock_count().await, before);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn session_context_for_id_waits_for_session_operation_lock() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-session-load-lock-{}", uuid::Uuid::new_v4()));
        let state = AppState::new(AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        })
        .unwrap();
        let original_id = state.active_session_summary().await.id;
        state
            .create_session(Some("Second".to_string()))
            .await
            .unwrap();
        let operation_lock = state.session_operation_lock(original_id).await;
        let operation_guard = operation_lock.lock().await;

        let load_result = tokio::time::timeout(
            std::time::Duration::from_millis(30),
            state.session_context_for_id(original_id),
        )
        .await;
        assert!(load_result.is_err());

        drop(operation_guard);
        assert_eq!(
            state
                .session_context_for_id(original_id)
                .await
                .unwrap()
                .id(),
            original_id
        );

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn activate_session_waits_for_target_session_operation_lock() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-activate-session-op-lock-{}",
            uuid::Uuid::new_v4()
        ));
        let state = AppState::new(AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        })
        .unwrap();
        let original_id = state.active_session_summary().await.id;
        state
            .create_session(Some("Second".to_string()))
            .await
            .unwrap();
        let operation_lock = state.session_operation_lock(original_id).await;
        let operation_guard = operation_lock.lock().await;

        let activate_result = tokio::time::timeout(
            std::time::Duration::from_millis(30),
            state.activate_session(original_id),
        )
        .await;
        assert!(activate_result.is_err());

        drop(operation_guard);
        assert_eq!(
            state.activate_session(original_id).await.unwrap().id,
            original_id
        );

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn activate_session_prunes_target_lock_when_session_is_deleted_while_waiting() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-activate-delete-race-lock-{}",
            uuid::Uuid::new_v4()
        ));
        let state = AppState::new(AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        })
        .unwrap();
        let target = state
            .sessions
            .create_session(Some("Deleted during activation".to_string()))
            .unwrap();
        let target_id = target.id;
        let before = state.session_operation_lock_count().await;
        let operation_lock = state.session_operation_lock(target_id).await;
        let operation_guard = operation_lock.lock().await;
        assert_eq!(state.session_operation_lock_count().await, before + 1);

        let mut activate_task = {
            let state = state.clone();
            tokio::spawn(async move { state.activate_session(target_id).await })
        };
        tokio::time::timeout(std::time::Duration::from_millis(30), &mut activate_task)
            .await
            .expect_err("activation should wait on the target session operation lock");

        state.sessions.delete_session(target_id).unwrap();
        drop(operation_guard);
        let error = activate_task.await.unwrap().unwrap_err();

        assert!(error.to_string().contains("was not found"));
        assert_eq!(state.session_operation_lock_count().await, before);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn activate_session_waits_for_current_session_operation_lock() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-activate-current-session-op-lock-{}",
            uuid::Uuid::new_v4()
        ));
        let state = AppState::new(AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        })
        .unwrap();
        let original_id = state.active_session_summary().await.id;
        let next = state
            .sessions
            .create_session(Some("Second".to_string()))
            .unwrap();
        let operation_lock = state.session_operation_lock(original_id).await;
        let operation_guard = operation_lock.lock().await;

        let activate_result = tokio::time::timeout(
            std::time::Duration::from_millis(30),
            state.activate_session(next.id),
        )
        .await;
        assert!(activate_result.is_err());
        assert_eq!(state.active_session_summary().await.id, original_id);

        drop(operation_guard);
        assert_eq!(state.activate_session(next.id).await.unwrap().id, next.id);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn activate_session_with_force_still_reports_work_it_cannot_stop() {
        // Forcing stops the session's streamed-response pumps, which is what
        // normally never drains. An owner guard held by something else — a replay
        // in flight — is not a stream, so forcing must not pretend it succeeded.
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-activate-force-{}",
            uuid::Uuid::new_v4()
        ));
        let state = AppState::new(AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        })
        .unwrap();
        let original_id = state.active_session_summary().await.id;
        let next = state
            .sessions
            .create_session(Some("Second".to_string()))
            .unwrap();

        let owner = crate::proxy::remember_active_proxy_session_owner(original_id, crate::proxy::PROXY_WORK_STREAMED_RESPONSE);
        let error = state
            .activate_session_with_options(next.id, true)
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("proxy activity is still running"));
        assert_eq!(state.active_session_summary().await.id, original_id);

        drop(owner);
        assert_eq!(
            state
                .activate_session_with_options(next.id, true)
                .await
                .unwrap()
                .id,
            next.id
        );

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn activate_session_rejects_current_active_proxy_work_until_owner_dropped() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-activate-current-active-proxy-{}",
            uuid::Uuid::new_v4()
        ));
        let state = AppState::new(AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        })
        .unwrap();
        let original_id = state.active_session_summary().await.id;
        let next = state
            .sessions
            .create_session(Some("Second".to_string()))
            .unwrap();

        let owner = crate::proxy::remember_active_proxy_session_owner(original_id, crate::proxy::PROXY_WORK_STREAMED_RESPONSE);
        let error = state.activate_session(next.id).await.unwrap_err();
        assert!(error
            .to_string()
            .contains("proxy activity is still running"));
        assert_eq!(state.active_session_summary().await.id, original_id);

        drop(owner);
        assert_eq!(state.activate_session(next.id).await.unwrap().id, next.id);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn create_session_activation_failure_removes_transient_operation_lock() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-create-session-active-proxy-cleanup-{}",
            uuid::Uuid::new_v4()
        ));
        let state = AppState::new(AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        })
        .unwrap();
        let original_id = state.active_session_summary().await.id;
        let _current_operation_lock = state.session_operation_lock(original_id).await;
        let before = state.session_operation_lock_count().await;

        let owner = crate::proxy::remember_active_proxy_session_owner(original_id, crate::proxy::PROXY_WORK_STREAMED_RESPONSE);
        for index in 0..3 {
            let error = state
                .create_session(Some(format!("Blocked {index}")))
                .await
                .unwrap_err();
            assert!(error
                .to_string()
                .contains("proxy activity is still running"));
            assert_eq!(state.session_operation_lock_count().await, before);
        }
        assert_eq!(state.active_session_summary().await.id, original_id);

        drop(owner);
        state
            .create_session(Some("Second".to_string()))
            .await
            .unwrap();

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn activate_session_rejects_target_active_proxy_work_until_owner_dropped() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-activate-target-active-proxy-{}",
            uuid::Uuid::new_v4()
        ));
        let state = AppState::new(AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        })
        .unwrap();
        let original_id = state.active_session_summary().await.id;
        let next = state
            .create_session(Some("Second".to_string()))
            .await
            .unwrap();

        let owner = crate::proxy::remember_active_proxy_session_owner(original_id, crate::proxy::PROXY_WORK_STREAMED_RESPONSE);
        let error = state.activate_session(original_id).await.unwrap_err();
        assert!(error
            .to_string()
            .contains("proxy activity is still running"));
        assert_eq!(state.active_session_summary().await.id, next.id);

        drop(owner);
        assert_eq!(
            state.activate_session(original_id).await.unwrap().id,
            original_id
        );

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn session_delete_waits_for_cached_context_mutation_guard() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-delete-mutation-{}", uuid::Uuid::new_v4()));
        let state = AppState::new(AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        })
        .unwrap();
        let original_id = state.active_session_summary().await.id;
        state
            .create_session(Some("Second".to_string()))
            .await
            .unwrap();
        let original = state.session_context_for_id(original_id).await.unwrap();
        let mutation_guard = original.mutation_guard().await;

        let delete_result = tokio::time::timeout(
            std::time::Duration::from_millis(30),
            state.delete_session(original_id),
        )
        .await;
        assert!(delete_result.is_err());

        drop(mutation_guard);
        state.delete_session(original_id).await.unwrap();

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn self_update_artifact_guard_removes_tmp_dir_on_drop() {
        let tmp_dir =
            std::env::temp_dir().join(format!("sniper-update-artifacts-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        std::fs::write(tmp_dir.join("download.dmg"), b"partial").unwrap();

        {
            let _guard = UpdateArtifactGuard::new(tmp_dir.clone());
        }

        assert!(!tmp_dir.exists());
    }

    #[test]
    fn self_update_identity_check_pins_bundle_executable_and_version() {
        let temp_dir =
            std::env::temp_dir().join(format!("sniper-identity-{}", uuid::Uuid::new_v4()));
        let app_dir = temp_dir.join("Sniper.app");
        write_test_info_plist(
            &app_dir,
            EXPECTED_APP_BUNDLE_IDENTIFIER,
            EXPECTED_APP_EXECUTABLE,
            "0.2.5",
        );

        verify_app_identity(&app_dir, "v0.2.5", "test app").unwrap();

        write_test_info_plist(
            &app_dir,
            "com.example.other",
            EXPECTED_APP_EXECUTABLE,
            "0.2.5",
        );
        assert!(verify_app_identity(&app_dir, "v0.2.5", "test app").is_err());

        write_test_info_plist(
            &app_dir,
            EXPECTED_APP_BUNDLE_IDENTIFIER,
            "OtherExecutable",
            "0.2.5",
        );
        assert!(verify_app_identity(&app_dir, "v0.2.5", "test app").is_err());

        write_test_info_plist(
            &app_dir,
            EXPECTED_APP_BUNDLE_IDENTIFIER,
            EXPECTED_APP_EXECUTABLE,
            "0.2.4",
        );
        assert!(verify_app_identity(&app_dir, "v0.2.5", "test app").is_err());

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn self_update_installer_waits_then_replaces_with_rollback() {
        let script = update_installer_script();
        let wait_pos = script
            .find("while kill -0 \"$pid\"")
            .expect("installer should wait for the old process");
        let ditto_pos = script
            .find("/usr/bin/ditto \"$staged\" \"$bundle\"")
            .expect("installer should copy the staged app");
        assert!(wait_pos < ditto_pos);
        assert!(script.contains("wait_attempts=$((wait_attempts + 1))"));
        assert!(script.contains("[ \"$wait_attempts\" -ge 150 ]"));
        assert!(script.contains("mv \"$bundle\" \"$backup\""));
        assert!(script.contains("if ! mv \"$bundle\" \"$backup\""));
        assert!(script.contains("if mv \"$backup\" \"$bundle\"; then"));
        assert!(script.contains("sniper_app_path_shape_ok()"));
        assert!(script.contains("sniper_app_identity_ok_if_present()"));
        assert!(script.contains("remove_sniper_app_dir()"));
        assert!(script.contains("remove_sniper_backup_dir()"));
        assert!(script.contains("[ ! -L \"$candidate\" ]"));
        assert!(script.contains("[ \"$candidate_name\" = \"Sniper.app\" ]"));
        assert!(script.contains("[ \"$candidate_parent\" = \"$bundle_parent\" ]"));
        assert!(script.contains("remove_sniper_backup_dir \"$backup\""));
        assert!(script.contains("remove_sniper_app_dir \"$bundle\""));
        assert!(!script.contains("rm -rf \"$bundle\""));
        assert!(!script.contains("rm -rf \"$backup\""));
        assert!(script.contains("log_installer()"));
        assert!(script.contains("sniper-installer: $1"));
        assert!(script.contains("log_installer \"waiting for old process $pid to exit\""));
        assert!(script.contains("log_installer \"timed out waiting for old process $pid\""));
        assert!(script.contains("log_installer \"installing staged app\""));
        assert!(script.contains("log_installer \"launch health check timed out\""));
        assert!(script.contains("log_installer \"launch health check failed\""));
        assert!(script.contains("log_installer \"installed app validation failed\""));
        assert!(script.contains("log_installer \"failed to copy or verify staged app\""));
        assert!(
            script.contains("log_installer \"restored previous app bundle after update failure\"")
        );
        assert!(script.contains("log_installer \"failed to restore previous app bundle\""));
        assert!(script.contains("log_installer \"self-update installer failed\""));
        assert!(script.contains("/usr/bin/codesign --verify --deep --strict \"$bundle\""));
        assert!(script.contains("sniper_executable=\"$bundle/Contents/MacOS/Sniper\""));
        assert!(script.contains("/bin/ps -axww -o pid= -o command="));
        assert!(script.contains("sub(/^[[:space:]]*[0-9]+[[:space:]]+/, \"\", $0)"));
        assert!(script.contains("index($0, exe) == 1"));
        assert!(!script.contains("pgrep -f \"$bundle/Contents/MacOS/Sniper\""));
        let health_check_pos = script
            .find("launch_health_check()")
            .expect("installer should define a launch health check");
        let before_pids_pos = script
            .find("before_pids=\"$(matching_sniper_pids)\"")
            .expect("installer should capture already-running app processes");
        let open_pos = script
            .find("if ! /usr/bin/open -n \"$bundle\"; then")
            .expect("installer should launch a new app instance inside the health check");
        let pgrep_pos = script
            .find("matching_sniper_pids | /usr/bin/grep -qx \"$candidate_pid\"")
            .expect("installer should verify the launched Sniper pid stays alive");
        let launch_pos = script
            .find("if launch_health_check; then")
            .expect("installer should require the launch health check before cleanup");
        let cleanup_pos = script
            .rfind("remove_sniper_backup_dir \"$backup\"")
            .expect("installer should clean up after a successful launch");
        assert!(health_check_pos < ditto_pos);
        assert!(before_pids_pos < open_pos);
        assert!(open_pos < pgrep_pos);
        assert!(pgrep_pos < launch_pos);
        assert!(launch_pos < cleanup_pos);
        assert!(script.contains("[ \"$launch_attempts\" -lt 50 ]"));
        assert!(script.contains("sleep 2"));
        assert!(script.contains("v*|V*) expected_version="));
        assert!(script.contains("v*|V*) installed_version="));
    }

    #[test]
    fn self_update_installer_log_is_private_and_rejects_symlink() {
        use std::io::Write as _;

        let temp_dir =
            std::env::temp_dir().join(format!("sniper-self-update-log-{}", uuid::Uuid::new_v4()));
        let log_path = self_update_installer_log_path(&temp_dir);
        {
            let mut log = open_self_update_installer_log(&log_path).unwrap();
            writeln!(log, "child output").unwrap();
        }

        let body = std::fs::read_to_string(&log_path).unwrap();
        assert!(body.contains("--- Sniper self-update installer "));
        assert!(body.contains("child output"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::{symlink, PermissionsExt as _};

            assert_eq!(
                std::fs::metadata(&log_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let symlink_path = temp_dir.join("symlink.log");
            symlink(&log_path, &symlink_path).unwrap();
            assert!(open_self_update_installer_log(&symlink_path).is_err());
        }

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn self_update_team_identifier_parser_rejects_missing_or_wrong_team() {
        assert_eq!(
            parse_codesign_team_identifier(
                "Executable=/Applications/Sniper.app/Contents/MacOS/Sniper\nTeamIdentifier=ABCDE12345\n"
            ),
            Some("ABCDE12345".to_string())
        );
        assert_eq!(
            parse_codesign_team_identifier("TeamIdentifier=not set\n"),
            None
        );
        assert_eq!(parse_codesign_team_identifier("Authority=Ad Hoc\n"), None);
    }

    fn write_test_info_plist(
        app_dir: &std::path::Path,
        bundle_id: &str,
        executable: &str,
        version: &str,
    ) {
        let contents_dir = app_dir.join("Contents");
        std::fs::create_dir_all(&contents_dir).unwrap();
        std::fs::write(
            contents_dir.join("Info.plist"),
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>{bundle_id}</string>
  <key>CFBundleExecutable</key>
  <string>{executable}</string>
  <key>CFBundleShortVersionString</key>
  <string>{version}</string>
</dict>
</plist>
"#
            ),
        )
        .unwrap();
    }
}
