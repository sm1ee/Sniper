use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    event_log::{EventLogEntry, EventLogStore},
    intercept::InterceptQueue,
    intruder::{IntruderAttackRecord, IntruderStore},
    match_replace::{MatchReplaceRule, MatchReplaceStore},
    model::{TransactionRecord, WebSocketSessionRecord},
    runtime::{RuntimeSettings, RuntimeSettingsSnapshot},
    store::TransactionStore,
    websocket::WebSocketStore,
    workspace::{WorkspaceStateSnapshot, WorkspaceStateStore},
};

const SESSIONS_DIR: &str = "sessions";
const REGISTRY_FILE: &str = "registry.json";
const SNAPSHOT_FILE: &str = "snapshot.json";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionMetadata {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_opened_at: DateTime<Utc>,
    pub request_count: usize,
    pub websocket_count: usize,
    pub event_count: usize,
    pub intruder_count: usize,
    pub rule_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionSummary {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_opened_at: DateTime<Utc>,
    pub request_count: usize,
    pub websocket_count: usize,
    pub event_count: usize,
    pub intruder_count: usize,
    pub rule_count: usize,
    pub storage_path: String,
    pub active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SessionRegistrySnapshot {
    active_session_id: Uuid,
    sessions: Vec<SessionMetadata>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct StoredSessionSnapshot {
    runtime: RuntimeSettingsSnapshot,
    transactions: Vec<TransactionRecord>,
    websockets: Vec<WebSocketSessionRecord>,
    event_log: Vec<EventLogEntry>,
    match_replace_rules: Vec<MatchReplaceRule>,
    intruder_attacks: Vec<IntruderAttackRecord>,
    workspace: WorkspaceStateSnapshot,
}

pub struct SessionContext {
    id: Uuid,
    storage_dir: PathBuf,
    max_entries: usize,
    pub store: Arc<TransactionStore>,
    pub runtime: Arc<RuntimeSettings>,
    pub intercepts: Arc<InterceptQueue>,
    pub websockets: Arc<WebSocketStore>,
    pub event_log: Arc<EventLogStore>,
    pub match_replace: Arc<MatchReplaceStore>,
    pub intruder: Arc<IntruderStore>,
    pub workspace: Arc<WorkspaceStateStore>,
    metadata: RwLock<SessionMetadata>,
}

impl SessionContext {
    fn from_snapshot(
        metadata: SessionMetadata,
        storage_dir: PathBuf,
        max_entries: usize,
        max_frames_per_session: usize,
        snapshot: StoredSessionSnapshot,
    ) -> Self {
        Self {
            id: metadata.id,
            storage_dir,
            max_entries,
            store: Arc::new(TransactionStore::from_records(
                max_entries,
                snapshot.transactions,
            )),
            runtime: Arc::new(RuntimeSettings::from_snapshot(snapshot.runtime)),
            intercepts: Arc::new(InterceptQueue::new()),
            websockets: Arc::new(WebSocketStore::from_sessions(
                max_entries,
                max_frames_per_session,
                snapshot.websockets,
            )),
            event_log: Arc::new(EventLogStore::from_entries(max_entries, snapshot.event_log)),
            match_replace: Arc::new(MatchReplaceStore::from_rules(snapshot.match_replace_rules)),
            intruder: Arc::new(IntruderStore::from_attacks(
                max_entries,
                snapshot.intruder_attacks,
            )),
            workspace: Arc::new(WorkspaceStateStore::from_snapshot(snapshot.workspace)),
            metadata: RwLock::new(metadata),
        }
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn storage_dir(&self) -> &Path {
        &self.storage_dir
    }

    pub fn summary(&self, active: bool) -> SessionSummary {
        let metadata = self
            .metadata
            .read()
            .expect("session metadata lock poisoned")
            .clone();
        session_summary(&metadata, &self.storage_dir, active)
    }

    pub async fn persist(&self) -> Result<SessionMetadata> {
        let snapshot = StoredSessionSnapshot {
            runtime: self.runtime.snapshot().await,
            transactions: self.store.snapshot(Some(self.max_entries)).await,
            websockets: self.websockets.snapshot(Some(self.max_entries)).await,
            event_log: self.event_log.snapshot(Some(self.max_entries)).await,
            match_replace_rules: self.match_replace.snapshot().await,
            intruder_attacks: self.intruder.snapshot(Some(self.max_entries)).await,
            workspace: self.workspace.snapshot().await,
        };

        let mut metadata = self
            .metadata
            .read()
            .expect("session metadata lock poisoned")
            .clone();
        metadata.updated_at = Utc::now();
        metadata.request_count = snapshot.transactions.len();
        metadata.websocket_count = snapshot.websockets.len();
        metadata.event_count = snapshot.event_log.len();
        metadata.intruder_count = snapshot.intruder_attacks.len();
        metadata.rule_count = snapshot.match_replace_rules.len();

        fs::create_dir_all(&self.storage_dir).with_context(|| {
            format!(
                "failed to create session directory {}",
                self.storage_dir.display()
            )
        })?;
        write_json(&snapshot_path(&self.storage_dir), &snapshot)?;

        *self
            .metadata
            .write()
            .expect("session metadata lock poisoned") = metadata.clone();

        Ok(metadata)
    }
}

pub struct SessionRegistry {
    root_dir: PathBuf,
    registry_path: PathBuf,
    max_entries: usize,
    max_frames_per_session: usize,
    inner: RwLock<SessionRegistrySnapshot>,
}

impl SessionRegistry {
    pub fn load_or_create(
        data_dir: &Path,
        max_entries: usize,
        max_frames_per_session: usize,
    ) -> Result<(Self, Arc<SessionContext>)> {
        let root_dir = data_dir.join(SESSIONS_DIR);
        fs::create_dir_all(&root_dir).with_context(|| {
            format!("failed to create sessions directory {}", root_dir.display())
        })?;
        let registry_path = root_dir.join(REGISTRY_FILE);

        let mut registry = match fs::read(&registry_path) {
            Ok(bytes) => {
                serde_json::from_slice::<SessionRegistrySnapshot>(&bytes).with_context(|| {
                    format!(
                        "failed to parse session registry {}",
                        registry_path.display()
                    )
                })?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let default = default_session_metadata("Default session");
                let snapshot = SessionRegistrySnapshot {
                    active_session_id: default.id,
                    sessions: vec![default.clone()],
                };
                persist_session_snapshot(&root_dir, &default, &StoredSessionSnapshot::default())?;
                write_json(&registry_path, &snapshot)?;
                snapshot
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to read session registry {}",
                        registry_path.display()
                    )
                })
            }
        };

        if registry.sessions.is_empty() {
            let default = default_session_metadata("Default session");
            registry.active_session_id = default.id;
            registry.sessions.push(default.clone());
            persist_session_snapshot(&root_dir, &default, &StoredSessionSnapshot::default())?;
            write_json(&registry_path, &registry)?;
        }

        if !registry
            .sessions
            .iter()
            .any(|session| session.id == registry.active_session_id)
        {
            registry.active_session_id = registry.sessions[0].id;
            write_json(&registry_path, &registry)?;
        }

        let this = Self {
            root_dir,
            registry_path,
            max_entries,
            max_frames_per_session,
            inner: RwLock::new(registry.clone()),
        };
        let active_metadata = this.touch_active_session(registry.active_session_id)?;
        let active_context = this.load_context(active_metadata.id)?;
        Ok((this, active_context))
    }

    pub fn summaries(&self) -> Vec<SessionSummary> {
        let registry = self.inner.read().expect("session registry lock poisoned");
        let active_id = registry.active_session_id;
        let mut sessions = registry
            .sessions
            .iter()
            .map(|metadata| {
                session_summary(
                    metadata,
                    &session_dir(&self.root_dir, metadata.id),
                    metadata.id == active_id,
                )
            })
            .collect::<Vec<_>>();
        sessions.sort_by(|left, right| right.last_opened_at.cmp(&left.last_opened_at));
        sessions
    }

    pub fn active_session_id(&self) -> Uuid {
        self.inner
            .read()
            .expect("session registry lock poisoned")
            .active_session_id
    }

    pub fn create_session(&self, name: Option<String>) -> Result<SessionMetadata> {
        let now = Utc::now();
        let metadata = SessionMetadata {
            id: Uuid::new_v4(),
            name: normalize_session_name(name.as_deref(), now),
            created_at: now,
            updated_at: now,
            last_opened_at: now,
            request_count: 0,
            websocket_count: 0,
            event_count: 0,
            intruder_count: 0,
            rule_count: 0,
        };

        {
            let mut registry = self.inner.write().expect("session registry lock poisoned");
            registry.sessions.push(metadata.clone());
            write_json(&self.registry_path, &*registry)?;
        }

        persist_session_snapshot(&self.root_dir, &metadata, &StoredSessionSnapshot::default())?;
        Ok(metadata)
    }

    pub fn activate_session(&self, id: Uuid) -> Result<SessionMetadata> {
        self.touch_active_session(id)
    }

    pub fn update_metadata(&self, metadata: SessionMetadata) -> Result<()> {
        let mut registry = self.inner.write().expect("session registry lock poisoned");
        let Some(existing) = registry
            .sessions
            .iter_mut()
            .find(|session| session.id == metadata.id)
        else {
            return Err(anyhow!("session {} was not found", metadata.id));
        };
        *existing = metadata;
        write_json(&self.registry_path, &*registry)
    }

    pub fn load_context(&self, id: Uuid) -> Result<Arc<SessionContext>> {
        let metadata = self
            .inner
            .read()
            .expect("session registry lock poisoned")
            .sessions
            .iter()
            .find(|session| session.id == id)
            .cloned()
            .ok_or_else(|| anyhow!("session {id} was not found"))?;
        let storage_dir = session_dir(&self.root_dir, id);
        let snapshot = load_session_snapshot(&storage_dir)?;
        Ok(Arc::new(SessionContext::from_snapshot(
            metadata,
            storage_dir,
            self.max_entries,
            self.max_frames_per_session,
            snapshot,
        )))
    }

    fn touch_active_session(&self, id: Uuid) -> Result<SessionMetadata> {
        let mut registry = self.inner.write().expect("session registry lock poisoned");
        let Some(index) = registry
            .sessions
            .iter()
            .position(|session| session.id == id)
        else {
            return Err(anyhow!("session {id} was not found"));
        };

        registry.sessions[index].last_opened_at = Utc::now();
        registry.active_session_id = id;
        let metadata = registry.sessions[index].clone();
        write_json(&self.registry_path, &*registry)?;
        Ok(metadata)
    }
}

fn default_session_metadata(name: &str) -> SessionMetadata {
    let now = Utc::now();
    SessionMetadata {
        id: Uuid::new_v4(),
        name: name.to_string(),
        created_at: now,
        updated_at: now,
        last_opened_at: now,
        request_count: 0,
        websocket_count: 0,
        event_count: 0,
        intruder_count: 0,
        rule_count: 0,
    }
}

fn normalize_session_name(name: Option<&str>, now: DateTime<Utc>) -> String {
    name.map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("Session {}", now.format("%Y-%m-%d %H:%M")))
}

fn session_summary(metadata: &SessionMetadata, storage_dir: &Path, active: bool) -> SessionSummary {
    SessionSummary {
        id: metadata.id,
        name: metadata.name.clone(),
        created_at: metadata.created_at,
        updated_at: metadata.updated_at,
        last_opened_at: metadata.last_opened_at,
        request_count: metadata.request_count,
        websocket_count: metadata.websocket_count,
        event_count: metadata.event_count,
        intruder_count: metadata.intruder_count,
        rule_count: metadata.rule_count,
        storage_path: storage_dir.display().to_string(),
        active,
    }
}

fn session_dir(root_dir: &Path, id: Uuid) -> PathBuf {
    root_dir.join(id.to_string())
}

fn snapshot_path(storage_dir: &Path) -> PathBuf {
    storage_dir.join(SNAPSHOT_FILE)
}

fn load_session_snapshot(storage_dir: &Path) -> Result<StoredSessionSnapshot> {
    fs::create_dir_all(storage_dir).with_context(|| {
        format!(
            "failed to create session directory {}",
            storage_dir.display()
        )
    })?;
    let path = snapshot_path(storage_dir);
    match fs::read(&path) {
        Ok(bytes) => serde_json::from_slice::<StoredSessionSnapshot>(&bytes)
            .with_context(|| format!("failed to parse session snapshot {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(StoredSessionSnapshot::default())
        }
        Err(error) => Err(error)
            .with_context(|| format!("failed to read session snapshot {}", path.display())),
    }
}

fn persist_session_snapshot(
    root_dir: &Path,
    metadata: &SessionMetadata,
    snapshot: &StoredSessionSnapshot,
) -> Result<()> {
    let storage_dir = session_dir(root_dir, metadata.id);
    fs::create_dir_all(&storage_dir).with_context(|| {
        format!(
            "failed to create session directory {}",
            storage_dir.display()
        )
    })?;
    write_json(&snapshot_path(&storage_dir), snapshot)
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create parent directory {}", parent.display()))?;
    }
    let data = serde_json::to_vec_pretty(value).context("failed to serialize JSON file")?;
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, &data)
        .with_context(|| format!("failed to write {}", tmp_path.display()))?;
    fs::rename(&tmp_path, path)
        .with_context(|| format!("failed to rename {} to {}", tmp_path.display(), path.display()))
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::SessionRegistry;
    use crate::{
        model::{BodyEncoding, EditableRequest, HeaderRecord, MessageRecord, TransactionRecord},
        workspace::{
            IntruderWorkspaceState, RepeaterHistoryEntryState, RepeaterTabState,
            RepeaterWorkspaceState, WorkspaceStateSnapshot,
        },
    };

    #[tokio::test]
    async fn registry_persists_created_session_and_active_context() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-session-test-{}", uuid::Uuid::new_v4()));
        let (registry, _active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();

        let created = registry.create_session(Some("Review".to_string())).unwrap();
        let active = registry.activate_session(created.id).unwrap();
        let loaded = registry.load_context(active.id).unwrap();

        assert_eq!(loaded.summary(true).name, "Review");
        assert!(registry
            .summaries()
            .iter()
            .any(|session| session.id == created.id));
    }

    #[tokio::test]
    async fn registry_persists_workspace_state() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-workspace-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();

        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            method: "POST".to_string(),
            path: "/login".to_string(),
            headers: vec![],
            body: "{\"name\":\"demo\"}".to_string(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };

        active
            .workspace
            .replace_snapshot(WorkspaceStateSnapshot {
                repeater: RepeaterWorkspaceState {
                    tabs: vec![RepeaterTabState {
                        id: "tab-1".to_string(),
                        sequence: 1,
                        base_request: Some(request.clone()),
                        source_transaction_id: None,
                        notice: "Saved".to_string(),
                        request_text: "POST /login HTTP/1.1".to_string(),
                        response_record: None,
                        target_scheme: "https".to_string(),
                        target_host: "example.com".to_string(),
                        target_port: "443".to_string(),
                        history_entries: vec![RepeaterHistoryEntryState {
                            request: request.clone(),
                            request_text: "POST /login HTTP/1.1".to_string(),
                            response_record: None,
                            notice: "Saved".to_string(),
                            target_scheme: "https".to_string(),
                            target_host: "example.com".to_string(),
                            target_port: "443".to_string(),
                        }],
                        history_index: Some(0),
                    }],
                    active_tab_id: Some("tab-1".to_string()),
                    tab_sequence: 1,
                },
                intruder: IntruderWorkspaceState {
                    base_request: Some(request.clone()),
                    source_transaction_id: None,
                    notice: "Ready".to_string(),
                    request_text: "POST /login HTTP/1.1".to_string(),
                    payloads_text: "admin\nuser".to_string(),
                    attack_record: None,
                },
            })
            .await;

        active.persist().await.unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let workspace = loaded.workspace.snapshot().await;
        assert_eq!(workspace.repeater.tabs.len(), 1);
        assert_eq!(workspace.repeater.active_tab_id.as_deref(), Some("tab-1"));
        assert_eq!(workspace.intruder.notice, "Ready");
        assert_eq!(workspace.intruder.payloads_text, "admin\nuser");
        assert_eq!(
            workspace
                .repeater
                .tabs
                .first()
                .and_then(|tab| tab.history_index),
            Some(0)
        );
        assert_eq!(
            workspace
                .repeater
                .tabs
                .first()
                .and_then(|tab| tab.base_request.as_ref())
                .map(|value| value.host.as_str()),
            Some("example.com")
        );
        assert_eq!(
            workspace
                .repeater
                .tabs
                .first()
                .and_then(|tab| tab.history_entries.first())
                .map(|entry| entry.target_port.as_str()),
            Some("443")
        );
    }

    #[tokio::test]
    async fn registry_persists_http_history_transactions() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-transactions-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();

        let request = MessageRecord {
            headers: vec![HeaderRecord {
                name: "host".to_string(),
                value: "example.com".to_string(),
            }],
            body_preview: "{\"hello\":\"world\"}".to_string(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 17,
            preview_truncated: false,
            content_type: Some("application/json".to_string()),
        };
        let response = MessageRecord {
            headers: vec![HeaderRecord {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            }],
            body_preview: "{\"ok\":true}".to_string(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 11,
            preview_truncated: false,
            content_type: Some("application/json".to_string()),
        };

        active
            .store
            .insert(TransactionRecord::http(
                Utc::now(),
                "POST".to_string(),
                "https".to_string(),
                "example.com:443".to_string(),
                "/api/login".to_string(),
                Some(201),
                42,
                request,
                Some(response),
                vec!["persisted".to_string()],
            ))
            .await;

        let metadata = active.persist().await.unwrap();
        registry.update_metadata(metadata).unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.store.snapshot(Some(10)).await;

        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].method, "POST");
        assert_eq!(restored[0].scheme, "https");
        assert_eq!(restored[0].host, "example.com:443");
        assert_eq!(restored[0].path, "/api/login");
        assert_eq!(restored[0].status, Some(201));
        assert_eq!(restored[0].duration_ms, 42);
        assert_eq!(
            restored[0].request.header_value("host"),
            Some("example.com")
        );
        assert_eq!(
            restored[0]
                .response
                .as_ref()
                .and_then(|message| message.header_value("content-type")),
            Some("application/json")
        );
    }
}
