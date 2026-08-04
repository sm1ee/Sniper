use std::future::Future;

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

use crate::{
    fuzzer::FuzzerAttackRecord,
    model::{EditableRequest, RequestTargetOverride, TransactionRecord},
    ws_replay::WsReplayFrame,
};

// Kept comfortably below the 64 MB HTTP body limit (see DefaultBodyLimit in
// src/api.rs). The whole workspace is rewritten to disk on every edit, so this
// bounds both the POST and the per-edit file write.
pub const MAX_WORKSPACE_SERIALIZED_BYTES: usize = 48 * 1024 * 1024;

/// Upper bound on replay tabs a workspace may hold. Bounds the serialized
/// workspace size; shared by the UI API validator and the CLI so `replay open`
/// refuses to push past it instead of creating a workspace the server rejects.
pub const MAX_WORKSPACE_REPLAY_TABS: usize = 512;

/// Small: subscribers only need to learn that a newer revision exists, and a
/// lagged receiver simply refetches the snapshot.
const WORKSPACE_EVENT_CAPACITY: usize = 64;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkspaceStateSnapshot {
    #[serde(default)]
    pub revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_active_session_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub client_version: u64,
    #[serde(alias = "repeater")]
    pub replay: ReplayWorkspaceState,
    #[serde(alias = "intruder")]
    pub fuzzer: FuzzerWorkspaceState,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

pub fn validate_workspace_serialized_size(
    snapshot: &WorkspaceStateSnapshot,
) -> std::result::Result<(), String> {
    let bytes = serde_json::to_vec(snapshot)
        .map_err(|error| format!("failed to measure workspace state: {error}"))?
        .len();
    if bytes > MAX_WORKSPACE_SERIALIZED_BYTES {
        return Err(format!(
            "workspace state cannot exceed {MAX_WORKSPACE_SERIALIZED_BYTES} serialized bytes"
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ReplayWorkspaceState {
    pub tabs: Vec<ReplayTabState>,
    pub active_tab_id: Option<String>,
    pub tab_sequence: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ReplayHistoryEntryState {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<EditableRequest>,
    pub request_text: String,
    #[serde(default)]
    pub http_version_mode: String,
    pub response_record: Option<TransactionRecord>,
    pub notice: String,
    pub target_scheme: String,
    pub target_host: String,
    pub target_port: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ReplayTabState {
    pub id: String,
    #[serde(rename = "type", default)]
    pub tab_type: String,
    pub sequence: usize,
    pub custom_label: String,
    pub base_request: Option<EditableRequest>,
    pub source_transaction_id: Option<Uuid>,
    pub notice: String,
    pub request_text: String,
    #[serde(default)]
    pub http_version_mode: String,
    pub response_record: Option<TransactionRecord>,
    #[serde(default, skip_serializing)]
    pub response_record_complete: Option<bool>,
    pub target_scheme: String,
    pub target_host: String,
    pub target_port: String,
    #[serde(default)]
    pub target_manually_edited: bool,
    pub history_entries: Vec<ReplayHistoryEntryState>,
    pub history_index: Option<usize>,
    #[serde(default, skip_serializing)]
    pub history_entries_complete: Option<bool>,
    #[serde(default)]
    pub pinned: bool,
    // WebSocket tab fields
    #[serde(default)]
    pub ws_scheme: String,
    #[serde(default)]
    pub ws_host: String,
    #[serde(default)]
    pub ws_port: serde_json::Value,
    #[serde(default)]
    pub ws_path: String,
    #[serde(default)]
    pub ws_headers: Vec<serde_json::Value>,
    #[serde(default)]
    pub ws_handshake_text: String,
    #[serde(default)]
    pub ws_handshake_edited: bool,
    #[serde(default)]
    pub ws_editor_text: String,
    #[serde(default)]
    pub ws_message_type: String,
    #[serde(default)]
    pub ws_editor_body_encoded: bool,
    #[serde(default)]
    pub ws_setup_notice: String,
    #[serde(default)]
    pub ws_setup_queue: Vec<serde_json::Value>,
    #[serde(default, skip_serializing)]
    pub ws_setup_queue_complete: Option<bool>,
    #[serde(default)]
    pub ws_frames: Vec<WsReplayFrame>,
    #[serde(default, skip_serializing)]
    pub ws_frames_complete: Option<bool>,
    #[serde(default)]
    pub ws_frames_truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_selected_frame_index: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_frame_window_start: Option<usize>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FuzzerWorkspaceState {
    pub base_request: Option<EditableRequest>,
    pub source_transaction_id: Option<Uuid>,
    pub target: Option<RequestTargetOverride>,
    pub target_request_authority: Option<String>,
    pub notice: String,
    pub request_text: String,
    pub payloads_text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attack_record_id: Option<Uuid>,
    #[serde(default, skip_serializing)]
    pub attack_record: Option<FuzzerAttackRecord>,
}

impl FuzzerWorkspaceState {
    pub fn clear_attack_record_reference(&mut self) {
        self.attack_record_id = None;
        self.attack_record = None;
    }

    pub fn migrate_attack_record_to_id(&mut self) {
        if self.attack_record_id.is_none() {
            self.attack_record_id = self.attack_record.as_ref().map(|record| record.id);
        }
        self.attack_record = None;
    }
}

pub struct WorkspaceStateStore {
    inner: RwLock<WorkspaceStateSnapshot>,
    /// Announces committed snapshots so other clients (the desktop UI) can pick
    /// up replay tabs created out-of-band, e.g. by `sniper-cli replay open`.
    events: broadcast::Sender<WorkspaceStateEvent>,
}

/// Broadcast when a workspace snapshot is committed. `client_id` is the writer,
/// so a client can ignore the echo of its own save.
#[derive(Clone, Debug, Serialize)]
pub struct WorkspaceStateEvent {
    pub session_id: Option<Uuid>,
    pub revision: u64,
    pub client_id: Option<String>,
}

#[derive(Debug)]
pub enum WorkspaceReplaceError<E> {
    Conflict(Box<WorkspaceStateSnapshot>),
    Persist(E),
}

impl WorkspaceStateStore {
    pub fn new() -> Self {
        Self::from_snapshot(WorkspaceStateSnapshot::default())
    }

    pub fn from_snapshot(snapshot: WorkspaceStateSnapshot) -> Self {
        let (events, _) = broadcast::channel(WORKSPACE_EVENT_CAPACITY);
        Self {
            inner: RwLock::new(snapshot),
            events,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<WorkspaceStateEvent> {
        self.events.subscribe()
    }

    fn announce(&self, snapshot: &WorkspaceStateSnapshot) {
        // Ignore send errors: no subscribers is the normal headless case.
        let _ = self.events.send(WorkspaceStateEvent {
            session_id: snapshot.session_id,
            revision: snapshot.revision,
            client_id: snapshot.client_id.clone(),
        });
    }

    pub async fn snapshot(&self) -> WorkspaceStateSnapshot {
        self.inner.read().await.clone()
    }

    pub async fn replace_snapshot(
        &self,
        snapshot: WorkspaceStateSnapshot,
    ) -> WorkspaceStateSnapshot {
        let mut current = self.inner.write().await;
        let mut snapshot = snapshot;
        snapshot.revision = current.revision.saturating_add(1);
        *current = snapshot;
        let committed = current.clone();
        drop(current);
        self.announce(&committed);
        committed
    }

    pub async fn replace_snapshot_checked(
        &self,
        snapshot: WorkspaceStateSnapshot,
    ) -> Result<WorkspaceStateSnapshot, WorkspaceStateSnapshot> {
        let mut current = self.inner.write().await;
        if !can_replace_snapshot(&snapshot, &current) {
            return Err(current.clone());
        }
        let mut snapshot = snapshot;
        snapshot.revision = current.revision.saturating_add(1);
        *current = snapshot;
        let committed = current.clone();
        drop(current);
        self.announce(&committed);
        Ok(committed)
    }

    pub async fn replace_snapshot_checked_persisting<F, Fut, T, E>(
        &self,
        snapshot: WorkspaceStateSnapshot,
        persist: F,
    ) -> Result<(WorkspaceStateSnapshot, T), WorkspaceReplaceError<E>>
    where
        F: FnOnce(WorkspaceStateSnapshot) -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        let mut current = self.inner.write().await;
        if !can_replace_snapshot(&snapshot, &current) {
            return Err(WorkspaceReplaceError::Conflict(Box::new(current.clone())));
        }
        let mut next = snapshot;
        next.revision = current.revision.saturating_add(1);

        let persist_result = persist(next.clone())
            .await
            .map_err(WorkspaceReplaceError::Persist)?;

        *current = next.clone();
        drop(current);
        self.announce(&next);
        Ok((next, persist_result))
    }
}

pub fn can_replace_snapshot(
    snapshot: &WorkspaceStateSnapshot,
    current: &WorkspaceStateSnapshot,
) -> bool {
    if snapshot.revision == current.revision {
        return true;
    }
    snapshot.client_id.is_some()
        && snapshot.client_id == current.client_id
        && snapshot.client_version > current.client_version
}

impl Default for WorkspaceStateStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FuzzerWorkspaceState, ReplayHistoryEntryState, ReplayTabState, ReplayWorkspaceState,
        WorkspaceStateSnapshot, WorkspaceStateStore,
    };
    use serde_json::json;
    use uuid::Uuid;

    #[test]
    fn fuzzer_workspace_migrates_legacy_attack_record_and_serializes_id_only() {
        let attack_id = Uuid::new_v4();
        let mut fuzzer: FuzzerWorkspaceState = serde_json::from_value(json!({
            "attack_record": {
                "id": attack_id,
                "started_at": "2026-01-01T00:00:00Z",
                "completed_at": "2026-01-01T00:00:01Z",
                "status": "completed",
                "template": {
                    "scheme": "https",
                    "host": "fuzzer.example",
                    "method": "GET",
                    "path": "/",
                    "headers": [],
                    "body": "",
                    "body_encoding": "utf8",
                    "preview_truncated": false
                },
                "payload_count": 1,
                "marker_count": 0,
                "results": [],
                "notes": []
            }
        }))
        .unwrap();

        fuzzer.migrate_attack_record_to_id();

        assert_eq!(fuzzer.attack_record_id, Some(attack_id));
        assert!(fuzzer.attack_record.is_none());
        let serialized = serde_json::to_value(&fuzzer).unwrap();
        assert_eq!(serialized["attack_record_id"], attack_id.to_string());
        assert!(serialized.get("attack_record").is_none());
    }

    #[tokio::test]
    async fn workspace_replace_rejects_stale_revision_zero_after_first_write() {
        let store = WorkspaceStateStore::new();
        let first = store
            .replace_snapshot_checked(WorkspaceStateSnapshot::default())
            .await
            .unwrap();
        assert_eq!(first.revision, 1);

        let stale = store
            .replace_snapshot_checked(WorkspaceStateSnapshot::default())
            .await
            .unwrap_err();
        assert_eq!(stale.revision, 1);
    }

    #[tokio::test]
    async fn workspace_replace_accepts_stale_revision_with_newer_same_client_version() {
        let store = WorkspaceStateStore::new();
        let first = store
            .replace_snapshot_checked(WorkspaceStateSnapshot {
                client_id: Some("client-a".to_string()),
                client_version: 1,
                ..WorkspaceStateSnapshot::default()
            })
            .await
            .unwrap();
        assert_eq!(first.revision, 1);

        let committed = store
            .replace_snapshot_checked(WorkspaceStateSnapshot {
                revision: 0,
                client_id: Some("client-a".to_string()),
                client_version: 2,
                replay: super::ReplayWorkspaceState {
                    active_tab_id: Some("latest-client-edit".to_string()),
                    ..super::ReplayWorkspaceState::default()
                },
                ..WorkspaceStateSnapshot::default()
            })
            .await
            .unwrap();

        assert_eq!(committed.revision, 2);
        assert_eq!(committed.client_id.as_deref(), Some("client-a"));
        assert_eq!(committed.client_version, 2);
        assert_eq!(
            committed.replay.active_tab_id.as_deref(),
            Some("latest-client-edit")
        );
    }

    #[tokio::test]
    async fn workspace_replace_rejects_stale_revision_from_different_client() {
        let store = WorkspaceStateStore::new();
        store
            .replace_snapshot_checked(WorkspaceStateSnapshot {
                client_id: Some("client-a".to_string()),
                client_version: 1,
                ..WorkspaceStateSnapshot::default()
            })
            .await
            .unwrap();

        let stale = store
            .replace_snapshot_checked(WorkspaceStateSnapshot {
                revision: 0,
                client_id: Some("client-b".to_string()),
                client_version: 2,
                ..WorkspaceStateSnapshot::default()
            })
            .await
            .unwrap_err();

        assert_eq!(stale.revision, 1);
        assert_eq!(stale.client_id.as_deref(), Some("client-a"));
    }

    #[tokio::test]
    async fn workspace_replace_rejects_stale_revision_even_with_older_client_version() {
        let store = WorkspaceStateStore::new();
        store
            .replace_snapshot_checked(WorkspaceStateSnapshot {
                client_id: Some("client-a".to_string()),
                client_version: 3,
                ..WorkspaceStateSnapshot::default()
            })
            .await
            .unwrap();

        let stale = store
            .replace_snapshot_checked(WorkspaceStateSnapshot {
                revision: 0,
                client_id: Some("client-a".to_string()),
                client_version: 2,
                ..WorkspaceStateSnapshot::default()
            })
            .await
            .unwrap_err();

        assert_eq!(stale.revision, 1);
        assert_eq!(stale.client_version, 3);
    }

    #[tokio::test]
    async fn workspace_replace_persisting_keeps_current_snapshot_on_persist_failure() {
        let store = WorkspaceStateStore::new();
        let current = store
            .replace_snapshot_checked(WorkspaceStateSnapshot {
                client_id: Some("client-a".to_string()),
                client_version: 1,
                ..WorkspaceStateSnapshot::default()
            })
            .await
            .unwrap();
        assert_eq!(current.revision, 1);

        let result = store
            .replace_snapshot_checked_persisting(
                WorkspaceStateSnapshot {
                    revision: 1,
                    client_id: Some("client-a".to_string()),
                    client_version: 2,
                    replay: super::ReplayWorkspaceState {
                        active_tab_id: Some("lost-if-committed".to_string()),
                        ..super::ReplayWorkspaceState::default()
                    },
                    ..WorkspaceStateSnapshot::default()
                },
                |_candidate| async { Err::<(), _>("disk failed") },
            )
            .await;

        assert!(matches!(
            result,
            Err(super::WorkspaceReplaceError::Persist("disk failed"))
        ));
        let after = store.snapshot().await;
        assert_eq!(after.revision, 1);
        assert_eq!(after.client_version, 1);
        assert!(after.replay.active_tab_id.is_none());
    }

    #[tokio::test]
    async fn workspace_replace_persisting_accepts_stale_newer_same_client_snapshot() {
        let store = WorkspaceStateStore::new();
        store
            .replace_snapshot_checked(WorkspaceStateSnapshot {
                client_id: Some("client-a".to_string()),
                client_version: 1,
                ..WorkspaceStateSnapshot::default()
            })
            .await
            .unwrap();

        let result = store
            .replace_snapshot_checked_persisting(
                WorkspaceStateSnapshot {
                    revision: 0,
                    client_id: Some("client-a".to_string()),
                    client_version: 2,
                    replay: super::ReplayWorkspaceState {
                        active_tab_id: Some("beacon-edit".to_string()),
                        ..super::ReplayWorkspaceState::default()
                    },
                    ..WorkspaceStateSnapshot::default()
                },
                |candidate| async move { Ok::<_, ()>(candidate.revision) },
            )
            .await
            .unwrap();

        let (committed, persisted_revision) = result;
        assert_eq!(persisted_revision, 2);
        assert_eq!(committed.revision, 2);
        assert_eq!(committed.client_id.as_deref(), Some("client-a"));
        assert_eq!(committed.client_version, 2);
        assert_eq!(
            committed.replay.active_tab_id.as_deref(),
            Some("beacon-edit")
        );
    }

    #[test]
    fn replay_history_entry_accepts_legacy_missing_request() {
        let entry: ReplayHistoryEntryState = serde_json::from_value(json!({
            "request_text": "GET /legacy HTTP/1.1",
            "notice": "old entry"
        }))
        .expect("legacy replay history entry should deserialize");

        assert!(entry.request.is_none());
        assert_eq!(entry.request_text, "GET /legacy HTTP/1.1");
        assert_eq!(entry.notice, "old entry");

        let serialized = serde_json::to_value(&entry).expect("entry should serialize");
        assert!(serialized.get("request").is_none());
    }

    #[test]
    fn websocket_replay_selection_state_round_trips() {
        let snapshot = WorkspaceStateSnapshot {
            replay: ReplayWorkspaceState {
                tabs: vec![ReplayTabState {
                    tab_type: "websocket".to_string(),
                    ws_selected_frame_index: Some(42),
                    ws_frame_window_start: Some(10),
                    ..ReplayTabState::default()
                }],
                ..ReplayWorkspaceState::default()
            },
            ..WorkspaceStateSnapshot::default()
        };

        let encoded = serde_json::to_value(&snapshot).expect("workspace should serialize");
        assert_eq!(
            encoded["replay"]["tabs"][0]["ws_selected_frame_index"],
            json!(42)
        );
        assert_eq!(
            encoded["replay"]["tabs"][0]["ws_frame_window_start"],
            json!(10)
        );

        let decoded: WorkspaceStateSnapshot =
            serde_json::from_value(encoded).expect("workspace should deserialize");
        let tab = &decoded.replay.tabs[0];
        assert_eq!(tab.ws_selected_frame_index, Some(42));
        assert_eq!(tab.ws_frame_window_start, Some(10));
    }
}
