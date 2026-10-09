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

#[derive(Clone, Copy, Debug)]
pub(crate) enum SavedHttpTabOperation {
    Close,
    Duplicate,
}

#[derive(Debug)]
pub(crate) enum WorkspaceTransformError<E> {
    Conflict { revision: u64 },
    Invalid(String),
    Persist(E),
    CommittedButUncertain(E),
}

/// Transform saved state only: draft text, embedded bodies and transaction
/// references must never pass through the request parser or body hydrator here.
pub(crate) fn transform_saved_http_tab(
    current: &WorkspaceStateSnapshot,
    tab_id: &str,
    operation: SavedHttpTabOperation,
) -> Result<WorkspaceStateSnapshot, String> {
    let index = current
        .replay
        .tabs
        .iter()
        .position(|tab| tab.id == tab_id)
        .ok_or_else(|| "saved Replay tab was not found".to_string())?;
    let source = &current.replay.tabs[index];
    if !matches!(source.tab_type.as_str(), "" | "http") {
        return Err("saved Replay tab must be an HTTP tab".to_string());
    }
    let mut next = current.clone();
    match operation {
        SavedHttpTabOperation::Close => {
            // Legacy counters can lag the saved tabs. Closing the last/highest
            // tab must not make its sequence available for reuse.
            next.replay.tab_sequence = current
                .replay
                .tabs
                .iter()
                .map(|tab| tab.sequence)
                .fold(current.replay.tab_sequence, usize::max);
            if current.replay.active_tab_id.as_deref() == Some(tab_id) {
                let mut visual: Vec<_> = current.replay.tabs.iter().collect();
                visual.sort_by_key(|tab| !tab.pinned);
                let position = visual.iter().position(|tab| tab.id == tab_id).unwrap();
                next.replay.active_tab_id = position
                    .checked_sub(1)
                    .and_then(|previous| visual.get(previous))
                    .or_else(|| visual.get(position + 1))
                    .map(|tab| tab.id.clone());
            }
            next.replay.tabs.remove(index);
            if next.replay.tabs.is_empty() {
                next.replay.active_tab_id = None;
            }
        }
        SavedHttpTabOperation::Duplicate => {
            if current.replay.tabs.len() >= MAX_WORKSPACE_REPLAY_TABS {
                return Err("workspace has reached the saved Replay tab limit".to_string());
            }
            let sequence = current
                .replay
                .tabs
                .iter()
                .map(|tab| tab.sequence)
                .fold(current.replay.tab_sequence, usize::max)
                .checked_add(1)
                .filter(|sequence| *sequence < usize::MAX)
                .ok_or_else(|| "replay tab sequence is too large".to_string())?;
            let mut duplicate = source.clone();
            loop {
                duplicate.id = Uuid::new_v4().to_string();
                if current.replay.tabs.iter().all(|tab| tab.id != duplicate.id) {
                    break;
                }
            }
            duplicate.sequence = sequence;
            duplicate.pinned = false;
            next.replay.tabs.push(duplicate);
            next.replay.tab_sequence = sequence;
        }
    }
    Ok(next)
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

    pub(crate) async fn transform_snapshot_checked_persisting<F, P, Fut, E>(
        &self,
        expected_revision: u64,
        transform: F,
        persist: P,
    ) -> Result<WorkspaceStateSnapshot, WorkspaceTransformError<E>>
    where
        F: FnOnce(&WorkspaceStateSnapshot) -> Result<WorkspaceStateSnapshot, String>,
        P: FnOnce(WorkspaceStateSnapshot) -> Fut,
        Fut: Future<Output = Result<Option<E>, E>>,
    {
        let mut current = self.inner.write().await;
        if current.revision != expected_revision {
            return Err(WorkspaceTransformError::Conflict {
                revision: current.revision,
            });
        }
        let revision = current.revision.checked_add(1).ok_or_else(|| {
            WorkspaceTransformError::Invalid("workspace revision is exhausted".to_string())
        })?;
        let mut next = transform(&current).map_err(WorkspaceTransformError::Invalid)?;
        next.revision = revision;
        next.expected_active_session_id = None;
        // A queued save from the previous writer must not use the legacy
        // same-client version bypass to resurrect a tab this operation closed.
        next.client_id = None;
        next.client_version = 0;
        let uncertainty = persist(next.clone())
            .await
            .map_err(WorkspaceTransformError::Persist)?;
        *current = next.clone();
        drop(current);
        self.announce(&next);
        if let Some(error) = uncertainty {
            // The rename happened, so exposing the old in-memory revision
            // would let a stale writer overwrite the committed disk snapshot.
            return Err(WorkspaceTransformError::CommittedButUncertain(error));
        }
        Ok(next)
    }
}

/// A client that has reset its state but has not yet loaded the session's
/// workspace looks exactly like this: no replay tabs, and the tab sequence back
/// at zero. Committing it would drop every stored tab, which is what happened
/// when switching sessions — the reset runs several round trips before the load
/// finishes, and any save in that window wrote an empty workspace.
///
/// Closing tabs by hand does not look like this: the sequence only ever counts
/// up, so a deliberate "close everything" still carries the sequence it reached.
fn discards_stored_replay_tabs(
    snapshot: &WorkspaceStateSnapshot,
    current: &WorkspaceStateSnapshot,
) -> bool {
    !current.replay.tabs.is_empty()
        && snapshot.replay.tabs.is_empty()
        && snapshot.replay.tab_sequence == 0
}

pub fn can_replace_snapshot(
    snapshot: &WorkspaceStateSnapshot,
    current: &WorkspaceStateSnapshot,
) -> bool {
    if discards_stored_replay_tabs(snapshot, current) {
        return false;
    }
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
    async fn workspace_replace_refuses_to_drop_stored_tabs_for_an_unloaded_client() {
        let store = WorkspaceStateStore::new();
        let with_tabs = |sequence: usize, tabs: Vec<ReplayTabState>| WorkspaceStateSnapshot {
            client_id: Some("ui".to_string()),
            replay: ReplayWorkspaceState {
                tabs,
                tab_sequence: sequence,
                ..ReplayWorkspaceState::default()
            },
            ..WorkspaceStateSnapshot::default()
        };
        let stored = store
            .replace_snapshot_checked(with_tabs(
                3,
                vec![ReplayTabState {
                    id: "keep-me".to_string(),
                    sequence: 1,
                    ..ReplayTabState::default()
                }],
            ))
            .await
            .unwrap();
        assert_eq!(stored.revision, 1);

        // A client that reset but has not loaded yet: no tabs, sequence back to 0.
        let mut unloaded = with_tabs(0, Vec::new());
        unloaded.revision = stored.revision;
        let rejected = store.replace_snapshot_checked(unloaded).await.unwrap_err();
        assert_eq!(rejected.replay.tabs.len(), 1, "stored tabs must survive");

        // Closing every tab by hand keeps the sequence, and is still accepted.
        let mut closed_by_user = with_tabs(3, Vec::new());
        closed_by_user.revision = stored.revision;
        let committed = store
            .replace_snapshot_checked(closed_by_user)
            .await
            .unwrap();
        assert!(committed.replay.tabs.is_empty());
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

#[cfg(test)]
mod saved_http_tab_tests {
    use super::*;
    use serde_json::{json, Value};

    fn fixture() -> WorkspaceStateSnapshot {
        serde_json::from_value(json!({
            "revision": 8, "client_id": "desktop", "client_version": 100,
            "replay": {
                "tab_sequence": 20, "active_tab_id": "middle",
                "tabs": [
                    {"id":"first","type":"http","sequence":1},
                    {"id":"middle","type":"","sequence":5,"pinned":true,
                     "custom_label":"saved label","request_text":"unfinished request\r\nraw \u{0000} text",
                     "http_version_mode":"HTTP/2","target_scheme":"https","target_host":"example.com","target_port":"443",
                     "target_manually_edited":true,"notice":"saved notice",
                     "source_transaction_id":"11111111-1111-4111-8111-111111111111",
                     "history_entries":[{"request_text":"first draft","http_version_mode":"HTTP/1.1","notice":"history notice"}],
                     "history_index":0},
                    {"id":"last","type":"http","sequence":3},
                    {"id":"pinned","type":"http","sequence":4,"pinned":true}
                ]
            }, "fuzzer":{"request_text":"other saved draft","payloads_text":"one\ntwo"}
        })).unwrap()
    }

    fn value(snapshot: &WorkspaceStateSnapshot) -> Value {
        serde_json::to_value(snapshot).unwrap()
    }

    #[test]
    fn saved_http_close_uses_stable_visual_order_and_retains_monotonic_sequence() {
        let current = fixture();
        let next =
            transform_saved_http_tab(&current, "middle", SavedHttpTabOperation::Close).unwrap();
        assert_eq!(next.replay.active_tab_id.as_deref(), Some("pinned"));
        assert_eq!(next.replay.tab_sequence, 20);
        assert_eq!(
            next.replay
                .tabs
                .iter()
                .map(|tab| tab.id.as_str())
                .collect::<Vec<_>>(),
            vec!["first", "last", "pinned"]
        );
        assert_eq!(value(&current)["fuzzer"], value(&next)["fuzzer"]);
        for (selected, expected) in [("first", "pinned"), ("last", "first"), ("pinned", "middle")] {
            let mut selected_state = current.clone();
            selected_state.replay.active_tab_id = Some(selected.into());
            let closed =
                transform_saved_http_tab(&selected_state, selected, SavedHttpTabOperation::Close)
                    .unwrap();
            assert_eq!(closed.replay.active_tab_id.as_deref(), Some(expected));
        }
        let nonselected =
            transform_saved_http_tab(&current, "last", SavedHttpTabOperation::Close).unwrap();
        assert_eq!(
            nonselected.replay.active_tab_id,
            current.replay.active_tab_id
        );
        let mut single = current.clone();
        single.replay.tabs.retain(|tab| tab.id == "middle");
        let empty =
            transform_saved_http_tab(&single, "middle", SavedHttpTabOperation::Close).unwrap();
        assert!(empty.replay.tabs.is_empty());
        assert!(empty.replay.active_tab_id.is_none());
        assert_eq!(empty.replay.tab_sequence, 20);
        single.replay.tab_sequence = 0;
        let empty =
            transform_saved_http_tab(&single, "middle", SavedHttpTabOperation::Close).unwrap();
        assert_eq!(empty.replay.tab_sequence, 5);
    }

    #[test]
    fn saved_http_duplicate_keeps_raw_saved_state_and_focus_with_fresh_unpinned_identity() {
        let current = fixture();
        let next =
            transform_saved_http_tab(&current, "middle", SavedHttpTabOperation::Duplicate).unwrap();
        assert_eq!(next.replay.active_tab_id, current.replay.active_tab_id);
        assert_eq!(next.replay.tab_sequence, 21);
        let mut duplicate = next.replay.tabs.last().unwrap().clone();
        assert!(Uuid::parse_str(&duplicate.id).is_ok());
        assert!(current.replay.tabs.iter().all(|tab| tab.id != duplicate.id));
        assert_eq!(duplicate.sequence, 21);
        assert!(!duplicate.pinned);
        duplicate.id = current.replay.tabs[1].id.clone();
        duplicate.sequence = current.replay.tabs[1].sequence;
        duplicate.pinned = current.replay.tabs[1].pinned;
        assert_eq!(
            serde_json::to_value(duplicate).unwrap(),
            value(&current)["replay"]["tabs"][1]
        );
        assert_eq!(
            &next.replay.tabs[..4]
                .iter()
                .map(|t| serde_json::to_value(t).unwrap())
                .collect::<Vec<_>>(),
            value(&current)["replay"]["tabs"].as_array().unwrap()
        );
        assert_eq!(value(&next)["fuzzer"], value(&current)["fuzzer"]);
        let mut behind = current.clone();
        behind.replay.tab_sequence = 0;
        assert_eq!(
            transform_saved_http_tab(&behind, "middle", SavedHttpTabOperation::Duplicate)
                .unwrap()
                .replay
                .tab_sequence,
            6
        );
    }

    #[test]
    fn saved_http_transform_rejects_missing_wrong_kind_cap_and_sequence_overflow() {
        let current = fixture();
        for operation in [
            SavedHttpTabOperation::Close,
            SavedHttpTabOperation::Duplicate,
        ] {
            assert!(transform_saved_http_tab(&current, " middle ", operation).is_err());
            for kind in ["websocket", "unknown", "HTTP"] {
                let mut wrong = current.clone();
                wrong.replay.tabs[1].tab_type = kind.into();
                assert!(transform_saved_http_tab(&wrong, "middle", operation).is_err());
            }
        }
        let mut full = current.clone();
        full.replay
            .tabs
            .resize(MAX_WORKSPACE_REPLAY_TABS, current.replay.tabs[0].clone());
        assert!(
            transform_saved_http_tab(&full, "middle", SavedHttpTabOperation::Duplicate).is_err()
        );
        for sequence in [usize::MAX, usize::MAX - 1] {
            let mut exhausted = current.clone();
            exhausted.replay.tab_sequence = sequence;
            assert!(transform_saved_http_tab(
                &exhausted,
                "middle",
                SavedHttpTabOperation::Duplicate
            )
            .is_err());
            exhausted.replay.tab_sequence = 0;
            exhausted.replay.tabs[0].sequence = sequence;
            assert!(transform_saved_http_tab(
                &exhausted,
                "middle",
                SavedHttpTabOperation::Duplicate
            )
            .is_err());
        }
    }

    #[tokio::test]
    async fn saved_http_strict_cas_clears_writer_and_blocks_queued_same_client_snapshot() {
        let current = fixture();
        let store = WorkspaceStateStore::from_snapshot(current.clone());
        let mut events = store.subscribe();
        let committed = store
            .transform_snapshot_checked_persisting(
                8,
                |current| transform_saved_http_tab(current, "middle", SavedHttpTabOperation::Close),
                |_| async { Ok::<_, String>(None) },
            )
            .await
            .unwrap();
        assert_eq!(committed.revision, 9);
        assert_eq!(events.try_recv().unwrap().revision, 9);
        assert!(committed.client_id.is_none());
        assert_eq!(committed.client_version, 0);
        let mut queued = current;
        queued.client_version = 999;
        assert!(store.replace_snapshot_checked(queued).await.is_err());
        let stale = store
            .transform_snapshot_checked_persisting(
                8,
                |_| panic!("stale CAS must not call transform"),
                |_| async {
                    panic!("stale CAS must not persist");
                    #[allow(unreachable_code)]
                    Ok::<_, String>(None)
                },
            )
            .await;
        assert!(matches!(
            stale,
            Err(WorkspaceTransformError::Conflict { revision: 9 })
        ));
        assert!(events.try_recv().is_err());
    }

    #[tokio::test]
    async fn saved_http_failed_persistence_is_not_published_but_postrename_uncertainty_is() {
        let current = fixture();
        let store = WorkspaceStateStore::from_snapshot(current.clone());
        let mut events = store.subscribe();
        let failure = store
            .transform_snapshot_checked_persisting(
                8,
                |current| transform_saved_http_tab(current, "middle", SavedHttpTabOperation::Close),
                |_| async { Err::<Option<String>, _>("before rename".into()) },
            )
            .await;
        assert!(matches!(failure, Err(WorkspaceTransformError::Persist(_))));
        assert_eq!(value(&store.snapshot().await), value(&current));
        assert!(events.try_recv().is_err());
        let uncertainty = store
            .transform_snapshot_checked_persisting(
                8,
                |current| transform_saved_http_tab(current, "middle", SavedHttpTabOperation::Close),
                |_| async { Ok::<_, String>(Some("directory sync failed after rename".into())) },
            )
            .await;
        assert!(matches!(
            uncertainty,
            Err(WorkspaceTransformError::CommittedButUncertain(_))
        ));
        assert_eq!(store.snapshot().await.revision, 9);
        assert!(store.snapshot().await.client_id.is_none());
        assert_eq!(events.try_recv().unwrap().revision, 9);
    }

    #[tokio::test]
    async fn saved_http_revision_exhaustion_and_invalid_transform_do_not_persist_or_announce() {
        for (revision, invalid) in [(u64::MAX, false), (8, true)] {
            let mut current = fixture();
            current.revision = revision;
            let store = WorkspaceStateStore::from_snapshot(current.clone());
            let mut events = store.subscribe();
            let result = store
                .transform_snapshot_checked_persisting(
                    revision,
                    |current| {
                        if invalid {
                            Err("invalid tab".into())
                        } else {
                            Ok(current.clone())
                        }
                    },
                    |_| async {
                        panic!("invalid transform must not persist");
                        #[allow(unreachable_code)]
                        Ok::<_, String>(None)
                    },
                )
                .await;
            assert!(matches!(result, Err(WorkspaceTransformError::Invalid(_))));
            assert_eq!(value(&store.snapshot().await), value(&current));
            assert!(events.try_recv().is_err());
        }
    }
}
