use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    fuzzer::FuzzerAttackRecord,
    model::{EditableRequest, TransactionRecord},
};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkspaceStateSnapshot {
    #[serde(alias = "repeater")]
    pub replay: ReplayWorkspaceState,
    #[serde(alias = "intruder")]
    pub fuzzer: FuzzerWorkspaceState,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ReplayWorkspaceState {
    pub tabs: Vec<ReplayTabState>,
    pub active_tab_id: Option<String>,
    pub tab_sequence: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplayHistoryEntryState {
    pub request: EditableRequest,
    pub request_text: String,
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
    pub sequence: usize,
    pub base_request: Option<EditableRequest>,
    pub source_transaction_id: Option<Uuid>,
    pub notice: String,
    pub request_text: String,
    pub response_record: Option<TransactionRecord>,
    pub target_scheme: String,
    pub target_host: String,
    pub target_port: String,
    pub history_entries: Vec<ReplayHistoryEntryState>,
    pub history_index: Option<usize>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FuzzerWorkspaceState {
    pub base_request: Option<EditableRequest>,
    pub source_transaction_id: Option<Uuid>,
    pub notice: String,
    pub request_text: String,
    pub payloads_text: String,
    pub attack_record: Option<FuzzerAttackRecord>,
}

pub struct WorkspaceStateStore {
    inner: RwLock<WorkspaceStateSnapshot>,
}

impl WorkspaceStateStore {
    pub fn new() -> Self {
        Self::from_snapshot(WorkspaceStateSnapshot::default())
    }

    pub fn from_snapshot(snapshot: WorkspaceStateSnapshot) -> Self {
        Self {
            inner: RwLock::new(snapshot),
        }
    }

    pub async fn snapshot(&self) -> WorkspaceStateSnapshot {
        self.inner.read().await.clone()
    }

    pub async fn replace_snapshot(
        &self,
        snapshot: WorkspaceStateSnapshot,
    ) -> WorkspaceStateSnapshot {
        let mut current = self.inner.write().await;
        *current = snapshot;
        current.clone()
    }
}
