use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
    io::{self, BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    sync::{mpsc, Arc, RwLock},
    thread,
};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use tokio::sync::{oneshot, Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};
use tracing::warn;
use uuid::Uuid;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::{
    api::validate_workspace_state,
    event_log::{EventLogEntry, EventLogStore},
    fuzzer::{FuzzerAttackRecord, FuzzerStore},
    intercept::{InterceptQueue, ResponseInterceptQueue},
    match_replace::{MatchReplaceRule, MatchReplaceStore},
    model::{
        compact_annotation_client_versions_for_insert, TransactionRecord, WebSocketFrameRecord,
        WebSocketSessionRecord,
    },
    runtime::{RuntimeSettings, RuntimeSettingsSnapshot},
    scanner::{scan_transaction, ScannerConfig, ScannerFinding, ScannerStore},
    sequence::{SequenceDefinition, SequenceRunRecord, SequenceStore},
    store::{
        normalize_storage_sequences, transaction_journal_checkpoint_path, NullableStringPatch,
        TransactionJournalEntry, TransactionStore,
    },
    websocket::{sessions_with_live_preserved, trim_frame_overflow, WebSocketStore},
    workspace::{validate_workspace_serialized_size, WorkspaceReplaceError},
    workspace::{WorkspaceStateSnapshot, WorkspaceStateStore},
};

pub(crate) const SESSIONS_DIR: &str = "sessions";
const REGISTRY_FILE: &str = "registry.json";
const SNAPSHOT_FILE: &str = "snapshot.json";
/// The workspace lives in its own file because it is the only high-frequency
/// writer: every replay tab rename or target edit persists it. Keeping it inside
/// snapshot.json meant rewriting the whole session document — 1.35 GB in a real
/// session, of which the workspace was 1 MB — for each of those edits.
const WORKSPACE_FILE: &str = "workspace.json";
const TRANSACTION_JOURNAL_FILE: &str = "transactions.journal";
const WEBSOCKET_JOURNAL_FILE: &str = "websockets.journal";
const MAX_SESSION_NAME_BYTES: usize = 256;
const MAX_PERSISTED_WEBSOCKET_FRAMES_PER_SESSION: usize = 1_000;

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
    #[serde(default, alias = "intruder_count")]
    pub fuzzer_count: usize,
    #[serde(default)]
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
    #[serde(default, alias = "intruder_count")]
    pub fuzzer_count: usize,
    #[serde(default)]
    pub rule_count: usize,
    pub storage_path: String,
    pub active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SessionRegistrySnapshot {
    active_session_id: Uuid,
    sessions: Vec<SessionMetadata>,
    #[serde(default)]
    deleted_session_ids: Vec<Uuid>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct StoredSessionRegistrySnapshot {
    active_session_id: Option<Uuid>,
    #[serde(default)]
    sessions: Vec<SessionMetadata>,
    #[serde(default)]
    deleted_session_ids: Vec<Uuid>,
}

impl StoredSessionRegistrySnapshot {
    fn into_snapshot(self) -> (SessionRegistrySnapshot, bool) {
        let repaired = self.active_session_id.is_none();
        let active_session_id = self
            .active_session_id
            .or_else(|| self.sessions.first().map(|session| session.id))
            .unwrap_or_else(Uuid::nil);
        (
            SessionRegistrySnapshot {
                active_session_id,
                sessions: self.sessions,
                deleted_session_ids: self.deleted_session_ids,
            },
            repaired,
        )
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct StoredSessionSnapshot {
    runtime: RuntimeSettingsSnapshot,
    transactions: Vec<TransactionRecord>,
    #[serde(default)]
    transaction_event_sequence: u64,
    websockets: Vec<WebSocketSessionRecord>,
    event_log: Vec<EventLogEntry>,
    match_replace_rules: Vec<MatchReplaceRule>,
    #[serde(alias = "intruder_attacks")]
    fuzzer_attacks: Vec<FuzzerAttackRecord>,
    #[serde(default)]
    scanner_findings: Vec<ScannerFinding>,
    #[serde(default)]
    scanner_config: ScannerConfig,
    #[serde(default)]
    intercept_rules: Vec<crate::intercept::InterceptRule>,
    #[serde(default)]
    sequence_definitions: Vec<SequenceDefinition>,
    #[serde(default)]
    sequence_runs: Vec<SequenceRunRecord>,
    #[serde(default)]
    oast_callbacks: Option<Vec<crate::oast::OastCallback>>,
    #[serde(default)]
    oast_cleared_callback_keys: Vec<crate::oast::OastCallbackDedupKey>,
    #[serde(default)]
    oast_registration: Option<crate::oast::StoredOastRegistration>,
    #[serde(default, deserialize_with = "deserialize_workspace_state_lossy")]
    workspace: WorkspaceStateSnapshot,
    #[serde(skip)]
    replayed_transaction_journal: bool,
    #[serde(skip)]
    replayed_transaction_ids: HashSet<Uuid>,
    #[serde(skip)]
    replayed_websocket_journal: bool,
    #[serde(skip)]
    compactable_websocket_journal: bool,
    #[serde(skip)]
    unresolved_websocket_journal: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionSnapshotLoadMode {
    Writable,
    ReadOnly,
}

struct TransactionJournalReplayResult {
    replayed_transaction_ids: HashSet<Uuid>,
    mutated_snapshot: bool,
    transaction_event_sequence: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct WebSocketJournalReplayResult {
    mutated_snapshot: bool,
    can_compact: bool,
    has_unresolved_delta: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WebSocketJournalApplyResult {
    Mutated,
    Noop,
    MissingParent,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WebSocketJournalEntry {
    Open {
        record: WebSocketSessionRecord,
    },
    Frame {
        id: Uuid,
        frame: WebSocketFrameRecord,
    },
    Close {
        id: Uuid,
        closed_at: DateTime<Utc>,
        duration_ms: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
}

enum WebSocketJournalCommand {
    Append {
        line: Vec<u8>,
        ack: oneshot::Sender<io::Result<()>>,
    },
    Clear {
        ack: mpsc::Sender<io::Result<()>>,
    },
}

fn deserialize_workspace_state_lossy<'de, D>(
    deserializer: D,
) -> std::result::Result<WorkspaceStateSnapshot, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(value) = Option::<serde_json::Value>::deserialize(deserializer)? else {
        return Ok(WorkspaceStateSnapshot::default());
    };
    match serde_json::from_value(value) {
        Ok(snapshot) => Ok(snapshot),
        Err(error) => {
            warn!(
                ?error,
                "discarding invalid workspace state from session snapshot"
            );
            Ok(WorkspaceStateSnapshot::default())
        }
    }
}

pub struct SessionContext {
    id: Uuid,
    storage_dir: PathBuf,
    max_entries: usize,
    max_transaction_entries: usize,
    pub store: Arc<TransactionStore>,
    pub runtime: Arc<RuntimeSettings>,
    pub intercepts: Arc<InterceptQueue>,
    pub response_intercepts: Arc<ResponseInterceptQueue>,
    pub intercept_rules: Arc<crate::intercept::InterceptRuleStore>,
    pub websockets: Arc<WebSocketStore>,
    pub event_log: Arc<EventLogStore>,
    pub match_replace: Arc<MatchReplaceStore>,
    pub fuzzer: Arc<FuzzerStore>,
    pub scanner: Arc<ScannerStore>,
    pub sequence: Arc<SequenceStore>,
    pub oast: Arc<crate::oast::OastStore>,
    pub workspace: Arc<WorkspaceStateStore>,
    websocket_journal_tx: Option<mpsc::Sender<WebSocketJournalCommand>>,
    metadata: RwLock<SessionMetadata>,
    mutation_lock: AsyncMutex<()>,
    persist_lock: AsyncMutex<()>,
}

impl SessionContext {
    fn from_snapshot(
        metadata: SessionMetadata,
        storage_dir: PathBuf,
        max_entries: usize,
        max_transaction_entries: usize,
        max_frames_per_session: usize,
        snapshot: StoredSessionSnapshot,
    ) -> Self {
        Self::from_snapshot_with_journal_mode(
            metadata,
            storage_dir,
            max_entries,
            max_transaction_entries,
            max_frames_per_session,
            snapshot,
            true,
        )
    }

    fn from_snapshot_read_only(
        metadata: SessionMetadata,
        storage_dir: PathBuf,
        max_entries: usize,
        max_transaction_entries: usize,
        max_frames_per_session: usize,
        snapshot: StoredSessionSnapshot,
    ) -> Self {
        Self::from_snapshot_with_journal_mode(
            metadata,
            storage_dir,
            max_entries,
            max_transaction_entries,
            max_frames_per_session,
            snapshot,
            false,
        )
    }

    fn from_snapshot_with_journal_mode(
        metadata: SessionMetadata,
        storage_dir: PathBuf,
        max_entries: usize,
        max_transaction_entries: usize,
        max_frames_per_session: usize,
        snapshot: StoredSessionSnapshot,
        enable_journal: bool,
    ) -> Self {
        let journal_path = transaction_journal_path(&storage_dir);
        let runtime_snapshot = snapshot.runtime.clone();
        let scanner_config =
            crate::scanner::sanitize_scanner_config(snapshot.scanner_config.clone());
        let scanner_findings = if snapshot.replayed_transaction_journal {
            recover_missing_scanner_findings(
                snapshot.scanner_findings,
                &snapshot.transactions,
                &snapshot.replayed_transaction_ids,
                &scanner_config,
                max_entries,
            )
        } else {
            snapshot.scanner_findings
        };
        let transaction_event_sequence = snapshot.transaction_event_sequence;
        let mut websockets = snapshot.websockets;
        close_restored_open_websockets(&mut websockets);
        let sequence_definitions = snapshot
            .sequence_definitions
            .into_iter()
            .filter(|definition| crate::api::validate_sequence_definition(definition).is_ok())
            .collect();
        let websocket_journal_tx = enable_journal
            .then(|| start_websocket_journal_writer(websocket_journal_path(&storage_dir)))
            .flatten();
        Self {
            id: metadata.id,
            storage_dir,
            max_entries,
            max_transaction_entries,
            store: Arc::new(if enable_journal {
                TransactionStore::from_records_with_journal_and_event_sequence(
                    snapshot.transactions,
                    journal_path,
                    Some(max_transaction_entries),
                    transaction_event_sequence,
                )
            } else {
                TransactionStore::from_records_with_max_entries_and_event_sequence(
                    snapshot.transactions,
                    Some(max_transaction_entries),
                    transaction_event_sequence,
                )
            }),
            runtime: Arc::new(RuntimeSettings::from_snapshot(runtime_snapshot.clone())),
            intercepts: Arc::new(InterceptQueue::new()),
            response_intercepts: Arc::new(ResponseInterceptQueue::new()),
            intercept_rules: Arc::new(crate::intercept::InterceptRuleStore::from_rules(
                snapshot.intercept_rules,
            )),
            websockets: Arc::new(WebSocketStore::from_sessions(
                max_entries,
                max_frames_per_session,
                websockets,
            )),
            event_log: Arc::new(EventLogStore::from_entries(max_entries, snapshot.event_log)),
            match_replace: Arc::new(MatchReplaceStore::from_rules(snapshot.match_replace_rules)),
            fuzzer: Arc::new(FuzzerStore::from_attacks(
                max_entries,
                snapshot.fuzzer_attacks,
            )),
            scanner: Arc::new(ScannerStore::from_findings_with_config(
                max_entries,
                scanner_findings,
                scanner_config,
            )),
            sequence: Arc::new(SequenceStore::from_data(
                max_entries,
                sequence_definitions,
                snapshot.sequence_runs,
            )),
            oast: {
                let store = Arc::new(crate::oast::OastStore::new_with_config(
                    max_entries,
                    crate::oast::OastConfig {
                        enabled: runtime_snapshot.oast_enabled,
                        server_url: runtime_snapshot.oast_server_url,
                        token: runtime_snapshot.oast_token,
                        polling_interval_secs: runtime_snapshot.oast_polling_interval_secs,
                        provider: runtime_snapshot.oast_provider,
                    },
                ));
                if let Some(callbacks) = snapshot.oast_callbacks {
                    store.restore_blocking(callbacks);
                }
                store.restore_cleared_keys_blocking(snapshot.oast_cleared_callback_keys);
                store.restore_registration_blocking(snapshot.oast_registration);
                store
            },
            workspace: Arc::new(WorkspaceStateStore::from_snapshot(snapshot.workspace)),
            websocket_journal_tx,
            metadata: RwLock::new(metadata),
            mutation_lock: AsyncMutex::new(()),
            persist_lock: AsyncMutex::new(()),
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

    pub fn replace_metadata(&self, metadata: SessionMetadata) {
        *self
            .metadata
            .write()
            .expect("session metadata lock poisoned") = metadata;
    }

    pub async fn persist(&self) -> Result<SessionMetadata> {
        let _mutation_guard = self.mutation_lock.lock().await;
        self.persist_mutation_locked().await
    }

    pub async fn mutation_guard(&self) -> AsyncMutexGuard<'_, ()> {
        self.mutation_lock.lock().await
    }

    pub async fn persist_mutation_locked(&self) -> Result<SessionMetadata> {
        let _persist_guard = self.persist_lock.lock().await;
        self.persist_with_workspace_snapshot_locked(self.workspace.snapshot().await)
            .await
    }

    pub async fn open_websocket_capture(&self, record: WebSocketSessionRecord) -> Result<()> {
        let _persist_guard = self.persist_lock.lock().await;
        self.append_websocket_journal_entry(&WebSocketJournalEntry::Open {
            record: record.clone(),
        })
        .await?;
        self.websockets.open(record).await;
        Ok(())
    }

    pub async fn append_websocket_capture_frame(
        &self,
        id: Uuid,
        frame: WebSocketFrameRecord,
    ) -> Result<bool> {
        let _persist_guard = self.persist_lock.lock().await;
        if !self.websockets.contains(id).await {
            return Ok(false);
        }
        self.append_websocket_journal_entry(&WebSocketJournalEntry::Frame {
            id,
            frame: frame.clone(),
        })
        .await?;
        Ok(self.websockets.append_frame(id, frame).await)
    }

    pub async fn close_websocket_capture(
        &self,
        id: Uuid,
        closed_at: DateTime<Utc>,
        duration_ms: u64,
        note: Option<String>,
    ) -> Result<bool> {
        let _persist_guard = self.persist_lock.lock().await;
        if !self.websockets.contains(id).await {
            return Ok(false);
        }
        self.append_websocket_journal_entry(&WebSocketJournalEntry::Close {
            id,
            closed_at,
            duration_ms,
            note: note.clone(),
        })
        .await?;
        Ok(self
            .websockets
            .close(id, closed_at, duration_ms, note)
            .await)
    }

    async fn append_websocket_journal_entry(&self, entry: &WebSocketJournalEntry) -> Result<()> {
        let line = encode_websocket_journal_line(entry)?;
        let tx = self
            .websocket_journal_tx
            .as_ref()
            .ok_or_else(|| anyhow!("websocket journal writer is not available"))?;
        append_websocket_journal(tx, line).await.with_context(|| {
            format!(
                "failed to append websocket journal for {}",
                self.storage_dir.display()
            )
        })
    }

    /// Bytes the next load would have to replay from the transaction journal:
    /// the active file plus the checkpoint, which holds rotated entries until a
    /// snapshot write discards them. Rewriting the session snapshot is what
    /// compacts both, so this is the signal for when that rewrite is worth its
    /// cost.
    pub fn transaction_journal_replay_bytes(&self) -> u64 {
        let journal = transaction_journal_path(&self.storage_dir);
        let checkpoint = transaction_journal_checkpoint_path(&journal);
        [journal, checkpoint]
            .iter()
            .filter_map(|path| fs::metadata(path).ok())
            .map(|metadata| metadata.len())
            .sum()
    }

    pub async fn replace_workspace_snapshot_checked_and_persist(
        &self,
        snapshot: WorkspaceStateSnapshot,
    ) -> std::result::Result<
        (WorkspaceStateSnapshot, Option<SessionMetadata>),
        WorkspaceReplaceError<anyhow::Error>,
    > {
        let _mutation_guard = self.mutation_lock.lock().await;
        let _persist_guard = self.persist_lock.lock().await;
        self.workspace
            .replace_snapshot_checked_persisting(snapshot, |workspace| async move {
                self.persist_workspace_snapshot_locked(workspace).await
            })
            .await
    }

    async fn persist_workspace_snapshot_locked(
        &self,
        workspace: WorkspaceStateSnapshot,
    ) -> Result<Option<SessionMetadata>> {
        self.persist_workspace_snapshot_locked_inner(workspace)
            .await
    }

    async fn persist_workspace_snapshot_locked_inner(
        &self,
        workspace: WorkspaceStateSnapshot,
    ) -> Result<Option<SessionMetadata>> {
        validate_workspace_serialized_size(&workspace)
            .map_err(anyhow::Error::msg)
            .with_context(|| "workspace snapshot is too large to persist")?;
        validate_workspace_state(&workspace)
            .map_err(anyhow::Error::msg)
            .with_context(|| "workspace snapshot is invalid")?;
        // Write only the workspace file. This used to read snapshot.json, parse
        // it, swap the workspace field and rewrite the whole document, which
        // costs 1.35 GB of I/O and 3.3 s of CPU per edit on a real session for a
        // 1 MB payload. snapshot.json is left untouched; its embedded workspace
        // copy stays as the load-time fallback, and a corrupt snapshot.json is
        // repaired on the next load rather than here.
        write_json(&workspace_path(&self.storage_dir), &workspace)?;
        Ok(None)
    }

    async fn persist_with_workspace_snapshot_locked(
        &self,
        workspace: WorkspaceStateSnapshot,
    ) -> Result<SessionMetadata> {
        validate_workspace_serialized_size(&workspace)
            .map_err(anyhow::Error::msg)
            .with_context(|| "workspace snapshot is too large to persist")?;
        validate_workspace_state(&workspace)
            .map_err(anyhow::Error::msg)
            .with_context(|| "workspace snapshot is invalid")?;
        let transactions = self
            .store
            .snapshot_for_persistence(Some(self.max_transaction_entries))
            .await
            .with_context(|| {
                format!(
                    "failed to rotate transaction journal for {}",
                    self.storage_dir.display()
                )
            })?;
        let snapshot = StoredSessionSnapshot {
            runtime: self.runtime.snapshot().await,
            transactions,
            transaction_event_sequence: self.store.latest_event_sequence(),
            websockets: self
                .websockets
                .snapshot_with_frame_limit(
                    Some(self.max_entries),
                    Some(MAX_PERSISTED_WEBSOCKET_FRAMES_PER_SESSION),
                )
                .await,
            event_log: self.event_log.snapshot(Some(self.max_entries)).await,
            match_replace_rules: self.match_replace.snapshot().await,
            fuzzer_attacks: self.fuzzer.snapshot(Some(self.max_entries)).await,
            scanner_findings: self.scanner.snapshot(Some(self.max_entries)).await,
            scanner_config: self.scanner.get_config().await,
            intercept_rules: self.intercept_rules.snapshot().await,
            sequence_definitions: self.sequence.snapshot_definitions().await,
            sequence_runs: self.sequence.snapshot_runs(Some(self.max_entries)).await,
            oast_callbacks: Some(self.oast.snapshot().await),
            oast_cleared_callback_keys: self.oast.snapshot_cleared_keys().await,
            oast_registration: self.oast.snapshot_registration().await,
            workspace,
            replayed_transaction_journal: false,
            replayed_transaction_ids: HashSet::new(),
            replayed_websocket_journal: false,
            compactable_websocket_journal: false,
            unresolved_websocket_journal: false,
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
        metadata.fuzzer_count = snapshot.fuzzer_attacks.len();
        metadata.rule_count = snapshot.match_replace_rules.len();

        create_private_dir_all(&self.storage_dir).with_context(|| {
            format!(
                "failed to create session directory {}",
                self.storage_dir.display()
            )
        })?;
        write_json(&snapshot_path(&self.storage_dir), &snapshot)?;
        if let Err(error) = discard_transaction_journal_checkpoint(&self.storage_dir) {
            warn!(
                %error,
                session_id = %self.id,
                "failed to remove transaction journal checkpoint after writing session snapshot"
            );
        }
        if let Some(tx) = &self.websocket_journal_tx {
            if let Err(error) = clear_websocket_journal(tx) {
                warn!(
                    %error,
                    session_id = %self.id,
                    "failed to clear websocket journal after writing session snapshot"
                );
            }
        }

        *self
            .metadata
            .write()
            .expect("session metadata lock poisoned") = metadata.clone();

        Ok(metadata)
    }
}

fn close_restored_open_websockets(records: &mut [WebSocketSessionRecord]) -> bool {
    let closed_at = Utc::now();
    let mut changed = false;
    for record in records {
        if record.closed_at.is_none() {
            record.duration_ms.get_or_insert_with(|| {
                closed_at
                    .signed_duration_since(record.started_at)
                    .num_milliseconds()
                    .max(0) as u64
            });
            record.closed_at = Some(closed_at);
            record
                .notes
                .push("Sniper restarted before this WebSocket session was closed.".to_string());
            changed = true;
        }
    }
    changed
}

fn recover_missing_scanner_findings(
    mut findings: Vec<ScannerFinding>,
    transactions: &[TransactionRecord],
    recovered_record_ids: &HashSet<Uuid>,
    config: &ScannerConfig,
    max_entries: usize,
) -> Vec<ScannerFinding> {
    if max_entries == 0 {
        findings.clear();
        return findings;
    }

    let covered_records: HashSet<Uuid> = findings.iter().map(|finding| finding.record_id).collect();
    let mut recovered = Vec::new();
    for record in transactions {
        if !recovered_record_ids.contains(&record.id) {
            continue;
        }
        if covered_records.contains(&record.id) {
            continue;
        }
        for finding in scan_transaction(record, config) {
            recovered.push(finding);
        }
    }
    recovered.extend(findings);
    recovered.truncate(max_entries);

    recovered
}

pub struct SessionRegistry {
    root_dir: PathBuf,
    registry_path: PathBuf,
    max_entries: usize,
    max_transaction_entries: usize,
    max_frames_per_session: usize,
    inner: RwLock<SessionRegistrySnapshot>,
}

impl SessionRegistry {
    pub fn load_or_create(
        data_dir: &Path,
        max_entries: usize,
        max_frames_per_session: usize,
    ) -> Result<(Self, Arc<SessionContext>)> {
        Self::load_or_create_with_transaction_limit(
            data_dir,
            max_entries,
            max_entries,
            max_frames_per_session,
        )
    }

    pub fn load_or_create_with_transaction_limit(
        data_dir: &Path,
        max_entries: usize,
        max_transaction_entries: usize,
        max_frames_per_session: usize,
    ) -> Result<(Self, Arc<SessionContext>)> {
        let root_dir = data_dir.join(SESSIONS_DIR);
        create_private_dir_all(&root_dir).with_context(|| {
            format!("failed to create sessions directory {}", root_dir.display())
        })?;
        let registry_path = root_dir.join(REGISTRY_FILE);

        let mut repair_registry = false;
        let mut registry = match fs::read(&registry_path) {
            Ok(bytes) => match serde_json::from_slice::<StoredSessionRegistrySnapshot>(&bytes) {
                Ok(snapshot) => {
                    let (snapshot, repaired) = snapshot.into_snapshot();
                    repair_registry |= repaired;
                    snapshot
                }
                Err(error) => {
                    warn!(
                        ?error,
                        path = %registry_path.display(),
                        "discarding corrupt session registry"
                    );
                    move_corrupt_session_file_aside(&root_dir, &registry_path, "registry");
                    repair_registry = true;
                    rebuild_registry_from_session_dirs(
                        &root_dir,
                        max_entries,
                        max_transaction_entries,
                    )?
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let snapshot = rebuild_registry_from_session_dirs(
                    &root_dir,
                    max_entries,
                    max_transaction_entries,
                )?;
                write_json(&registry_path, &snapshot)?;
                snapshot
            }
            Err(error) if registry_path.is_dir() => {
                warn!(
                    ?error,
                    path = %registry_path.display(),
                    "discarding invalid session registry path"
                );
                move_corrupt_session_file_aside(&root_dir, &registry_path, "registry");
                repair_registry = true;
                rebuild_registry_from_session_dirs(&root_dir, max_entries, max_transaction_entries)?
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

        if remove_orphan_quarantined_deleted_session_storage(&root_dir) {
            repair_registry = true;
        }

        if normalize_registry_snapshot(&root_dir, &mut registry) {
            repair_registry = true;
        }

        if registry.sessions.is_empty() {
            registry = rebuild_registry_from_session_dirs_excluding(
                &root_dir,
                max_entries,
                max_transaction_entries,
                &registry
                    .deleted_session_ids
                    .iter()
                    .copied()
                    .collect::<HashSet<_>>(),
            )?;
            repair_registry = true;
        }

        if recover_unregistered_session_dirs(
            &root_dir,
            max_entries,
            max_transaction_entries,
            &mut registry,
        )? {
            repair_registry = true;
        }

        if normalize_registry_snapshot(&root_dir, &mut registry) {
            repair_registry = true;
        }

        if !registry
            .sessions
            .iter()
            .any(|session| session.id == registry.active_session_id)
        {
            registry.active_session_id = registry.sessions[0].id;
            repair_registry = true;
        }

        if repair_registry {
            write_json(&registry_path, &registry)?;
        }

        let this = Self {
            root_dir,
            registry_path,
            max_entries,
            max_transaction_entries,
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
        sessions.sort_by_key(|session| std::cmp::Reverse(session.last_opened_at));
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
            name: normalize_session_name(name.as_deref(), now)?,
            created_at: now,
            updated_at: now,
            last_opened_at: now,
            request_count: 0,
            websocket_count: 0,
            event_count: 0,
            fuzzer_count: 0,
            rule_count: 0,
        };

        persist_session_snapshot(&self.root_dir, &metadata, &StoredSessionSnapshot::default())?;
        let registry_result = {
            let mut registry = self.inner.write().expect("session registry lock poisoned");
            let mut next = registry.clone();
            next.sessions.push(metadata.clone());
            next.deleted_session_ids
                .retain(|deleted_id| *deleted_id != metadata.id);
            write_json(&self.registry_path, &next).map(|()| {
                *registry = next;
            })
        };
        if let Err(error) = registry_result {
            let _ = fs::remove_dir_all(session_dir(&self.root_dir, metadata.id));
            return Err(error);
        }
        Ok(metadata)
    }

    pub fn activate_session(&self, id: Uuid) -> Result<SessionMetadata> {
        self.touch_active_session(id)
    }

    pub fn update_metadata(&self, metadata: SessionMetadata) -> Result<()> {
        let mut registry = self.inner.write().expect("session registry lock poisoned");
        let mut next = registry.clone();
        let Some(existing) = next
            .sessions
            .iter_mut()
            .find(|session| session.id == metadata.id)
        else {
            return Err(anyhow!("session {} was not found", metadata.id));
        };
        *existing = metadata;
        write_json(&self.registry_path, &next)?;
        *registry = next;
        Ok(())
    }

    pub fn contains_session(&self, id: Uuid) -> bool {
        let registry = self.inner.read().expect("session registry lock poisoned");
        registry.sessions.iter().any(|session| session.id == id)
    }

    pub fn delete_session(&self, id: Uuid) -> Result<()> {
        let mut registry = self.inner.write().expect("session registry lock poisoned");
        if registry.active_session_id == id {
            return Err(anyhow!("cannot delete the active session"));
        }
        let mut next = registry.clone();
        if !next.sessions.iter().any(|session| session.id == id) {
            return Err(anyhow!("session {id} was not found"));
        }

        let storage_dir = session_dir(&self.root_dir, id);
        let storage_metadata = session_storage_metadata(&storage_dir)?;
        let quarantined_storage = if storage_metadata.is_some() {
            let quarantine_dir = deleted_session_dir(&self.root_dir, id);
            fs::rename(&storage_dir, &quarantine_dir).with_context(|| {
                format!(
                    "failed to quarantine session storage directory {}",
                    storage_dir.display()
                )
            })?;
            Some(quarantine_dir)
        } else {
            None
        };

        next.sessions.retain(|session| session.id != id);
        if !next.deleted_session_ids.contains(&id) {
            next.deleted_session_ids.push(id);
        }
        if let Err(error) = write_json(&self.registry_path, &next) {
            if let Some(quarantine_dir) = quarantined_storage.as_ref() {
                if let Err(rollback_error) = fs::rename(quarantine_dir, &storage_dir) {
                    warn!(
                        ?rollback_error,
                        session_id = %id,
                        source = %quarantine_dir.display(),
                        target = %storage_dir.display(),
                        "failed to restore quarantined session storage after registry delete failure"
                    );
                }
            }
            return Err(error);
        }
        *registry = next;
        drop(registry);

        let storage_removed = quarantined_storage
            .as_deref()
            .is_none_or(|quarantine_dir| remove_quarantined_session_storage(id, quarantine_dir));
        let mut registry = self.inner.write().expect("session registry lock poisoned");
        if storage_removed && registry.deleted_session_ids.contains(&id) {
            let mut cleaned = registry.clone();
            cleaned
                .deleted_session_ids
                .retain(|deleted_id| *deleted_id != id);
            match write_json(&self.registry_path, &cleaned) {
                Ok(()) => {
                    *registry = cleaned;
                }
                Err(error) => {
                    warn!(
                        %error,
                        session_id = %id,
                        "failed to prune deleted session tombstone after storage removal"
                    );
                }
            }
        }
        Ok(())
    }

    pub fn session_storage_path(&self, id: Uuid) -> Result<PathBuf> {
        let registry = self.inner.read().expect("session registry lock poisoned");
        if !registry.sessions.iter().any(|s| s.id == id) {
            return Err(anyhow!("session {id} was not found"));
        }
        let storage_dir = session_dir(&self.root_dir, id);
        ensure_existing_private_session_dir(&storage_dir)?;
        Ok(storage_dir)
    }

    pub fn load_context(&self, id: Uuid) -> Result<Arc<SessionContext>> {
        let mut metadata = self
            .inner
            .read()
            .expect("session registry lock poisoned")
            .sessions
            .iter()
            .find(|session| session.id == id)
            .cloned()
            .ok_or_else(|| anyhow!("session {id} was not found"))?;
        let storage_dir = session_dir(&self.root_dir, id);
        let mut snapshot =
            load_session_snapshot(&storage_dir, self.max_entries, self.max_transaction_entries)?;
        let repaired_open_websockets = close_restored_open_websockets(&mut snapshot.websockets);
        let replayed_transaction_journal = snapshot.replayed_transaction_journal;
        if replayed_transaction_journal && !snapshot.replayed_transaction_ids.is_empty() {
            snapshot.scanner_findings = recover_missing_scanner_findings(
                std::mem::take(&mut snapshot.scanner_findings),
                &snapshot.transactions,
                &snapshot.replayed_transaction_ids,
                &snapshot.scanner_config,
                self.max_entries,
            );
        }
        let replayed_websocket_journal = snapshot.replayed_websocket_journal;
        let compactable_websocket_journal = snapshot.compactable_websocket_journal;
        let unresolved_websocket_journal = snapshot.unresolved_websocket_journal;
        if repaired_open_websockets || replayed_transaction_journal || replayed_websocket_journal {
            write_json(&snapshot_path(&storage_dir), &snapshot)?;
        }
        if replayed_transaction_journal {
            if let Err(error) = compact_replayed_transaction_journal(&storage_dir) {
                warn!(
                    %error,
                    session_id = %id,
                    "failed to compact replayed transaction journal after loading session"
                );
            }
        }
        if compactable_websocket_journal && !unresolved_websocket_journal {
            if let Err(error) = compact_replayed_websocket_journal(&storage_dir) {
                warn!(
                    %error,
                    session_id = %id,
                    "failed to compact replayed websocket journal after loading session"
                );
            }
        } else if unresolved_websocket_journal {
            warn!(
                session_id = %id,
                "preserving websocket journal because it contains frame or close deltas without a parent session"
            );
        }
        if update_metadata_counts_from_snapshot(
            &mut metadata,
            &snapshot,
            self.max_entries,
            self.max_transaction_entries,
        ) {
            if let Err(error) = self.update_metadata(metadata.clone()) {
                warn!(
                    ?error,
                    session_id = %id,
                    "failed to refresh session registry metadata from loaded snapshot"
                );
            }
        }
        Ok(Arc::new(SessionContext::from_snapshot(
            metadata,
            storage_dir,
            self.max_entries,
            self.max_transaction_entries,
            self.max_frames_per_session,
            snapshot,
        )))
    }

    pub fn load_context_read_only(&self, id: Uuid) -> Result<Arc<SessionContext>> {
        let mut metadata = self
            .inner
            .read()
            .expect("session registry lock poisoned")
            .sessions
            .iter()
            .find(|session| session.id == id)
            .cloned()
            .ok_or_else(|| anyhow!("session {id} was not found"))?;
        let storage_dir = session_dir(&self.root_dir, id);
        let mut snapshot = load_session_snapshot_read_only(
            &storage_dir,
            self.max_entries,
            self.max_transaction_entries,
        )?;
        close_restored_open_websockets(&mut snapshot.websockets);
        update_metadata_counts_from_snapshot(
            &mut metadata,
            &snapshot,
            self.max_entries,
            self.max_transaction_entries,
        );
        Ok(Arc::new(SessionContext::from_snapshot_read_only(
            metadata,
            storage_dir,
            self.max_entries,
            self.max_transaction_entries,
            self.max_frames_per_session,
            snapshot,
        )))
    }

    fn touch_active_session(&self, id: Uuid) -> Result<SessionMetadata> {
        let mut registry = self.inner.write().expect("session registry lock poisoned");
        let mut next = registry.clone();
        let Some(index) = next.sessions.iter().position(|session| session.id == id) else {
            return Err(anyhow!("session {id} was not found"));
        };

        next.sessions[index].last_opened_at = Utc::now();
        next.active_session_id = id;
        let metadata = next.sessions[index].clone();
        write_json(&self.registry_path, &next)?;
        *registry = next;
        Ok(metadata)
    }
}

fn update_metadata_counts_from_snapshot(
    metadata: &mut SessionMetadata,
    snapshot: &StoredSessionSnapshot,
    max_entries: usize,
    max_transaction_entries: usize,
) -> bool {
    let next_request_count = snapshot.transactions.len().min(max_transaction_entries);
    let next_websocket_count = snapshot.websockets.len();
    let next_event_count = snapshot.event_log.len().min(max_entries);
    let next_fuzzer_count = snapshot.fuzzer_attacks.len().min(max_entries);
    let next_rule_count = snapshot
        .match_replace_rules
        .len()
        .min(crate::match_replace::MAX_MATCH_REPLACE_RULES);

    let changed = metadata.request_count != next_request_count
        || metadata.websocket_count != next_websocket_count
        || metadata.event_count != next_event_count
        || metadata.fuzzer_count != next_fuzzer_count
        || metadata.rule_count != next_rule_count;

    metadata.request_count = next_request_count;
    metadata.websocket_count = next_websocket_count;
    metadata.event_count = next_event_count;
    metadata.fuzzer_count = next_fuzzer_count;
    metadata.rule_count = next_rule_count;

    changed
}

fn normalize_registry_snapshot(root_dir: &Path, registry: &mut SessionRegistrySnapshot) -> bool {
    let mut changed = false;

    let previous_deleted_len = registry.deleted_session_ids.len();
    let mut deleted_seen = HashSet::new();
    registry.deleted_session_ids.retain(|id| {
        deleted_seen.insert(*id) && deleted_session_storage_still_exists(root_dir, *id)
    });
    changed |= registry.deleted_session_ids.len() != previous_deleted_len;

    let deleted_ids = registry
        .deleted_session_ids
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    let previous_sessions_len = registry.sessions.len();
    let mut session_seen = HashSet::new();
    registry.sessions.retain(|session| {
        if deleted_ids.contains(&session.id) {
            return false;
        }
        if !session_seen.insert(session.id) {
            return false;
        }
        registered_session_storage_is_valid(root_dir, session.id)
    });
    changed |= registry.sessions.len() != previous_sessions_len;

    changed
}

fn registered_session_storage_is_valid(root_dir: &Path, id: Uuid) -> bool {
    let storage_dir = session_dir(root_dir, id);
    match session_storage_metadata(&storage_dir) {
        Ok(Some(_)) => true,
        Ok(None) => {
            warn!(
                session_id = %id,
                path = %storage_dir.display(),
                "dropping registered session with missing storage directory"
            );
            false
        }
        Err(error) => {
            warn!(
                %error,
                session_id = %id,
                path = %storage_dir.display(),
                "dropping registered session with invalid storage directory"
            );
            false
        }
    }
}

fn remove_quarantined_session_storage(id: Uuid, quarantine_dir: &Path) -> bool {
    match fs::remove_dir_all(quarantine_dir) {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => true,
        Err(error) => {
            warn!(
                %error,
                session_id = %id,
                path = %quarantine_dir.display(),
                "session registry delete committed but quarantined storage cleanup failed"
            );
            false
        }
    }
}

fn deleted_session_storage_still_exists(root_dir: &Path, id: Uuid) -> bool {
    let mut still_exists = remove_deleted_session_storage_path(&session_dir(root_dir, id), id);
    still_exists |= remove_quarantined_deleted_session_storage(root_dir, id);
    still_exists
}

fn remove_quarantined_deleted_session_storage(root_dir: &Path, id: Uuid) -> bool {
    let entries = match fs::read_dir(root_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return false,
        Err(error) => {
            warn!(
                %error,
                session_id = %id,
                path = %root_dir.display(),
                "failed to inspect session root for quarantined tombstoned storage"
            );
            return true;
        }
    };
    let prefix = format!(".deleted-{id}-");
    let mut still_exists = false;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                warn!(
                    %error,
                    session_id = %id,
                    path = %root_dir.display(),
                    "failed to inspect quarantined tombstoned session storage entry"
                );
                still_exists = true;
                continue;
            }
        };
        let file_name = entry.file_name();
        if !file_name.to_string_lossy().starts_with(&prefix) {
            continue;
        }
        still_exists |= remove_deleted_session_storage_path(&entry.path(), id);
    }
    still_exists
}

fn remove_orphan_quarantined_deleted_session_storage(root_dir: &Path) -> bool {
    let entries = match fs::read_dir(root_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return false,
        Err(error) => {
            warn!(
                %error,
                path = %root_dir.display(),
                "failed to inspect session root for orphaned quarantined storage"
            );
            return false;
        }
    };
    let mut removed_any = false;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                warn!(
                    %error,
                    path = %root_dir.display(),
                    "failed to inspect orphaned quarantined session storage entry"
                );
                continue;
            }
        };
        let file_name = entry.file_name();
        let Some(id) =
            quarantined_deleted_session_id_from_name(file_name.to_string_lossy().as_ref())
        else {
            continue;
        };
        removed_any |= !remove_deleted_session_storage_path(&entry.path(), id);
    }
    removed_any
}

fn quarantined_deleted_session_id_from_name(name: &str) -> Option<Uuid> {
    let value = name.strip_prefix(".deleted-")?;
    let id_text = value.get(..36)?;
    let suffix = value.get(36..)?;
    if !suffix.starts_with('-') {
        return None;
    }
    Uuid::parse_str(id_text).ok()
}

fn remove_deleted_session_storage_path(path: &Path, id: Uuid) -> bool {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return false,
        Err(error) => {
            warn!(
                %error,
                session_id = %id,
                path = %path.display(),
                "failed to inspect tombstoned session storage"
            );
            return true;
        }
    };

    let removal = if metadata.file_type().is_symlink() || metadata.is_file() {
        fs::remove_file(path)
    } else {
        fs::remove_dir_all(path)
    };

    match removal {
        Ok(()) => false,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => {
            warn!(
                %error,
                session_id = %id,
                path = %path.display(),
                "failed to remove tombstoned session storage"
            );
            true
        }
    }
}

fn rebuild_registry_from_session_dirs(
    root_dir: &Path,
    max_entries: usize,
    max_transaction_entries: usize,
) -> Result<SessionRegistrySnapshot> {
    rebuild_registry_from_session_dirs_excluding(
        root_dir,
        max_entries,
        max_transaction_entries,
        &HashSet::new(),
    )
}

fn rebuild_registry_from_session_dirs_excluding(
    root_dir: &Path,
    max_entries: usize,
    max_transaction_entries: usize,
    deleted_ids: &HashSet<Uuid>,
) -> Result<SessionRegistrySnapshot> {
    let mut sessions = Vec::new();
    for entry in fs::read_dir(root_dir)
        .with_context(|| format!("failed to read sessions directory {}", root_dir.display()))?
    {
        let entry = entry.with_context(|| {
            format!(
                "failed to read session directory entry in {}",
                root_dir.display()
            )
        })?;
        let path = entry.path();
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        let Ok(id) = Uuid::parse_str(name) else {
            continue;
        };
        if deleted_ids.contains(&id) {
            continue;
        }
        match load_session_snapshot(&path, max_entries, max_transaction_entries) {
            Ok(snapshot) => {
                sessions.push(recovered_session_metadata(
                    id,
                    &path,
                    &snapshot,
                    max_entries,
                    max_transaction_entries,
                ));
            }
            Err(error) => {
                warn!(
                    %error,
                    session_id = %id,
                    path = %path.display(),
                    "skipping unrecoverable session while rebuilding registry"
                );
            }
        }
    }

    if sessions.is_empty() {
        let default = default_session_metadata("Default session");
        persist_session_snapshot(root_dir, &default, &StoredSessionSnapshot::default())?;
        sessions.push(default);
    }

    sessions.sort_by_key(|session| std::cmp::Reverse(session.last_opened_at));
    Ok(SessionRegistrySnapshot {
        active_session_id: sessions[0].id,
        sessions,
        deleted_session_ids: deleted_ids
            .iter()
            .copied()
            .filter(|id| fs::symlink_metadata(session_dir(root_dir, *id)).is_ok())
            .collect(),
    })
}

fn recover_unregistered_session_dirs(
    root_dir: &Path,
    max_entries: usize,
    max_transaction_entries: usize,
    registry: &mut SessionRegistrySnapshot,
) -> Result<bool> {
    let mut known = registry
        .sessions
        .iter()
        .map(|session| session.id)
        .collect::<HashSet<_>>();
    let deleted = registry
        .deleted_session_ids
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    let mut recovered = false;
    for entry in fs::read_dir(root_dir)
        .with_context(|| format!("failed to read sessions directory {}", root_dir.display()))?
    {
        let entry = entry.with_context(|| {
            format!(
                "failed to read session directory entry in {}",
                root_dir.display()
            )
        })?;
        let path = entry.path();
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        let Ok(id) = Uuid::parse_str(name) else {
            continue;
        };
        if known.contains(&id) || deleted.contains(&id) {
            continue;
        }
        match load_session_snapshot(&path, max_entries, max_transaction_entries) {
            Ok(snapshot) => {
                registry.sessions.push(recovered_session_metadata(
                    id,
                    &path,
                    &snapshot,
                    max_entries,
                    max_transaction_entries,
                ));
                known.insert(id);
                recovered = true;
            }
            Err(error) => {
                warn!(
                    %error,
                    session_id = %id,
                    path = %path.display(),
                    "skipping unrecoverable unregistered session"
                );
            }
        }
    }
    if recovered {
        registry
            .sessions
            .sort_by_key(|session| std::cmp::Reverse(session.last_opened_at));
    }
    Ok(recovered)
}

fn recovered_session_metadata(
    id: Uuid,
    storage_dir: &Path,
    snapshot: &StoredSessionSnapshot,
    max_entries: usize,
    max_transaction_entries: usize,
) -> SessionMetadata {
    let fallback_time = Utc::now();
    let updated_at = fs::metadata(storage_dir)
        .and_then(|metadata| metadata.modified())
        .map(DateTime::<Utc>::from)
        .unwrap_or(fallback_time);
    let mut metadata = SessionMetadata {
        id,
        name: format!("Recovered session {}", &id.to_string()[..8]),
        created_at: updated_at,
        updated_at,
        last_opened_at: updated_at,
        request_count: 0,
        websocket_count: 0,
        event_count: 0,
        fuzzer_count: 0,
        rule_count: 0,
    };
    update_metadata_counts_from_snapshot(
        &mut metadata,
        snapshot,
        max_entries,
        max_transaction_entries,
    );
    metadata
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
        fuzzer_count: 0,
        rule_count: 0,
    }
}

fn normalize_session_name(name: Option<&str>, now: DateTime<Utc>) -> Result<String> {
    let normalized = name
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("Session {}", now.format("%Y-%m-%d %H:%M")));
    if normalized.len() > MAX_SESSION_NAME_BYTES {
        bail!("session name cannot exceed {MAX_SESSION_NAME_BYTES} bytes");
    }
    Ok(normalized)
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
        fuzzer_count: metadata.fuzzer_count,
        rule_count: metadata.rule_count,
        storage_path: storage_dir.display().to_string(),
        active,
    }
}

fn session_dir(root_dir: &Path, id: Uuid) -> PathBuf {
    root_dir.join(id.to_string())
}

fn deleted_session_dir(root_dir: &Path, id: Uuid) -> PathBuf {
    root_dir.join(format!(".deleted-{id}-{}", Uuid::new_v4()))
}

fn snapshot_path(storage_dir: &Path) -> PathBuf {
    storage_dir.join(SNAPSHOT_FILE)
}

fn workspace_path(storage_dir: &Path) -> PathBuf {
    storage_dir.join(WORKSPACE_FILE)
}

/// Reads the standalone workspace file. Returns `None` when it is absent — the
/// normal case for a session written before the split, and for a session that
/// has not been edited since — so the caller keeps the copy embedded in
/// snapshot.json as the fallback.
fn read_workspace_file(
    storage_dir: &Path,
    mode: SessionSnapshotLoadMode,
) -> Option<WorkspaceStateSnapshot> {
    let path = workspace_path(storage_dir);
    match fs::read(&path) {
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(workspace) => Some(workspace),
            Err(error) => {
                warn!(
                    ?error,
                    path = %path.display(),
                    "discarding corrupt workspace file"
                );
                if mode == SessionSnapshotLoadMode::Writable {
                    move_corrupt_session_file_aside(storage_dir, &path, "workspace");
                }
                None
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            warn!(
                ?error,
                path = %path.display(),
                "discarding unreadable workspace file"
            );
            if mode == SessionSnapshotLoadMode::Writable {
                move_corrupt_session_file_aside(storage_dir, &path, "workspace");
            }
            None
        }
    }
}

fn transaction_journal_path(storage_dir: &Path) -> PathBuf {
    storage_dir.join(TRANSACTION_JOURNAL_FILE)
}

fn websocket_journal_path(storage_dir: &Path) -> PathBuf {
    storage_dir.join(WEBSOCKET_JOURNAL_FILE)
}

fn session_storage_metadata(storage_dir: &Path) -> Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(storage_dir) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_symlink() || !file_type.is_dir() {
                return Err(anyhow!(
                    "failed to access session storage directory {}",
                    storage_dir.display()
                ));
            }
            Ok(Some(metadata))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to access session storage directory {}",
                storage_dir.display()
            )
        }),
    }
}

fn create_private_session_dir(storage_dir: &Path) -> Result<()> {
    if session_storage_metadata(storage_dir)?.is_none() {
        fs::create_dir_all(storage_dir).with_context(|| {
            format!(
                "failed to create session directory {}",
                storage_dir.display()
            )
        })?;
        session_storage_metadata(storage_dir)?;
    }
    tighten_private_dir(storage_dir).with_context(|| {
        format!(
            "failed to set private permissions on session directory {}",
            storage_dir.display()
        )
    })
}

fn ensure_existing_private_session_dir(storage_dir: &Path) -> Result<()> {
    match session_storage_metadata(storage_dir)? {
        Some(_) => tighten_private_dir(storage_dir).with_context(|| {
            format!(
                "failed to set private permissions on session directory {}",
                storage_dir.display()
            )
        }),
        None => Err(anyhow!(
            "session storage directory {} was not found",
            storage_dir.display()
        )),
    }
}

fn create_private_dir_all(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    tighten_private_dir(path)
}

#[cfg(unix)]
fn tighten_private_dir(path: &Path) -> io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn tighten_private_dir(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_private_file(path: &Path) -> io::Result<fs::File> {
    fs::File::create(path)
}

#[cfg(unix)]
fn open_private_append_file(path: &Path) -> io::Result<fs::File> {
    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    tighten_private_file(path)?;
    Ok(file)
}

#[cfg(not(unix))]
fn open_private_append_file(path: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new().create(true).append(true).open(path)
}

#[cfg(unix)]
fn tighten_private_file(path: &Path) -> io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn tighten_private_file(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn load_session_snapshot(
    storage_dir: &Path,
    max_entries: usize,
    max_transaction_entries: usize,
) -> Result<StoredSessionSnapshot> {
    load_session_snapshot_with_mode(
        storage_dir,
        max_entries,
        max_transaction_entries,
        SessionSnapshotLoadMode::Writable,
    )
}

fn load_session_snapshot_read_only(
    storage_dir: &Path,
    max_entries: usize,
    max_transaction_entries: usize,
) -> Result<StoredSessionSnapshot> {
    load_session_snapshot_with_mode(
        storage_dir,
        max_entries,
        max_transaction_entries,
        SessionSnapshotLoadMode::ReadOnly,
    )
}

fn load_session_snapshot_with_mode(
    storage_dir: &Path,
    max_entries: usize,
    max_transaction_entries: usize,
    mode: SessionSnapshotLoadMode,
) -> Result<StoredSessionSnapshot> {
    match mode {
        SessionSnapshotLoadMode::Writable => ensure_existing_private_session_dir(storage_dir)?,
        SessionSnapshotLoadMode::ReadOnly => {
            if session_storage_metadata(storage_dir)?.is_none() {
                bail!(
                    "session storage directory {} was not found",
                    storage_dir.display()
                );
            }
        }
    }
    let path = snapshot_path(storage_dir);
    let mut snapshot = match fs::read(&path) {
        Ok(bytes) => match serde_json::from_slice::<StoredSessionSnapshot>(&bytes) {
            Ok(snapshot) => Ok(snapshot),
            Err(error) => {
                warn!(
                    ?error,
                    path = %path.display(),
                    "discarding corrupt session snapshot"
                );
                if mode == SessionSnapshotLoadMode::Writable {
                    move_corrupt_session_file_aside(storage_dir, &path, "snapshot");
                }
                Ok(StoredSessionSnapshot::default())
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(StoredSessionSnapshot::default())
        }
        Err(error) if path.exists() => {
            warn!(
                ?error,
                path = %path.display(),
                "discarding unreadable session snapshot"
            );
            if mode == SessionSnapshotLoadMode::Writable {
                move_corrupt_session_file_aside(storage_dir, &path, "snapshot");
            }
            Ok(StoredSessionSnapshot::default())
        }
        Err(error) => Err(error)
            .with_context(|| format!("failed to read session snapshot {}", path.display())),
    }?;
    // Prefer the standalone workspace file, but never over a newer copy inside
    // snapshot.json. Revisions are monotonic per commit (see
    // WorkspaceStateStore::replace_snapshot_checked), and a build from before the
    // split writes the workspace only into snapshot.json — so after a downgrade
    // and back, the embedded copy can be the newer of the two.
    if let Some(workspace) = read_workspace_file(storage_dir, mode) {
        if workspace.revision >= snapshot.workspace.revision {
            snapshot.workspace = workspace;
        } else {
            warn!(
                workspace_revision = workspace.revision,
                snapshot_revision = snapshot.workspace.revision,
                "keeping the newer workspace embedded in the session snapshot"
            );
        }
    }
    snapshot.workspace.fuzzer.migrate_attack_record_to_id();
    if let Err(error) = validate_workspace_state(&snapshot.workspace) {
        warn!(
            ?error,
            path = %path.display(),
            "discarding invalid stored workspace state"
        );
        snapshot.workspace = WorkspaceStateSnapshot::default();
    }
    let replay_result = replay_transaction_journal(
        storage_dir,
        max_transaction_entries,
        &mut snapshot,
        mode == SessionSnapshotLoadMode::Writable,
    )?;
    snapshot.transaction_event_sequence = replay_result.transaction_event_sequence;
    snapshot.replayed_transaction_ids = replay_result.replayed_transaction_ids;
    snapshot.replayed_transaction_journal = replay_result.mutated_snapshot;
    let websocket_replay_result = replay_websocket_journal(
        storage_dir,
        max_entries,
        &mut snapshot,
        mode == SessionSnapshotLoadMode::Writable,
    )?;
    snapshot.replayed_websocket_journal = websocket_replay_result.mutated_snapshot;
    snapshot.compactable_websocket_journal = websocket_replay_result.can_compact;
    snapshot.unresolved_websocket_journal = websocket_replay_result.has_unresolved_delta;
    Ok(snapshot)
}

fn move_corrupt_session_file_aside(parent_dir: &Path, path: &Path, label: &str) {
    let corrupt_path = parent_dir.join(format!(".{label}.corrupt-{}.json", Uuid::new_v4()));
    if let Err(rename_error) = fs::rename(path, &corrupt_path) {
        warn!(
            ?rename_error,
            path = %path.display(),
            corrupt_path = %corrupt_path.display(),
            "failed to move corrupt session file aside"
        );
    }
}

fn replay_transaction_journal(
    storage_dir: &Path,
    max_entries: usize,
    snapshot: &mut StoredSessionSnapshot,
    repair_files: bool,
) -> Result<TransactionJournalReplayResult> {
    let journal_path = transaction_journal_path(storage_dir);
    let checkpoint_path = transaction_journal_checkpoint_path(&journal_path);
    let checkpoint_consumed = checkpoint_path.exists();

    normalize_snapshot_transaction_sequences(&mut snapshot.transactions);
    let mut order = Vec::with_capacity(snapshot.transactions.len());
    let mut records = HashMap::with_capacity(snapshot.transactions.len());
    let mut seen = HashSet::with_capacity(snapshot.transactions.len());
    for record in snapshot.transactions.drain(..) {
        if seen.insert(record.id) {
            order.push(record.id);
            records.insert(record.id, record);
        }
    }
    let mut replayed_transaction_ids = HashSet::new();
    let mut inserted_order = VecDeque::new();
    trim_transaction_replay_state(
        max_entries,
        &mut order,
        &mut inserted_order,
        &mut records,
        &mut replayed_transaction_ids,
    );
    let snapshot_record_ids = seen.clone();
    let mut backfill_order = VecDeque::new();
    let mut backfill_records = HashMap::new();
    let snapshot_fills_retention_window = max_entries > 0 && records.len() >= max_entries;
    let replay_insert_after_sequence = (snapshot_fills_retention_window && !records.is_empty())
        .then(|| {
            records
                .values()
                .map(|record| record.sequence)
                .max()
                .unwrap_or(0)
        });
    let mut transaction_event_sequence = snapshot.transaction_event_sequence.max(
        records
            .values()
            .map(|record| record.sequence)
            .max()
            .unwrap_or(0),
    );

    let mut annotation_mutated_record_ids = HashSet::new();
    annotation_mutated_record_ids.extend(replay_transaction_journal_file(
        &checkpoint_path,
        replay_insert_after_sequence,
        &mut order,
        &mut records,
        &mut seen,
        &mut replayed_transaction_ids,
        &mut backfill_order,
        &mut backfill_records,
        Some(&snapshot_record_ids),
        max_entries,
        repair_files,
        &mut transaction_event_sequence,
    )?);
    annotation_mutated_record_ids.extend(replay_transaction_journal_file(
        &journal_path,
        replay_insert_after_sequence,
        &mut order,
        &mut records,
        &mut seen,
        &mut replayed_transaction_ids,
        &mut backfill_order,
        &mut backfill_records,
        None,
        max_entries,
        repair_files,
        &mut transaction_event_sequence,
    )?);
    apply_transaction_journal_backfill(
        max_entries,
        &snapshot_record_ids,
        &mut order,
        &mut records,
        &mut replayed_transaction_ids,
        &mut backfill_order,
        &mut backfill_records,
    );

    snapshot.transactions = order
        .into_iter()
        .filter_map(|id| records.remove(&id))
        .take(max_entries)
        .collect();
    let retained_ids: HashSet<Uuid> = snapshot
        .transactions
        .iter()
        .map(|record| record.id)
        .collect();
    replayed_transaction_ids.retain(|id| retained_ids.contains(id));
    let mutated_snapshot = checkpoint_consumed
        || !replayed_transaction_ids.is_empty()
        || annotation_mutated_record_ids
            .iter()
            .any(|id| retained_ids.contains(id));
    Ok(TransactionJournalReplayResult {
        replayed_transaction_ids,
        mutated_snapshot,
        transaction_event_sequence,
    })
}

fn start_websocket_journal_writer(
    journal_path: PathBuf,
) -> Option<mpsc::Sender<WebSocketJournalCommand>> {
    let (tx, rx) = mpsc::channel::<WebSocketJournalCommand>();
    let (ready_tx, ready_rx) = mpsc::sync_channel::<io::Result<()>>(1);
    let spawn_result = thread::Builder::new()
        .name("sniper-websocket-journal".to_string())
        .spawn(move || {
            if let Some(parent) = journal_path.parent() {
                if let Err(error) = create_private_dir_all(parent) {
                    warn!(?error, path = %parent.display(), "failed to create websocket journal directory");
                    let _ = ready_tx.send(Err(error));
                    return;
                }
            }

            let mut file = match open_private_append_file(&journal_path) {
                Ok(file) => file,
                Err(error) => {
                    warn!(?error, path = %journal_path.display(), "failed to open websocket journal");
                    let _ = ready_tx.send(Err(error));
                    return;
                }
            };
            let _ = ready_tx.send(Ok(()));

            while let Ok(command) = rx.recv() {
                match command {
                    WebSocketJournalCommand::Append { line, ack } => {
                        let result = file
                            .write_all(&line)
                            .and_then(|()| file.flush())
                            .and_then(|()| file.sync_data());
                        let failed = result.is_err();
                        if let Err(error) = &result {
                            warn!(?error, path = %journal_path.display(), "failed to append websocket journal entry");
                        }
                        let _ = ack.send(result);
                        if failed {
                            return;
                        }
                    }
                    WebSocketJournalCommand::Clear { ack } => {
                        let result = file.set_len(0).and_then(|()| file.sync_all());
                        if let Err(error) = &result {
                            warn!(?error, path = %journal_path.display(), "failed to clear websocket journal");
                        }
                        let failed = result.is_err();
                        let _ = ack.send(result);
                        if failed {
                            return;
                        }
                    }
                }
            }
        });

    match spawn_result {
        Ok(_) => match ready_rx.recv() {
            Ok(Ok(())) => Some(tx),
            Ok(Err(_)) => None,
            Err(error) => {
                warn!(
                    ?error,
                    "websocket journal writer stopped before startup completed"
                );
                None
            }
        },
        Err(error) => {
            warn!(?error, "failed to spawn websocket journal writer");
            None
        }
    }
}

async fn append_websocket_journal(
    tx: &mpsc::Sender<WebSocketJournalCommand>,
    line: Vec<u8>,
) -> io::Result<()> {
    let (ack, rx) = oneshot::channel();
    tx.send(WebSocketJournalCommand::Append { line, ack })
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "websocket journal writer stopped",
            )
        })?;
    rx.await.map_err(|_| {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            "websocket journal writer stopped",
        )
    })?
}

fn clear_websocket_journal(tx: &mpsc::Sender<WebSocketJournalCommand>) -> io::Result<()> {
    let (ack, rx) = mpsc::channel();
    tx.send(WebSocketJournalCommand::Clear { ack })
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "websocket journal writer stopped",
            )
        })?;
    rx.recv().map_err(|_| {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            "websocket journal writer stopped",
        )
    })?
}

fn encode_websocket_journal_line(entry: &WebSocketJournalEntry) -> Result<Vec<u8>> {
    let mut line = serde_json::to_vec(entry).context("failed to encode websocket journal entry")?;
    line.push(b'\n');
    Ok(line)
}

fn replay_websocket_journal(
    storage_dir: &Path,
    max_entries: usize,
    snapshot: &mut StoredSessionSnapshot,
    repair_files: bool,
) -> Result<WebSocketJournalReplayResult> {
    let journal_path = websocket_journal_path(storage_dir);
    let file = match fs::File::open(&journal_path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(WebSocketJournalReplayResult::default());
        }
        Err(error) if journal_path.exists() => {
            warn!(
                ?error,
                path = %journal_path.display(),
                "discarding unreadable websocket journal"
            );
            if repair_files {
                move_unreadable_websocket_journal_aside(&journal_path);
            }
            return Ok(WebSocketJournalReplayResult::default());
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to read websocket journal {}",
                    journal_path.display()
                )
            })
        }
    };
    if file
        .metadata()
        .map(|metadata| metadata.is_dir())
        .unwrap_or(false)
    {
        warn!(
            path = %journal_path.display(),
            "discarding directory websocket journal"
        );
        if repair_files {
            move_unreadable_websocket_journal_aside(&journal_path);
        }
        return Ok(WebSocketJournalReplayResult::default());
    }

    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    let mut offset = 0u64;
    let mut valid_prefix_len = 0u64;
    let mut line_number = 0usize;
    let mut replay_result = WebSocketJournalReplayResult::default();
    loop {
        line.clear();
        let bytes = reader.read_until(b'\n', &mut line).with_context(|| {
            format!(
                "failed to read websocket journal {}",
                journal_path.display()
            )
        })?;
        if bytes == 0 {
            break;
        }
        let line_start_offset = offset;
        offset = offset.saturating_add(bytes as u64);
        line_number += 1;
        let line_has_newline = line.ends_with(b"\n");
        let trimmed = trim_ascii_whitespace(&line);
        if trimmed.is_empty() {
            if line_has_newline {
                valid_prefix_len = offset;
            }
            continue;
        }
        if !line_has_newline {
            warn!(
                path = %journal_path.display(),
                line = line_number,
                "ignoring trailing partial websocket journal line"
            );
            if repair_files {
                repair_corrupt_websocket_journal_tail(&journal_path, valid_prefix_len);
            }
            break;
        }
        let entry: WebSocketJournalEntry = match serde_json::from_slice(trimmed) {
            Ok(entry) => entry,
            Err(error) => {
                warn!(
                    ?error,
                    path = %journal_path.display(),
                    line = line_number,
                    "stopping websocket journal replay at corrupt line"
                );
                if repair_files {
                    repair_corrupt_websocket_journal_tail(&journal_path, line_start_offset);
                }
                break;
            }
        };
        match apply_websocket_journal_entry(&mut snapshot.websockets, entry) {
            WebSocketJournalApplyResult::Mutated => {
                replay_result.mutated_snapshot = true;
            }
            WebSocketJournalApplyResult::Noop => {}
            WebSocketJournalApplyResult::MissingParent => {
                replay_result.has_unresolved_delta = true;
                warn!(
                    path = %journal_path.display(),
                    line = line_number,
                    "preserving websocket journal line with missing parent session"
                );
            }
        }
        valid_prefix_len = offset;
    }
    replay_result.can_compact = valid_prefix_len > 0 && !replay_result.has_unresolved_delta;
    if replay_result.mutated_snapshot {
        snapshot.websockets = sessions_with_live_preserved(
            std::mem::take(&mut snapshot.websockets),
            max_entries,
            MAX_PERSISTED_WEBSOCKET_FRAMES_PER_SESSION,
        );
    }
    Ok(replay_result)
}

fn apply_websocket_journal_entry(
    records: &mut Vec<WebSocketSessionRecord>,
    entry: WebSocketJournalEntry,
) -> WebSocketJournalApplyResult {
    match entry {
        WebSocketJournalEntry::Open { record } => {
            if records.iter().any(|existing| existing.id == record.id) {
                return WebSocketJournalApplyResult::Noop;
            }
            records.insert(0, record);
            WebSocketJournalApplyResult::Mutated
        }
        WebSocketJournalEntry::Frame { id, frame } => {
            let Some(record) = records.iter_mut().find(|record| record.id == id) else {
                return WebSocketJournalApplyResult::MissingParent;
            };
            if record
                .frames
                .last()
                .is_some_and(|latest| frame.index <= latest.index)
            {
                return WebSocketJournalApplyResult::Noop;
            }
            if record
                .frames
                .iter()
                .any(|existing| existing.index == frame.index)
            {
                return WebSocketJournalApplyResult::Noop;
            }
            record.frames.push(frame);
            trim_frame_overflow(
                &mut record.frames,
                MAX_PERSISTED_WEBSOCKET_FRAMES_PER_SESSION,
            );
            WebSocketJournalApplyResult::Mutated
        }
        WebSocketJournalEntry::Close {
            id,
            closed_at,
            duration_ms,
            note,
        } => {
            let Some(record) = records.iter_mut().find(|record| record.id == id) else {
                return WebSocketJournalApplyResult::MissingParent;
            };
            let mut mutated =
                record.closed_at != Some(closed_at) || record.duration_ms != Some(duration_ms);
            record.closed_at = Some(closed_at);
            record.duration_ms = Some(duration_ms);
            if let Some(note) = note {
                if !record.notes.iter().any(|existing| existing == &note) {
                    record.notes.push(note);
                    mutated = true;
                }
            }
            if mutated {
                WebSocketJournalApplyResult::Mutated
            } else {
                WebSocketJournalApplyResult::Noop
            }
        }
    }
}

fn compact_replayed_websocket_journal(storage_dir: &Path) -> Result<()> {
    let journal_path = websocket_journal_path(storage_dir);
    match create_private_file(&journal_path) {
        Ok(file) => {
            file.sync_all()
                .with_context(|| format!("failed to sync {}", journal_path.display()))?;
            if let Some(parent) = journal_path.parent() {
                sync_directory(parent, "websocket journal directory")?;
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to compact websocket journal {}",
                journal_path.display()
            )
        }),
    }
}

fn repair_corrupt_websocket_journal_tail(journal_path: &Path, valid_prefix_len: u64) {
    preserve_corrupt_websocket_journal(journal_path);
    match fs::OpenOptions::new().write(true).open(journal_path) {
        Ok(file) => {
            if let Err(error) = file.set_len(valid_prefix_len).and_then(|_| file.sync_all()) {
                warn!(
                    ?error,
                    path = %journal_path.display(),
                    valid_prefix_len,
                    "failed to truncate corrupt websocket journal tail"
                );
                return;
            }
            if let Some(parent) = journal_path.parent() {
                if let Err(error) = sync_directory(parent, "websocket journal directory") {
                    warn!(
                        ?error,
                        path = %journal_path.display(),
                        "failed to sync repaired websocket journal directory"
                    );
                }
            }
        }
        Err(error) => warn!(
            ?error,
            path = %journal_path.display(),
            "failed to open corrupt websocket journal for repair"
        ),
    }
}

fn preserve_corrupt_websocket_journal(journal_path: &Path) {
    let Some(parent) = journal_path.parent() else {
        return;
    };
    let corrupt_path = parent.join(format!(".websockets.journal.corrupt-{}", Uuid::new_v4()));
    if let Err(error) = fs::copy(journal_path, &corrupt_path) {
        warn!(
            ?error,
            path = %journal_path.display(),
            corrupt_path = %corrupt_path.display(),
            "failed to preserve corrupt websocket journal"
        );
    }
}

fn move_unreadable_websocket_journal_aside(journal_path: &Path) {
    let parent = journal_path.parent().unwrap_or_else(|| Path::new("."));
    let corrupt_path = parent.join(format!(".websockets.journal.corrupt-{}", Uuid::new_v4()));
    if let Err(error) = fs::rename(journal_path, &corrupt_path) {
        warn!(
            ?error,
            source = %journal_path.display(),
            corrupt_path = %corrupt_path.display(),
            "failed to move unreadable websocket journal aside"
        );
    }
}

fn normalize_snapshot_transaction_sequences(records: &mut [TransactionRecord]) {
    records.reverse();
    normalize_storage_sequences(records);
    records.reverse();
}

fn replay_transaction_journal_file(
    journal_path: &Path,
    insert_after_sequence: Option<u64>,
    order: &mut Vec<Uuid>,
    records: &mut HashMap<Uuid, TransactionRecord>,
    seen: &mut HashSet<Uuid>,
    replayed_transaction_ids: &mut HashSet<Uuid>,
    backfill_order: &mut VecDeque<Uuid>,
    backfill_records: &mut HashMap<Uuid, TransactionRecord>,
    skip_annotations_for: Option<&HashSet<Uuid>>,
    max_entries: usize,
    repair_files: bool,
    transaction_event_sequence: &mut u64,
) -> Result<HashSet<Uuid>> {
    let file = match fs::File::open(journal_path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(HashSet::new()),
        Err(error) if journal_path.exists() => {
            warn!(
                ?error,
                path = %journal_path.display(),
                "discarding unreadable transaction journal"
            );
            if repair_files {
                move_unreadable_transaction_journal_aside(journal_path);
            }
            return Ok(HashSet::new());
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to read transaction journal {}",
                    journal_path.display()
                )
            })
        }
    };
    if file
        .metadata()
        .map(|metadata| metadata.is_dir())
        .unwrap_or(false)
    {
        warn!(
            path = %journal_path.display(),
            "discarding directory transaction journal"
        );
        if repair_files {
            move_unreadable_transaction_journal_aside(journal_path);
        }
        return Ok(HashSet::new());
    }

    let mut reader = BufReader::new(file);
    let mut inserted_order = VecDeque::new();
    let mut annotation_mutated_record_ids = HashSet::new();
    let mut line = Vec::new();
    let mut line_number = 0usize;
    let mut offset = 0u64;
    let mut valid_prefix_len = 0u64;
    loop {
        line.clear();
        let bytes = reader.read_until(b'\n', &mut line).with_context(|| {
            format!(
                "failed to read transaction journal {}",
                journal_path.display()
            )
        })?;
        if bytes == 0 {
            break;
        }
        let line_start_offset = offset;
        offset = offset.saturating_add(bytes as u64);
        line_number += 1;
        let line_has_newline = line.ends_with(b"\n");
        let trimmed = trim_ascii_whitespace(&line);
        if trimmed.is_empty() {
            if line_has_newline {
                valid_prefix_len = offset;
            }
            continue;
        }
        if !line_has_newline {
            warn!(
                path = %journal_path.display(),
                line = line_number,
                "ignoring trailing partial transaction journal line"
            );
            if repair_files {
                repair_corrupt_transaction_journal_tail(journal_path, valid_prefix_len);
            }
            break;
        }
        let entry: TransactionJournalEntry = match serde_json::from_slice(trimmed) {
            Ok(entry) => entry,
            Err(error) => {
                warn!(
                    ?error,
                    path = %journal_path.display(),
                    line = line_number,
                    "stopping transaction journal replay at corrupt line"
                );
                if repair_files {
                    repair_corrupt_transaction_journal_tail(journal_path, line_start_offset);
                }
                break;
            }
        };
        *transaction_event_sequence = transaction_event_sequence.saturating_add(1);
        match entry {
            TransactionJournalEntry::Insert { record } => {
                if insert_after_sequence.is_some_and(|sequence| record.sequence <= sequence) {
                    if seen.insert(record.id) {
                        backfill_order.push_back(record.id);
                        backfill_records.insert(record.id, record);
                    }
                    continue;
                }
                if seen.insert(record.id) {
                    replayed_transaction_ids.insert(record.id);
                    inserted_order.push_back(record.id);
                    records.insert(record.id, record);
                    trim_transaction_replay_state(
                        max_entries,
                        order,
                        &mut inserted_order,
                        records,
                        replayed_transaction_ids,
                    );
                }
            }
            TransactionJournalEntry::Update { record } => {
                let id = record.id;
                if let Some(existing) = records.get_mut(&id) {
                    *existing = record;
                    annotation_mutated_record_ids.insert(id);
                } else if let Some(existing) = backfill_records.get_mut(&id) {
                    *existing = record;
                    annotation_mutated_record_ids.insert(id);
                }
            }
            TransactionJournalEntry::Annotation {
                id,
                color_tag,
                user_note,
                annotation_revision,
                previous_annotation_revision: _,
                annotation_client_id,
                annotation_client_version,
                previous_color_tag,
                previous_user_note,
            } => {
                if let Some(record) = records
                    .get_mut(&id)
                    .or_else(|| backfill_records.get_mut(&id))
                {
                    if annotation_client_version_is_stale(
                        record,
                        annotation_client_id.as_deref(),
                        annotation_client_version,
                    ) {
                        continue;
                    }
                    if skip_annotations_for.is_some_and(|ids| ids.contains(&id))
                        && !annotation_previous_values_match(
                            record,
                            previous_color_tag.as_ref(),
                            previous_user_note.as_ref(),
                        )
                    {
                        continue;
                    }
                    let has_annotation_patch = color_tag.is_some() || user_note.is_some();
                    apply_nullable_string_patch(&mut record.color_tag, color_tag);
                    apply_nullable_string_patch(&mut record.user_note, user_note);
                    if has_annotation_patch {
                        annotation_mutated_record_ids.insert(id);
                        record.annotation_revision = annotation_revision
                            .unwrap_or_else(|| record.annotation_revision.saturating_add(1).max(1));
                        if let (Some(client_id), Some(client_version)) =
                            (annotation_client_id, annotation_client_version)
                        {
                            if !client_id.is_empty() && client_version > 0 {
                                compact_annotation_client_versions_for_insert(
                                    &mut record.annotation_client_versions,
                                    &client_id,
                                );
                                record
                                    .annotation_client_versions
                                    .insert(client_id, client_version);
                            }
                        }
                    }
                }
            }
        }
        valid_prefix_len = offset;
    }
    if !inserted_order.is_empty() {
        let mut replayed_order = Vec::with_capacity(inserted_order.len() + order.len());
        replayed_order.extend(inserted_order.into_iter().rev());
        replayed_order.append(order);
        *order = replayed_order;
    }
    Ok(annotation_mutated_record_ids)
}

fn apply_transaction_journal_backfill(
    max_entries: usize,
    snapshot_record_ids: &HashSet<Uuid>,
    order: &mut Vec<Uuid>,
    records: &mut HashMap<Uuid, TransactionRecord>,
    replayed_transaction_ids: &mut HashSet<Uuid>,
    backfill_order: &mut VecDeque<Uuid>,
    backfill_records: &mut HashMap<Uuid, TransactionRecord>,
) {
    if max_entries == 0 || records.len() >= max_entries {
        return;
    }

    let mut replayed_backfill_order = Vec::new();
    while records.len() < max_entries {
        let Some(id) = backfill_order.pop_back() else {
            break;
        };
        let Some(record) = backfill_records.remove(&id) else {
            continue;
        };
        replayed_transaction_ids.insert(id);
        records.insert(id, record);
        replayed_backfill_order.push(id);
    }
    if replayed_backfill_order.is_empty() {
        return;
    }

    let snapshot_start = order
        .iter()
        .position(|id| snapshot_record_ids.contains(id))
        .unwrap_or(order.len());
    let mut replayed_order = Vec::with_capacity(order.len() + replayed_backfill_order.len());
    replayed_order.extend_from_slice(&order[..snapshot_start]);
    replayed_order.extend(replayed_backfill_order);
    replayed_order.extend_from_slice(&order[snapshot_start..]);
    *order = replayed_order;
}

fn trim_transaction_replay_state(
    max_entries: usize,
    order: &mut Vec<Uuid>,
    inserted_order: &mut VecDeque<Uuid>,
    records: &mut HashMap<Uuid, TransactionRecord>,
    replayed_transaction_ids: &mut HashSet<Uuid>,
) {
    while records.len() > max_entries {
        let evicted = order.pop().or_else(|| inserted_order.pop_front());
        let Some(evicted) = evicted else {
            break;
        };
        records.remove(&evicted);
        replayed_transaction_ids.remove(&evicted);
    }
}

fn trim_ascii_whitespace(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map(|index| index + 1)
        .unwrap_or(start);
    &bytes[start..end]
}

fn preserve_corrupt_transaction_journal(journal_path: &Path) {
    let Some(parent) = journal_path.parent() else {
        return;
    };
    let corrupt_path = parent.join(format!(".transactions.journal.corrupt-{}", Uuid::new_v4()));
    if let Err(error) = fs::copy(journal_path, &corrupt_path) {
        warn!(
            ?error,
            path = %journal_path.display(),
            corrupt_path = %corrupt_path.display(),
            "failed to preserve corrupt transaction journal"
        );
    }
}

fn repair_corrupt_transaction_journal_tail(journal_path: &Path, valid_prefix_len: u64) {
    preserve_corrupt_transaction_journal(journal_path);
    match fs::OpenOptions::new().write(true).open(journal_path) {
        Ok(file) => {
            if let Err(error) = file.set_len(valid_prefix_len).and_then(|_| file.sync_all()) {
                warn!(
                    ?error,
                    path = %journal_path.display(),
                    valid_prefix_len,
                    "failed to truncate corrupt transaction journal tail"
                );
                return;
            }
            if let Some(parent) = journal_path.parent() {
                if let Err(error) = sync_directory(parent, "transaction journal directory") {
                    warn!(
                        ?error,
                        path = %journal_path.display(),
                        "failed to sync repaired transaction journal directory"
                    );
                }
            }
        }
        Err(error) => warn!(
            ?error,
            path = %journal_path.display(),
            "failed to open corrupt transaction journal for repair"
        ),
    }
}

fn move_unreadable_transaction_journal_aside(journal_path: &Path) {
    let parent = journal_path.parent().unwrap_or_else(|| Path::new("."));
    let corrupt_path = parent.join(format!(".transactions.journal.corrupt-{}", Uuid::new_v4()));
    if let Err(error) = fs::rename(journal_path, &corrupt_path) {
        warn!(
            ?error,
            source = %journal_path.display(),
            corrupt_path = %corrupt_path.display(),
            "failed to move unreadable transaction journal aside"
        );
    }
}

fn annotation_previous_values_match(
    record: &TransactionRecord,
    previous_color_tag: Option<&NullableStringPatch>,
    previous_user_note: Option<&NullableStringPatch>,
) -> bool {
    let (Some(previous_color_tag), Some(previous_user_note)) =
        (previous_color_tag, previous_user_note)
    else {
        return false;
    };
    nullable_string_patch_matches(&record.color_tag, previous_color_tag)
        && nullable_string_patch_matches(&record.user_note, previous_user_note)
}

fn annotation_client_version_is_stale(
    record: &TransactionRecord,
    client_id: Option<&str>,
    client_version: Option<u64>,
) -> bool {
    let (Some(client_id), Some(client_version)) = (client_id, client_version) else {
        return false;
    };
    if client_id.is_empty() || client_version == 0 {
        return false;
    }
    record
        .annotation_client_versions
        .get(client_id)
        .is_some_and(|seen_version| client_version <= *seen_version)
}

fn nullable_string_patch_matches(value: &Option<String>, patch: &NullableStringPatch) -> bool {
    match patch {
        NullableStringPatch::Set(expected) => value.as_deref() == Some(expected.as_str()),
        NullableStringPatch::Clear => value.is_none(),
    }
}

fn apply_nullable_string_patch(target: &mut Option<String>, patch: Option<NullableStringPatch>) {
    match patch {
        Some(NullableStringPatch::Set(value)) => *target = Some(value),
        Some(NullableStringPatch::Clear) => *target = None,
        None => {}
    }
}

fn discard_transaction_journal_checkpoint(storage_dir: &Path) -> Result<()> {
    let checkpoint_path =
        transaction_journal_checkpoint_path(&transaction_journal_path(storage_dir));
    match fs::remove_file(&checkpoint_path) {
        Ok(()) => {
            if let Some(parent) = checkpoint_path.parent() {
                sync_directory(parent, "transaction journal checkpoint directory")?;
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to remove transaction journal checkpoint {}",
                checkpoint_path.display()
            )
        }),
    }
}

fn compact_replayed_transaction_journal(storage_dir: &Path) -> Result<()> {
    discard_transaction_journal_checkpoint(storage_dir)?;
    let journal_path = transaction_journal_path(storage_dir);
    match create_private_file(&journal_path) {
        Ok(file) => {
            file.sync_all()
                .with_context(|| format!("failed to sync {}", journal_path.display()))?;
            if let Some(parent) = journal_path.parent() {
                sync_directory(parent, "transaction journal directory")?;
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to compact transaction journal {}",
                journal_path.display()
            )
        }),
    }
}

fn persist_session_snapshot(
    root_dir: &Path,
    metadata: &SessionMetadata,
    snapshot: &StoredSessionSnapshot,
) -> Result<()> {
    let storage_dir = session_dir(root_dir, metadata.id);
    create_private_session_dir(&storage_dir)?;
    write_json(&snapshot_path(&storage_dir), snapshot)
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        create_private_dir_all(parent)
            .with_context(|| format!("failed to create parent directory {}", parent.display()))?;
    }
    let tmp_path = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let mut tmp_guard = TempJsonFile::new(tmp_path.clone());
    {
        let mut file = create_private_file(&tmp_path)
            .with_context(|| format!("failed to write {}", tmp_path.display()))?;
        {
            let mut writer = BufWriter::new(&mut file);
            serde_json::to_writer_pretty(&mut writer, value)
                .context("failed to serialize JSON file")?;
            writer
                .flush()
                .with_context(|| format!("failed to flush {}", tmp_path.display()))?;
        }
        file.sync_all()
            .with_context(|| format!("failed to sync {}", tmp_path.display()))?;
    }
    fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "failed to rename {} to {}",
            tmp_path.display(),
            path.display()
        )
    })?;
    tmp_guard.commit();
    tighten_private_file(path).with_context(|| {
        format!(
            "failed to set private permissions on session JSON {}",
            path.display()
        )
    })?;
    if let Some(parent) = path.parent() {
        sync_directory(parent, "session JSON directory")?;
    }
    Ok(())
}

struct TempJsonFile {
    path: PathBuf,
    committed: bool,
}

impl TempJsonFile {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            committed: false,
        }
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for TempJsonFile {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn sync_directory(path: &Path, label: &str) -> Result<()> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("failed to sync {label} {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet, VecDeque};

    use chrono::{Duration as ChronoDuration, Utc};
    use uuid::Uuid;

    use super::SessionRegistry;
    use crate::{
        match_replace::{MatchReplaceRule, MatchReplaceScope, MatchReplaceTarget},
        model::{
            BodyEncoding, EditableRequest, HeaderRecord, MessageRecord, TransactionRecord,
            WebSocketFrameDirection, WebSocketFrameKind, WebSocketFrameRecord,
            WebSocketSessionRecord,
        },
        oast::OastProvider,
        runtime::RuntimeSettingsUpdate,
        scanner::{CustomRule, ScannerConfig, ScannerFinding, Severity, BUILTIN_RULES},
        sequence::{ExtractionRule, ExtractionSource, SequenceDefinition, SequenceStep},
        store::{
            transaction_journal_checkpoint_path, NullableStringPatch, TransactionJournalEntry,
        },
        workspace::{
            FuzzerWorkspaceState, ReplayHistoryEntryState, ReplayTabState, ReplayWorkspaceState,
            WorkspaceStateSnapshot,
        },
        ws_replay::WsReplayFrame,
    };

    #[test]
    fn write_json_syncs_and_replaces_without_leaving_temp_files() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-write-json-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&data_dir).unwrap();
        let path = data_dir.join("snapshot.json");

        super::write_json(&path, &serde_json::json!({ "version": 1 })).unwrap();
        super::write_json(&path, &serde_json::json!({ "version": 2 })).unwrap();

        let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap())
            .expect("snapshot should be valid json");
        assert_eq!(saved["version"], 2);
        let temp_files = std::fs::read_dir(&data_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .count();
        assert_eq!(temp_files, 0);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn load_session_snapshot_migrates_legacy_workspace_fuzzer_attack_record() {
        let storage_dir = std::env::temp_dir().join(format!(
            "sniper-load-legacy-fuzzer-workspace-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&storage_dir).unwrap();
        let attack_id = Uuid::new_v4();
        super::write_json(
            &super::snapshot_path(&storage_dir),
            &serde_json::json!({
                "workspace": {
                    "fuzzer": {
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
                    }
                }
            }),
        )
        .unwrap();

        let loaded = super::load_session_snapshot(&storage_dir, 100, 100).unwrap();

        assert_eq!(loaded.workspace.fuzzer.attack_record_id, Some(attack_id));
        assert!(loaded.workspace.fuzzer.attack_record.is_none());

        let _ = std::fs::remove_dir_all(storage_dir);
    }

    #[test]
    fn load_session_snapshot_discards_oversized_workspace_only() {
        let storage_dir = std::env::temp_dir().join(format!(
            "sniper-load-oversized-workspace-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&storage_dir).unwrap();
        let request = MessageRecord {
            headers: vec![HeaderRecord {
                name: "Host".to_string(),
                value: "example.test".to_string(),
            }],
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };
        let transaction = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "example.test".to_string(),
            "/kept".to_string(),
            Some(200),
            1,
            request,
            None,
            Vec::new(),
            None,
            None,
        );
        let snapshot = super::StoredSessionSnapshot {
            transactions: vec![transaction.clone()],
            workspace: WorkspaceStateSnapshot {
                fuzzer: FuzzerWorkspaceState {
                    target_request_authority: Some(
                        "x".repeat(crate::workspace::MAX_WORKSPACE_SERIALIZED_BYTES),
                    ),
                    ..FuzzerWorkspaceState::default()
                },
                ..WorkspaceStateSnapshot::default()
            },
            ..super::StoredSessionSnapshot::default()
        };
        super::write_json(&super::snapshot_path(&storage_dir), &snapshot).unwrap();

        let loaded = super::load_session_snapshot(&storage_dir, 100, 100).unwrap();

        assert_eq!(loaded.transactions.len(), 1);
        assert_eq!(loaded.transactions[0].id, transaction.id);
        assert!(loaded.workspace.fuzzer.target_request_authority.is_none());

        let _ = std::fs::remove_dir_all(storage_dir);
    }

    #[test]
    fn transaction_journal_replay_bytes_counts_the_checkpoint_too() {
        let data_dir = std::env::temp_dir()
            .join(format!("sniper-journal-replay-bytes-{}", uuid::Uuid::new_v4()));
        let (_registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
        let journal = super::transaction_journal_path(active.storage_dir());
        let checkpoint = transaction_journal_checkpoint_path(&journal);

        // Both files are replayed on load, so both count toward the compaction
        // threshold — a checkpoint holds rotated entries until a snapshot write
        // discards it, so counting only the active file understates the load cost.
        std::fs::write(&journal, vec![b'a'; 300]).unwrap();
        assert_eq!(active.transaction_journal_replay_bytes(), 300);
        std::fs::write(&checkpoint, vec![b'b'; 45]).unwrap();
        assert_eq!(active.transaction_journal_replay_bytes(), 345);
        std::fs::remove_file(&journal).unwrap();
        assert_eq!(active.transaction_journal_replay_bytes(), 45);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn load_session_snapshot_prefers_the_workspace_file_but_not_over_a_newer_snapshot_copy() {
        for (workspace_file_revision, snapshot_revision, expected_tab) in [
            (7u64, 3u64, "from-workspace-file"),
            (7, 7, "from-workspace-file"),
            // An older build writes the workspace only into snapshot.json, so
            // after a downgrade and back the embedded copy can be the newer one.
            (3, 7, "from-snapshot-copy"),
        ] {
            let storage_dir = std::env::temp_dir()
                .join(format!("sniper-workspace-precedence-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&storage_dir).unwrap();
            let tab = |id: &str| {
                serde_json::json!({
                    "replay": { "tabs": [{ "id": id, "sequence": 1 }], "active_tab_id": id }
                })
            };

            let mut snapshot_workspace = tab("from-snapshot-copy");
            snapshot_workspace["revision"] = snapshot_revision.into();
            super::write_json(
                &super::snapshot_path(&storage_dir),
                &serde_json::json!({ "workspace": snapshot_workspace }),
            )
            .unwrap();

            let mut file_workspace = tab("from-workspace-file");
            file_workspace["revision"] = workspace_file_revision.into();
            super::write_json(&super::workspace_path(&storage_dir), &file_workspace).unwrap();

            let loaded = super::load_session_snapshot(&storage_dir, 32, 32).unwrap();
            assert_eq!(
                loaded.workspace.replay.active_tab_id.as_deref(),
                Some(expected_tab),
                "workspace file revision {workspace_file_revision} vs snapshot revision {snapshot_revision}"
            );

            let _ = std::fs::remove_dir_all(storage_dir);
        }
    }

    #[test]
    fn load_session_snapshot_discards_malformed_workspace_only() {
        let storage_dir = std::env::temp_dir().join(format!(
            "sniper-load-malformed-workspace-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&storage_dir).unwrap();
        let request = MessageRecord {
            headers: vec![HeaderRecord {
                name: "Host".to_string(),
                value: "example.test".to_string(),
            }],
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };
        let transaction = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "example.test".to_string(),
            "/kept".to_string(),
            Some(200),
            1,
            request,
            None,
            Vec::new(),
            None,
            None,
        );
        let transaction_id = transaction.id;
        super::write_json(
            &super::snapshot_path(&storage_dir),
            &serde_json::json!({
                "transactions": [transaction],
                "workspace": {
                    "replay": {
                        "tabs": [{
                            "type": "websocket",
                            "ws_selected_frame_index": -1
                        }]
                    }
                }
            }),
        )
        .unwrap();

        let loaded = super::load_session_snapshot(&storage_dir, 100, 100).unwrap();

        assert_eq!(loaded.transactions.len(), 1);
        assert_eq!(loaded.transactions[0].id, transaction_id);
        assert!(loaded.workspace.replay.tabs.is_empty());
        assert!(super::snapshot_path(&storage_dir).exists());

        let _ = std::fs::remove_dir_all(storage_dir);
    }

    #[test]
    fn load_session_snapshot_discards_semantically_invalid_workspace_only() {
        let storage_dir = std::env::temp_dir().join(format!(
            "sniper-load-invalid-workspace-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&storage_dir).unwrap();
        let request = MessageRecord {
            headers: vec![HeaderRecord {
                name: "Host".to_string(),
                value: "example.test".to_string(),
            }],
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };
        let transaction = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "example.test".to_string(),
            "/kept".to_string(),
            Some(200),
            1,
            request,
            None,
            Vec::new(),
            None,
            None,
        );
        let transaction_id = transaction.id;
        let snapshot = super::StoredSessionSnapshot {
            transactions: vec![transaction],
            workspace: WorkspaceStateSnapshot {
                replay: ReplayWorkspaceState {
                    active_tab_id: Some("bad-tab".to_string()),
                    tabs: vec![ReplayTabState {
                        id: "bad-tab".to_string(),
                        sequence: 1,
                        base_request: Some(EditableRequest {
                            scheme: "https".to_string(),
                            host: " bad.example".to_string(),
                            method: "GET".to_string(),
                            path: "/".to_string(),
                            headers: Vec::new(),
                            body: String::new(),
                            body_encoding: BodyEncoding::Utf8,
                            preview_truncated: false,
                        }),
                        ..ReplayTabState::default()
                    }],
                    ..ReplayWorkspaceState::default()
                },
                ..WorkspaceStateSnapshot::default()
            },
            ..super::StoredSessionSnapshot::default()
        };
        super::write_json(&super::snapshot_path(&storage_dir), &snapshot).unwrap();

        let loaded = super::load_session_snapshot(&storage_dir, 100, 100).unwrap();

        assert_eq!(loaded.transactions.len(), 1);
        assert_eq!(loaded.transactions[0].id, transaction_id);
        assert!(loaded.workspace.replay.tabs.is_empty());
        assert!(loaded.workspace.replay.active_tab_id.is_none());
        assert!(super::snapshot_path(&storage_dir).exists());

        let _ = std::fs::remove_dir_all(storage_dir);
    }

    #[test]
    fn restored_open_websockets_are_marked_closed_after_restart() {
        let started_at = Utc::now() - ChronoDuration::seconds(5);
        let mut records = vec![WebSocketSessionRecord {
            id: Uuid::new_v4(),
            sequence: 0,
            started_at,
            closed_at: None,
            duration_ms: None,
            scheme: "wss".to_string(),
            host: "example.test".to_string(),
            path: "/ws".to_string(),
            status: Some(101),
            request: MessageRecord::from_headers_and_body(&http::HeaderMap::new(), &[], 1024),
            response: None,
            frames: Vec::new(),
            notes: Vec::new(),
        }];
        assert!(super::close_restored_open_websockets(&mut records));

        let restored = &records[0];
        assert!(restored.closed_at.is_some());
        assert!(restored.duration_ms.unwrap_or_default() >= 5_000);
        assert!(restored
            .notes
            .iter()
            .any(|note| note.contains("restarted before this WebSocket session was closed")));
    }

    #[tokio::test]
    async fn load_context_persists_restored_websocket_close_marker() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-websocket-close-repair-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
        let storage_dir = registry.session_storage_path(active.id()).unwrap();
        let websocket_id = Uuid::new_v4();
        let snapshot = super::StoredSessionSnapshot {
            websockets: vec![WebSocketSessionRecord {
                id: websocket_id,
                sequence: 0,
                started_at: Utc::now() - ChronoDuration::seconds(5),
                closed_at: None,
                duration_ms: None,
                scheme: "wss".to_string(),
                host: "example.test".to_string(),
                path: "/ws".to_string(),
                status: Some(101),
                request: MessageRecord::from_headers_and_body(&http::HeaderMap::new(), &[], 1024),
                response: None,
                frames: Vec::new(),
                notes: Vec::new(),
            }],
            ..Default::default()
        };
        super::write_json(&super::snapshot_path(&storage_dir), &snapshot).unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.websockets.get(websocket_id).await.unwrap();
        assert!(restored.closed_at.is_some());

        let disk_snapshot: super::StoredSessionSnapshot =
            serde_json::from_slice(&std::fs::read(super::snapshot_path(&storage_dir)).unwrap())
                .unwrap();
        assert!(disk_snapshot.websockets[0].closed_at.is_some());
        assert_eq!(disk_snapshot.websockets[0].notes.len(), 1);

        let reloaded = registry.load_context(active.id()).unwrap();
        let restored_again = reloaded.websockets.get(websocket_id).await.unwrap();
        assert_eq!(restored_again.notes.len(), 1);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn load_context_recovers_websocket_capture_from_journal() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-websocket-journal-recovery-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
        let storage_dir = registry.session_storage_path(active.id()).unwrap();
        let websocket_id = Uuid::new_v4();

        active
            .open_websocket_capture(WebSocketSessionRecord {
                id: websocket_id,
                sequence: 0,
                started_at: Utc::now() - ChronoDuration::seconds(1),
                closed_at: None,
                duration_ms: None,
                scheme: "wss".to_string(),
                host: "journal-ws.example.test".to_string(),
                path: "/socket".to_string(),
                status: Some(101),
                request: MessageRecord::from_headers_and_body(&http::HeaderMap::new(), &[], 1024),
                response: None,
                frames: Vec::new(),
                notes: Vec::new(),
            })
            .await
            .unwrap();
        active
            .append_websocket_capture_frame(
                websocket_id,
                WebSocketFrameRecord {
                    index: 0,
                    captured_at: Utc::now(),
                    direction: WebSocketFrameDirection::ClientToServer,
                    kind: WebSocketFrameKind::Text,
                    body_preview: "hello".to_string(),
                    body_encoding: BodyEncoding::Utf8,
                    body_size: 5,
                    preview_truncated: false,
                },
            )
            .await
            .unwrap();

        let journal_path = super::websocket_journal_path(&storage_dir);
        assert!(std::fs::metadata(&journal_path).unwrap().len() > 0);

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.websockets.get(websocket_id).await.unwrap();

        assert_eq!(restored.host, "journal-ws.example.test");
        assert_eq!(restored.frames.len(), 1);
        assert_eq!(restored.frames[0].body_preview, "hello");
        assert!(restored.closed_at.is_some());
        assert!(restored
            .notes
            .iter()
            .any(|note| note.contains("restarted before this WebSocket session was closed")));
        assert_eq!(std::fs::metadata(&journal_path).unwrap().len(), 0);

        let disk_snapshot: super::StoredSessionSnapshot =
            serde_json::from_slice(&std::fs::read(super::snapshot_path(&storage_dir)).unwrap())
                .unwrap();
        assert_eq!(disk_snapshot.websockets.len(), 1);
        assert_eq!(disk_snapshot.websockets[0].frames.len(), 1);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn websocket_capture_does_not_journal_missing_parent_deltas() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-websocket-orphan-write-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
        let storage_dir = registry.session_storage_path(active.id()).unwrap();
        let websocket_id = Uuid::new_v4();

        let appended = active
            .append_websocket_capture_frame(
                websocket_id,
                WebSocketFrameRecord {
                    index: 0,
                    captured_at: Utc::now(),
                    direction: WebSocketFrameDirection::ClientToServer,
                    kind: WebSocketFrameKind::Text,
                    body_preview: "late".to_string(),
                    body_encoding: BodyEncoding::Utf8,
                    body_size: 4,
                    preview_truncated: false,
                },
            )
            .await
            .unwrap();
        let closed = active
            .close_websocket_capture(websocket_id, Utc::now(), 1, Some("late close".to_string()))
            .await
            .unwrap();

        assert!(!appended);
        assert!(!closed);
        let journal_path = super::websocket_journal_path(&storage_dir);
        let journal_len = std::fs::metadata(&journal_path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        assert_eq!(journal_len, 0);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn load_context_preserves_websocket_journal_with_missing_parent_delta() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-websocket-orphan-replay-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
        let storage_dir = registry.session_storage_path(active.id()).unwrap();
        let websocket_id = Uuid::new_v4();
        let journal = super::encode_websocket_journal_line(&super::WebSocketJournalEntry::Frame {
            id: websocket_id,
            frame: WebSocketFrameRecord {
                index: 0,
                captured_at: Utc::now(),
                direction: WebSocketFrameDirection::ServerToClient,
                kind: WebSocketFrameKind::Text,
                body_preview: "orphan".to_string(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 6,
                preview_truncated: false,
            },
        })
        .unwrap();
        let journal_path = super::websocket_journal_path(&storage_dir);
        std::fs::write(&journal_path, &journal).unwrap();

        let loaded = registry.load_context(active.id()).unwrap();

        assert!(loaded.websockets.get(websocket_id).await.is_none());
        assert_eq!(std::fs::read(&journal_path).unwrap(), journal);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn load_context_repairs_websocket_count_with_preserved_orphan_journal() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-websocket-mixed-orphan-replay-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
        let storage_dir = registry.session_storage_path(active.id()).unwrap();
        let websocket_id = Uuid::new_v4();
        let orphan_id = Uuid::new_v4();
        let open = super::encode_websocket_journal_line(&super::WebSocketJournalEntry::Open {
            record: WebSocketSessionRecord {
                id: websocket_id,
                sequence: 0,
                started_at: Utc::now() - ChronoDuration::seconds(1),
                closed_at: None,
                duration_ms: None,
                scheme: "wss".to_string(),
                host: "valid.example.test".to_string(),
                path: "/socket".to_string(),
                status: Some(101),
                request: MessageRecord::from_headers_and_body(&http::HeaderMap::new(), &[], 1024),
                response: None,
                frames: Vec::new(),
                notes: Vec::new(),
            },
        })
        .unwrap();
        let orphan = super::encode_websocket_journal_line(&super::WebSocketJournalEntry::Frame {
            id: orphan_id,
            frame: WebSocketFrameRecord {
                index: 0,
                captured_at: Utc::now(),
                direction: WebSocketFrameDirection::ServerToClient,
                kind: WebSocketFrameKind::Text,
                body_preview: "orphan".to_string(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 6,
                preview_truncated: false,
            },
        })
        .unwrap();
        let journal_path = super::websocket_journal_path(&storage_dir);
        let mut journal = open.clone();
        journal.extend_from_slice(&orphan);
        std::fs::write(&journal_path, &journal).unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.websockets.get(websocket_id).await.unwrap();
        assert_eq!(restored.host, "valid.example.test");
        assert_eq!(std::fs::read(&journal_path).unwrap(), journal);
        let summary = registry
            .summaries()
            .into_iter()
            .find(|summary| summary.id == active.id())
            .unwrap();
        assert_eq!(summary.websocket_count, 1);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn load_context_read_only_does_not_create_transaction_journal() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-read-only-no-journal-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, _active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
        let inactive = registry
            .create_session(Some("Inactive".to_string()))
            .unwrap();
        let storage_dir = super::session_dir(&data_dir.join(super::SESSIONS_DIR), inactive.id);
        let journal_path = super::transaction_journal_path(&storage_dir);
        assert!(!journal_path.exists());

        let loaded = registry.load_context_read_only(inactive.id).unwrap();

        assert_eq!(loaded.id(), inactive.id);
        assert!(!journal_path.exists());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn load_context_read_only_does_not_repair_corrupt_session_files() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-read-only-no-repair-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, _active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
        let inactive = registry
            .create_session(Some("Inactive".to_string()))
            .unwrap();
        let storage_dir = super::session_dir(&data_dir.join(super::SESSIONS_DIR), inactive.id);
        let snapshot_path = super::snapshot_path(&storage_dir);
        let journal_path = super::transaction_journal_path(&storage_dir);
        let corrupt_snapshot = b"{not-json";
        let corrupt_journal = b"{\"type\":\"insert\"}\n{not-json}\n";
        std::fs::write(&snapshot_path, corrupt_snapshot).unwrap();
        std::fs::write(&journal_path, corrupt_journal).unwrap();

        let loaded = registry.load_context_read_only(inactive.id).unwrap();

        assert_eq!(loaded.id(), inactive.id);
        assert_eq!(std::fs::read(&snapshot_path).unwrap(), corrupt_snapshot);
        assert_eq!(std::fs::read(&journal_path).unwrap(), corrupt_journal);
        let has_repair_artifact = std::fs::read_dir(&storage_dir).unwrap().any(|entry| {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            name.starts_with(".snapshot.corrupt-")
                || name.starts_with(".transactions.journal.corrupt-")
        });
        assert!(!has_repair_artifact);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn session_persist_caps_websocket_frames_to_tail_window() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-websocket-persist-cap-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 2_000).unwrap();
        let websocket_id = Uuid::new_v4();
        let total_frames = super::MAX_PERSISTED_WEBSOCKET_FRAMES_PER_SESSION + 507;
        let frames = (0..total_frames)
            .map(|index| WebSocketFrameRecord {
                index,
                captured_at: Utc::now(),
                direction: WebSocketFrameDirection::ClientToServer,
                kind: WebSocketFrameKind::Binary,
                body_preview: "AAECAwQFBgcICQ==".to_string(),
                body_encoding: BodyEncoding::Base64,
                body_size: 10,
                preview_truncated: false,
            })
            .collect::<Vec<_>>();

        active
            .websockets
            .open(WebSocketSessionRecord {
                id: websocket_id,
                sequence: 0,
                started_at: Utc::now(),
                closed_at: Some(Utc::now()),
                duration_ms: Some(1),
                scheme: "wss".to_string(),
                host: "socket.example.test".to_string(),
                path: "/stream".to_string(),
                status: Some(101),
                request: MessageRecord::from_headers_and_body(&http::HeaderMap::new(), &[], 1024),
                response: None,
                frames,
                notes: Vec::new(),
            })
            .await;
        assert_eq!(
            active
                .websockets
                .get(websocket_id)
                .await
                .unwrap()
                .frames
                .len(),
            total_frames
        );

        active.persist().await.unwrap();
        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.websockets.get(websocket_id).await.unwrap();

        assert_eq!(
            restored.frames.len(),
            super::MAX_PERSISTED_WEBSOCKET_FRAMES_PER_SESSION
        );
        assert_eq!(
            restored.frames[0].index,
            total_frames - super::MAX_PERSISTED_WEBSOCKET_FRAMES_PER_SESSION
        );
        assert_eq!(restored.frames.last().unwrap().index, total_frames - 1);
        let summary = restored.summary();
        assert_eq!(summary.frame_count, total_frames);
        assert_eq!(
            summary.retained_frame_count,
            super::MAX_PERSISTED_WEBSOCKET_FRAMES_PER_SESSION
        );

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn websocket_journal_replay_keeps_capped_snapshot_tail_order() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-websocket-journal-tail-order-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 2_000).unwrap();
        let storage_dir = registry.session_storage_path(active.id()).unwrap();
        let websocket_id = Uuid::new_v4();
        let total_frames = super::MAX_PERSISTED_WEBSOCKET_FRAMES_PER_SESSION + 507;
        let frames = (0..total_frames)
            .map(|index| WebSocketFrameRecord {
                index,
                captured_at: Utc::now(),
                direction: WebSocketFrameDirection::ClientToServer,
                kind: WebSocketFrameKind::Binary,
                body_preview: "AAECAwQFBgcICQ==".to_string(),
                body_encoding: BodyEncoding::Base64,
                body_size: 10,
                preview_truncated: false,
            })
            .collect::<Vec<_>>();
        let tail_start = total_frames - super::MAX_PERSISTED_WEBSOCKET_FRAMES_PER_SESSION;
        let snapshot_record = WebSocketSessionRecord {
            id: websocket_id,
            sequence: 0,
            started_at: Utc::now(),
            closed_at: Some(Utc::now()),
            duration_ms: Some(1),
            scheme: "wss".to_string(),
            host: "socket.example.test".to_string(),
            path: "/stream".to_string(),
            status: Some(101),
            request: MessageRecord::from_headers_and_body(&http::HeaderMap::new(), &[], 1024),
            response: None,
            frames: frames[tail_start..].to_vec(),
            notes: Vec::new(),
        };
        super::write_json(
            &super::snapshot_path(&storage_dir),
            &super::StoredSessionSnapshot {
                websockets: vec![snapshot_record.clone()],
                ..Default::default()
            },
        )
        .unwrap();

        let mut journal =
            super::encode_websocket_journal_line(&super::WebSocketJournalEntry::Open {
                record: WebSocketSessionRecord {
                    frames: Vec::new(),
                    ..snapshot_record
                },
            })
            .unwrap();
        for frame in frames {
            journal.extend(
                super::encode_websocket_journal_line(&super::WebSocketJournalEntry::Frame {
                    id: websocket_id,
                    frame,
                })
                .unwrap(),
            );
        }
        std::fs::write(super::websocket_journal_path(&storage_dir), journal).unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.websockets.get(websocket_id).await.unwrap();

        assert_eq!(
            restored.frames.len(),
            super::MAX_PERSISTED_WEBSOCKET_FRAMES_PER_SESSION
        );
        assert_eq!(restored.frames[0].index, tail_start);
        assert_eq!(restored.frames.last().unwrap().index, total_frames - 1);
        assert!(restored
            .frames
            .windows(2)
            .all(|frames| frames[0].index < frames[1].index));
        assert_eq!(
            std::fs::metadata(super::websocket_journal_path(&storage_dir))
                .unwrap()
                .len(),
            0
        );

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[cfg(unix)]
    #[test]
    fn write_json_creates_private_file_and_parent_directory() {
        use std::os::unix::fs::PermissionsExt as _;

        let data_dir = std::env::temp_dir()
            .join(format!(
                "sniper-write-json-private-{}",
                uuid::Uuid::new_v4()
            ))
            .join("session");
        let path = data_dir.join("snapshot.json");

        super::write_json(&path, &serde_json::json!({ "version": 1 })).unwrap();

        let dir_mode = std::fs::metadata(&data_dir).unwrap().permissions().mode() & 0o777;
        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert_eq!(file_mode, 0o600);

        let _ = std::fs::remove_dir_all(data_dir.parent().unwrap());
    }

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
    async fn registry_rejects_oversized_session_names() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-session-name-cap-{}", uuid::Uuid::new_v4()));
        let (registry, _active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();

        let error = registry
            .create_session(Some("x".repeat(super::MAX_SESSION_NAME_BYTES + 1)))
            .unwrap_err();
        assert!(error.to_string().contains("session name"));

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn workspace_only_persist_keeps_transaction_journal_active() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-workspace-only-{}", uuid::Uuid::new_v4()));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
        let record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "journal.example:443".to_string(),
            "/kept-in-journal".to_string(),
            Some(200),
            1,
            MessageRecord {
                headers: vec![],
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            },
            None,
            vec![],
            None,
            None,
        );
        let record_id = record.id;
        active.store.insert(record).await;

        let journal_path = super::transaction_journal_path(active.storage_dir());
        let checkpoint_path = transaction_journal_checkpoint_path(&journal_path);
        assert!(std::fs::metadata(&journal_path).unwrap().len() > 0);
        assert!(!checkpoint_path.exists());

        let mut workspace = active.workspace.snapshot().await;
        workspace.client_id = Some("test-ui".to_string());
        workspace.client_version = 1;
        workspace.replay = ReplayWorkspaceState {
            active_tab_id: Some("workspace-only-tab".to_string()),
            tabs: vec![ReplayTabState {
                id: "workspace-only-tab".to_string(),
                sequence: 1,
                ..ReplayTabState::default()
            }],
            ..ReplayWorkspaceState::default()
        };

        let (committed, fallback_metadata) = active
            .replace_workspace_snapshot_checked_and_persist(workspace)
            .await
            .unwrap();

        assert!(fallback_metadata.is_none());
        assert_eq!(
            committed.replay.active_tab_id.as_deref(),
            Some("workspace-only-tab")
        );
        assert!(!checkpoint_path.exists());
        assert!(std::fs::metadata(&journal_path).unwrap().len() > 0);

        let loaded = registry.load_context(active.id()).unwrap();
        let durable_workspace = loaded.workspace.snapshot().await;
        assert_eq!(
            durable_workspace.replay.active_tab_id.as_deref(),
            Some("workspace-only-tab")
        );
        let records = loaded.store.snapshot(Some(10)).await;
        assert!(records.iter().any(|restored| restored.id == record_id));

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn workspace_only_persist_recovers_snapshot_directory_path() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-workspace-snapshot-directory-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
        let snapshot_path = super::snapshot_path(active.storage_dir());
        std::fs::remove_file(&snapshot_path).unwrap();
        std::fs::create_dir(&snapshot_path).expect("snapshot directory should be created");

        let mut workspace = active.workspace.snapshot().await;
        workspace.client_id = Some("test-ui".to_string());
        workspace.client_version = 1;
        workspace.replay = ReplayWorkspaceState {
            active_tab_id: Some("recovered-workspace-tab".to_string()),
            tabs: vec![ReplayTabState {
                id: "recovered-workspace-tab".to_string(),
                sequence: 1,
                ..ReplayTabState::default()
            }],
            ..ReplayWorkspaceState::default()
        };

        let (committed, fallback_metadata) = active
            .replace_workspace_snapshot_checked_and_persist(workspace)
            .await
            .unwrap();

        // The workspace now has its own file, so saving it neither reads nor
        // rewrites snapshot.json: an unusable snapshot.json no longer forces a
        // full-session persist, and no longer blocks the save at all.
        assert!(fallback_metadata.is_none());
        assert_eq!(
            committed.replay.active_tab_id.as_deref(),
            Some("recovered-workspace-tab")
        );
        assert!(super::workspace_path(active.storage_dir()).is_file());
        assert!(snapshot_path.is_dir(), "the workspace save must not touch snapshot.json");

        // The unusable snapshot.json is cleared out of the way on the next load
        // instead, and the workspace still restores — from its own file.
        let loaded = registry.load_context(active.id()).unwrap();
        assert!(
            !snapshot_path.is_dir(),
            "loading must move the unusable snapshot.json aside"
        );
        let has_corrupt_backup = std::fs::read_dir(active.storage_dir())
            .unwrap()
            .any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".snapshot.corrupt-")
            });
        assert!(has_corrupt_backup);

        let durable_workspace = loaded.workspace.snapshot().await;
        assert_eq!(
            durable_workspace.replay.active_tab_id.as_deref(),
            Some("recovered-workspace-tab")
        );

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn registry_delete_session_preserves_metadata_when_storage_delete_fails() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-delete-failure-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, _active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
        let created = registry
            .create_session(Some("delete me".to_string()))
            .unwrap();
        let storage_path = registry.session_storage_path(created.id).unwrap();

        std::fs::remove_dir_all(&storage_path).unwrap();
        std::fs::write(&storage_path, b"not a directory").unwrap();

        let error = registry
            .delete_session(created.id)
            .expect_err("file in place of session dir should fail deletion");

        assert!(error.to_string().contains("session storage directory"));
        assert!(registry.contains_session(created.id));

        let _ = std::fs::remove_file(storage_path);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn quarantined_session_cleanup_failure_is_nonfatal() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-quarantine-cleanup-failure-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&data_dir).unwrap();
        let quarantine_path = data_dir.join(".deleted-session");
        std::fs::write(&quarantine_path, b"not a directory").unwrap();

        assert!(!super::remove_quarantined_session_storage(
            uuid::Uuid::new_v4(),
            &quarantine_path
        ));

        assert!(quarantine_path.is_file());
        let _ = std::fs::remove_file(quarantine_path);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn registry_normalization_removes_quarantined_tombstoned_storage() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-quarantine-normalize-{}",
            uuid::Uuid::new_v4()
        ));
        let root_dir = data_dir.join(super::SESSIONS_DIR);
        std::fs::create_dir_all(&root_dir).unwrap();
        let deleted_id = uuid::Uuid::new_v4();
        let quarantine_path =
            root_dir.join(format!(".deleted-{deleted_id}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&quarantine_path).unwrap();
        std::fs::write(quarantine_path.join("snapshot.json"), b"{}").unwrap();
        let mut snapshot = super::SessionRegistrySnapshot {
            active_session_id: uuid::Uuid::new_v4(),
            sessions: Vec::new(),
            deleted_session_ids: vec![deleted_id],
        };

        assert!(super::normalize_registry_snapshot(&root_dir, &mut snapshot));

        assert!(snapshot.deleted_session_ids.is_empty());
        assert!(!quarantine_path.exists());
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn registry_load_removes_crash_left_orphan_quarantined_storage() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-orphan-quarantine-load-{}",
            uuid::Uuid::new_v4()
        ));
        let root_dir = data_dir.join(super::SESSIONS_DIR);
        let active = super::default_session_metadata("Active");
        let orphan = super::default_session_metadata("Orphaned delete");
        super::persist_session_snapshot(
            &root_dir,
            &active,
            &super::StoredSessionSnapshot::default(),
        )
        .expect("active snapshot should be written");
        super::persist_session_snapshot(
            &root_dir,
            &orphan,
            &super::StoredSessionSnapshot::default(),
        )
        .expect("orphan snapshot should be written before quarantine");
        let orphan_storage = super::session_dir(&root_dir, orphan.id);
        let quarantine_path = super::deleted_session_dir(&root_dir, orphan.id);
        std::fs::rename(&orphan_storage, &quarantine_path)
            .expect("orphan session storage should be quarantined");
        super::write_json(
            &root_dir.join(super::REGISTRY_FILE),
            &serde_json::json!({
                "active_session_id": active.id,
                "sessions": [active.clone(), orphan.clone()]
            }),
        )
        .expect("pre-crash registry should be written");

        let (registry, loaded_active) = SessionRegistry::load_or_create(&data_dir, 32, 32)
            .expect("registry should repair orphaned quarantine");

        assert_eq!(loaded_active.id(), active.id);
        assert!(registry.contains_session(active.id));
        assert!(!registry.contains_session(orphan.id));
        assert!(!orphan_storage.exists());
        assert!(!quarantine_path.exists());

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn registry_tombstone_prevents_deleted_session_resurrection() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-delete-tombstone-test-{}",
            uuid::Uuid::new_v4()
        ));
        let root_dir = data_dir.join(super::SESSIONS_DIR);
        let active = super::default_session_metadata("Active");
        let deleted = super::default_session_metadata("Deleted");
        super::persist_session_snapshot(
            &root_dir,
            &active,
            &super::StoredSessionSnapshot::default(),
        )
        .expect("active snapshot should be written");
        super::persist_session_snapshot(
            &root_dir,
            &deleted,
            &super::StoredSessionSnapshot::default(),
        )
        .expect("deleted snapshot should be left behind");
        super::write_json(
            &root_dir.join(super::REGISTRY_FILE),
            &serde_json::json!({
                "active_session_id": active.id,
                "sessions": [active.clone()],
                "deleted_session_ids": [deleted.id]
            }),
        )
        .expect("registry with tombstone should be written");

        let (registry, loaded_active) = SessionRegistry::load_or_create(&data_dir, 32, 32)
            .expect("registry with deleted tombstone should load");

        assert_eq!(loaded_active.id(), active.id);
        assert!(registry.contains_session(active.id));
        assert!(!registry.contains_session(deleted.id));
        assert!(!super::session_dir(&root_dir, deleted.id).exists());
        let saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root_dir.join(super::REGISTRY_FILE)).unwrap())
                .unwrap();
        assert!(saved
            .get("deleted_session_ids")
            .and_then(|value| value.as_array())
            .is_none_or(|ids| ids.is_empty()));

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn registry_rebuilds_when_only_registered_session_is_tombstoned() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-active-tombstone-test-{}",
            uuid::Uuid::new_v4()
        ));
        let root_dir = data_dir.join(super::SESSIONS_DIR);
        let tombstoned = super::default_session_metadata("Tombstoned");
        super::persist_session_snapshot(
            &root_dir,
            &tombstoned,
            &super::StoredSessionSnapshot::default(),
        )
        .expect("tombstoned snapshot should be left behind");
        super::write_json(
            &root_dir.join(super::REGISTRY_FILE),
            &serde_json::json!({
                "active_session_id": tombstoned.id,
                "sessions": [tombstoned.clone()],
                "deleted_session_ids": [tombstoned.id]
            }),
        )
        .expect("registry should be written");

        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32)
            .expect("tombstoned active registry should repair without panicking");

        assert_ne!(active.id(), tombstoned.id);
        assert!(!registry.contains_session(tombstoned.id));
        assert_eq!(registry.summaries().len(), 1);
        assert!(!super::session_dir(&root_dir, tombstoned.id).exists());

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn registry_empty_rebuild_removes_tombstoned_storage() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-empty-tombstone-test-{}",
            uuid::Uuid::new_v4()
        ));
        let root_dir = data_dir.join(super::SESSIONS_DIR);
        let tombstoned = super::default_session_metadata("Tombstoned");
        super::persist_session_snapshot(
            &root_dir,
            &tombstoned,
            &super::StoredSessionSnapshot::default(),
        )
        .expect("tombstoned snapshot should be left behind");
        super::write_json(
            &root_dir.join(super::REGISTRY_FILE),
            &serde_json::json!({
                "active_session_id": tombstoned.id,
                "sessions": [],
                "deleted_session_ids": [tombstoned.id]
            }),
        )
        .expect("empty registry with tombstone should be written");

        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32)
            .expect("empty registry should repair without resurrecting tombstones");

        assert_ne!(active.id(), tombstoned.id);
        assert!(!registry.contains_session(tombstoned.id));
        assert_eq!(registry.summaries().len(), 1);
        assert!(!super::session_dir(&root_dir, tombstoned.id).exists());

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn registry_prunes_registered_session_with_missing_storage() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-missing-storage-test-{}",
            uuid::Uuid::new_v4()
        ));
        let root_dir = data_dir.join(super::SESSIONS_DIR);
        let active = super::default_session_metadata("Active");
        let missing = super::default_session_metadata("Missing");
        super::persist_session_snapshot(
            &root_dir,
            &active,
            &super::StoredSessionSnapshot::default(),
        )
        .expect("active snapshot should be written");
        super::write_json(
            &root_dir.join(super::REGISTRY_FILE),
            &serde_json::json!({
                "active_session_id": active.id,
                "sessions": [active.clone(), missing.clone()]
            }),
        )
        .expect("registry with missing storage should be written");

        let (registry, loaded_active) = SessionRegistry::load_or_create(&data_dir, 32, 32)
            .expect("registry should repair missing storage");

        assert_eq!(loaded_active.id(), active.id);
        assert!(registry.contains_session(active.id));
        assert!(!registry.contains_session(missing.id));
        assert!(!super::session_dir(&root_dir, missing.id).exists());

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn registry_rebuilds_when_active_session_storage_is_missing() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-missing-active-storage-test-{}",
            uuid::Uuid::new_v4()
        ));
        let root_dir = data_dir.join(super::SESSIONS_DIR);
        let missing = super::default_session_metadata("Missing active");
        super::write_json(
            &root_dir.join(super::REGISTRY_FILE),
            &serde_json::json!({
                "active_session_id": missing.id,
                "sessions": [missing.clone()]
            }),
        )
        .expect("registry with missing active storage should be written");

        let (registry, loaded_active) = SessionRegistry::load_or_create(&data_dir, 32, 32)
            .expect("registry should rebuild missing active storage");

        assert_ne!(loaded_active.id(), missing.id);
        assert_eq!(registry.summaries().len(), 1);
        assert!(!registry.contains_session(missing.id));
        assert!(!super::session_dir(&root_dir, missing.id).exists());

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn registry_delete_prunes_tombstone_after_storage_removal() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-delete-prune-test-{}",
            uuid::Uuid::new_v4()
        ));
        let root_dir = data_dir.join(super::SESSIONS_DIR);
        let (registry, _active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
        let created = registry
            .create_session(Some("delete me".to_string()))
            .unwrap();

        registry.delete_session(created.id).unwrap();

        let saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root_dir.join(super::REGISTRY_FILE)).unwrap())
                .unwrap();
        let deleted = saved
            .get("deleted_session_ids")
            .and_then(|value| value.as_array())
            .cloned()
            .unwrap_or_default();
        let created_id = created.id.to_string();
        assert!(!deleted
            .iter()
            .any(|value| value.as_str() == Some(created_id.as_str())));

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn registry_normalizes_duplicate_ids_before_delete() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-duplicate-registry-test-{}",
            uuid::Uuid::new_v4()
        ));
        let root_dir = data_dir.join(super::SESSIONS_DIR);
        let active = super::default_session_metadata("Active");
        let duplicate = super::default_session_metadata("Duplicate");
        let mut duplicate_stale = duplicate.clone();
        duplicate_stale.name = "Duplicate stale".to_string();
        duplicate_stale.request_count = 999;
        super::persist_session_snapshot(
            &root_dir,
            &active,
            &super::StoredSessionSnapshot::default(),
        )
        .expect("active snapshot should be written");
        super::persist_session_snapshot(
            &root_dir,
            &duplicate,
            &super::StoredSessionSnapshot::default(),
        )
        .expect("duplicate snapshot should be written");
        super::write_json(
            &root_dir.join(super::REGISTRY_FILE),
            &serde_json::json!({
                "active_session_id": active.id,
                "sessions": [active.clone(), duplicate.clone(), duplicate_stale]
            }),
        )
        .expect("duplicate registry should be written");

        let (registry, _active) = SessionRegistry::load_or_create(&data_dir, 32, 32)
            .expect("duplicate registry should be normalized");
        registry
            .delete_session(duplicate.id)
            .expect("deleting duplicate id should remove every duplicate entry");

        assert!(!registry.contains_session(duplicate.id));
        let saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root_dir.join(super::REGISTRY_FILE)).unwrap())
                .unwrap();
        let duplicate_id = duplicate.id.to_string();
        let occurrences = saved
            .get("sessions")
            .and_then(|value| value.as_array())
            .unwrap()
            .iter()
            .filter(|session| {
                session.get("id").and_then(|id| id.as_str()) == Some(duplicate_id.as_str())
            })
            .count();
        assert_eq!(occurrences, 0);

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[cfg(unix)]
    #[test]
    fn registry_rejects_uuid_symlink_session_dir() {
        use std::os::unix::fs::symlink;

        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-symlink-registry-test-{}",
            uuid::Uuid::new_v4()
        ));
        let root_dir = data_dir.join(super::SESSIONS_DIR);
        let external_dir = std::env::temp_dir().join(format!(
            "sniper-session-symlink-target-{}",
            uuid::Uuid::new_v4()
        ));
        let active = super::default_session_metadata("Active");
        let linked = super::default_session_metadata("Linked");
        super::persist_session_snapshot(
            &root_dir,
            &active,
            &super::StoredSessionSnapshot::default(),
        )
        .expect("active snapshot should be written");
        std::fs::create_dir_all(&external_dir).expect("external dir should be created");
        symlink(&external_dir, root_dir.join(linked.id.to_string()))
            .expect("uuid symlink should be created");

        let rebuilt = super::rebuild_registry_from_session_dirs(&root_dir, 32, 32)
            .expect("registry rebuild should skip uuid symlink dirs");
        assert!(rebuilt
            .sessions
            .iter()
            .any(|session| session.id == active.id));
        assert!(!rebuilt
            .sessions
            .iter()
            .any(|session| session.id == linked.id));

        super::write_json(
            &root_dir.join(super::REGISTRY_FILE),
            &serde_json::json!({
                "active_session_id": linked.id,
                "sessions": [linked.clone()]
            }),
        )
        .expect("registry pointing at symlink should be written");
        let (registry, repaired_active) = SessionRegistry::load_or_create(&data_dir, 32, 32)
            .expect("registered uuid symlink should be pruned and repaired");
        assert_ne!(repaired_active.id(), linked.id);
        assert!(!registry.contains_session(linked.id));

        let _ = std::fs::remove_dir_all(&data_dir);
        let _ = std::fs::remove_dir_all(&external_dir);
    }

    #[cfg(unix)]
    #[test]
    fn registry_prunes_inactive_uuid_symlink_session_dir() {
        use std::os::unix::fs::symlink;

        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-inactive-symlink-registry-test-{}",
            uuid::Uuid::new_v4()
        ));
        let root_dir = data_dir.join(super::SESSIONS_DIR);
        let external_dir = std::env::temp_dir().join(format!(
            "sniper-session-inactive-symlink-target-{}",
            uuid::Uuid::new_v4()
        ));
        let active = super::default_session_metadata("Active");
        let linked = super::default_session_metadata("Linked");
        super::persist_session_snapshot(
            &root_dir,
            &active,
            &super::StoredSessionSnapshot::default(),
        )
        .expect("active snapshot should be written");
        std::fs::create_dir_all(&external_dir).expect("external dir should be created");
        symlink(&external_dir, root_dir.join(linked.id.to_string()))
            .expect("uuid symlink should be created");
        super::write_json(
            &root_dir.join(super::REGISTRY_FILE),
            &serde_json::json!({
                "active_session_id": active.id,
                "sessions": [active.clone(), linked.clone()]
            }),
        )
        .expect("registry pointing at inactive symlink should be written");

        let (registry, loaded_active) = SessionRegistry::load_or_create(&data_dir, 32, 32)
            .expect("inactive uuid symlink should be pruned");

        assert_eq!(loaded_active.id(), active.id);
        assert!(registry.contains_session(active.id));
        assert!(!registry.contains_session(linked.id));
        assert!(registry.session_storage_path(linked.id).is_err());

        let _ = std::fs::remove_dir_all(&data_dir);
        let _ = std::fs::remove_dir_all(&external_dir);
    }

    #[test]
    fn registry_accepts_missing_active_session_id() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-registry-legacy-{}",
            uuid::Uuid::new_v4()
        ));
        let root_dir = data_dir.join(super::SESSIONS_DIR);
        let metadata = super::default_session_metadata("Imported");
        super::persist_session_snapshot(
            &root_dir,
            &metadata,
            &super::StoredSessionSnapshot::default(),
        )
        .expect("session snapshot should be written");
        super::write_json(
            &root_dir.join(super::REGISTRY_FILE),
            &serde_json::json!({ "sessions": [metadata.clone()] }),
        )
        .expect("legacy registry should be written");

        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32)
            .expect("legacy registry should be repaired");

        assert_eq!(registry.active_session_id(), metadata.id);
        assert_eq!(active.id(), metadata.id);
        let expected_active_id = metadata.id.to_string();
        let repaired: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root_dir.join(super::REGISTRY_FILE)).unwrap())
                .unwrap();
        assert_eq!(
            repaired
                .get("active_session_id")
                .and_then(|value| value.as_str()),
            Some(expected_active_id.as_str())
        );

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[tokio::test]
    async fn registry_recovers_from_corrupt_json_by_scanning_session_dirs() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-registry-corrupt-{}",
            uuid::Uuid::new_v4()
        ));
        let root_dir = data_dir.join(super::SESSIONS_DIR);
        let metadata = super::default_session_metadata("Recoverable");
        super::persist_session_snapshot(
            &root_dir,
            &metadata,
            &super::StoredSessionSnapshot::default(),
        )
        .expect("session snapshot should be written");
        std::fs::write(root_dir.join(super::REGISTRY_FILE), b"{not json")
            .expect("corrupt registry should be written");

        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32)
            .expect("corrupt registry should recover");

        assert_eq!(active.id(), metadata.id);
        assert!(registry.contains_session(metadata.id));
        let repaired: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root_dir.join(super::REGISTRY_FILE)).unwrap())
                .unwrap();
        let expected_active_id = metadata.id.to_string();
        assert_eq!(
            repaired
                .get("active_session_id")
                .and_then(|value| value.as_str()),
            Some(expected_active_id.as_str())
        );
        let has_corrupt_backup = std::fs::read_dir(&root_dir).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".registry.corrupt-")
        });
        assert!(has_corrupt_backup);

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[tokio::test]
    async fn registry_corrupt_recovery_ignores_quarantined_deleted_session_dirs() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-registry-corrupt-deleted-{}",
            uuid::Uuid::new_v4()
        ));
        let root_dir = data_dir.join(super::SESSIONS_DIR);
        let active = super::default_session_metadata("Active");
        let deleted = super::default_session_metadata("Deleted");
        super::persist_session_snapshot(
            &root_dir,
            &active,
            &super::StoredSessionSnapshot::default(),
        )
        .expect("active snapshot should be written");
        super::persist_session_snapshot(
            &root_dir,
            &deleted,
            &super::StoredSessionSnapshot::default(),
        )
        .expect("deleted snapshot should be written before quarantine");
        let deleted_storage = super::session_dir(&root_dir, deleted.id);
        let quarantine_dir = root_dir.join(format!(".deleted-{}", deleted.id));
        std::fs::rename(&deleted_storage, &quarantine_dir)
            .expect("deleted session storage should be quarantined");
        std::fs::write(root_dir.join(super::REGISTRY_FILE), b"{not json")
            .expect("corrupt registry should be written");

        let (registry, loaded_active) = SessionRegistry::load_or_create(&data_dir, 32, 32)
            .expect("corrupt registry should recover");

        assert_eq!(loaded_active.id(), active.id);
        assert!(registry.contains_session(active.id));
        assert!(!registry.contains_session(deleted.id));
        assert!(!deleted_storage.exists());
        assert!(quarantine_dir.exists());

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[tokio::test]
    async fn registry_recovers_missing_json_by_scanning_session_dirs() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-registry-missing-{}",
            uuid::Uuid::new_v4()
        ));
        let root_dir = data_dir.join(super::SESSIONS_DIR);
        let metadata = super::default_session_metadata("Recoverable");
        super::persist_session_snapshot(
            &root_dir,
            &metadata,
            &super::StoredSessionSnapshot::default(),
        )
        .expect("session snapshot should be written");

        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32)
            .expect("missing registry should recover from session dirs");

        assert_eq!(active.id(), metadata.id);
        assert!(registry.contains_session(metadata.id));

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[tokio::test]
    async fn registry_recovers_empty_json_by_scanning_session_dirs() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-registry-empty-{}",
            uuid::Uuid::new_v4()
        ));
        let root_dir = data_dir.join(super::SESSIONS_DIR);
        let metadata = super::default_session_metadata("Recoverable");
        super::persist_session_snapshot(
            &root_dir,
            &metadata,
            &super::StoredSessionSnapshot::default(),
        )
        .expect("session snapshot should be written");
        super::write_json(
            &root_dir.join(super::REGISTRY_FILE),
            &serde_json::json!({ "active_session_id": metadata.id, "sessions": [] }),
        )
        .expect("empty registry should be written");

        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32)
            .expect("empty registry should recover from session dirs");

        assert_eq!(active.id(), metadata.id);
        assert!(registry.contains_session(metadata.id));

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[tokio::test]
    async fn registry_recovers_unregistered_session_dir_from_valid_registry() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-registry-orphan-{}",
            uuid::Uuid::new_v4()
        ));
        let root_dir = data_dir.join(super::SESSIONS_DIR);
        let active = super::default_session_metadata("Active");
        let orphan = super::default_session_metadata("Orphan");
        super::persist_session_snapshot(
            &root_dir,
            &active,
            &super::StoredSessionSnapshot::default(),
        )
        .expect("active snapshot should be written");
        super::persist_session_snapshot(
            &root_dir,
            &orphan,
            &super::StoredSessionSnapshot::default(),
        )
        .expect("orphan snapshot should be written");
        super::write_json(
            &root_dir.join(super::REGISTRY_FILE),
            &serde_json::json!({
                "active_session_id": active.id,
                "sessions": [active.clone()]
            }),
        )
        .expect("valid partial registry should be written");

        let (registry, loaded_active) = SessionRegistry::load_or_create(&data_dir, 32, 32)
            .expect("valid registry should recover unregistered session dirs");

        assert_eq!(loaded_active.id(), active.id);
        assert!(registry.contains_session(active.id));
        assert!(registry.contains_session(orphan.id));
        let repaired: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root_dir.join(super::REGISTRY_FILE)).unwrap())
                .unwrap();
        let sessions = repaired
            .get("sessions")
            .and_then(|value| value.as_array())
            .expect("repaired registry should contain sessions");
        let expected_orphan_id = orphan.id.to_string();
        assert!(sessions.iter().any(|session| {
            session.get("id").and_then(|id| id.as_str()) == Some(expected_orphan_id.as_str())
        }));

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[tokio::test]
    async fn create_session_does_not_publish_when_registry_write_fails() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-create-failure-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, _) = SessionRegistry::load_or_create(&data_dir, 100, 100).unwrap();
        let before_ids = registry
            .summaries()
            .into_iter()
            .map(|session| session.id)
            .collect::<HashSet<_>>();

        std::fs::remove_file(&registry.registry_path).unwrap();
        std::fs::create_dir(&registry.registry_path).unwrap();

        let error = registry
            .create_session(Some("Broken registry".to_string()))
            .unwrap_err();

        assert!(error.to_string().contains("failed to rename"));
        let after_ids = registry
            .summaries()
            .into_iter()
            .map(|session| session.id)
            .collect::<HashSet<_>>();
        assert_eq!(after_ids, before_ids);

        let session_dir_ids = std::fs::read_dir(&registry.root_dir)
            .unwrap()
            .filter_map(|entry| {
                let path = entry.ok()?.path();
                if !path.is_dir() {
                    return None;
                }
                let name = path.file_name()?.to_str()?;
                uuid::Uuid::parse_str(name).ok()
            })
            .collect::<HashSet<_>>();
        assert_eq!(session_dir_ids, before_ids);
        let temp_files = std::fs::read_dir(&registry.root_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .count();
        assert_eq!(temp_files, 0);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn load_context_recovers_corrupt_snapshot_by_replaying_transaction_journal() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-snapshot-corrupt-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();

        active
            .store
            .insert(TransactionRecord::http(
                Utc::now(),
                "GET".to_string(),
                "https".to_string(),
                "journal.example:443".to_string(),
                "/from-journal".to_string(),
                Some(200),
                1,
                MessageRecord {
                    headers: vec![],
                    body_preview: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    body_size: 0,
                    decoded_body_size: None,
                    preview_truncated: false,
                    content_type: None,
                    content_decoded: false,
                },
                None,
                vec![],
                None,
                None,
            ))
            .await;
        std::fs::write(super::snapshot_path(active.storage_dir()), b"{not json")
            .expect("corrupt snapshot should be written");

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.store.snapshot(Some(10)).await;

        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].host, "journal.example:443");
        let has_corrupt_backup = std::fs::read_dir(active.storage_dir())
            .unwrap()
            .any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".snapshot.corrupt-")
            });
        assert!(has_corrupt_backup);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn load_context_recovers_snapshot_directory_by_replaying_transaction_journal() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-snapshot-directory-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();

        active
            .store
            .insert(TransactionRecord::http(
                Utc::now(),
                "GET".to_string(),
                "https".to_string(),
                "snapshot-dir.example:443".to_string(),
                "/from-journal".to_string(),
                Some(200),
                1,
                MessageRecord {
                    headers: vec![],
                    body_preview: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    body_size: 0,
                    decoded_body_size: None,
                    preview_truncated: false,
                    content_type: None,
                    content_decoded: false,
                },
                None,
                vec![],
                None,
                None,
            ))
            .await;
        let snapshot_path = super::snapshot_path(active.storage_dir());
        let _ = std::fs::remove_file(&snapshot_path);
        std::fs::create_dir(&snapshot_path).expect("snapshot directory should be created");

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.store.snapshot(Some(10)).await;

        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].host, "snapshot-dir.example:443");
        assert!(!snapshot_path.is_dir());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn load_context_stops_at_corrupt_complete_transaction_journal_line() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-journal-corrupt-line-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
        let storage_dir = active.storage_dir().to_path_buf();
        let journal_path = super::transaction_journal_path(&storage_dir);
        let mut journal = Vec::new();
        serde_json::to_writer(
            &mut journal,
            &TransactionJournalEntry::Insert {
                record: TransactionRecord::http(
                    Utc::now(),
                    "GET".to_string(),
                    "https".to_string(),
                    "valid-journal.example:443".to_string(),
                    "/valid".to_string(),
                    Some(200),
                    1,
                    MessageRecord {
                        headers: vec![],
                        body_preview: String::new(),
                        body_encoding: BodyEncoding::Utf8,
                        body_size: 0,
                        decoded_body_size: None,
                        preview_truncated: false,
                        content_type: None,
                        content_decoded: false,
                    },
                    None,
                    vec![],
                    None,
                    None,
                ),
            },
        )
        .unwrap();
        journal.extend_from_slice(b"\n{not json}\n");
        std::fs::write(&journal_path, journal).unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.store.snapshot(Some(10)).await;

        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].host, "valid-journal.example:443");
        let has_corrupt_backup = std::fs::read_dir(&storage_dir).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".transactions.journal.corrupt-")
        });
        assert!(has_corrupt_backup);
        assert_eq!(std::fs::metadata(&journal_path).unwrap().len(), 0);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn transaction_journal_replay_moves_directory_aside() {
        let storage_dir = std::env::temp_dir().join(format!(
            "sniper-session-journal-directory-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&storage_dir).unwrap();
        let journal_path = super::transaction_journal_path(&storage_dir);
        std::fs::create_dir(&journal_path).unwrap();

        let mut order = Vec::new();
        let mut records = HashMap::new();
        let mut seen = HashSet::new();
        let mut replayed = HashSet::new();
        let mut backfill_order = VecDeque::new();
        let mut backfill_records = HashMap::new();
        let mut transaction_event_sequence = 0;
        super::replay_transaction_journal_file(
            &journal_path,
            None,
            &mut order,
            &mut records,
            &mut seen,
            &mut replayed,
            &mut backfill_order,
            &mut backfill_records,
            None,
            100,
            true,
            &mut transaction_event_sequence,
        )
        .expect("directory journal should be moved aside");

        assert!(order.is_empty());
        assert_eq!(transaction_event_sequence, 0);
        assert!(!journal_path.exists());
        let has_corrupt_backup = std::fs::read_dir(&storage_dir).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".transactions.journal.corrupt-")
        });
        assert!(has_corrupt_backup);

        let _ = std::fs::remove_dir_all(storage_dir);
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
                revision: 0,
                replay: ReplayWorkspaceState {
                    tabs: vec![
                        ReplayTabState {
                            id: "tab-1".to_string(),
                            sequence: 1,
                            custom_label: "Login replay".to_string(),
                            base_request: Some(request.clone()),
                            source_transaction_id: None,
                            notice: "Saved".to_string(),
                            request_text: "POST /login HTTP/1.1".to_string(),
                            response_record: None,
                            target_scheme: "https".to_string(),
                            target_host: "example.com".to_string(),
                            target_port: "443".to_string(),
                            history_entries: vec![ReplayHistoryEntryState {
                                request: Some(request.clone()),
                                request_text: "POST /login HTTP/1.1".to_string(),
                                http_version_mode: "HTTP/2".to_string(),
                                response_record: None,
                                notice: "Saved".to_string(),
                                target_scheme: "https".to_string(),
                                target_host: "example.com".to_string(),
                                target_port: "443".to_string(),
                            }],
                            history_index: Some(0),
                            ..Default::default()
                        },
                        ReplayTabState {
                            id: "11111111-1111-4111-8111-111111111111".to_string(),
                            tab_type: "websocket".to_string(),
                            sequence: 2,
                            custom_label: "Chat socket".to_string(),
                            ws_scheme: "wss".to_string(),
                            ws_host: "socket.example.com".to_string(),
                            ws_port: serde_json::json!(443),
                            ws_path: "/stream".to_string(),
                            ws_handshake_text: "Authorization: Bearer test".to_string(),
                            ws_editor_text: "{\"type\":\"ping\"}".to_string(),
                            ws_message_type: "binary".to_string(),
                            ws_editor_body_encoded: true,
                            ws_setup_queue: vec![serde_json::json!({
                                "label": "subscribe",
                                "body": "{\"op\":\"subscribe\"}",
                                "autoSend": true,
                                "sent": true
                            })],
                            ws_frames: vec![WsReplayFrame {
                                index: 0,
                                captured_at: Utc::now().to_rfc3339(),
                                direction: WebSocketFrameDirection::ClientToServer,
                                kind: WebSocketFrameKind::Text,
                                body: "{\"op\":\"subscribe\"}".to_string(),
                                body_encoding: BodyEncoding::Utf8,
                                body_size: 18,
                                preview_truncated: false,
                            }],
                            ..Default::default()
                        },
                    ],
                    active_tab_id: Some("tab-1".to_string()),
                    tab_sequence: 2,
                },
                fuzzer: FuzzerWorkspaceState {
                    base_request: Some(request.clone()),
                    source_transaction_id: None,
                    target: Some(crate::model::RequestTargetOverride {
                        scheme: "https".to_string(),
                        host: "override.example.com".to_string(),
                        port: "8443".to_string(),
                    }),
                    target_request_authority: Some("https://example.com".to_string()),
                    notice: "Ready".to_string(),
                    request_text: "POST /login HTTP/1.1".to_string(),
                    payloads_text: "admin\nuser".to_string(),
                    ..FuzzerWorkspaceState::default()
                },
                ..Default::default()
            })
            .await;

        active.persist().await.unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let workspace = loaded.workspace.snapshot().await;
        assert_eq!(workspace.replay.tabs.len(), 2);
        assert_eq!(workspace.replay.active_tab_id.as_deref(), Some("tab-1"));
        assert_eq!(
            workspace
                .replay
                .tabs
                .first()
                .map(|tab| tab.custom_label.as_str()),
            Some("Login replay")
        );
        assert_eq!(workspace.fuzzer.notice, "Ready");
        assert_eq!(workspace.fuzzer.payloads_text, "admin\nuser");
        assert_eq!(
            workspace.fuzzer.target.as_ref().map(|target| (
                target.scheme.as_str(),
                target.host.as_str(),
                target.port.as_str()
            )),
            Some(("https", "override.example.com", "8443"))
        );
        assert_eq!(
            workspace
                .replay
                .tabs
                .first()
                .and_then(|tab| tab.history_index),
            Some(0)
        );
        assert_eq!(
            workspace
                .replay
                .tabs
                .first()
                .and_then(|tab| tab.base_request.as_ref())
                .map(|value| value.host.as_str()),
            Some("example.com")
        );
        assert_eq!(
            workspace
                .replay
                .tabs
                .first()
                .and_then(|tab| tab.history_entries.first())
                .map(|entry| entry.target_port.as_str()),
            Some("443")
        );
        assert_eq!(
            workspace
                .replay
                .tabs
                .first()
                .and_then(|tab| tab.history_entries.first())
                .map(|entry| entry.http_version_mode.as_str()),
            Some("HTTP/2")
        );
        let ws_tab = workspace
            .replay
            .tabs
            .iter()
            .find(|tab| tab.id == "11111111-1111-4111-8111-111111111111")
            .expect("websocket replay tab should persist");
        assert_eq!(ws_tab.tab_type, "websocket");
        assert_eq!(ws_tab.ws_editor_text, "{\"type\":\"ping\"}");
        assert_eq!(ws_tab.ws_message_type, "binary");
        assert!(ws_tab.ws_editor_body_encoded);
        assert_eq!(
            ws_tab
                .ws_setup_queue
                .first()
                .and_then(|item| item.get("sent"))
                .and_then(|value| value.as_bool()),
            Some(true)
        );
        assert_eq!(ws_tab.ws_frames.len(), 1);
        assert_eq!(ws_tab.ws_frames[0].body, "{\"op\":\"subscribe\"}");
    }

    #[test]
    fn stored_snapshot_accepts_legacy_replay_history_without_request() {
        let snapshot: super::StoredSessionSnapshot = serde_json::from_value(serde_json::json!({
            "workspace": {
                "replay": {
                    "tabs": [{
                        "id": "tab-legacy",
                        "sequence": 1,
                        "base_request": {
                            "scheme": "https",
                            "host": "example.com",
                            "method": "GET",
                            "path": "/",
                            "headers": [],
                            "body": "",
                            "body_encoding": "utf8",
                            "preview_truncated": false
                        },
                        "history_entries": [{
                            "request_text": "GET /legacy HTTP/1.1",
                            "notice": "saved before request snapshots"
                        }]
                    }],
                    "active_tab_id": "tab-legacy",
                    "tab_sequence": 1
                }
            }
        }))
        .expect("legacy workspace snapshot should deserialize");

        let entry = snapshot.workspace.replay.tabs[0]
            .history_entries
            .first()
            .expect("history entry should survive");
        assert!(entry.request.is_none());
        assert_eq!(entry.request_text, "GET /legacy HTTP/1.1");
    }

    #[test]
    fn stored_snapshot_accepts_replay_base_request_missing_body_metadata() {
        let snapshot: super::StoredSessionSnapshot = serde_json::from_value(serde_json::json!({
            "workspace": {
                "replay": {
                    "tabs": [{
                        "id": "tab-partial",
                        "sequence": 1,
                        "base_request": {
                            "scheme": "https",
                            "host": "example.com",
                            "method": "GET",
                            "path": "/",
                            "headers": [{ "name": "host", "value": "example.com" }]
                        }
                    }],
                    "active_tab_id": "tab-partial",
                    "tab_sequence": 1
                }
            }
        }))
        .expect("partial replay base request should not break snapshot parsing");

        let request = snapshot.workspace.replay.tabs[0]
            .base_request
            .as_ref()
            .expect("base request should survive");
        assert_eq!(request.body, "");
        assert_eq!(request.body_encoding, BodyEncoding::Utf8);
        assert!(!request.preview_truncated);
    }

    #[tokio::test]
    async fn registry_restores_oast_store_config_from_runtime_snapshot() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-oast-config-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();

        active
            .runtime
            .update(RuntimeSettingsUpdate {
                oast_enabled: Some(true),
                oast_server_url: Some("https://oast.example.test".to_string()),
                oast_token: Some("token-a".to_string()),
                oast_polling_interval_secs: Some(11),
                oast_provider: Some(OastProvider::Interactsh),
                ..RuntimeSettingsUpdate::default()
            })
            .await
            .unwrap();
        active.persist().await.unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let config = loaded.oast.get_config().await;

        assert!(config.enabled);
        assert_eq!(config.server_url, "https://oast.example.test");
        assert_eq!(config.token, "token-a");
        assert_eq!(config.polling_interval_secs, 11);
        assert_eq!(config.provider, OastProvider::Interactsh);
    }

    #[tokio::test]
    async fn registry_persists_scanner_config() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-scanner-config-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();

        let mut config = ScannerConfig {
            enabled: false,
            ..ScannerConfig::default()
        };
        config.rules.insert("jwt".to_string(), false);
        active.scanner.update_config(config).await;
        active.persist().await.unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.scanner.get_config().await;
        assert!(!restored.enabled);
        assert_eq!(restored.rules.get("jwt"), Some(&false));
    }

    #[test]
    fn stored_snapshot_accepts_partial_scanner_config() {
        let snapshot: super::StoredSessionSnapshot = serde_json::from_value(serde_json::json!({
            "scanner_config": {
                "enabled": false
            }
        }))
        .expect("legacy scanner config should not break session snapshot parsing");

        assert!(!snapshot.scanner_config.enabled);
        assert!(snapshot.scanner_config.custom_rules.is_empty());
        assert_eq!(snapshot.scanner_config.rules.get("jwt"), Some(&true));
    }

    #[test]
    fn missing_scanner_findings_are_recovered_from_restored_transactions() {
        let request = MessageRecord {
            headers: vec![],
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };
        let response = MessageRecord {
            headers: vec![HeaderRecord {
                name: "content-type".to_string(),
                value: "text/html".to_string(),
            }],
            body_preview: "<html><body>ok</body></html>".to_string(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 28,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: Some("text/html".to_string()),
            content_decoded: false,
        };
        let record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "example.test".to_string(),
            "/".to_string(),
            Some(200),
            1,
            request,
            Some(response),
            Vec::new(),
            None,
            None,
        );

        let recovered_record_ids = HashSet::from([record.id]);
        let findings = super::recover_missing_scanner_findings(
            Vec::new(),
            &[record],
            &recovered_record_ids,
            &ScannerConfig::default(),
            100,
        );

        assert!(findings
            .iter()
            .any(|finding| finding.title == "Missing Content-Security-Policy"));
    }

    #[tokio::test]
    async fn journal_scanner_recovery_does_not_resurrect_cleared_snapshot_findings() {
        fn html_record(host: &str, sequence: u64) -> TransactionRecord {
            let request = MessageRecord {
                headers: vec![],
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            };
            let response = MessageRecord {
                headers: vec![HeaderRecord {
                    name: "content-type".to_string(),
                    value: "text/html".to_string(),
                }],
                body_preview: "<html><body>journal</body></html>".to_string(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 33,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: Some("text/html".to_string()),
                content_decoded: false,
            };
            let mut record = TransactionRecord::http(
                Utc::now(),
                "GET".to_string(),
                "https".to_string(),
                host.to_string(),
                "/".to_string(),
                Some(200),
                sequence,
                request,
                Some(response),
                Vec::new(),
                None,
                None,
            );
            record.sequence = sequence;
            record
        }

        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-scanner-journal-recovery-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
        let storage_dir = registry.session_storage_path(active.id()).unwrap();

        let cleared_record = html_record("cleared.example", 1);
        let cleared_record_id = cleared_record.id;
        let journal_record = html_record("journal.example", 2);
        let journal_record_id = journal_record.id;

        let snapshot = super::StoredSessionSnapshot {
            transactions: vec![cleared_record],
            scanner_findings: Vec::new(),
            scanner_config: ScannerConfig {
                custom_rules: vec![CustomRule {
                    id: "journal-body".to_string(),
                    name: "Journal body".to_string(),
                    enabled: true,
                    target: "response_body".to_string(),
                    header_name: String::new(),
                    pattern: "journal".to_string(),
                    severity: Severity::Info,
                    category: "custom".to_string(),
                    description: String::new(),
                }],
                ..ScannerConfig::default()
            },
            ..Default::default()
        };
        super::write_json(&super::snapshot_path(&storage_dir), &snapshot).unwrap();

        let journal_path = super::transaction_journal_path(&storage_dir);
        let mut lines = Vec::new();
        serde_json::to_writer(
            &mut lines,
            &TransactionJournalEntry::Insert {
                record: journal_record,
            },
        )
        .unwrap();
        lines.push(b'\n');
        std::fs::write(&journal_path, lines).unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let records = loaded.store.snapshot(Some(32)).await;
        assert!(records.iter().any(|record| record.id == journal_record_id));
        assert!(records.iter().any(|record| record.id == cleared_record_id));

        let findings = loaded.scanner.snapshot(Some(32)).await;

        assert!(findings
            .iter()
            .any(|finding| finding.record_id == journal_record_id));
        assert!(!findings
            .iter()
            .any(|finding| finding.record_id == cleared_record_id));
        assert_eq!(std::fs::metadata(&journal_path).unwrap().len(), 0);

        let reloaded = registry.load_context(active.id()).unwrap();
        let reloaded_findings = reloaded.scanner.snapshot(Some(32)).await;
        assert!(reloaded_findings
            .iter()
            .any(|finding| finding.record_id == journal_record_id));
        assert!(!reloaded_findings
            .iter()
            .any(|finding| finding.record_id == cleared_record_id));

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn recovered_scanner_findings_evict_older_persisted_findings_at_capacity() {
        let request = MessageRecord {
            headers: vec![],
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };
        let response = MessageRecord {
            headers: vec![HeaderRecord {
                name: "content-type".to_string(),
                value: "text/html".to_string(),
            }],
            body_preview: "<html><body>restored</body></html>".to_string(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 34,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: Some("text/html".to_string()),
            content_decoded: false,
        };
        let restored_record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "new.example".to_string(),
            "/".to_string(),
            Some(200),
            2,
            request,
            Some(response),
            Vec::new(),
            None,
            None,
        );
        let old_finding = ScannerFinding {
            id: Uuid::new_v4(),
            record_id: Uuid::new_v4(),
            found_at: Utc::now(),
            rule_id: String::new(),
            severity: crate::scanner::Severity::Low,
            category: "old".to_string(),
            title: "Old persisted finding".to_string(),
            detail: String::new(),
            evidence: String::new(),
            host: "old.example".to_string(),
            path: "/".to_string(),
            location: None,
        };

        let recovered_record_ids = HashSet::from([restored_record.id]);
        let findings = super::recover_missing_scanner_findings(
            vec![old_finding],
            &[restored_record],
            &recovered_record_ids,
            &ScannerConfig::default(),
            1,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].host, "new.example");
        assert_ne!(findings[0].title, "Old persisted finding");
    }

    #[test]
    fn stored_snapshot_accepts_legacy_websocket_without_collections() {
        let snapshot: super::StoredSessionSnapshot = serde_json::from_value(serde_json::json!({
            "websockets": [{
                "id": "00000000-0000-0000-0000-00000000a001",
                "started_at": "2026-01-01T00:00:00Z",
                "scheme": "wss",
                "host": "socket.example.com",
                "path": "/events",
                "request": {
                    "headers": [{ "name": "host", "value": "socket.example.com" }]
                }
            }]
        }))
        .expect("legacy websocket session should not break snapshot parsing");

        let websocket = snapshot
            .websockets
            .first()
            .expect("websocket should survive");
        assert!(websocket.frames.is_empty());
        assert!(websocket.notes.is_empty());
        assert_eq!(websocket.request.body_encoding, BodyEncoding::Utf8);
        assert_eq!(websocket.summary().frame_count, 0);
    }

    #[test]
    fn metadata_count_repair_respects_max_entries_for_capped_stores() {
        let mut snapshot: super::StoredSessionSnapshot =
            serde_json::from_value(serde_json::json!({
                "transactions": [
                    {
                        "id": "00000000-0000-0000-0000-00000000c101",
                        "started_at": "2026-01-01T00:00:00Z",
                        "method": "GET",
                        "scheme": "https",
                        "host": "one.example",
                        "path": "/one",
                        "status": 200,
                        "request": { "headers": [] }
                    },
                    {
                        "id": "00000000-0000-0000-0000-00000000c102",
                        "started_at": "2026-01-01T00:00:01Z",
                        "method": "GET",
                        "scheme": "https",
                        "host": "two.example",
                        "path": "/two",
                        "status": 200,
                        "request": { "headers": [] }
                    }
                ],
                "websockets": [
                    {
                        "id": "00000000-0000-0000-0000-00000000c201",
                        "started_at": "2026-01-01T00:00:00Z",
                        "scheme": "wss",
                        "host": "socket-one.example",
                        "path": "/ws",
                        "request": { "headers": [] }
                    },
                    {
                        "id": "00000000-0000-0000-0000-00000000c202",
                        "started_at": "2026-01-01T00:00:01Z",
                        "scheme": "wss",
                        "host": "socket-two.example",
                        "path": "/ws",
                        "request": { "headers": [] }
                    }
                ],
                "event_log": [
                    {
                        "id": "00000000-0000-0000-0000-00000000c301",
                        "captured_at": "2026-01-01T00:00:00Z",
                        "level": "info",
                        "source": "test",
                        "title": "one",
                        "message": "one"
                    },
                    {
                        "id": "00000000-0000-0000-0000-00000000c302",
                        "captured_at": "2026-01-01T00:00:01Z",
                        "level": "info",
                        "source": "test",
                        "title": "two",
                        "message": "two"
                    }
                ],
                "fuzzer_attacks": [
                    {
                        "id": "00000000-0000-0000-0000-00000000c401",
                        "started_at": "2026-01-01T00:00:00Z",
                        "completed_at": "2026-01-01T00:00:01Z",
                        "status": "completed",
                        "template": {
                            "scheme": "https",
                            "host": "one.example",
                            "method": "GET",
                            "path": "/"
                        }
                    },
                    {
                        "id": "00000000-0000-0000-0000-00000000c402",
                        "started_at": "2026-01-01T00:00:01Z",
                        "completed_at": "2026-01-01T00:00:02Z",
                        "status": "completed",
                        "template": {
                            "scheme": "https",
                            "host": "two.example",
                            "method": "GET",
                            "path": "/"
                        }
                    }
                ]
            }))
            .expect("snapshot should deserialize");
        snapshot.match_replace_rules = (0..=crate::match_replace::MAX_MATCH_REPLACE_RULES)
            .map(|index| MatchReplaceRule {
                id: Uuid::new_v4(),
                enabled: true,
                description: format!("rule {index}"),
                scope: MatchReplaceScope::Request,
                target: MatchReplaceTarget::Path,
                search: "/old".to_string(),
                replace: "/new".to_string(),
                regex: false,
                case_sensitive: false,
            })
            .collect();
        let mut metadata = super::default_session_metadata("counts");

        assert!(super::update_metadata_counts_from_snapshot(
            &mut metadata,
            &snapshot,
            1,
            1
        ));

        assert_eq!(metadata.request_count, 1);
        assert_eq!(metadata.websocket_count, 2);
        assert_eq!(metadata.event_count, 1);
        assert_eq!(metadata.fuzzer_count, 1);
        assert_eq!(
            metadata.rule_count,
            crate::match_replace::MAX_MATCH_REPLACE_RULES
        );
    }

    #[tokio::test]
    async fn session_restore_drops_invalid_sequence_definitions() {
        let storage_dir = std::env::temp_dir().join(format!(
            "sniper-invalid-sequence-restore-{}",
            uuid::Uuid::new_v4()
        ));
        let invalid = SequenceDefinition {
            id: Uuid::new_v4(),
            name: "Invalid restored sequence".to_string(),
            steps: vec![SequenceStep {
                id: Uuid::new_v4(),
                label: "extract".to_string(),
                request: EditableRequest {
                    scheme: "https".to_string(),
                    host: "example.com".to_string(),
                    method: "GET".to_string(),
                    path: "/".to_string(),
                    headers: Vec::new(),
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                source_transaction_id: None,
                http_version: None,
                target: None,
                request_text: None,
                request_parse_error: None,
                extractions: vec![ExtractionRule {
                    variable_name: "token".to_string(),
                    source: ExtractionSource::ResponseBody,
                    pattern: "(".to_string(),
                    group: 1,
                }],
            }],
        };
        let valid_id = Uuid::new_v4();
        let valid = SequenceDefinition {
            id: valid_id,
            name: "Valid restored sequence".to_string(),
            steps: Vec::new(),
        };
        let snapshot = super::StoredSessionSnapshot {
            sequence_definitions: vec![invalid, valid],
            ..super::StoredSessionSnapshot::default()
        };

        let session = super::SessionContext::from_snapshot_read_only(
            super::default_session_metadata("sequence restore"),
            storage_dir.clone(),
            100,
            100,
            super::MAX_PERSISTED_WEBSOCKET_FRAMES_PER_SESSION,
            snapshot,
        );

        let definitions = session.sequence.list_definitions().await;
        assert_eq!(definitions.len(), 1);
        assert_eq!(definitions[0].id, valid_id);

        let _ = std::fs::remove_dir_all(storage_dir);
    }

    #[test]
    fn stored_snapshot_accepts_legacy_transaction_without_optional_metadata() {
        let snapshot: super::StoredSessionSnapshot = serde_json::from_value(serde_json::json!({
            "transactions": [{
                "id": "00000000-0000-0000-0000-00000000b101",
                "started_at": "2026-01-01T00:00:00Z",
                "method": "GET",
                "scheme": "https",
                "host": "example.com",
                "path": "/legacy",
                "status": 200,
                "request": {
                    "headers": [{ "name": "host", "value": "example.com" }]
                }
            }]
        }))
        .expect("legacy transaction should not break snapshot parsing");

        let transaction = snapshot
            .transactions
            .first()
            .expect("transaction should survive");
        assert!(matches!(transaction.kind, crate::model::TrafficKind::Http));
        assert_eq!(transaction.duration_ms, 0);
        assert!(transaction.notes.is_empty());
        assert_eq!(transaction.summary().note_count, 0);
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
            decoded_body_size: None,
            preview_truncated: false,
            content_type: Some("application/json".to_string()),
            content_decoded: false,
        };
        let response = MessageRecord {
            headers: vec![HeaderRecord {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            }],
            body_preview: "{\"ok\":true}".to_string(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 11,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: Some("application/json".to_string()),
            content_decoded: false,
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
                None,
                None,
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

    #[tokio::test]
    async fn registry_replays_transaction_journal_entries_after_snapshot() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-journal-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();

        let request = MessageRecord {
            headers: vec![HeaderRecord {
                name: "host".to_string(),
                value: "journal.example".to_string(),
            }],
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };
        let record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "journal.example:443".to_string(),
            "/from-journal".to_string(),
            Some(200),
            7,
            request,
            None,
            vec!["journaled".to_string()],
            None,
            None,
        );
        let record_id = record.id;

        let storage_dir = registry.session_storage_path(active.id()).unwrap();
        let journal_path = super::transaction_journal_path(&storage_dir);
        let mut lines = Vec::new();
        serde_json::to_writer(&mut lines, &TransactionJournalEntry::Insert { record }).unwrap();
        lines.push(b'\n');
        serde_json::to_writer(
            &mut lines,
            &TransactionJournalEntry::Annotation {
                id: record_id,
                color_tag: Some(NullableStringPatch::Set("red".to_string())),
                user_note: Some(NullableStringPatch::Set("remember me".to_string())),
                annotation_revision: Some(1),
                previous_annotation_revision: Some(0),
                annotation_client_id: None,
                annotation_client_version: None,
                previous_color_tag: None,
                previous_user_note: None,
            },
        )
        .unwrap();
        lines.push(b'\n');
        std::fs::write(&journal_path, lines).unwrap();
        let registry_path = data_dir
            .join(super::SESSIONS_DIR)
            .join(super::REGISTRY_FILE);
        let registry_before = std::fs::read(&registry_path).unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.store.snapshot(Some(10)).await;

        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].method, "GET");
        assert_eq!(restored[0].host, "journal.example:443");
        assert_eq!(restored[0].path, "/from-journal");
        assert_eq!(restored[0].notes, vec!["journaled".to_string()]);
        assert_eq!(restored[0].color_tag.as_deref(), Some("red"));
        assert_eq!(restored[0].user_note.as_deref(), Some("remember me"));
        assert_eq!(loaded.summary(true).request_count, 1);
        assert_ne!(std::fs::read(&registry_path).unwrap(), registry_before);
        let summary = registry
            .summaries()
            .into_iter()
            .find(|summary| summary.id == active.id())
            .unwrap();
        assert_eq!(summary.request_count, 1);
        assert_eq!(std::fs::metadata(&journal_path).unwrap().len(), 0);
    }

    #[tokio::test]
    async fn registry_replays_transaction_journal_update_after_insert() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-journal-update-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();

        let request = MessageRecord {
            headers: vec![HeaderRecord {
                name: "host".to_string(),
                value: "streamed.example".to_string(),
            }],
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };
        let provisional = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "streamed.example:443".to_string(),
            "/events".to_string(),
            None,
            0,
            request,
            None,
            vec!["Streaming response capture is still in progress.".to_string()],
            None,
            None,
        );
        let record_id = provisional.id;
        let mut completed = provisional.clone();
        completed.status = Some(200);
        completed.duration_ms = 42;
        completed.response = Some(MessageRecord {
            headers: vec![HeaderRecord {
                name: "content-type".to_string(),
                value: "text/event-stream".to_string(),
            }],
            body_preview: "done".to_string(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 4,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: Some("text/event-stream".to_string()),
            content_decoded: false,
        });
        completed.notes = vec!["stream complete".to_string()];

        let storage_dir = registry.session_storage_path(active.id()).unwrap();
        let journal_path = super::transaction_journal_path(&storage_dir);
        let mut lines = Vec::new();
        serde_json::to_writer(
            &mut lines,
            &TransactionJournalEntry::Insert {
                record: provisional,
            },
        )
        .unwrap();
        lines.push(b'\n');
        serde_json::to_writer(
            &mut lines,
            &TransactionJournalEntry::Update { record: completed },
        )
        .unwrap();
        lines.push(b'\n');
        std::fs::write(&journal_path, lines).unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.store.snapshot(Some(10)).await;

        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].id, record_id);
        assert_eq!(restored[0].status, Some(200));
        assert_eq!(restored[0].duration_ms, 42);
        assert_eq!(restored[0].notes, vec!["stream complete".to_string()]);
        assert_eq!(
            restored[0]
                .response
                .as_ref()
                .map(|response| response.body_preview.as_str()),
            Some("done")
        );
        assert_eq!(std::fs::metadata(&journal_path).unwrap().len(), 0);
    }

    #[tokio::test]
    async fn registry_replay_advances_transaction_event_sequence_for_annotations() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-journal-event-sequence-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
        let storage_dir = registry.session_storage_path(active.id()).unwrap();

        let mut record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "event-sequence.example:443".to_string(),
            "/snapshot".to_string(),
            Some(200),
            1,
            MessageRecord {
                headers: vec![],
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            },
            None,
            vec![],
            None,
            None,
        );
        record.sequence = 1;
        let record_id = record.id;
        super::write_json(
            &super::snapshot_path(&storage_dir),
            &super::StoredSessionSnapshot {
                transactions: vec![record],
                transaction_event_sequence: 1,
                ..Default::default()
            },
        )
        .unwrap();

        let mut journal = Vec::new();
        serde_json::to_writer(
            &mut journal,
            &TransactionJournalEntry::Annotation {
                id: record_id,
                color_tag: Some(NullableStringPatch::Set("green".to_string())),
                user_note: None,
                annotation_revision: Some(1),
                previous_annotation_revision: Some(0),
                annotation_client_id: None,
                annotation_client_version: None,
                previous_color_tag: None,
                previous_user_note: None,
            },
        )
        .unwrap();
        journal.push(b'\n');
        std::fs::write(super::transaction_journal_path(&storage_dir), journal).unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.store.snapshot(Some(10)).await;

        assert_eq!(loaded.store.latest_sequence(), 1);
        assert_eq!(loaded.store.latest_event_sequence(), 2);
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].color_tag.as_deref(), Some("green"));

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn registry_replays_journal_after_repairing_unadvanceable_snapshot_sequence() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-journal-sequence-repair-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
        let storage_dir = registry.session_storage_path(active.id()).unwrap();

        let mut snapshot_record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "snapshot-max.example:443".to_string(),
            "/snapshot-max".to_string(),
            Some(200),
            1,
            MessageRecord {
                headers: vec![],
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            },
            None,
            vec![],
            None,
            None,
        );
        snapshot_record.sequence = u64::MAX;
        super::write_json(
            &super::snapshot_path(&storage_dir),
            &super::StoredSessionSnapshot {
                transactions: vec![snapshot_record],
                ..Default::default()
            },
        )
        .unwrap();

        let mut journal_record = TransactionRecord::http(
            Utc::now(),
            "POST".to_string(),
            "https".to_string(),
            "journal-after-max.example:443".to_string(),
            "/journal-after-max".to_string(),
            Some(201),
            1,
            MessageRecord {
                headers: vec![],
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            },
            None,
            vec![],
            None,
            None,
        );
        journal_record.sequence = 2;
        let mut journal = Vec::new();
        serde_json::to_writer(
            &mut journal,
            &TransactionJournalEntry::Insert {
                record: journal_record,
            },
        )
        .unwrap();
        journal.push(b'\n');
        std::fs::write(super::transaction_journal_path(&storage_dir), journal).unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.store.snapshot(Some(10)).await;

        assert_eq!(
            restored
                .iter()
                .map(|record| (record.host.as_str(), record.sequence))
                .collect::<Vec<_>>(),
            vec![
                ("journal-after-max.example:443", 2),
                ("snapshot-max.example:443", 1),
            ]
        );

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn registry_replays_low_sequence_journal_when_snapshot_window_is_not_full() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-journal-low-sequence-replay-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
        let storage_dir = registry.session_storage_path(active.id()).unwrap();

        let mut snapshot_record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "snapshot-high.example:443".to_string(),
            "/snapshot-high".to_string(),
            Some(200),
            1,
            MessageRecord {
                headers: vec![],
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            },
            None,
            vec![],
            None,
            None,
        );
        snapshot_record.sequence = 1_000_000;
        let scanner_config = ScannerConfig {
            enabled: true,
            rules: BUILTIN_RULES
                .iter()
                .map(|(id, _)| ((*id).to_string(), false))
                .collect(),
            custom_rules: vec![CustomRule {
                id: "journal-secret".to_string(),
                name: "Journal secret".to_string(),
                enabled: true,
                target: "response_body".to_string(),
                header_name: String::new(),
                pattern: "journal-secret-token".to_string(),
                severity: Severity::High,
                category: "custom".to_string(),
                description: "journal replay scanner recovery".to_string(),
            }],
        };
        super::write_json(
            &super::snapshot_path(&storage_dir),
            &super::StoredSessionSnapshot {
                transactions: vec![snapshot_record],
                scanner_config,
                ..Default::default()
            },
        )
        .unwrap();

        let mut journal_record = TransactionRecord::http(
            Utc::now(),
            "POST".to_string(),
            "https".to_string(),
            "journal-low.example:443".to_string(),
            "/journal-low".to_string(),
            Some(201),
            1,
            MessageRecord {
                headers: vec![],
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            },
            Some(MessageRecord {
                headers: vec![],
                body_preview: "journal-secret-token".to_string(),
                body_encoding: BodyEncoding::Utf8,
                body_size: "journal-secret-token".len(),
                decoded_body_size: None,
                preview_truncated: false,
                content_type: Some("text/plain".to_string()),
                content_decoded: false,
            }),
            vec![],
            None,
            None,
        );
        journal_record.sequence = 2;
        let journal_record_id = journal_record.id;
        let mut journal = Vec::new();
        serde_json::to_writer(
            &mut journal,
            &TransactionJournalEntry::Insert {
                record: journal_record,
            },
        )
        .unwrap();
        journal.push(b'\n');
        std::fs::write(super::transaction_journal_path(&storage_dir), journal).unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.store.snapshot(Some(10)).await;
        let findings = loaded.scanner.list(None).await;

        assert_eq!(
            restored
                .iter()
                .map(|record| record.host.as_str())
                .collect::<Vec<_>>(),
            vec!["journal-low.example:443", "snapshot-high.example:443"]
        );
        assert!(findings.iter().any(|finding| {
            finding.record_id == journal_record_id && finding.rule_id == "journal-secret"
        }));

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn registry_ignores_trailing_partial_transaction_journal_line() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-journal-partial-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();

        let request = MessageRecord {
            headers: vec![HeaderRecord {
                name: "host".to_string(),
                value: "partial.example".to_string(),
            }],
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };
        let record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "partial.example:443".to_string(),
            "/before-partial".to_string(),
            Some(200),
            5,
            request,
            None,
            vec![],
            None,
            None,
        );

        let storage_dir = registry.session_storage_path(active.id()).unwrap();
        let journal_path = super::transaction_journal_path(&storage_dir);
        let mut lines = Vec::new();
        serde_json::to_writer(&mut lines, &TransactionJournalEntry::Insert { record }).unwrap();
        lines.push(b'\n');
        lines.extend_from_slice(br#"{"type":"insert""#);
        std::fs::write(journal_path, lines).unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.store.snapshot(Some(10)).await;

        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].host, "partial.example:443");
        assert_eq!(restored[0].path, "/before-partial");
    }

    #[tokio::test]
    async fn registry_repairs_partial_transaction_journal_tail_before_future_appends() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-journal-partial-append-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();

        let first = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "partial-before.example:443".to_string(),
            "/before-partial".to_string(),
            Some(200),
            1,
            MessageRecord {
                headers: vec![],
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            },
            None,
            vec![],
            None,
            None,
        );

        let storage_dir = registry.session_storage_path(active.id()).unwrap();
        let journal_path = super::transaction_journal_path(&storage_dir);
        let mut lines = Vec::new();
        serde_json::to_writer(
            &mut lines,
            &TransactionJournalEntry::Insert { record: first },
        )
        .unwrap();
        lines.push(b'\n');
        lines.extend_from_slice(br#"{"type":"insert""#);
        std::fs::write(&journal_path, lines).unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        loaded
            .store
            .insert(TransactionRecord::http(
                Utc::now(),
                "POST".to_string(),
                "https".to_string(),
                "partial-after.example:443".to_string(),
                "/after-partial".to_string(),
                Some(201),
                2,
                MessageRecord {
                    headers: vec![],
                    body_preview: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    body_size: 0,
                    decoded_body_size: None,
                    preview_truncated: false,
                    content_type: None,
                    content_decoded: false,
                },
                None,
                vec![],
                None,
                None,
            ))
            .await;

        let reloaded = registry.load_context(active.id()).unwrap();
        let restored = reloaded.store.snapshot(Some(10)).await;
        assert!(restored
            .iter()
            .any(|record| record.host == "partial-before.example:443"));
        assert!(restored
            .iter()
            .any(|record| record.host == "partial-after.example:443"));

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn registry_ignores_trailing_partial_utf8_transaction_journal_line() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-journal-partial-utf8-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();

        let record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "partial-utf8.example:443".to_string(),
            "/before-partial-utf8".to_string(),
            Some(200),
            6,
            MessageRecord {
                headers: vec![],
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            },
            None,
            vec![],
            None,
            None,
        );

        let storage_dir = registry.session_storage_path(active.id()).unwrap();
        let journal_path = super::transaction_journal_path(&storage_dir);
        let mut lines = Vec::new();
        serde_json::to_writer(&mut lines, &TransactionJournalEntry::Insert { record }).unwrap();
        lines.push(b'\n');
        lines.extend_from_slice(b"{\"type\":\"insert\",\"record\":{\"body\":\"");
        lines.extend_from_slice(&[0xF0, 0x9F]);
        std::fs::write(journal_path, lines).unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.store.snapshot(Some(10)).await;

        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].host, "partial-utf8.example:443");
        assert_eq!(restored[0].path, "/before-partial-utf8");
    }

    #[tokio::test]
    async fn registry_replays_transaction_journal_checkpoint_before_active_journal() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-journal-checkpoint-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();

        let old_record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "checkpoint.example:443".to_string(),
            "/checkpoint".to_string(),
            Some(200),
            1,
            MessageRecord {
                headers: vec![],
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            },
            None,
            vec![],
            None,
            None,
        );
        let new_record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "active.example:443".to_string(),
            "/active".to_string(),
            Some(200),
            1,
            MessageRecord {
                headers: vec![],
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            },
            None,
            vec![],
            None,
            None,
        );

        let storage_dir = registry.session_storage_path(active.id()).unwrap();
        let journal_path = super::transaction_journal_path(&storage_dir);
        let checkpoint_path = transaction_journal_checkpoint_path(&journal_path);

        let mut checkpoint = Vec::new();
        serde_json::to_writer(
            &mut checkpoint,
            &TransactionJournalEntry::Insert { record: old_record },
        )
        .unwrap();
        checkpoint.push(b'\n');
        std::fs::write(&checkpoint_path, checkpoint).unwrap();

        let mut active_journal = Vec::new();
        serde_json::to_writer(
            &mut active_journal,
            &TransactionJournalEntry::Insert { record: new_record },
        )
        .unwrap();
        active_journal.push(b'\n');
        std::fs::write(&journal_path, active_journal).unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.store.snapshot(Some(10)).await;

        assert_eq!(restored.len(), 2);
        assert_eq!(restored[0].host, "active.example:443");
        assert_eq!(restored[1].host, "checkpoint.example:443");
        assert_eq!(std::fs::metadata(&journal_path).unwrap().len(), 0);
        assert!(!checkpoint_path.exists());
    }

    #[tokio::test]
    async fn registry_compacts_duplicate_checkpoint_without_repeated_event_gap() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-duplicate-checkpoint-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
        let storage_dir = registry.session_storage_path(active.id()).unwrap();

        let mut record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "duplicate-checkpoint.example:443".to_string(),
            "/snapshot".to_string(),
            Some(200),
            1,
            MessageRecord {
                headers: vec![],
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            },
            None,
            vec![],
            None,
            None,
        );
        record.sequence = 1;
        super::write_json(
            &super::snapshot_path(&storage_dir),
            &super::StoredSessionSnapshot {
                transactions: vec![record.clone()],
                transaction_event_sequence: 1,
                ..Default::default()
            },
        )
        .unwrap();

        let journal_path = super::transaction_journal_path(&storage_dir);
        let checkpoint_path = transaction_journal_checkpoint_path(&journal_path);
        let mut checkpoint = Vec::new();
        serde_json::to_writer(&mut checkpoint, &TransactionJournalEntry::Insert { record })
            .unwrap();
        checkpoint.push(b'\n');
        std::fs::write(&checkpoint_path, checkpoint).unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.store.snapshot(Some(10)).await;

        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].host, "duplicate-checkpoint.example:443");
        assert_eq!(loaded.store.latest_event_sequence(), 2);
        assert!(!checkpoint_path.exists());

        let persisted: super::StoredSessionSnapshot =
            serde_json::from_slice(&std::fs::read(super::snapshot_path(&storage_dir)).unwrap())
                .unwrap();
        assert_eq!(persisted.transaction_event_sequence, 2);
        assert_eq!(persisted.transactions.len(), 1);
    }

    #[tokio::test]
    async fn registry_keeps_replayed_checkpoint_entries_when_journal_rotates_before_snapshot() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-journal-merge-checkpoint-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();

        let old_record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "checkpoint.example:443".to_string(),
            "/checkpoint".to_string(),
            Some(200),
            1,
            MessageRecord {
                headers: vec![],
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            },
            None,
            vec![],
            None,
            None,
        );
        let new_record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "active.example:443".to_string(),
            "/active".to_string(),
            Some(200),
            1,
            MessageRecord {
                headers: vec![],
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            },
            None,
            vec![],
            None,
            None,
        );

        let storage_dir = registry.session_storage_path(active.id()).unwrap();
        let journal_path = super::transaction_journal_path(&storage_dir);
        let checkpoint_path = transaction_journal_checkpoint_path(&journal_path);
        let mut checkpoint = Vec::new();
        serde_json::to_writer(
            &mut checkpoint,
            &TransactionJournalEntry::Insert { record: old_record },
        )
        .unwrap();
        checkpoint.push(b'\n');
        std::fs::write(&checkpoint_path, checkpoint).unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        loaded.store.insert(new_record).await;
        loaded
            .store
            .snapshot_for_persistence(Some(32))
            .await
            .unwrap();

        let reloaded = registry.load_context(active.id()).unwrap();
        let restored = reloaded.store.snapshot(Some(10)).await;

        assert_eq!(restored.len(), 2);
        assert!(restored
            .iter()
            .any(|record| record.host == "active.example:443"));
        assert!(restored
            .iter()
            .any(|record| record.host == "checkpoint.example:443"));
    }

    #[tokio::test]
    async fn registry_checkpoint_annotations_do_not_overwrite_snapshot_records() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-journal-checkpoint-annotation-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();

        let mut record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "checkpoint-annotation.example:443".to_string(),
            "/checkpoint-annotation".to_string(),
            Some(200),
            1,
            MessageRecord {
                headers: vec![],
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            },
            None,
            vec![],
            None,
            None,
        );
        record.sequence = 9;
        record.color_tag = Some("blue".to_string());
        let record_id = record.id;

        let storage_dir = registry.session_storage_path(active.id()).unwrap();
        let snapshot = super::StoredSessionSnapshot {
            transactions: vec![record],
            ..Default::default()
        };
        super::write_json(&super::snapshot_path(&storage_dir), &snapshot).unwrap();

        let journal_path = super::transaction_journal_path(&storage_dir);
        let checkpoint_path = transaction_journal_checkpoint_path(&journal_path);
        let mut checkpoint = Vec::new();
        serde_json::to_writer(
            &mut checkpoint,
            &TransactionJournalEntry::Annotation {
                id: record_id,
                color_tag: Some(NullableStringPatch::Set("red".to_string())),
                user_note: None,
                annotation_revision: Some(1),
                previous_annotation_revision: Some(0),
                annotation_client_id: None,
                annotation_client_version: None,
                previous_color_tag: None,
                previous_user_note: None,
            },
        )
        .unwrap();
        checkpoint.push(b'\n');
        std::fs::write(checkpoint_path, checkpoint).unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.store.snapshot(Some(10)).await;

        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].color_tag.as_deref(), Some("blue"));
    }

    #[tokio::test]
    async fn registry_checkpoint_annotation_with_previous_updates_old_snapshot_record() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-journal-checkpoint-annotation-previous-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();

        let mut record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "checkpoint-annotation-previous.example:443".to_string(),
            "/checkpoint-annotation-previous".to_string(),
            Some(200),
            1,
            MessageRecord {
                headers: vec![],
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            },
            None,
            vec![],
            None,
            None,
        );
        record.sequence = 9;
        record.color_tag = Some("blue".to_string());
        let record_id = record.id;

        let storage_dir = registry.session_storage_path(active.id()).unwrap();
        let snapshot = super::StoredSessionSnapshot {
            transactions: vec![record],
            ..Default::default()
        };
        super::write_json(&super::snapshot_path(&storage_dir), &snapshot).unwrap();

        let journal_path = super::transaction_journal_path(&storage_dir);
        let checkpoint_path = transaction_journal_checkpoint_path(&journal_path);
        let mut checkpoint = Vec::new();
        serde_json::to_writer(
            &mut checkpoint,
            &TransactionJournalEntry::Annotation {
                id: record_id,
                color_tag: Some(NullableStringPatch::Set("red".to_string())),
                user_note: None,
                annotation_revision: Some(1),
                previous_annotation_revision: Some(0),
                annotation_client_id: None,
                annotation_client_version: None,
                previous_color_tag: Some(NullableStringPatch::Set("blue".to_string())),
                previous_user_note: Some(NullableStringPatch::Clear),
            },
        )
        .unwrap();
        checkpoint.push(b'\n');
        std::fs::write(checkpoint_path, checkpoint).unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.store.snapshot(Some(10)).await;

        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].color_tag.as_deref(), Some("red"));
    }

    #[tokio::test]
    async fn registry_active_journal_annotations_still_update_snapshot_records() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-journal-active-annotation-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();

        let mut record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "active-annotation.example:443".to_string(),
            "/active-annotation".to_string(),
            Some(200),
            1,
            MessageRecord {
                headers: vec![],
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            },
            None,
            vec![],
            None,
            None,
        );
        record.sequence = 11;
        record.color_tag = Some("blue".to_string());
        let record_id = record.id;

        let storage_dir = registry.session_storage_path(active.id()).unwrap();
        let snapshot = super::StoredSessionSnapshot {
            transactions: vec![record],
            ..Default::default()
        };
        super::write_json(&super::snapshot_path(&storage_dir), &snapshot).unwrap();

        let journal_path = super::transaction_journal_path(&storage_dir);
        let mut journal = Vec::new();
        serde_json::to_writer(
            &mut journal,
            &TransactionJournalEntry::Annotation {
                id: record_id,
                color_tag: Some(NullableStringPatch::Set("green".to_string())),
                user_note: None,
                annotation_revision: Some(1),
                previous_annotation_revision: Some(0),
                annotation_client_id: None,
                annotation_client_version: None,
                previous_color_tag: None,
                previous_user_note: None,
            },
        )
        .unwrap();
        journal.push(b'\n');
        std::fs::write(&journal_path, journal).unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.store.snapshot(Some(10)).await;

        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].color_tag.as_deref(), Some("green"));
        assert_eq!(std::fs::metadata(&journal_path).unwrap().len(), 0);

        let disk_snapshot: super::StoredSessionSnapshot =
            serde_json::from_slice(&std::fs::read(super::snapshot_path(&storage_dir)).unwrap())
                .unwrap();
        assert_eq!(
            disk_snapshot.transactions[0].color_tag.as_deref(),
            Some("green")
        );

        let reloaded = registry.load_context(active.id()).unwrap();
        let reloaded_records = reloaded.store.snapshot(Some(10)).await;
        assert_eq!(reloaded_records[0].color_tag.as_deref(), Some("green"));
    }

    #[tokio::test]
    async fn registry_ignores_old_journal_entries_already_trimmed_from_snapshot() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-journal-trim-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 2, 32).unwrap();

        let mut records = Vec::new();
        for sequence in 1..=4 {
            let mut record = TransactionRecord::http(
                Utc::now(),
                "GET".to_string(),
                "https".to_string(),
                format!("{sequence}.example:443"),
                format!("/{sequence}"),
                Some(200),
                1,
                MessageRecord {
                    headers: vec![],
                    body_preview: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    body_size: 0,
                    decoded_body_size: None,
                    preview_truncated: false,
                    content_type: None,
                    content_decoded: false,
                },
                None,
                vec![],
                None,
                None,
            );
            record.sequence = sequence;
            records.push(record);
        }

        let storage_dir = registry.session_storage_path(active.id()).unwrap();
        let snapshot = super::StoredSessionSnapshot {
            transactions: vec![records[3].clone(), records[2].clone()],
            ..Default::default()
        };
        super::write_json(&super::snapshot_path(&storage_dir), &snapshot).unwrap();

        let journal_path = super::transaction_journal_path(&storage_dir);
        let mut journal = Vec::new();
        for record in records {
            serde_json::to_writer(&mut journal, &TransactionJournalEntry::Insert { record })
                .unwrap();
            journal.push(b'\n');
        }
        std::fs::write(journal_path, journal).unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.store.snapshot(Some(10)).await;

        assert_eq!(restored.len(), 2);
        assert_eq!(restored[0].host, "4.example:443");
        assert_eq!(restored[1].host, "3.example:443");
    }

    #[tokio::test]
    async fn registry_backfill_does_not_evict_full_snapshot_window() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-journal-backfill-full-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 2, 32).unwrap();

        let mut records = Vec::new();
        for sequence in 1..=4 {
            let mut record = TransactionRecord::http(
                Utc::now(),
                "GET".to_string(),
                "https".to_string(),
                format!("{sequence}.example:443"),
                format!("/{sequence}"),
                Some(200),
                1,
                MessageRecord {
                    headers: vec![],
                    body_preview: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    body_size: 0,
                    decoded_body_size: None,
                    preview_truncated: false,
                    content_type: None,
                    content_decoded: false,
                },
                None,
                vec![],
                None,
                None,
            );
            record.sequence = sequence;
            records.push(record);
        }

        let storage_dir = registry.session_storage_path(active.id()).unwrap();
        let snapshot = super::StoredSessionSnapshot {
            transactions: vec![records[3].clone(), records[2].clone()],
            ..Default::default()
        };
        super::write_json(&super::snapshot_path(&storage_dir), &snapshot).unwrap();

        let mut journal = Vec::new();
        for record in [records[0].clone(), records[1].clone()] {
            serde_json::to_writer(&mut journal, &TransactionJournalEntry::Insert { record })
                .unwrap();
            journal.push(b'\n');
        }
        std::fs::write(super::transaction_journal_path(&storage_dir), journal).unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.store.snapshot(Some(10)).await;

        assert_eq!(
            restored
                .iter()
                .map(|record| record.host.as_str())
                .collect::<Vec<_>>(),
            vec!["4.example:443", "3.example:443"]
        );
    }

    #[tokio::test]
    async fn registry_keeps_journal_when_only_trimmed_backfill_annotation_mutates() {
        fn record(sequence: u64) -> TransactionRecord {
            let mut record = TransactionRecord::http(
                Utc::now(),
                "GET".to_string(),
                "https".to_string(),
                format!("{sequence}.example:443"),
                format!("/{sequence}"),
                Some(200),
                1,
                MessageRecord {
                    headers: vec![],
                    body_preview: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    body_size: 0,
                    decoded_body_size: None,
                    preview_truncated: false,
                    content_type: None,
                    content_decoded: false,
                },
                None,
                vec![],
                None,
                None,
            );
            record.sequence = sequence;
            record
        }

        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-journal-backfill-annotation-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 1, 32).unwrap();
        let retained_record = record(2);
        let backfill_record = record(1);
        let backfill_record_id = backfill_record.id;

        let storage_dir = registry.session_storage_path(active.id()).unwrap();
        let snapshot = super::StoredSessionSnapshot {
            transactions: vec![retained_record],
            ..Default::default()
        };
        super::write_json(&super::snapshot_path(&storage_dir), &snapshot).unwrap();

        let journal_path = super::transaction_journal_path(&storage_dir);
        let mut journal = Vec::new();
        serde_json::to_writer(
            &mut journal,
            &TransactionJournalEntry::Insert {
                record: backfill_record,
            },
        )
        .unwrap();
        journal.push(b'\n');
        serde_json::to_writer(
            &mut journal,
            &TransactionJournalEntry::Annotation {
                id: backfill_record_id,
                color_tag: Some(NullableStringPatch::Set("red".to_string())),
                user_note: None,
                annotation_revision: Some(1),
                previous_annotation_revision: Some(0),
                annotation_client_id: None,
                annotation_client_version: None,
                previous_color_tag: None,
                previous_user_note: None,
            },
        )
        .unwrap();
        journal.push(b'\n');
        std::fs::write(&journal_path, journal).unwrap();
        let journal_len_before = std::fs::metadata(&journal_path).unwrap().len();

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.store.snapshot(Some(10)).await;

        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].host, "2.example:443");
        assert_eq!(
            std::fs::metadata(&journal_path).unwrap().len(),
            journal_len_before
        );

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn registry_bounds_active_journal_replay_to_max_entries() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-journal-replay-bound-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 2, 32).unwrap();

        let storage_dir = registry.session_storage_path(active.id()).unwrap();
        super::write_json(
            &super::snapshot_path(&storage_dir),
            &super::StoredSessionSnapshot::default(),
        )
        .unwrap();

        let journal_path = super::transaction_journal_path(&storage_dir);
        let mut journal = Vec::new();
        for sequence in 1..=32 {
            let mut record = TransactionRecord::http(
                Utc::now(),
                "GET".to_string(),
                "https".to_string(),
                format!("{sequence}.example:443"),
                format!("/{sequence}"),
                Some(200),
                1,
                MessageRecord {
                    headers: vec![],
                    body_preview: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    body_size: 0,
                    decoded_body_size: None,
                    preview_truncated: false,
                    content_type: None,
                    content_decoded: false,
                },
                None,
                vec![],
                None,
                None,
            );
            record.sequence = sequence;
            serde_json::to_writer(&mut journal, &TransactionJournalEntry::Insert { record })
                .unwrap();
            journal.push(b'\n');
        }
        std::fs::write(journal_path, journal).unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.store.snapshot(Some(10)).await;

        assert_eq!(restored.len(), 2);
        assert_eq!(restored[0].host, "32.example:443");
        assert_eq!(restored[1].host, "31.example:443");
    }

    #[tokio::test]
    async fn registry_uses_separate_transaction_retention_limit() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-transaction-retention-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) =
            SessionRegistry::load_or_create_with_transaction_limit(&data_dir, 2, 5, 32).unwrap();

        let storage_dir = registry.session_storage_path(active.id()).unwrap();
        super::write_json(
            &super::snapshot_path(&storage_dir),
            &super::StoredSessionSnapshot::default(),
        )
        .unwrap();

        let journal_path = super::transaction_journal_path(&storage_dir);
        let mut journal = Vec::new();
        for sequence in 1..=8 {
            let mut record = TransactionRecord::http(
                Utc::now(),
                "GET".to_string(),
                "https".to_string(),
                format!("{sequence}.example:443"),
                format!("/{sequence}"),
                Some(200),
                1,
                MessageRecord {
                    headers: vec![],
                    body_preview: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    body_size: 0,
                    decoded_body_size: None,
                    preview_truncated: false,
                    content_type: None,
                    content_decoded: false,
                },
                None,
                vec![],
                None,
                None,
            );
            record.sequence = sequence;
            serde_json::to_writer(&mut journal, &TransactionJournalEntry::Insert { record })
                .unwrap();
            journal.push(b'\n');
        }
        std::fs::write(journal_path, journal).unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.store.snapshot(Some(10)).await;

        assert_eq!(restored.len(), 5);
        assert_eq!(
            restored
                .iter()
                .map(|record| record.host.as_str())
                .collect::<Vec<_>>(),
            vec![
                "8.example:443",
                "7.example:443",
                "6.example:443",
                "5.example:443",
                "4.example:443"
            ]
        );

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn registry_persist_compacts_transaction_journal_after_snapshot() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-journal-compact-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();

        active
            .store
            .insert(TransactionRecord::http(
                Utc::now(),
                "GET".to_string(),
                "https".to_string(),
                "compact.example:443".to_string(),
                "/compact".to_string(),
                Some(200),
                1,
                MessageRecord {
                    headers: vec![],
                    body_preview: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    body_size: 0,
                    decoded_body_size: None,
                    preview_truncated: false,
                    content_type: None,
                    content_decoded: false,
                },
                None,
                vec![],
                None,
                None,
            ))
            .await;

        active.persist().await.unwrap();

        let storage_dir = registry.session_storage_path(active.id()).unwrap();
        let journal_path = super::transaction_journal_path(&storage_dir);
        let checkpoint_path = transaction_journal_checkpoint_path(&journal_path);
        let journal_len = std::fs::metadata(&journal_path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        assert_eq!(journal_len, 0);
        assert!(!checkpoint_path.exists());

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.store.snapshot(Some(10)).await;
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].host, "compact.example:443");
    }
}
