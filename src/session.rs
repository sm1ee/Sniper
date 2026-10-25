use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
    io::{self, BufRead, BufReader, BufWriter, Read, Seek, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc, RwLock,
    },
    thread,
};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use tokio::sync::{oneshot, Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard, OwnedMutexGuard};
use tracing::warn;
use uuid::Uuid;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::{
    api::validate_workspace_state,
    event_log::{EventLogEntry, EventLogStore},
    fuzzer::{FuzzerAttackRecord, FuzzerStore},
    intercept::{InterceptQueue, ResponseInterceptQueue},
    match_replace::{MatchReplaceRule, MatchReplaceScope, MatchReplaceStore, MatchReplaceTarget},
    model::{
        compact_annotation_client_versions_for_insert, TransactionRecord, WebSocketFrameRecord,
        WebSocketSessionRecord,
    },
    runtime::{RuntimeSettings, RuntimeSettingsSnapshot},
    scanner::{scan_transaction, ScannerConfig, ScannerFinding, ScannerStore, Severity},
    sequence::{SequenceDefinition, SequenceRunRecord, SequenceStore},
    store::{
        normalize_storage_sequences, transaction_journal_checkpoint_path, NullableStringPatch,
        TransactionJournalEntry, TransactionStore,
    },
    websocket::{sessions_with_live_preserved, trim_frame_overflow, WebSocketStore},
    workspace::{
        transform_saved_replay_tab, validate_workspace_serialized_size, SavedReplayTabOperation,
        WorkspacePersistCommit, WorkspaceReplaceError, WorkspaceTransformError,
    },
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
/// Everything except transactions and websockets. Those two dominate the session
/// document (89.9% on a real 1.35 GB session) and are durable through their own
/// journals, so the small components get a file that can be rewritten cheaply.
const STATE_FILE: &str = "state.json";
/// Captured transactions, one compact JSON record per line. Newline-delimited so
/// the 100,000 records of a real session can be parsed across cores: 2,408 ms to
/// parse them inside snapshot.json, 331 ms as this file on 10 threads.
const TRANSACTIONS_FILE: &str = "transactions.ndjson";
/// Body-less copies of the same records plus where each one's bodies sit, so a
/// load can skip reading the bodies at all. About 1.5 KB per record against 12 KB
/// in transactions.ndjson. Rebuilt from that file whenever it does not match.
const TRANSACTIONS_META_FILE: &str = "transactions.meta.ndjson";
/// Batches state-only persists. Long enough to fold a burst of scanner findings
/// into one write, short enough that a crash loses little.
const STATE_PERSIST_DEBOUNCE: std::time::Duration = std::time::Duration::from_millis(750);
/// Parsing is CPU-bound and each line is independent, but splitting work costs
/// something, so stay single-threaded for small files.
const PARALLEL_TRANSACTION_PARSE_MIN_BYTES: usize = 8 * 1024 * 1024;
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
    #[serde(default)]
    pub overview: SessionOverview,
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

/// A session as the Session screen lists it: its summary, what it holds, and
/// the bytes its files take on disk. Kept apart from `SessionSummary`, whose
/// fields the saved.v1 contract fixes and whose copies rename receipts keep.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionListing {
    #[serde(flatten)]
    pub summary: SessionSummary,
    pub overview: SessionOverview,
    pub storage_bytes: u64,
}

/// Findings counted by severity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl SeverityCounts {
    pub fn count<'a>(findings: impl IntoIterator<Item = &'a ScannerFinding>) -> Self {
        let mut counts = Self::default();
        for finding in findings {
            *match finding.severity {
                Severity::Critical => &mut counts.critical,
                Severity::High => &mut counts.high,
                Severity::Medium => &mut counts.medium,
                Severity::Low => &mut counts.low,
                Severity::Info => &mut counts.info,
            } += 1;
        }
        counts
    }
}

/// A host and how many of a session's requests went to it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRequestCount {
    pub host: String,
    pub requests: usize,
}

/// A scan or Recon job as the overview names it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityEntry {
    /// `manual scan`, `auto scan` or `recon`.
    pub kind: String,
    pub target: String,
    pub started_at: DateTime<Utc>,
    pub status: String,
    /// Templates that matched, for a scan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<usize>,
}

/// What tells sessions apart without opening them: the scope set, where the
/// traffic went, what the operator marked, pinned, rewrote and scanned, and
/// what was found. Stored with the counts on a full save; a loaded session
/// reports live values. Labels are the operator's own (a pinned tab's name, a
/// rule's description) or a method, host and path without its query, so no
/// captured value or rule text is copied into the registry.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionOverview {
    pub scope: Vec<String>,
    pub scope_count: usize,
    pub excluded_scope: Vec<String>,
    pub excluded_scope_count: usize,
    pub top_hosts: Vec<HostRequestCount>,
    pub last_captured_at: Option<DateTime<Utc>>,
    pub marked_requests: usize,
    pub pinned_replays: Vec<String>,
    pub pinned_replay_count: usize,
    pub replace_rules: Vec<String>,
    pub replace_rule_count: usize,
    pub activity: Vec<ActivityEntry>,
    pub activity_count: usize,
    pub findings: SeverityCounts,
}

/// How many of each list the overview keeps by name, and how long a name is.
const OVERVIEW_LIST_LIMIT: usize = 5;
const OVERVIEW_SCOPE_LIMIT: usize = 8;
const OVERVIEW_LABEL_CHARS: usize = 80;

/// What a session's records say about it.
#[derive(Debug, Default, PartialEq)]
pub struct TrafficOverview {
    pub top_hosts: Vec<HostRequestCount>,
    pub last_captured_at: Option<DateTime<Utc>>,
    pub marked_requests: usize,
}

impl TrafficOverview {
    /// CONNECT tunnels and records without a host stay out of the hosts, as the
    /// site map leaves them out. A mark is a colour or the operator's note, not
    /// a note Sniper adds itself.
    pub fn from_records<'a>(records: impl IntoIterator<Item = &'a TransactionRecord>) -> Self {
        let mut hosts: HashMap<&str, usize> = HashMap::new();
        let mut overview = Self::default();
        for record in records {
            overview.last_captured_at = overview.last_captured_at.max(Some(record.started_at));
            if record.color_tag.is_some() || record.user_note.is_some() {
                overview.marked_requests += 1;
            }
            if record.method != "CONNECT" && !record.host.is_empty() {
                *hosts.entry(record.host.as_str()).or_default() += 1;
            }
        }
        let mut ranked: Vec<_> = hosts.into_iter().collect();
        ranked
            .sort_unstable_by(|(a_host, a), (b_host, b)| b.cmp(a).then_with(|| a_host.cmp(b_host)));
        overview.top_hosts = ranked
            .into_iter()
            .take(OVERVIEW_LIST_LIMIT)
            .map(|(host, requests)| HostRequestCount {
                host: host.to_string(),
                requests,
            })
            .collect();
        overview
    }
}

impl SessionOverview {
    fn new(traffic: TrafficOverview, state: &StoredSessionSnapshot) -> Self {
        let pinned: Vec<_> = state
            .workspace
            .replay
            .tabs
            .iter()
            .filter(|tab| tab.pinned)
            .collect();
        let rules: Vec<_> = state
            .match_replace_rules
            .iter()
            .filter(|rule| rule.enabled)
            .collect();
        let mut activity: Vec<_> = state
            .template_scans
            .jobs
            .iter()
            .map(|job| ActivityEntry {
                kind: if job.auto { "auto scan" } else { "manual scan" }.to_string(),
                target: list_label(&job.targets),
                started_at: job.started_at,
                status: job.status.clone(),
                matched: Some(job.matched),
            })
            .chain(state.recon.jobs.iter().map(|job| ActivityEntry {
                kind: "recon".to_string(),
                target: overview_label(&job.target_url),
                started_at: job.started_at,
                status: job.status.clone(),
                matched: None,
            }))
            .collect();
        activity.sort_by(|a, b| b.started_at.cmp(&a.started_at));
        let activity_count = activity.len();
        activity.truncate(OVERVIEW_LIST_LIMIT);
        let runtime = &state.runtime;
        Self {
            scope: runtime
                .scope_patterns
                .iter()
                .take(OVERVIEW_SCOPE_LIMIT)
                .cloned()
                .collect(),
            scope_count: runtime.scope_patterns.len(),
            excluded_scope: runtime
                .excluded_scope_patterns
                .iter()
                .take(OVERVIEW_SCOPE_LIMIT)
                .cloned()
                .collect(),
            excluded_scope_count: runtime.excluded_scope_patterns.len(),
            top_hosts: traffic.top_hosts,
            last_captured_at: traffic.last_captured_at,
            marked_requests: traffic.marked_requests,
            pinned_replays: pinned
                .iter()
                .take(OVERVIEW_LIST_LIMIT)
                .map(|tab| replay_tab_label(tab))
                .collect(),
            pinned_replay_count: pinned.len(),
            replace_rules: rules
                .iter()
                .take(OVERVIEW_LIST_LIMIT)
                .map(|rule| replace_rule_label(rule))
                .collect(),
            replace_rule_count: rules.len(),
            activity,
            activity_count,
            findings: SeverityCounts::count(&state.scanner_findings),
        }
    }
}

fn overview_label(text: &str) -> String {
    let text = text.trim();
    if text.chars().count() <= OVERVIEW_LABEL_CHARS {
        return text.to_string();
    }
    let mut short: String = text.chars().take(OVERVIEW_LABEL_CHARS - 1).collect();
    short.push('…');
    short
}

fn list_label(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => overview_label(one),
        [first, rest @ ..] => format!("{} +{}", overview_label(first), rest.len()),
    }
}

/// A pinned tab by the name the operator gave it, else by its method, host and
/// path without the query.
fn replay_tab_label(tab: &crate::workspace::ReplayTabState) -> String {
    if !tab.custom_label.trim().is_empty() {
        return overview_label(&tab.custom_label);
    }
    match &tab.base_request {
        Some(request) => {
            let path = request.path.split(['?', '#']).next().unwrap_or_default();
            overview_label(&format!("{} {}{}", request.method, request.host, path))
        }
        None => {
            let host = if tab.target_host.is_empty() {
                &tab.ws_host
            } else {
                &tab.target_host
            };
            overview_label(&format!("Replay {host}"))
        }
    }
}

/// A rule by the description the operator gave it, else by what it rewrites:
/// its search and replace text stay out of the registry.
fn replace_rule_label(rule: &MatchReplaceRule) -> String {
    if !rule.description.trim().is_empty() {
        return overview_label(&rule.description);
    }
    let scope = match rule.scope {
        MatchReplaceScope::Request => "Request",
        MatchReplaceScope::Response => "Response",
    };
    let target = match rule.target {
        MatchReplaceTarget::Any => "",
        MatchReplaceTarget::Path => " path",
        MatchReplaceTarget::HeaderName => " header name",
        MatchReplaceTarget::HeaderValue => " header value",
        MatchReplaceTarget::Body => " body",
    };
    format!("{scope}{target} rule")
}

/// Bytes the files under `dir` take. Links are not followed and unreadable
/// entries count as nothing.
pub fn directory_bytes(dir: &Path) -> u64 {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .map(|entry| match entry.file_type() {
            Ok(kind) if kind.is_dir() => directory_bytes(&entry.path()),
            Ok(kind) if kind.is_file() => {
                entry.metadata().map(|metadata| metadata.len()).unwrap_or(0)
            }
            _ => 0,
        })
        .sum()
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
    recon: crate::recon::ReconSnapshot,
    #[serde(default)]
    template_scans: crate::templates::scan::TemplateScanSnapshot,
    #[serde(default)]
    oast_callbacks: Option<Vec<crate::oast::OastCallback>>,
    #[serde(default)]
    oast_cleared_callback_keys: Vec<crate::oast::OastCallbackDedupKey>,
    #[serde(default)]
    oast_registration: Option<crate::oast::StoredOastRegistration>,
    #[serde(default, deserialize_with = "deserialize_workspace_state_lossy")]
    workspace: WorkspaceStateSnapshot,
    /// Where each record's line sits in transactions.ndjson, for records whose
    /// bodies can therefore be dropped from memory. Never serialized: it describes
    /// the file we just read, not the session.
    #[serde(skip)]
    transaction_locators: HashMap<Uuid, BodyLocator>,
    #[serde(skip)]
    replayed_transaction_journal: bool,
    #[serde(skip)]
    replayed_transaction_deletion: bool,
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
    replayed_deletion: bool,
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

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum WorkspaceWriteFault {
    BeforeReplacement,
    AfterReplacement,
}

#[cfg(test)]
struct WorkspaceCommitGate {
    entered: oneshot::Sender<()>,
    resume: mpsc::Receiver<()>,
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SnapshotTestPhase {
    Prepared,
    BeforeRename,
    Published,
    BeforeCleanup,
}

#[cfg(test)]
struct SnapshotTestGate {
    phase: SnapshotTestPhase,
    gate: WorkspaceCommitGate,
}

#[cfg(test)]
fn wait_snapshot_gate(gate: &mut Option<SnapshotTestGate>, phase: SnapshotTestPhase) {
    if gate.as_ref().is_some_and(|gate| gate.phase == phase) {
        let gate = gate.take().unwrap().gate;
        let _ = gate.entered.send(());
        gate.resume
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("snapshot test gate must be released");
    }
}

pub struct SessionContext {
    pub(crate) upstream_peer_settings: crate::upstream_peer_settings::SessionPeerSettingsState,
    pub(crate) history_retention: crate::history_retention::SessionRetentionState,
    retention_writable: bool,
    id: Uuid,
    storage_dir: PathBuf,
    max_entries: usize,
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
    pub recon: Arc<crate::recon::ReconStore>,
    pub template_scans: Arc<crate::templates::scan::TemplateScanStore>,
    pub oast: Arc<crate::oast::OastStore>,
    pub workspace: Arc<WorkspaceStateStore>,
    websocket_journal_tx: Option<mpsc::Sender<WebSocketJournalCommand>>,
    metadata: Arc<RwLock<SessionMetadata>>,
    mutation_lock: Arc<AsyncMutex<()>>,
    persist_lock: Arc<AsyncMutex<()>>,
    confirmed_transaction_compaction_sequence: Arc<AtomicU64>,
    /// Held through the write, not just the debounce: a slow disk must not
    /// accumulate a new context-owning task every debounce interval.
    state_persist_scheduled: AtomicBool,
    /// A change since the current worker started taking its snapshot.
    state_persist_dirty: AtomicBool,
    #[cfg(test)]
    workspace_write_fault: std::sync::Mutex<Option<WorkspaceWriteFault>>,
    #[cfg(test)]
    history_retention_write_fault: std::sync::Mutex<Option<WorkspaceWriteFault>>,
    #[cfg(test)]
    upstream_peer_write_fault:
        std::sync::Mutex<Option<crate::upstream_peer_settings::SettingsWriteFault>>,
    #[cfg(test)]
    workspace_commit_gate: std::sync::Mutex<Option<WorkspaceCommitGate>>,
    #[cfg(test)]
    snapshot_gate: std::sync::Mutex<Option<SnapshotTestGate>>,
    #[cfg(test)]
    state_persist_gate: std::sync::Mutex<Option<SnapshotTestGate>>,
    #[cfg(test)]
    state_persist_handoff_gate:
        std::sync::Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>,
    #[cfg(test)]
    snapshot_capture_gate: std::sync::Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>,
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
        _max_transaction_entries: usize,
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
        let store = Arc::new(if enable_journal {
            TransactionStore::from_located_records_with_journal(
                snapshot.transactions,
                snapshot.transaction_locators,
                &snapshot.replayed_transaction_ids,
                journal_path,
                transaction_event_sequence,
            )
        } else {
            TransactionStore::from_located_records_read_only(
                snapshot.transactions,
                snapshot.transaction_locators,
                &snapshot.replayed_transaction_ids,
                storage_dir.clone(),
                transaction_event_sequence,
            )
        });
        if !enable_journal && snapshot.replayed_transaction_deletion {
            store.mark_retention_compaction_pending(transaction_event_sequence);
        }
        Self {
            upstream_peer_settings: Default::default(),
            history_retention: Default::default(),
            retention_writable: enable_journal,
            id: metadata.id,
            storage_dir,
            max_entries,
            store,
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
            recon: Arc::new(crate::recon::ReconStore::from_snapshot(snapshot.recon)),
            template_scans: Arc::new(crate::templates::scan::TemplateScanStore::from_snapshot(
                snapshot.template_scans,
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
            metadata: Arc::new(RwLock::new(metadata)),
            mutation_lock: Arc::new(AsyncMutex::new(())),
            persist_lock: Arc::new(AsyncMutex::new(())),
            confirmed_transaction_compaction_sequence: Arc::new(AtomicU64::new(0)),
            state_persist_scheduled: AtomicBool::new(false),
            state_persist_dirty: AtomicBool::new(false),
            #[cfg(test)]
            workspace_write_fault: std::sync::Mutex::new(None),
            #[cfg(test)]
            history_retention_write_fault: std::sync::Mutex::new(None),
            #[cfg(test)]
            upstream_peer_write_fault: std::sync::Mutex::new(None),
            #[cfg(test)]
            workspace_commit_gate: std::sync::Mutex::new(None),
            #[cfg(test)]
            snapshot_gate: std::sync::Mutex::new(None),
            #[cfg(test)]
            state_persist_gate: std::sync::Mutex::new(None),
            #[cfg(test)]
            state_persist_handoff_gate: std::sync::Mutex::new(None),
            #[cfg(test)]
            snapshot_capture_gate: std::sync::Mutex::new(None),
        }
    }

    /// Queues a state-only persist and returns immediately.
    ///
    /// Callers are on the capture path — a scanner finding, an intercept enqueue —
    /// and some run inside tasks that count as active proxy work. Awaiting a
    /// multi-megabyte fsync there keeps the session marked busy, which blocks
    /// switching away from it. One write is queued at a time; it snapshots the
    /// state when it runs, so anything that changes meanwhile is either included
    /// or queues the next one.
    pub fn schedule_state_persist(self: &Arc<Self>) {
        self.state_persist_dirty.store(true, Ordering::SeqCst);
        if self.state_persist_scheduled.swap(true, Ordering::SeqCst) {
            return;
        }
        let session = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(STATE_PERSIST_DEBOUNCE).await;
                session.state_persist_dirty.store(false, Ordering::SeqCst);
                if let Err(error) = session.persist_state_only().await {
                    warn!(?error, session_id = %session.id, "failed to persist session state");
                }
                // Release ownership before checking for later changes. A caller
                // either leaves dirty work for this worker to reclaim, or owns
                // the next worker itself. Keeping the flag set while returning
                // would lose that caller's wakeup; clearing it before the write
                // would let blocked writers accumulate without a bound.
                session
                    .state_persist_scheduled
                    .store(false, Ordering::SeqCst);
                #[cfg(test)]
                {
                    let gate = session.state_persist_handoff_gate.lock().unwrap().take();
                    if let Some((entered, resume)) = gate {
                        let _ = entered.send(());
                        let _ = resume.await;
                    }
                }
                if !session.state_persist_dirty.load(Ordering::SeqCst)
                    || session.state_persist_scheduled.swap(true, Ordering::SeqCst)
                {
                    break;
                }
            }
        });
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

    pub(crate) fn apply_renamed_metadata(&self, renamed: &SessionMetadata) {
        let mut metadata = self
            .metadata
            .write()
            .expect("session metadata lock poisoned");
        metadata.name.clone_from(&renamed.name);
        metadata.updated_at = metadata.updated_at.max(renamed.updated_at);
    }

    /// Sample once before the first ordinary send, and carry the result through
    /// fallback and completion. No lock escapes this helper. An already eligible
    /// exchange may finish recording its observation after the user saves Off.
    pub async fn upstream_peer_capture_eligible(&self) -> bool {
        // Copy the coherent runtime inputs, then release its lock before reading
        // the durability gate, preserving the existing sampling order.
        let inputs = self.runtime.upstream_peer_capture_inputs().await;
        inputs
            .status(self.upstream_peer_settings.uncertain())
            .effective_enabled
    }

    /// Caller owns operation and mutation guards. Only this narrow explicit
    /// save can clear uncertainty; a broad runtime or session save cannot.
    pub(crate) async fn persist_upstream_peer_settings(
        &self,
        enabled: bool,
        revision: Option<u64>,
    ) -> std::result::Result<(), crate::upstream_peer_settings::SettingsWriteError> {
        use crate::upstream_peer_settings::SettingsWriteError;
        self.upstream_peer_settings.mark_uncertain(true);
        let _persist_guard = self.persist_lock.lock().await;
        let mut state = self
            .build_state_snapshot(self.workspace.snapshot().await)
            .await;
        state.runtime.upstream_peer_capture_enabled = enabled && revision.is_some();
        state.runtime.upstream_peer_capture_revision = revision;
        let path = state_path(&self.storage_dir);
        #[cfg(test)]
        let fault = self.upstream_peer_write_fault.lock().unwrap().take();
        let result = tokio::task::spawn_blocking(move || {
            #[cfg(test)]
            match fault {
                Some(crate::upstream_peer_settings::SettingsWriteFault::BeforeReplacement) => {
                    return Err(JsonWriteFailure {
                        error: anyhow!("synthetic peer settings write failure"),
                        committed: false,
                    });
                }
                Some(crate::upstream_peer_settings::SettingsWriteFault::AfterReplacement) => {
                    return write_json_finalizing(&path, &state, |_| {
                        bail!("synthetic peer settings finalization failure")
                    });
                }
                Some(crate::upstream_peer_settings::SettingsWriteFault::OutcomeUnknown) => {
                    let _ = write_json_with_commit_status(&path, &state);
                    panic!("synthetic peer settings writer outcome unknown");
                }
                None => (),
            }
            write_json_with_commit_status(&path, &state)
        })
        .await;
        let result = match result {
            Ok(result) => result,
            Err(_) => {
                // The candidate may already be on disk. Reserve its revision
                // instead of reviving a previously issued CAS token. This is
                // explicitly an attempted value, never confirmed durability.
                self.runtime
                    .set_upstream_peer_capture_config(enabled, revision)
                    .await;
                return Err(SettingsWriteError::OutcomeUnknown);
            }
        };
        match result {
            Ok(()) => {
                self.runtime
                    .set_upstream_peer_capture_config(enabled, revision)
                    .await;
                self.upstream_peer_settings.mark_uncertain(false);
                Ok(())
            }
            Err(failure) if failure.committed => {
                // Visible replacement is known, but durability is not. Publish
                // that value honestly while leaving new exchanges gated Off.
                self.runtime
                    .set_upstream_peer_capture_config(enabled, revision)
                    .await;
                Err(SettingsWriteError::CommittedButUncertain)
            }
            Err(_) => Err(SettingsWriteError::NotCommitted),
        }
    }

    #[cfg(test)]
    pub(crate) fn fail_next_upstream_peer_write(
        &self,
        fault: crate::upstream_peer_settings::SettingsWriteFault,
    ) {
        *self.upstream_peer_write_fault.lock().unwrap() = Some(fault);
    }

    pub(crate) fn retention_writable(&self) -> bool {
        self.retention_writable
    }

    /// Called under the session mutation lock. Publish the new policy only
    /// after its state-only atomic write has confirmed durability.
    pub(crate) async fn persist_history_retention_policy(
        &self,
        policy: crate::history_retention::HistoryRetentionPolicy,
        revision: u64,
    ) -> std::result::Result<(), crate::history_retention::PolicyWriteError> {
        use crate::history_retention::PolicyWriteError;
        let _persist_guard = self.persist_lock.lock().await;
        let mut state = self
            .build_state_snapshot(self.workspace.snapshot().await)
            .await;
        state.runtime.http_history_retention = policy.clone();
        state.runtime.http_history_retention_revision = Some(revision);
        let path = state_path(&self.storage_dir);
        #[cfg(test)]
        let fault = self.history_retention_write_fault.lock().unwrap().take();
        let result = tokio::task::spawn_blocking(move || {
            #[cfg(test)]
            match fault {
                Some(WorkspaceWriteFault::BeforeReplacement) => {
                    return Err(JsonWriteFailure {
                        error: anyhow!("synthetic retention write failure before replacement"),
                        committed: false,
                    })
                }
                Some(WorkspaceWriteFault::AfterReplacement) => {
                    return write_json_finalizing(&path, &state, |_| {
                        bail!("synthetic retention write finalization failure")
                    })
                }
                None => (),
            }
            write_json_with_commit_status(&path, &state)
        })
        .await
        .map_err(|_| PolicyWriteError::OutcomeUnknown)?;
        match result {
            Ok(()) => {
                self.runtime
                    .set_history_retention_policy(policy, revision)
                    .await;
                Ok(())
            }
            Err(failure) if failure.committed => {
                // Keep memory aligned with the visible replacement, but the
                // caller gates destructive work until a durable retry succeeds.
                self.runtime
                    .set_history_retention_policy(policy, revision)
                    .await;
                Err(PolicyWriteError::CommittedButUncertain)
            }
            Err(_) => Err(PolicyWriteError::NotCommitted),
        }
    }

    #[cfg(test)]
    pub(crate) fn fail_next_history_retention_write(&self, fault: WorkspaceWriteFault) {
        *self.history_retention_write_fault.lock().unwrap() = Some(fault);
    }

    pub async fn persist(&self) -> Result<SessionMetadata> {
        let _mutation_guard = self.mutation_lock.lock().await;
        self.persist_mutation_locked().await
    }

    pub async fn mutation_guard(&self) -> AsyncMutexGuard<'_, ()> {
        self.mutation_lock.lock().await
    }

    pub(crate) async fn owned_mutation_guard(&self) -> OwnedMutexGuard<()> {
        self.mutation_lock.clone().lock_owned().await
    }

    pub(crate) async fn owned_persist_guard(&self) -> OwnedMutexGuard<()> {
        let guard = self.persist_lock.clone().lock_owned().await;
        // A canceled snapshot may still have an offline journal rotation queued
        // on the blocking pool. Its store permit is the remaining filesystem
        // lifetime guard; deletion/replacement must drain it before proceeding.
        drop(self.store.owned_persistence_mutation_guard().await);
        guard
    }

    /// The latest transaction boundary whose snapshot and journal cleanup both
    /// completed. A successful metadata save alone does not establish cleanup.
    pub fn transaction_compacted_event_sequence(&self) -> u64 {
        self.confirmed_transaction_compaction_sequence
            .load(Ordering::Acquire)
    }

    pub async fn persist_mutation_locked(&self) -> Result<SessionMetadata> {
        let persist_guard = self.owned_persist_guard().await;
        // A request queued behind session deletion must not recreate its root.
        ensure_existing_private_session_dir(&self.storage_dir)?;
        self.persist_with_workspace_snapshot_locked(self.workspace.snapshot().await, persist_guard)
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

    pub(crate) async fn mutate_saved_replay_tab_and_persist(
        &self,
        tab_id: &str,
        expected_revision: u64,
        operation: SavedReplayTabOperation,
    ) -> std::result::Result<WorkspaceStateSnapshot, WorkspaceTransformError<anyhow::Error>> {
        let _mutation_guard = self.mutation_lock.lock().await;
        let _persist_guard = self.persist_lock.lock().await;
        let path = workspace_path(&self.storage_dir);
        self.workspace
            .transform_snapshot_checked_persisting(
                expected_revision,
                |current| {
                    let mut next = transform_saved_replay_tab(current, tab_id, operation)?;
                    next.session_id = Some(self.id());
                    next.revision = expected_revision + 1;
                    next.expected_active_session_id = None;
                    next.client_id = None;
                    next.client_version = 0;
                    validate_workspace_state(&next)?;
                    Ok(next)
                },
                |workspace| async move {
                    // Workspace-only persistence is also safe for a read-only
                    // inactive context. Do not hydrate its unrelated journals.
                    match tokio::task::spawn_blocking(move || {
                        ensure_existing_private_session_dir(
                            path.parent().expect("workspace has a session root"),
                        )
                        .map_err(|error| JsonWriteFailure {
                            error,
                            committed: false,
                        })?;
                        write_json_with_commit_status(&path, &workspace)
                    })
                    .await?
                    {
                        Ok(()) => Ok(None),
                        Err(failure) if failure.committed => Ok(Some(failure.error)),
                        Err(failure) => Err(failure.error),
                    }
                },
            )
            .await
    }

    async fn persist_workspace_snapshot_locked(
        &self,
        workspace: WorkspaceStateSnapshot,
    ) -> Result<WorkspacePersistCommit<Option<SessionMetadata>, anyhow::Error>> {
        self.persist_workspace_snapshot_locked_inner(workspace)
            .await
    }

    async fn persist_workspace_snapshot_locked_inner(
        &self,
        workspace: WorkspaceStateSnapshot,
    ) -> Result<WorkspacePersistCommit<Option<SessionMetadata>, anyhow::Error>> {
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
        // Keep replacement and the caller's in-memory publication in one poll:
        // yielding here would let cancellation leave memory behind disk.
        let finalization_error = match self.write_workspace_snapshot(&workspace) {
            Ok(()) => None,
            Err(failure) if failure.committed => Some(failure.error),
            Err(failure) => return Err(failure.error),
        };
        Ok(WorkspacePersistCommit {
            value: None,
            finalization_error,
        })
    }

    fn write_workspace_snapshot(
        &self,
        workspace: &WorkspaceStateSnapshot,
    ) -> std::result::Result<(), JsonWriteFailure> {
        ensure_existing_private_session_dir(&self.storage_dir).map_err(|error| {
            JsonWriteFailure {
                error,
                committed: false,
            }
        })?;
        let path = workspace_path(&self.storage_dir);
        #[cfg(test)]
        {
            let fault = self.workspace_write_fault.lock().unwrap().take();
            let gate = self.workspace_commit_gate.lock().unwrap().take();
            if fault.is_some() || gate.is_some() {
                // Hooks affect only this context's workspace.json, once.
                let result = match fault {
                    Some(WorkspaceWriteFault::BeforeReplacement) => Err(JsonWriteFailure {
                        error: anyhow!("synthetic workspace failure before replacement"),
                        committed: false,
                    }),
                    Some(WorkspaceWriteFault::AfterReplacement) => {
                        write_json_finalizing(&path, workspace, |_| {
                            bail!("synthetic workspace finalization failure")
                        })
                    }
                    None => write_json_with_commit_status(&path, workspace),
                };
                if result
                    .as_ref()
                    .map_or_else(|failure| failure.committed, |_| true)
                {
                    if let Some(gate) = gate {
                        let _ = gate.entered.send(());
                        gate.resume
                            .recv_timeout(std::time::Duration::from_secs(5))
                            .expect("workspace commit test gate must be released");
                    }
                }
                return result;
            }
        }
        write_json_with_commit_status(&path, workspace)
    }

    #[cfg(test)]
    pub(crate) fn fail_next_workspace_write(&self, fault: WorkspaceWriteFault) {
        *self.workspace_write_fault.lock().unwrap() = Some(fault);
    }

    #[cfg(test)]
    pub(crate) fn pause_next_workspace_commit(&self) -> (oneshot::Receiver<()>, mpsc::Sender<()>) {
        let (entered, ready) = oneshot::channel();
        let (resume, release) = mpsc::channel();
        *self.workspace_commit_gate.lock().unwrap() = Some(WorkspaceCommitGate {
            entered,
            resume: release,
        });
        (ready, resume)
    }

    #[cfg(test)]
    fn pause_next_snapshot_capture(&self) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (entered, ready) = oneshot::channel();
        let (resume, release) = oneshot::channel();
        *self.snapshot_capture_gate.lock().unwrap() = Some((entered, release));
        (ready, resume)
    }

    #[cfg(test)]
    fn pause_next_state_write(&self) -> (oneshot::Receiver<()>, mpsc::Sender<()>) {
        let (entered, ready) = oneshot::channel();
        let (resume, release) = mpsc::channel();
        *self.state_persist_gate.lock().unwrap() = Some(SnapshotTestGate {
            phase: SnapshotTestPhase::Prepared,
            gate: WorkspaceCommitGate {
                entered,
                resume: release,
            },
        });
        (ready, resume)
    }

    #[cfg(test)]
    fn pause_next_state_handoff(&self) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (entered, ready) = oneshot::channel();
        let (resume, release) = oneshot::channel();
        *self.state_persist_handoff_gate.lock().unwrap() = Some((entered, release));
        (ready, resume)
    }

    #[cfg(test)]
    pub(crate) fn pause_next_snapshot(
        &self,
        phase: SnapshotTestPhase,
    ) -> (oneshot::Receiver<()>, mpsc::Sender<()>) {
        let (entered, ready) = oneshot::channel();
        let (resume, release) = mpsc::channel();
        *self.snapshot_gate.lock().unwrap() = Some(SnapshotTestGate {
            phase,
            gate: WorkspaceCommitGate {
                entered,
                resume: release,
            },
        });
        (ready, resume)
    }

    /// Everything in the session document except the two big journal-backed
    /// sections, which are left empty. Written on its own to `state.json` so that
    /// changing a scanner finding, an intercept queue entry or a fuzzer attack
    /// does not rewrite the transactions — 89.9% of a real 1.35 GB session.
    async fn build_state_snapshot(
        &self,
        workspace: WorkspaceStateSnapshot,
    ) -> StoredSessionSnapshot {
        StoredSessionSnapshot {
            runtime: self.runtime.snapshot().await,
            transactions: Vec::new(),
            transaction_event_sequence: 0,
            websockets: Vec::new(),
            event_log: self.event_log.snapshot(Some(self.max_entries)).await,
            match_replace_rules: self.match_replace.snapshot().await,
            fuzzer_attacks: self.fuzzer.snapshot(Some(self.max_entries)).await,
            scanner_findings: self.scanner.snapshot(Some(self.max_entries)).await,
            scanner_config: self.scanner.get_config().await,
            intercept_rules: self.intercept_rules.snapshot().await,
            sequence_definitions: self.sequence.snapshot_definitions().await,
            sequence_runs: self.sequence.snapshot_runs(Some(self.max_entries)).await,
            recon: self.recon.snapshot(),
            template_scans: self.template_scans.snapshot(),
            oast_callbacks: Some(self.oast.snapshot().await),
            oast_cleared_callback_keys: self.oast.snapshot_cleared_keys().await,
            oast_registration: self.oast.snapshot_registration().await,
            workspace,
            transaction_locators: HashMap::new(),
            replayed_transaction_journal: false,
            replayed_transaction_deletion: false,
            replayed_transaction_ids: HashSet::new(),
            replayed_websocket_journal: false,
            compactable_websocket_journal: false,
            unresolved_websocket_journal: false,
        }
    }

    /// This session's overview from its live state. Only the parts it names are
    /// copied: the CLI lists sessions on most calls, and the event log or a
    /// fuzzer's results can be large.
    pub async fn overview(&self) -> SessionOverview {
        let state = StoredSessionSnapshot {
            runtime: self.runtime.snapshot().await,
            match_replace_rules: self.match_replace.snapshot().await,
            scanner_findings: self.scanner.snapshot(Some(self.max_entries)).await,
            recon: self.recon.snapshot(),
            template_scans: self.template_scans.snapshot(),
            workspace: self.workspace.snapshot().await,
            ..StoredSessionSnapshot::default()
        };
        SessionOverview::new(self.store.traffic_overview().await, &state)
    }

    /// Persists everything except transactions and websockets. Those two are
    /// durable through their own journals, so the callers that only changed a
    /// small component — an intercept enqueue, a scanner finding, a websocket
    /// open — can pay a few MB instead of the whole session document.
    pub async fn persist_state_only(&self) -> Result<()> {
        let persist_guard = self.persist_lock.clone().lock_owned().await;
        let state = self
            .build_state_snapshot(self.workspace.snapshot().await)
            .await;
        let storage_dir = self.storage_dir.clone();
        #[cfg(test)]
        let mut state_gate = self.state_persist_gate.lock().unwrap().take();
        // Recon inventories can be several MiB; keep fsync and serialization off
        // the async runtime, while retaining the permit through publication.
        tokio::task::spawn_blocking(move || {
            let _persist_guard = persist_guard;
            #[cfg(test)]
            wait_snapshot_gate(&mut state_gate, SnapshotTestPhase::Prepared);
            ensure_existing_private_session_dir(&storage_dir)?;
            write_json(&state_path(&storage_dir), &state)
        })
        .await
        .context("session state writer failed")?
    }

    /// What an API change to the small components needs: runtime settings,
    /// rules, the event log, OAST callbacks, sequence runs. They are all in
    /// state.json, and the session list's counts are refreshed with them. The
    /// full save copied the whole of transactions.ndjson for each, gigabytes on
    /// a large session for one intercept toggle; captured traffic is durable
    /// through its journal, and a full save still compacts that once it grows
    /// (TRANSACTION_JOURNAL_COMPACT_BYTES).
    pub async fn persist_state_mutation_locked(&self) -> Result<SessionMetadata> {
        let persist_guard = self.owned_persist_guard().await;
        // A request queued behind session deletion must not recreate its root.
        ensure_existing_private_session_dir(&self.storage_dir)?;
        let state = self
            .build_state_snapshot(self.workspace.snapshot().await)
            .await;
        let mut metadata = self
            .metadata
            .read()
            .expect("session metadata lock poisoned")
            .clone();
        // The request and websocket counts are the full save's to keep: these
        // changes leave captured traffic as it is.
        metadata.updated_at = Utc::now();
        metadata.event_count = state.event_log.len();
        metadata.fuzzer_count = state.fuzzer_attacks.len();
        metadata.rule_count = state.match_replace_rules.len();
        let storage_dir = self.storage_dir.clone();
        tokio::task::spawn_blocking(move || {
            let _persist_guard = persist_guard;
            ensure_existing_private_session_dir(&storage_dir)?;
            write_json(&state_path(&storage_dir), &state)
        })
        .await
        .context("session state writer failed")??;
        // Registry-owned fields may have moved meanwhile, as in a full save.
        let mut current = self
            .metadata
            .write()
            .expect("session metadata lock poisoned");
        metadata.name.clone_from(&current.name);
        metadata.created_at = current.created_at;
        metadata.last_opened_at = current.last_opened_at;
        metadata.updated_at = metadata.updated_at.max(current.updated_at);
        *current = metadata.clone();
        Ok(metadata)
    }

    async fn persist_with_workspace_snapshot_locked(
        &self,
        workspace: WorkspaceStateSnapshot,
        persist_guard: OwnedMutexGuard<()>,
    ) -> Result<SessionMetadata> {
        validate_workspace_serialized_size(&workspace)
            .map_err(anyhow::Error::msg)
            .with_context(|| "workspace snapshot is too large to persist")?;
        validate_workspace_state(&workspace)
            .map_err(anyhow::Error::msg)
            .with_context(|| "workspace snapshot is invalid")?;
        // Live HTTP history and journal replay are uncapped. Limiting only the
        // snapshot silently loses older records when the session next reloads.
        let transactions = self
            .store
            .snapshot_for_persistence(None)
            .await
            .with_context(|| {
                format!(
                    "failed to rotate transaction journal for {}",
                    self.storage_dir.display()
                )
            })?;
        #[cfg(test)]
        {
            let gate = self.snapshot_capture_gate.lock().unwrap().take();
            if let Some((entered, resume)) = gate {
                let _ = entered.send(());
                let _ = resume.await;
            }
        }
        let websockets = self
            .websockets
            .snapshot_with_frame_limit(
                Some(self.max_entries),
                Some(MAX_PERSISTED_WEBSOCKET_FRAMES_PER_SESSION),
            )
            .await;
        let state = self.build_state_snapshot(workspace).await;
        // The two big sections are the only ones that need the full document
        // rewritten; everything else is a few MB and gets its own file. Cloning
        // `state` here copies only those small sections — the big ones are still
        // empty at this point.
        let mut snapshot = state.clone();
        snapshot.websockets = websockets;
        snapshot.transaction_event_sequence = transactions.latest_event_sequence;

        let mut metadata = self
            .metadata
            .read()
            .expect("session metadata lock poisoned")
            .clone();
        metadata.updated_at = Utc::now();
        metadata.request_count = transactions.len();
        metadata.websocket_count = snapshot.websockets.len();
        metadata.event_count = snapshot.event_log.len();
        metadata.fuzzer_count = snapshot.fuzzer_attacks.len();
        metadata.rule_count = snapshot.match_replace_rules.len();
        metadata.overview = SessionOverview::new(
            TrafficOverview::from_records(transactions.iter().map(|(record, _)| record)),
            &snapshot,
        );

        let snapshot_file = snapshot_path(&self.storage_dir);
        let transactions_file = transactions_path(&self.storage_dir);
        let storage_dir = self.storage_dir.clone();
        let store = Arc::clone(&self.store);
        let websocket_journal_tx = self.websocket_journal_tx.clone();
        let confirmed_compaction = Arc::clone(&self.confirmed_transaction_compaction_sequence);
        let session_id = self.id;
        let live_metadata = Arc::clone(&self.metadata);
        #[cfg(test)]
        let mut snapshot_gate = self.snapshot_gate.lock().unwrap().take();
        // Cancellation only drops the waiter. The owned permit stays with the
        // writer through publication and journal cleanup, so a second snapshot
        // cannot rotate its checkpoint or replace its source underneath it.
        let (metadata, _persist_guard) = tokio::task::spawn_blocking(move || -> Result<_> {
            let _persist_guard = persist_guard;
            ensure_existing_private_session_dir(&storage_dir)?;
            let mut prepared = prepare_transactions_file_streaming(
                &transactions_file,
                &transactions_file,
                &transactions,
            )?;
            #[cfg(test)]
            wait_snapshot_gate(&mut snapshot_gate, SnapshotTestPhase::Prepared);
            invalidate_transactions_meta(&storage_dir)?;
            let locators = prepared.locators.clone();
            store.publish_persistence_snapshot(&transactions, locators, || {
                #[cfg(test)]
                wait_snapshot_gate(&mut snapshot_gate, SnapshotTestPhase::BeforeRename);
                prepared.rename_into_place(&transactions_file)
            })?;
            #[cfg(test)]
            wait_snapshot_gate(&mut snapshot_gate, SnapshotTestPhase::Published);
            // No fallible finalization runs between replacement and publishing
            // its locators. Even a later failure must leave readers on this file.
            prepared.finalize(&transactions_file)?;
            write_json(&snapshot_file, &snapshot)?;
            write_json(&state_path(&storage_dir), &state)?;
            #[cfg(test)]
            wait_snapshot_gate(&mut snapshot_gate, SnapshotTestPhase::BeforeCleanup);
            if transactions.journal_rotation_confirmed {
                match discard_transaction_journal_checkpoint(&storage_dir) {
                    Ok(()) => {
                        confirmed_compaction.fetch_max(
                            transactions.latest_event_sequence,
                            Ordering::Release,
                        );
                        store.mark_retention_compacted(transactions.latest_event_sequence);
                    }
                    Err(error) => warn!(
                        %error,
                        %session_id,
                        "failed to remove transaction journal checkpoint after writing session snapshot"
                    ),
                }
            }
            if let Some(tx) = &websocket_journal_tx {
                if let Err(error) = clear_websocket_journal(tx) {
                    warn!(%error, %session_id, "failed to clear websocket journal after writing session snapshot");
                }
            }
            // A canceled caller must not skip live bookkeeping. Registry-owned
            // fields may have advanced during a concurrent rename/activation.
            let mut current = live_metadata.write().expect("session metadata lock poisoned");
            metadata.name.clone_from(&current.name);
            metadata.created_at = current.created_at;
            metadata.last_opened_at = current.last_opened_at;
            metadata.updated_at = metadata.updated_at.max(current.updated_at);
            *current = metadata.clone();
            drop(current);
            Ok((metadata, _persist_guard))
        })
        .await
        .context("session snapshot writer panicked")??;
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
        // A rule that panics on one recovered row must not keep the session
        // from loading at every start; that row just gets no findings.
        let Ok(found) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            scan_transaction(record, config)
        })) else {
            continue;
        };
        recovered.extend(found);
    }
    recovered.extend(findings);
    recovered.truncate(max_entries);

    recovered
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum SessionRenameFault {
    BeforeReplacement,
    AfterReplacement,
}

pub(crate) struct SessionRenameCommit {
    pub metadata: SessionMetadata,
    pub finalization_error: Option<anyhow::Error>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionDeleteWrite {
    Commit,
    Prune,
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum SessionDeleteFault {
    BeforeReplacement,
    AfterReplacement,
}

pub(crate) struct SessionDeleteCommit {
    pub finalization_error: Option<anyhow::Error>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionMetadataWrite {
    Create,
    Update,
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum SessionMetadataFault {
    BeforeReplacement,
    AfterReplacement,
}

pub(crate) struct SessionActivationCommit {
    pub metadata: SessionMetadata,
    pub finalization_error: Option<anyhow::Error>,
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum SessionActivationFault {
    BeforeReplacement,
    AfterReplacement,
}

#[cfg(test)]
struct SessionActivationGate {
    entered: oneshot::Sender<()>,
    resume: mpsc::Receiver<()>,
}

pub struct SessionRegistry {
    root_dir: PathBuf,
    registry_path: PathBuf,
    max_entries: usize,
    max_transaction_entries: usize,
    max_frames_per_session: usize,
    inner: RwLock<SessionRegistrySnapshot>,
    #[cfg(test)]
    rename_fault: std::sync::Mutex<Option<SessionRenameFault>>,
    #[cfg(test)]
    delete_fault: std::sync::Mutex<Option<(SessionDeleteWrite, SessionDeleteFault)>>,
    #[cfg(test)]
    metadata_fault: std::sync::Mutex<Option<(SessionMetadataWrite, SessionMetadataFault)>>,
    #[cfg(test)]
    activation_fault: std::sync::Mutex<Option<SessionActivationFault>>,
    #[cfg(test)]
    activation_gate: std::sync::Mutex<Option<SessionActivationGate>>,
    #[cfg(test)]
    activation_panic: AtomicBool,
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
        // Inventory before registry recovery: rebuilding a missing/corrupt
        // registry must not turn uncertain deletion evidence into orphan data.
        let quarantines = inspect_quarantined_session_storage(&root_dir)?;

        let mut repair_registry = false;
        let mut registry = match fs::read(&registry_path) {
            Ok(bytes) => match serde_json::from_slice::<StoredSessionRegistrySnapshot>(&bytes) {
                Ok(snapshot) => {
                    if !quarantines.is_empty()
                        && serde_json::from_slice::<serde_json::Value>(&bytes)?
                            .get("sessions")
                            .is_none()
                    {
                        return Err(quarantine_recovery_required(
                            &root_dir,
                            &quarantines[0],
                            "the registry does not declare session membership",
                        ));
                    }
                    let (snapshot, repaired) = snapshot.into_snapshot();
                    validate_quarantined_session_storage(&root_dir, &snapshot, &quarantines)?;
                    repair_registry |= repaired;
                    snapshot
                }
                Err(error) => {
                    if let Some(path) = quarantines.first() {
                        return Err(quarantine_recovery_required(
                            &root_dir,
                            path,
                            "the registry is corrupt",
                        ));
                    }
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
                if let Some(path) = quarantines.first() {
                    return Err(quarantine_recovery_required(
                        &root_dir,
                        path,
                        "the registry is missing",
                    ));
                }
                let snapshot = rebuild_registry_from_session_dirs(
                    &root_dir,
                    max_entries,
                    max_transaction_entries,
                )?;
                write_json(&registry_path, &snapshot)?;
                snapshot
            }
            Err(error) if registry_path.is_dir() => {
                if let Some(path) = quarantines.first() {
                    return Err(quarantine_recovery_required(
                        &root_dir,
                        path,
                        "the registry path is not a file",
                    ));
                }
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
            #[cfg(test)]
            rename_fault: std::sync::Mutex::new(None),
            #[cfg(test)]
            delete_fault: std::sync::Mutex::new(None),
            #[cfg(test)]
            metadata_fault: std::sync::Mutex::new(None),
            #[cfg(test)]
            activation_fault: std::sync::Mutex::new(None),
            #[cfg(test)]
            activation_gate: std::sync::Mutex::new(None),
            #[cfg(test)]
            activation_panic: AtomicBool::new(false),
        };
        let active_metadata = this.touch_active_session(registry.active_session_id)?;
        let active_context = this.load_context(active_metadata.id)?;
        Ok((this, active_context))
    }

    pub fn summaries(&self) -> Vec<SessionSummary> {
        self.listings()
            .into_iter()
            .map(|listing| listing.summary)
            .collect()
    }

    /// Sessions newest opened first, each with the overview its last save kept.
    pub fn listings(&self) -> Vec<SessionListing> {
        let registry = self.inner.read().expect("session registry lock poisoned");
        let active_id = registry.active_session_id;
        let mut sessions = registry
            .sessions
            .iter()
            .map(|metadata| SessionListing {
                summary: session_summary(
                    metadata,
                    &session_dir(&self.root_dir, metadata.id),
                    metadata.id == active_id,
                ),
                overview: metadata.overview.clone(),
                storage_bytes: 0,
            })
            .collect::<Vec<_>>();
        sessions.sort_by_key(|session| std::cmp::Reverse(session.summary.last_opened_at));
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
            overview: SessionOverview::default(),
        };

        persist_session_snapshot(&self.root_dir, &metadata, &StoredSessionSnapshot::default())?;
        let registry_result = {
            let mut registry = self.inner.write().expect("session registry lock poisoned");
            let mut next = registry.clone();
            next.sessions.push(metadata.clone());
            next.deleted_session_ids
                .retain(|deleted_id| *deleted_id != metadata.id);
            match self.write_registry_metadata(&next, SessionMetadataWrite::Create) {
                Ok(()) => {
                    *registry = next;
                    Ok(())
                }
                Err(failure) => {
                    if failure.committed {
                        *registry = next;
                    }
                    Err(failure)
                }
            }
        };
        if let Err(failure) = registry_result {
            // A visible registry entry must retain its storage even when the
            // write's durability could not be acknowledged to the caller.
            if !failure.committed {
                let _ = fs::remove_dir_all(session_dir(&self.root_dir, metadata.id));
            }
            return Err(failure.error);
        }
        Ok(metadata)
    }

    pub fn activate_session(&self, id: Uuid) -> Result<SessionMetadata> {
        self.touch_active_session(id)
    }

    pub fn rename_session(&self, id: Uuid, name: &str) -> Result<SessionMetadata> {
        let commit = self.rename_session_with_commit_status(id, name)?;
        match commit.finalization_error {
            Some(error) => Err(error),
            None => Ok(commit.metadata),
        }
    }

    pub(crate) fn rename_session_with_commit_status(
        &self,
        id: Uuid,
        name: &str,
    ) -> Result<SessionRenameCommit> {
        let name = name.trim();
        if name.is_empty() {
            bail!("session name cannot be blank");
        }
        if name.len() > MAX_SESSION_NAME_BYTES {
            bail!("session name cannot exceed {MAX_SESSION_NAME_BYTES} bytes");
        }
        if name.chars().any(char::is_control) {
            bail!("session name cannot contain control characters");
        }

        let mut registry = self.inner.write().expect("session registry lock poisoned");
        let mut next = registry.clone();
        let metadata = next
            .sessions
            .iter_mut()
            .find(|session| session.id == id)
            .ok_or_else(|| anyhow!("session {id} was not found"))?;
        if metadata.name != name {
            metadata.name = name.to_owned();
            metadata.updated_at = metadata.updated_at.max(Utc::now());
        }
        // Even an unchanged name must persist: an earlier replacement may have
        // been visible without its finalization being acknowledged.
        let renamed = metadata.clone();
        let finalization_error = match self.write_renamed_registry(&next) {
            Ok(()) => None,
            Err(failure) if failure.committed => Some(failure.error),
            Err(failure) => return Err(failure.error),
        };
        // Replacement is already visible even when finalization fails. Publish
        // the same metadata so a later snapshot cannot restore the old name.
        // This does not establish crash durability; the caller still gets Err.
        *registry = next;
        Ok(SessionRenameCommit {
            metadata: renamed,
            finalization_error,
        })
    }

    #[cfg(test)]
    pub(crate) fn fail_next_rename(&self, fault: SessionRenameFault) {
        *self.rename_fault.lock().unwrap() = Some(fault);
    }

    fn write_renamed_registry(
        &self,
        next: &SessionRegistrySnapshot,
    ) -> std::result::Result<(), JsonWriteFailure> {
        #[cfg(test)]
        if let Some(fault) = self.rename_fault.lock().unwrap().take() {
            return match fault {
                SessionRenameFault::BeforeReplacement => Err(JsonWriteFailure {
                    error: anyhow!("synthetic rename failure before replacement"),
                    committed: false,
                }),
                SessionRenameFault::AfterReplacement => {
                    write_json_finalizing(&self.registry_path, next, |_| {
                        bail!("synthetic rename finalization failure")
                    })
                }
            };
        }
        write_json_with_commit_status(&self.registry_path, next)
    }

    pub fn update_metadata(&self, mut metadata: SessionMetadata) -> Result<()> {
        let mut registry = self.inner.write().expect("session registry lock poisoned");
        let mut next = registry.clone();
        let Some(existing) = next
            .sessions
            .iter_mut()
            .find(|session| session.id == metadata.id)
        else {
            return Err(anyhow!("session {} was not found", metadata.id));
        };
        // A snapshot writer can finish after a rename or activation. These
        // fields belong to the registry, not to the writer's earlier snapshot.
        metadata.name.clone_from(&existing.name);
        metadata.created_at = existing.created_at;
        metadata.last_opened_at = existing.last_opened_at;
        metadata.updated_at = metadata.updated_at.max(existing.updated_at);
        *existing = metadata;
        let finalization_error =
            match self.write_registry_metadata(&next, SessionMetadataWrite::Update) {
                Ok(()) => None,
                Err(failure) if failure.committed => Some(failure.error),
                Err(failure) => return Err(failure.error),
            };
        // Later registry writes clone this snapshot, so leaving it stale would
        // overwrite metadata whose replacement is already visible on disk.
        *registry = next;
        match finalization_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    #[cfg(test)]
    pub(crate) fn fail_next_metadata_write(
        &self,
        purpose: SessionMetadataWrite,
        fault: SessionMetadataFault,
    ) {
        *self.metadata_fault.lock().unwrap() = Some((purpose, fault));
    }

    fn write_registry_metadata(
        &self,
        next: &SessionRegistrySnapshot,
        _purpose: SessionMetadataWrite,
    ) -> std::result::Result<(), JsonWriteFailure> {
        #[cfg(test)]
        {
            let fault = {
                let mut fault = self.metadata_fault.lock().unwrap();
                if fault
                    .as_ref()
                    .is_some_and(|(purpose, _)| *purpose == _purpose)
                {
                    fault.take().map(|(_, fault)| fault)
                } else {
                    None
                }
            };
            if let Some(fault) = fault {
                return match fault {
                    SessionMetadataFault::BeforeReplacement => Err(JsonWriteFailure {
                        error: anyhow!("synthetic metadata failure before replacement"),
                        committed: false,
                    }),
                    SessionMetadataFault::AfterReplacement => {
                        write_json_finalizing(&self.registry_path, next, |_| {
                            bail!("synthetic metadata finalization failure")
                        })
                    }
                };
            }
        }
        write_json_with_commit_status(&self.registry_path, next)
    }

    pub fn contains_session(&self, id: Uuid) -> bool {
        let registry = self.inner.read().expect("session registry lock poisoned");
        registry.sessions.iter().any(|session| session.id == id)
    }

    pub fn delete_session(&self, id: Uuid) -> Result<()> {
        let commit = self.delete_session_with_commit_status(id)?;
        match commit.finalization_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    pub(crate) fn delete_session_with_commit_status(
        &self,
        id: Uuid,
    ) -> Result<SessionDeleteCommit> {
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
            crate::platform::rename(&storage_dir, &quarantine_dir).with_context(|| {
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
        let finalization_error = match self
            .write_deleted_registry(&next, SessionDeleteWrite::Commit)
        {
            Ok(()) => None,
            Err(failure) if failure.committed => Some(failure.error),
            Err(failure) => {
                if let Some(quarantine_dir) = quarantined_storage.as_ref() {
                    if let Err(rollback_error) =
                        crate::platform::rename(quarantine_dir, &storage_dir)
                    {
                        warn!(
                            ?rollback_error,
                            session_id = %id,
                            source = %quarantine_dir.display(),
                            target = %storage_dir.display(),
                            "failed to restore quarantined session storage after registry delete failure"
                        );
                    }
                }
                return Err(failure.error);
            }
        };
        *registry = next;
        drop(registry);

        if finalization_error.is_some() {
            // Replacement is visible, but durability was not acknowledged. Keep
            // the quarantine and tombstone for recovery rather than restoring
            // a session that the next restart would silently delete again.
            return Ok(SessionDeleteCommit { finalization_error });
        }

        let storage_removed = quarantined_storage
            .as_deref()
            .is_none_or(|quarantine_dir| remove_quarantined_session_storage(id, quarantine_dir));
        let mut registry = self.inner.write().expect("session registry lock poisoned");
        if storage_removed && registry.deleted_session_ids.contains(&id) {
            let mut cleaned = registry.clone();
            cleaned
                .deleted_session_ids
                .retain(|deleted_id| *deleted_id != id);
            match self.write_deleted_registry(&cleaned, SessionDeleteWrite::Prune) {
                Ok(()) => {
                    *registry = cleaned;
                }
                Err(failure) => {
                    if failure.committed {
                        *registry = cleaned;
                    }
                    warn!(
                        error = %failure.error,
                        session_id = %id,
                        "failed to prune deleted session tombstone after storage removal"
                    );
                }
            }
        }
        Ok(SessionDeleteCommit {
            finalization_error: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn fail_next_delete_write(
        &self,
        purpose: SessionDeleteWrite,
        fault: SessionDeleteFault,
    ) {
        *self.delete_fault.lock().unwrap() = Some((purpose, fault));
    }

    fn write_deleted_registry(
        &self,
        next: &SessionRegistrySnapshot,
        _purpose: SessionDeleteWrite,
    ) -> std::result::Result<(), JsonWriteFailure> {
        #[cfg(test)]
        {
            let fault = {
                let mut fault = self.delete_fault.lock().unwrap();
                if fault
                    .as_ref()
                    .is_some_and(|(purpose, _)| *purpose == _purpose)
                {
                    fault.take().map(|(_, fault)| fault)
                } else {
                    None
                }
            };
            if let Some(fault) = fault {
                return match fault {
                    SessionDeleteFault::BeforeReplacement => Err(JsonWriteFailure {
                        error: anyhow!("synthetic delete failure before replacement"),
                        committed: false,
                    }),
                    SessionDeleteFault::AfterReplacement => {
                        write_json_finalizing(&self.registry_path, next, |_| {
                            bail!("synthetic delete finalization failure")
                        })
                    }
                };
            }
        }
        write_json_with_commit_status(&self.registry_path, next)
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
            // Same split as a normal persist: transactions to their own file,
            // snapshot.json without them. Writing `snapshot` whole here would put
            // the ~1.2 GB of records back where they were just moved out of.
            let transactions = std::mem::take(&mut snapshot.transactions);
            let entries: Vec<_> = transactions
                .into_iter()
                .map(|record| {
                    let locator = snapshot.transaction_locators.get(&record.id).copied();
                    (record, locator)
                })
                .collect();
            let path = transactions_path(&storage_dir);
            // Journal deletion can leave metadata-only survivors. Copy their
            // existing body lines and adopt the new offsets before truncating
            // the journal, rather than serializing empty bodies over the file.
            snapshot.transaction_locators =
                write_transactions_file_streaming(&path, &path, &entries)?;
            write_json(&snapshot_path(&storage_dir), &snapshot)?;
            snapshot.transactions = entries.into_iter().map(|(record, _)| record).collect();
        }
        let mut retention_compaction_pending = false;
        if replayed_transaction_journal {
            if let Err(error) = compact_replayed_transaction_journal(&storage_dir) {
                retention_compaction_pending = snapshot.replayed_transaction_deletion;
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
        let session = Arc::new(SessionContext::from_snapshot(
            metadata,
            storage_dir,
            self.max_entries,
            self.max_transaction_entries,
            self.max_frames_per_session,
            snapshot,
        ));
        if retention_compaction_pending {
            session
                .store
                .mark_retention_compaction_pending(session.store.latest_event_sequence());
        }
        Ok(session)
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
        let commit = self.activate_session_with_commit_status(id)?;
        match commit.finalization_error {
            Some(error) => Err(error),
            None => Ok(commit.metadata),
        }
    }

    pub(crate) fn activate_session_with_commit_status(
        &self,
        id: Uuid,
    ) -> Result<SessionActivationCommit> {
        #[cfg(test)]
        {
            let gate = self.activation_gate.lock().unwrap().take();
            if let Some(gate) = gate {
                let _ = gate.entered.send(());
                let _ = gate.resume.recv();
            }
            // Simulate a genuine worker JoinError without poisoning the registry.
            if self.activation_panic.swap(false, Ordering::SeqCst) {
                panic!("synthetic activation writer panic");
            }
        }
        let mut registry = self.inner.write().expect("session registry lock poisoned");
        let mut next = registry.clone();
        let Some(index) = next.sessions.iter().position(|session| session.id == id) else {
            return Err(anyhow!("session {id} was not found"));
        };

        next.sessions[index].last_opened_at = Utc::now();
        next.active_session_id = id;
        let metadata = next.sessions[index].clone();
        let finalization_error = match self.write_activated_registry(&next) {
            Ok(()) => None,
            Err(failure) if failure.committed => Some(failure.error),
            Err(failure) => return Err(failure.error),
        };
        *registry = next;
        Ok(SessionActivationCommit {
            metadata,
            finalization_error,
        })
    }

    #[cfg(test)]
    pub(crate) fn fail_next_activation(&self, fault: SessionActivationFault) {
        *self.activation_fault.lock().unwrap() = Some(fault);
    }

    #[cfg(test)]
    pub(crate) fn pause_next_activation(&self) -> (oneshot::Receiver<()>, mpsc::Sender<()>) {
        let (entered, ready) = oneshot::channel();
        let (resume, release) = mpsc::channel();
        *self.activation_gate.lock().unwrap() = Some(SessionActivationGate {
            entered,
            resume: release,
        });
        (ready, resume)
    }

    #[cfg(test)]
    pub(crate) fn panic_next_activation(&self) {
        self.activation_panic.store(true, Ordering::SeqCst);
    }

    fn write_activated_registry(
        &self,
        next: &SessionRegistrySnapshot,
    ) -> std::result::Result<(), JsonWriteFailure> {
        #[cfg(test)]
        {
            let fault = self.activation_fault.lock().unwrap().take();
            if let Some(fault) = fault {
                return match fault {
                    SessionActivationFault::BeforeReplacement => Err(JsonWriteFailure {
                        error: anyhow!("synthetic activation failure before replacement"),
                        committed: false,
                    }),
                    SessionActivationFault::AfterReplacement => {
                        write_json_finalizing(&self.registry_path, next, |_| {
                            bail!("synthetic activation finalization failure")
                        })
                    }
                };
            }
        }
        write_json_with_commit_status(&self.registry_path, next)
    }
}

fn update_metadata_counts_from_snapshot(
    metadata: &mut SessionMetadata,
    snapshot: &StoredSessionSnapshot,
    max_entries: usize,
    _max_transaction_entries: usize,
) -> bool {
    let next_request_count = snapshot.transactions.len();
    let next_websocket_count = snapshot.websockets.len();
    let next_event_count = snapshot.event_log.len().min(max_entries);
    let next_fuzzer_count = snapshot.fuzzer_attacks.len().min(max_entries);
    let next_rule_count = snapshot
        .match_replace_rules
        .len()
        .min(crate::match_replace::MAX_MATCH_REPLACE_RULES);

    let next_overview = SessionOverview::new(
        TrafficOverview::from_records(&snapshot.transactions),
        snapshot,
    );

    let changed = metadata.request_count != next_request_count
        || metadata.websocket_count != next_websocket_count
        || metadata.event_count != next_event_count
        || metadata.fuzzer_count != next_fuzzer_count
        || metadata.rule_count != next_rule_count
        || metadata.overview != next_overview;

    metadata.request_count = next_request_count;
    metadata.websocket_count = next_websocket_count;
    metadata.event_count = next_event_count;
    metadata.fuzzer_count = next_fuzzer_count;
    metadata.rule_count = next_rule_count;
    metadata.overview = next_overview;

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

fn inspect_quarantined_session_storage(root_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut quarantines = Vec::new();
    for entry in fs::read_dir(root_dir).with_context(|| {
        format!(
            "session recovery required: failed to inspect {}; startup stopped to preserve session data",
            root_dir.display()
        )
    })? {
        let entry = entry.with_context(|| {
            format!(
                "session recovery required: failed to inspect an entry in {}; startup stopped to preserve session data",
                root_dir.display()
            )
        })?;
        // Names alone are evidence. Following a symlink or requiring a directory
        // here would allow unusual storage paths to evade the preservation gate.
        if entry.file_name().to_string_lossy().starts_with(".deleted-") {
            quarantines.push(entry.path());
        }
    }
    quarantines.sort();
    Ok(quarantines)
}

fn quarantine_recovery_required(root_dir: &Path, path: &Path, reason: &str) -> anyhow::Error {
    let owner = path
        .file_name()
        .and_then(|name| quarantined_session_owner_from_name(&name.to_string_lossy()));
    let session = owner.map_or_else(String::new, |id| {
        format!(
            "session {id}, canonical storage {}; ",
            session_dir(root_dir, id).display()
        )
    });
    anyhow!(
        "session recovery required: {session}{reason}; quarantined path {}; automatic startup stopped. Preserve the entire sessions directory {} for recovery; no automatic restore was performed",
        path.display(),
        root_dir.display()
    )
}

fn validate_quarantined_session_storage(
    root_dir: &Path,
    registry: &SessionRegistrySnapshot,
    quarantines: &[PathBuf],
) -> Result<()> {
    let live = registry
        .sessions
        .iter()
        .map(|session| session.id)
        .collect::<HashSet<_>>();
    let deleted = registry
        .deleted_session_ids
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    for path in quarantines {
        let name = path.file_name().unwrap().to_string_lossy();
        let Some(id) = quarantined_deleted_session_id_from_name(&name) else {
            return Err(quarantine_recovery_required(
                root_dir,
                path,
                "the quarantine name is not a complete generated deletion name",
            ));
        };
        if live.contains(&id) && !deleted.contains(&id) {
            return Err(quarantine_recovery_required(
                root_dir,
                path,
                "the registry still lists this session without a deletion tombstone",
            ));
        }
    }
    Ok(())
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
    if value.len() != 73 {
        return None;
    }
    let id = Uuid::parse_str(value.get(..36)?).ok()?;
    let nonce = Uuid::parse_str(value.get(37..)?).ok()?;
    (value == format!("{id}-{nonce}")).then_some(id)
}

fn quarantined_session_owner_from_name(name: &str) -> Option<Uuid> {
    let value = name.strip_prefix(".deleted-")?;
    let id_text = value.get(..36)?;
    let suffix = value.get(36..)?;
    if !suffix.is_empty() && !suffix.starts_with('-') {
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
        overview: SessionOverview::default(),
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
        overview: SessionOverview::default(),
    }
}

/// Validate creation names without changing the caller's raw value or choosing a timestamp.
pub fn validate_session_creation_name(name: Option<&str>) -> Result<()> {
    if name.is_some_and(|value| value.trim().len() > MAX_SESSION_NAME_BYTES) {
        bail!("session name cannot exceed {MAX_SESSION_NAME_BYTES} bytes");
    }
    Ok(())
}

fn normalize_session_name(name: Option<&str>, now: DateTime<Utc>) -> Result<String> {
    validate_session_creation_name(name)?;
    let normalized = name
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("Session {}", now.format("%Y-%m-%d %H:%M")));
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

fn state_path(storage_dir: &Path) -> PathBuf {
    storage_dir.join(STATE_FILE)
}

#[cfg(test)]
pub(crate) fn write_transactions_file_for_test(
    storage_dir: &Path,
    records: &[TransactionRecord],
) -> Result<()> {
    write_transactions_file(&transactions_path(storage_dir), records).map(|_| ())
}

#[cfg(test)]
pub(crate) fn rewrite_transactions_file_for_test(
    storage_dir: &Path,
    entries: &[(TransactionRecord, Option<BodyLocator>)],
) -> Result<HashMap<Uuid, BodyLocator>> {
    let path = transactions_path(storage_dir);
    write_transactions_file_streaming(&path, &path.clone(), entries)
}

#[cfg(test)]
pub(crate) fn write_transactions_file_for_test_returning_locators(
    storage_dir: &Path,
    records: &[TransactionRecord],
) -> Result<HashMap<Uuid, BodyLocator>> {
    write_transactions_file(&transactions_path(storage_dir), records)
}

#[cfg(test)]
pub(crate) fn read_transactions_file_for_test(
    storage_dir: &Path,
) -> Option<Vec<(TransactionRecord, BodyLocator)>> {
    read_transactions_file(storage_dir)
}

fn transactions_path(storage_dir: &Path) -> PathBuf {
    storage_dir.join(TRANSACTIONS_FILE)
}

fn transactions_meta_path(storage_dir: &Path) -> PathBuf {
    storage_dir.join(TRANSACTIONS_META_FILE)
}

/// First line of the metadata file: what it was written against. A load compares
/// this with the real transactions.ndjson and falls back to reading that file when
/// they disagree, so a metadata file can never describe the wrong bodies.
#[derive(Serialize, Deserialize)]
struct TransactionsMetaHeader {
    source_len: u64,
    records: usize,
}

#[derive(Serialize, Deserialize)]
struct TransactionsMetaLine {
    #[serde(rename = "r")]
    record: TransactionRecord,
    #[serde(rename = "o")]
    offset: u64,
    #[serde(rename = "l")]
    len: u32,
}

fn write_transactions_meta(
    storage_dir: &Path,
    source_len: u64,
    entries: &[(TransactionRecord, BodyLocator)],
) -> Result<()> {
    let path = transactions_meta_path(storage_dir);
    let tmp_path = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let mut tmp_guard = TempJsonFile::new(tmp_path.clone());
    {
        let mut file = create_private_file(&tmp_path)
            .with_context(|| format!("failed to write {}", tmp_path.display()))?;
        {
            let mut writer = BufWriter::new(&mut file);
            serde_json::to_writer(
                &mut writer,
                &TransactionsMetaHeader {
                    source_len,
                    records: entries.len(),
                },
            )?;
            writer.write_all(b"\n")?;
            for (record, locator) in entries {
                let mut lean = record.clone();
                crate::store::strip_transaction_bodies(&mut lean);
                serde_json::to_writer(
                    &mut writer,
                    &TransactionsMetaLine {
                        record: lean,
                        offset: locator.offset,
                        len: locator.len,
                    },
                )?;
                writer.write_all(b"\n")?;
            }
            writer.flush()?;
        }
        file.sync_all()?;
    }
    crate::platform::rename(&tmp_path, &path)?;
    tmp_guard.commit();
    tighten_private_file(&path)?;
    if let Some(parent) = path.parent() {
        sync_directory(parent, "transactions metadata directory")?;
    }
    Ok(())
}

/// Reads the metadata file, or `None` when it is absent or does not describe the
/// transactions file that is actually there.
fn read_transactions_meta(storage_dir: &Path) -> Option<Vec<(TransactionRecord, BodyLocator)>> {
    let source_len = fs::metadata(transactions_path(storage_dir)).ok()?.len();
    let bytes = fs::read(transactions_meta_path(storage_dir)).ok()?;
    let mut lines = bytes.split(|byte| *byte == b'\n');
    let header: TransactionsMetaHeader = serde_json::from_slice(lines.next()?).ok()?;
    if header.source_len != source_len {
        warn!(
            expected = header.source_len,
            actual = source_len,
            "transaction metadata does not match the transactions file; rereading it"
        );
        return None;
    }
    let mut records = Vec::with_capacity(header.records);
    for line in lines {
        if trim_ascii_whitespace(line).is_empty() {
            continue;
        }
        let parsed: TransactionsMetaLine = serde_json::from_slice(line).ok()?;
        records.push((
            parsed.record,
            BodyLocator {
                offset: parsed.offset,
                len: parsed.len,
            },
        ));
    }
    if records.len() != header.records {
        return None;
    }
    Some(records)
}

/// Splits `bytes` into `parts` slices that each end on a line boundary, so every
/// line lands wholly inside exactly one slice.
fn split_on_line_boundaries(bytes: &[u8], parts: usize) -> Vec<&[u8]> {
    let mut bounds = Vec::with_capacity(parts + 1);
    bounds.push(0);
    for part in 1..parts {
        let mut at = bytes.len() * part / parts;
        while at < bytes.len() && bytes[at] != b'\n' {
            at += 1;
        }
        if at < bytes.len() {
            at += 1;
        }
        bounds.push(at.min(bytes.len()));
    }
    bounds.push(bytes.len());
    bounds.dedup();
    bounds.windows(2).map(|w| &bytes[w[0]..w[1]]).collect()
}

/// A record's line in transactions.ndjson, so its bodies can be read back on
/// demand instead of being held in memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodyLocator {
    pub offset: u64,
    pub len: u32,
}

/// Parses one chunk, recording where each line sits in the whole file.
/// `chunk_start` is the chunk's own offset, so locators are file-absolute.
fn parse_transaction_lines(
    bytes: &[u8],
    chunk_start: u64,
) -> Vec<(TransactionRecord, BodyLocator)> {
    let mut parsed = Vec::new();
    let mut line_start = 0usize;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b'\n' {
            continue;
        }
        let line = &bytes[line_start..index];
        push_transaction_line(&mut parsed, line, chunk_start + line_start as u64);
        line_start = index + 1;
    }
    if line_start < bytes.len() {
        let line = &bytes[line_start..];
        push_transaction_line(&mut parsed, line, chunk_start + line_start as u64);
    }
    parsed
}

fn push_transaction_line(
    parsed: &mut Vec<(TransactionRecord, BodyLocator)>,
    line: &[u8],
    offset: u64,
) {
    if trim_ascii_whitespace(line).is_empty() {
        return;
    }
    match serde_json::from_slice::<TransactionRecord>(line) {
        Ok(record) => parsed.push((
            record,
            BodyLocator {
                offset,
                len: line.len() as u32,
            },
        )),
        Err(error) => warn!(?error, "skipping unreadable transaction record"),
    }
}

/// Reads one record straight out of transactions.ndjson. Used to put bodies back
/// on a record whose bodies were dropped after loading.
pub fn read_transaction_at(storage_dir: &Path, locator: BodyLocator) -> Option<TransactionRecord> {
    let path = transactions_path(storage_dir);
    let mut file = fs::File::open(&path).ok()?;
    file.seek(std::io::SeekFrom::Start(locator.offset)).ok()?;
    let mut line = vec![0u8; locator.len as usize];
    file.read_exact(&mut line).ok()?;
    match serde_json::from_slice(&line) {
        Ok(record) => Some(record),
        Err(error) => {
            warn!(?error, path = %path.display(), "transaction line did not parse");
            None
        }
    }
}

/// Reads the transactions file. Returns `None` when it is absent, which is the
/// normal case for a session written before transactions moved out of
/// snapshot.json — the caller then keeps the copy embedded there.
fn read_transactions_file(storage_dir: &Path) -> Option<Vec<(TransactionRecord, BodyLocator)>> {
    let path = transactions_path(storage_dir);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            warn!(?error, path = %path.display(), "ignoring unreadable transactions file");
            return None;
        }
    };
    let threads = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1);
    if threads < 2 || bytes.len() < PARALLEL_TRANSACTION_PARSE_MIN_BYTES {
        return Some(parse_transaction_lines(&bytes, 0));
    }
    let chunks = split_on_line_boundaries(&bytes, threads);
    let mut chunk_start = 0u64;
    let chunks: Vec<(&[u8], u64)> = chunks
        .into_iter()
        .map(|chunk| {
            let start = chunk_start;
            chunk_start += chunk.len() as u64;
            (chunk, start)
        })
        .collect();
    let parsed: Vec<Vec<(TransactionRecord, BodyLocator)>> = std::thread::scope(|scope| {
        let handles: Vec<_> = chunks
            .into_iter()
            .map(|(chunk, start)| scope.spawn(move || parse_transaction_lines(chunk, start)))
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap_or_default())
            .collect()
    });
    Some(parsed.into_iter().flatten().collect())
}

/// Writes the transactions file atomically, one compact record per line.
/// Writes the transactions file from records that may still have their bodies on
/// disk, copying those lines straight across instead of loading them.
///
/// Compaction used to materialize every record: with bodies on disk that meant
/// reopening the file once per record — 115,000 opens on a real session — and
/// holding the whole 1.2 GB in memory to write it straight back out. Records that
/// have not changed since the last rewrite are copied byte for byte.
struct PreparedTransactionsFile {
    temp: TempJsonFile,
    locators: HashMap<Uuid, BodyLocator>,
    metadata: Vec<(TransactionRecord, BodyLocator)>,
    bytes: u64,
}

impl PreparedTransactionsFile {
    /// This is the only operation allowed inside the store publication barrier.
    /// Once rename succeeds, the caller must publish its locators before doing
    /// anything else that can fail or wait.
    fn rename_into_place(&mut self, path: &Path) -> io::Result<()> {
        crate::platform::rename(&self.temp.path, path)?;
        self.temp.commit();
        Ok(())
    }

    fn finalize(&self, path: &Path) -> Result<()> {
        // The private temporary file already had its permissions and contents
        // synced. Directory durability is deliberately outside the store lock.
        if let Some(storage_dir) = path.parent() {
            sync_directory(storage_dir, "transactions directory")?;
            if let Err(error) = write_transactions_meta(storage_dir, self.bytes, &self.metadata) {
                warn!(
                    ?error,
                    "failed to write transaction metadata; it will be rebuilt"
                );
            }
        }
        Ok(())
    }
}

/// Remove the old offset cache durably before replacing its body source. Length
/// alone cannot distinguish two different snapshots of equal serialized size.
fn invalidate_transactions_meta(storage_dir: &Path) -> Result<()> {
    match fs::remove_file(transactions_meta_path(storage_dir)) {
        Ok(()) => sync_directory(storage_dir, "transaction metadata invalidation directory"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // A previous unlink may have succeeded while its directory sync
            // failed. A retry must establish durable absence before replacing.
            sync_directory(storage_dir, "transaction metadata invalidation directory")
        }
        Err(error) => Err(error).context("failed to invalidate previous transaction metadata"),
    }
}

fn prepare_transactions_file_streaming(
    path: &Path,
    source: &Path,
    entries: &[(TransactionRecord, Option<BodyLocator>)],
) -> Result<PreparedTransactionsFile> {
    if let Some(parent) = path.parent() {
        // A live session directory is created by the registry, never by a stale
        // snapshot writer that might have waited behind its deletion.
        ensure_existing_private_session_dir(parent)?;
    }
    let needs_source = entries.iter().any(|(_, locator)| locator.is_some());
    let mut reader = if needs_source {
        Some(BufReader::new(fs::File::open(source).context(
            "failed to open stored transaction bodies for snapshot",
        )?))
    } else {
        None
    };
    let tmp_path = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let temp = TempJsonFile::new(tmp_path.clone());
    let mut locators = HashMap::with_capacity(entries.len());
    let mut metadata = Vec::with_capacity(entries.len());
    let mut offset = 0u64;
    let mut kept_aside = false;
    {
        let mut file = create_private_file(&tmp_path)
            .with_context(|| format!("failed to write {}", tmp_path.display()))?;
        {
            let mut writer = BufWriter::new(&mut file);
            let mut line = Vec::new();
            for (record, locator) in entries {
                line.clear();
                if let Some(locator) = locator {
                    let reader = reader
                        .as_mut()
                        .expect("located rows require a source reader");
                    line.resize(locator.len as usize, 0);
                    reader
                        .seek(std::io::SeekFrom::Start(locator.offset))
                        .and_then(|_| reader.read_exact(&mut line))
                        .context("failed to copy stored transaction bodies for snapshot")?;
                    if let Ok(mut full) = serde_json::from_slice::<TransactionRecord>(&line) {
                        // A whole line of another record means stale offsets,
                        // not damage: emptying the row would drop a body that
                        // is still in the file.
                        if full.id != record.id {
                            bail!("stored transaction locator does not match its record");
                        }
                        // An annotation changes without materializing the body. Its
                        // durable line must still carry the snapshot's annotations:
                        // the optional metadata cache cannot be their sole copy.
                        if full.notes != record.notes
                            || full.color_tag != record.color_tag
                            || full.user_note != record.user_note
                            || full.annotation_revision != record.annotation_revision
                            || full.annotation_client_versions != record.annotation_client_versions
                        {
                            full.notes.clone_from(&record.notes);
                            full.color_tag.clone_from(&record.color_tag);
                            full.user_note.clone_from(&record.user_note);
                            full.annotation_revision = record.annotation_revision;
                            full.annotation_client_versions
                                .clone_from(&record.annotation_client_versions);
                            line = serde_json::to_vec(&full)
                                .context("failed to serialize annotated transaction record")?;
                        }
                    } else {
                        // A torn write after power loss. Refusing would refuse
                        // every later save and load, so the row keeps its
                        // metadata without bodies, and the file as it was goes
                        // aside first: nothing this rewrite drops is lost.
                        if !kept_aside {
                            keep_damaged_transactions_file_aside(source);
                            kept_aside = true;
                        }
                        warn!(
                            record_id = %record.id,
                            offset = locator.offset,
                            "stored transaction line is damaged; keeping the record without bodies"
                        );
                        line = serde_json::to_vec(record)
                            .context("failed to serialize transaction record")?;
                    }
                } else {
                    line = serde_json::to_vec(record)
                        .context("failed to serialize transaction record")?;
                }
                let locator = BodyLocator {
                    offset,
                    len: u32::try_from(line.len())
                        .context("transaction line exceeds locator size")?,
                };
                // Entries are newest-first, matching by_id's authoritative row
                // when old data contains repeated UUIDs.
                locators.entry(record.id).or_insert(locator);
                let mut lean = record.clone();
                crate::store::strip_transaction_bodies(&mut lean);
                metadata.push((lean, locator));
                offset = offset
                    .checked_add(line.len() as u64 + 1)
                    .context("transaction snapshot size overflow")?;
                writer.write_all(&line)?;
                writer.write_all(b"\n")?;
            }
            writer
                .flush()
                .with_context(|| format!("failed to flush {}", tmp_path.display()))?;
        }
        file.sync_all()
            .with_context(|| format!("failed to sync {}", tmp_path.display()))?;
    }
    // Close the old source before publication on every platform.
    drop(reader);
    Ok(PreparedTransactionsFile {
        temp,
        locators,
        metadata,
        bytes: offset,
    })
}

fn write_transactions_file_streaming(
    path: &Path,
    source: &Path,
    entries: &[(TransactionRecord, Option<BodyLocator>)],
) -> Result<HashMap<Uuid, BodyLocator>> {
    let mut prepared = prepare_transactions_file_streaming(path, source, entries)?;
    if let Some(storage_dir) = path.parent() {
        invalidate_transactions_meta(storage_dir)?;
    }
    prepared.rename_into_place(path)?;
    prepared.finalize(path)?;
    Ok(prepared.locators)
}

/// Writes the transactions file and returns where each record landed. Compaction
/// changes every offset after the first record whose serialized form changed, so
/// the caller must replace its locators with these — a stale locator does not
/// error, it hands back a different request's traffic.
#[cfg(test)]
fn write_transactions_file(
    path: &Path,
    records: &[TransactionRecord],
) -> Result<HashMap<Uuid, BodyLocator>> {
    if let Some(parent) = path.parent() {
        create_private_dir_all(parent)
            .with_context(|| format!("failed to create parent directory {}", parent.display()))?;
    }
    let tmp_path = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let mut tmp_guard = TempJsonFile::new(tmp_path.clone());
    let mut locators = HashMap::with_capacity(records.len());
    let mut offset = 0u64;
    {
        let mut file = create_private_file(&tmp_path)
            .with_context(|| format!("failed to write {}", tmp_path.display()))?;
        {
            let mut writer = BufWriter::new(&mut file);
            for record in records {
                let line =
                    serde_json::to_vec(record).context("failed to serialize transaction record")?;
                locators.insert(
                    record.id,
                    BodyLocator {
                        offset,
                        len: line.len() as u32,
                    },
                );
                offset += line.len() as u64 + 1;
                writer.write_all(&line)?;
                writer.write_all(b"\n")?;
            }
            writer
                .flush()
                .with_context(|| format!("failed to flush {}", tmp_path.display()))?;
        }
        file.sync_all()
            .with_context(|| format!("failed to sync {}", tmp_path.display()))?;
    }
    crate::platform::rename(&tmp_path, path).with_context(|| {
        format!(
            "failed to rename {} to {}",
            tmp_path.display(),
            path.display()
        )
    })?;
    tmp_guard.commit();
    tighten_private_file(path)
        .with_context(|| format!("failed to set private permissions on {}", path.display()))?;
    if let Some(parent) = path.parent() {
        sync_directory(parent, "transactions directory")?;
    }
    Ok(locators)
}

/// Reads the standalone state file, but only when it is at least as new as
/// snapshot.json. Both are written by the same full persist (snapshot.json
/// first), so state.json is normally the newer one; a build from before the split
/// writes only snapshot.json, so after a downgrade the embedded copy is newer and
/// has to win. Returns `None` when the file is absent, stale or unusable.
fn read_state_file(
    storage_dir: &Path,
    mode: SessionSnapshotLoadMode,
) -> Option<StoredSessionSnapshot> {
    let path = state_path(storage_dir);
    let state_modified = fs::metadata(&path).ok()?.modified().ok();
    let snapshot_modified = fs::metadata(snapshot_path(storage_dir))
        .ok()
        .and_then(|metadata| metadata.modified().ok());
    if let (Some(state), Some(snapshot)) = (state_modified, snapshot_modified) {
        if state < snapshot {
            warn!(
                path = %path.display(),
                "ignoring state file older than the session snapshot"
            );
            return None;
        }
    }
    match fs::read(&path) {
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(state) => Some(state),
            Err(error) => {
                warn!(?error, path = %path.display(), "discarding corrupt state file");
                if mode == SessionSnapshotLoadMode::Writable {
                    move_corrupt_session_file_aside(storage_dir, &path, "state");
                }
                None
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            warn!(?error, path = %path.display(), "discarding unreadable state file");
            if mode == SessionSnapshotLoadMode::Writable {
                move_corrupt_session_file_aside(storage_dir, &path, "state");
            }
            None
        }
    }
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
pub(crate) fn create_private_file(path: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
pub(crate) fn create_private_file(path: &Path) -> io::Result<fs::File> {
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
    // Validate the storage root without changing its permissions before reading
    // preflight files; symlink/non-directory roots must still be rejected.
    if session_storage_metadata(storage_dir)?.is_none() {
        bail!(
            "session storage directory {} was not found",
            storage_dir.display()
        );
    }
    // Prepare duplicate rows and reject ambiguous journals before any writable
    // load repairs. A rejected saved history must retain every original file.
    let located =
        read_transactions_meta(storage_dir).or_else(|| read_transactions_file(storage_dir));
    let prepared_transactions = if let Some(located) = located {
        let mut occurrences = HashMap::<Uuid, usize>::new();
        for (record, _) in &located {
            *occurrences.entry(record.id).or_default() += 1;
        }
        if occurrences.values().any(|count| *count > 1) {
            ensure_empty_duplicate_recovery_journals(storage_dir)?;
        }
        let mut records = Vec::with_capacity(located.len());
        let mut locators = HashMap::with_capacity(located.len());
        for (record, locator) in located {
            if occurrences[&record.id] > 1 {
                // A by-ID locator cannot represent two different body lines.
                // Preserve each repeated row from its own offset, without
                // changing its identity or order. Unique IDs remain lazy.
                let mut full = read_transaction_at(storage_dir, locator)
                    .filter(|full| full.id == record.id)
                    .ok_or_else(|| {
                        anyhow!("failed to read a repeated transaction row from its stored offset")
                    })?;
                full.notes = record.notes;
                full.color_tag = record.color_tag;
                full.user_note = record.user_note;
                full.annotation_revision = record.annotation_revision;
                full.annotation_client_versions = record.annotation_client_versions;
                records.push(full);
            } else {
                locators.insert(record.id, locator);
                records.push(record);
            }
        }
        Some((records, locators))
    } else {
        // Legacy inline histories need the same read-only preflight. Parse only
        // when no standalone body file was loaded, before any repair can rename
        // an unrelated corrupt session component.
        if let Ok(bytes) = fs::read(snapshot_path(storage_dir)) {
            if let Ok(legacy) = serde_json::from_slice::<StoredSessionSnapshot>(&bytes) {
                if repeated_transaction_ids(&legacy.transactions) {
                    ensure_empty_duplicate_recovery_journals(storage_dir)?;
                }
            }
        }
        None
    };
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
    if let Some((records, locators)) = prepared_transactions {
        snapshot.transactions = records;
        snapshot.transaction_locators = locators;
    }
    // Take the small components from state.json when it is present, keeping the
    // two big journal-backed sections from snapshot.json. Using the state file as
    // the base means a component added later is read from the file that actually
    // writes it, rather than being silently dropped.
    if let Some(mut state) = read_state_file(storage_dir, mode) {
        state.transactions = std::mem::take(&mut snapshot.transactions);
        state.websockets = std::mem::take(&mut snapshot.websockets);
        state.transaction_event_sequence = snapshot.transaction_event_sequence;
        // Carried across with the transactions they describe. Dropping them here
        // left the store with no way to read bodies back, so every record loaded
        // from disk showed an empty body.
        state.transaction_locators = std::mem::take(&mut snapshot.transaction_locators);
        snapshot = state;
    }
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
    // Captured traffic is not discarded any more, so replay keeps every record it
    // finds. Memory is bounded by dropping bodies in the store, not by dropping
    // records here.
    let _ = max_transaction_entries;
    let replay_result = replay_transaction_journal(
        storage_dir,
        usize::MAX,
        &mut snapshot,
        mode == SessionSnapshotLoadMode::Writable,
    )?;
    snapshot.transaction_event_sequence = replay_result.transaction_event_sequence;
    snapshot.replayed_transaction_ids = replay_result.replayed_transaction_ids;
    snapshot.replayed_transaction_journal = replay_result.mutated_snapshot;
    snapshot.replayed_transaction_deletion = replay_result.replayed_deletion;
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
    if let Err(rename_error) = crate::platform::rename(path, &corrupt_path) {
        warn!(
            ?rename_error,
            path = %path.display(),
            corrupt_path = %corrupt_path.display(),
            "failed to move corrupt session file aside"
        );
    }
}

/// Keeps the transactions file as it was before a rewrite drops a damaged line
/// from it. A hard link costs no space until the rewrite replaces the file; a
/// copy stands in where links are unsupported.
fn keep_damaged_transactions_file_aside(source: &Path) {
    let Some(parent_dir) = source.parent() else {
        return;
    };
    let aside = parent_dir.join(format!(".transactions.ndjson.corrupt-{}", Uuid::new_v4()));
    if let Err(error) =
        fs::hard_link(source, &aside).or_else(|_| fs::copy(source, &aside).map(drop))
    {
        warn!(
            ?error,
            path = %aside.display(),
            "failed to keep the damaged transactions file aside"
        );
    }
}

fn repeated_transaction_ids(records: &[TransactionRecord]) -> bool {
    let mut ids = HashSet::with_capacity(records.len());
    records.iter().any(|record| !ids.insert(record.id))
}

fn ensure_empty_duplicate_recovery_journals(storage_dir: &Path) -> Result<()> {
    let journal = transaction_journal_path(storage_dir);
    let checkpoint = transaction_journal_checkpoint_path(&journal);
    for path in [&checkpoint, &journal] {
        let mut file = match fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error)
                    .context("failed to inspect duplicate transaction recovery journal")
            }
        };
        let mut byte = [0u8; 1];
        if file
            .read(&mut byte)
            .context("failed to inspect duplicate transaction recovery journal")?
            != 0
        {
            bail!("ambiguous transaction recovery: repeated record IDs with nonempty journal data; original files were preserved for review");
        }
    }
    Ok(())
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

    if repeated_transaction_ids(&snapshot.transactions) {
        // A by-ID replay map would silently discard older repeated rows.
        ensure_empty_duplicate_recovery_journals(storage_dir)?;
        normalize_snapshot_transaction_sequences(&mut snapshot.transactions);
        return Ok(TransactionJournalReplayResult {
            replayed_transaction_ids: HashSet::new(),
            replayed_deletion: false,
            mutated_snapshot: false,
            transaction_event_sequence: snapshot.transaction_event_sequence.max(
                snapshot
                    .transactions
                    .iter()
                    .map(|record| record.sequence)
                    .max()
                    .unwrap_or(0),
            ),
        });
    }

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
    let mut replayed_deletion = false;
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
        &mut snapshot.transaction_locators,
        &mut replayed_deletion,
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
        &mut snapshot.transaction_locators,
        &mut replayed_deletion,
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

    // An annotation replay changes metadata while its bodies may still exist
    // only in the old transaction file. Materialize just those changed records
    // so journal compaction cannot copy stale annotations into the durable line.
    for id in &annotation_mutated_record_ids {
        let Some(record) = records.get_mut(id) else {
            continue;
        };
        let Some(locator) = snapshot.transaction_locators.remove(id) else {
            continue;
        };
        let Some(mut full) =
            read_transaction_at(storage_dir, locator).filter(|full| full.id == *id)
        else {
            // The record keeps its replayed annotations, and the rewrite this
            // replay leads to judges the line as it judges any other.
            snapshot.transaction_locators.insert(*id, locator);
            continue;
        };
        full.notes = std::mem::take(&mut record.notes);
        full.color_tag = record.color_tag.take();
        full.user_note = record.user_note.take();
        full.annotation_revision = record.annotation_revision;
        full.annotation_client_versions = std::mem::take(&mut record.annotation_client_versions);
        *record = full;
    }

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
        || replayed_deletion
        || !replayed_transaction_ids.is_empty()
        || annotation_mutated_record_ids
            .iter()
            .any(|id| retained_ids.contains(id));
    Ok(TransactionJournalReplayResult {
        replayed_transaction_ids,
        replayed_deletion,
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

            let file = match open_private_append_file(&journal_path) {
                Ok(file) => file,
                Err(error) => {
                    warn!(?error, path = %journal_path.display(), "failed to open websocket journal");
                    let _ = ready_tx.send(Err(error));
                    return;
                }
            };
            #[cfg(not(windows))]
            let mut file = file;
            // An idle open child file prevents renaming its session directory
            // on Windows. Close before acknowledging every queued write too.
            #[cfg(windows)]
            drop(file);
            let _ = ready_tx.send(Ok(()));

            while let Ok(command) = rx.recv() {
                #[cfg(windows)]
                let mut file = match open_private_append_file(&journal_path) {
                    Ok(file) => file,
                    Err(error) => {
                        warn!(?error, path = %journal_path.display(), "failed to reopen session journal");
                        return;
                    }
                };
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
                        #[cfg(windows)]
                        drop(file);
                        let _ = ack.send(result);
                        if failed {
                            return;
                        }
                    }
                    WebSocketJournalCommand::Clear { ack } => {
                        let result = crate::platform::truncate_journal(&file, &journal_path);
                        if let Err(error) = &result {
                            warn!(?error, path = %journal_path.display(), "failed to clear websocket journal");
                        }
                        let failed = result.is_err();
                        #[cfg(windows)]
                        drop(file);
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
    if let Err(error) = crate::platform::rename(journal_path, &corrupt_path) {
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
    transaction_locators: &mut HashMap<Uuid, BodyLocator>,
    replayed_deletion: &mut bool,
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
                    transaction_locators.remove(&id);
                    annotation_mutated_record_ids.insert(id);
                } else if let Some(existing) = backfill_records.get_mut(&id) {
                    *existing = record;
                    transaction_locators.remove(&id);
                    annotation_mutated_record_ids.insert(id);
                }
            }
            TransactionJournalEntry::Delete { ids } => {
                let deleted: HashSet<_> = ids.into_iter().collect();
                *replayed_deletion |= !deleted.is_empty();
                // Keep the ids in `seen`: a duplicate insert in an overlapping
                // checkpoint or active journal must not resurrect a tombstone.
                for id in &deleted {
                    seen.insert(*id);
                    records.remove(id);
                    backfill_records.remove(id);
                    replayed_transaction_ids.remove(id);
                    transaction_locators.remove(id);
                }
                order.retain(|id| !deleted.contains(id));
                inserted_order.retain(|id| !deleted.contains(id));
                backfill_order.retain(|id| !deleted.contains(id));
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
    if let Err(error) = crate::platform::rename(journal_path, &corrupt_path) {
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
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            sync_directory(storage_dir, "transaction journal checkpoint directory")
        }
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

pub(crate) fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    write_json_with_commit_status(path, value).map_err(|failure| failure.error)
}

struct JsonWriteFailure {
    error: anyhow::Error,
    committed: bool,
}

fn write_json_with_commit_status(
    path: &Path,
    value: &impl Serialize,
) -> std::result::Result<(), JsonWriteFailure> {
    write_json_finalizing(path, value, |path| {
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
    })
}

fn write_json_finalizing(
    path: &Path,
    value: &impl Serialize,
    finalize: impl FnOnce(&Path) -> Result<()>,
) -> std::result::Result<(), JsonWriteFailure> {
    let mut committed = false;
    let result = (|| -> Result<()> {
        if let Some(parent) = path.parent() {
            create_private_dir_all(parent).with_context(|| {
                format!("failed to create parent directory {}", parent.display())
            })?;
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
        crate::platform::rename(&tmp_path, path).with_context(|| {
            format!(
                "failed to rename {} to {}",
                tmp_path.display(),
                path.display()
            )
        })?;
        tmp_guard.commit();
        committed = true;
        finalize(path)
    })();
    result.map_err(|error| JsonWriteFailure { error, committed })
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
    crate::platform::sync_directory(path)
        .with_context(|| format!("failed to sync {label} {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet, VecDeque};

    use chrono::{DateTime, Duration as ChronoDuration, Utc};
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

    #[tokio::test]
    async fn scheduled_state_writes_stay_bounded_behind_a_blocked_writer() {
        let (root, registry, session) = snapshot_correction_fixture().await;
        let references = std::sync::Arc::strong_count(&session);
        let writer = session.persist_lock.clone().lock_owned().await;
        let mut pending_references = Vec::new();
        for step in 0..4 {
            session
                .runtime
                .update(RuntimeSettingsUpdate {
                    scope_patterns: Some(vec![format!("step-{step}.example.com")]),
                    ..Default::default()
                })
                .await
                .unwrap();
            session.schedule_state_persist();
            // The writer lock is the barrier; this only advances the existing
            // debounce, not a disk-speed or scheduler-throughput assertion.
            tokio::time::sleep(
                super::STATE_PERSIST_DEBOUNCE + std::time::Duration::from_millis(50),
            )
            .await;
            pending_references.push(std::sync::Arc::strong_count(&session) - references);
        }
        drop(writer);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let state = std::fs::read(super::state_path(session.storage_dir()))
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
                if state.is_some_and(|state| {
                    state["runtime"]["scope_patterns"] == serde_json::json!(["step-3.example.com"])
                }) && std::sync::Arc::strong_count(&session) == references
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the latest state did not persist after releasing the writer");
        drop(session);
        drop(registry);
        std::fs::remove_dir_all(root).unwrap();
        assert!(
            pending_references.iter().all(|count| *count <= 2),
            "at most one writer and one coalesced pending task, not an accumulating queue: {pending_references:?}"
        );
    }

    #[tokio::test]
    async fn scheduled_state_write_keeps_changes_after_its_snapshot_was_captured() {
        let (root, registry, session) = snapshot_correction_fixture().await;
        let references = std::sync::Arc::strong_count(&session);
        session
            .runtime
            .update(RuntimeSettingsUpdate {
                scope_patterns: Some(vec!["before.example.com".into()]),
                ..Default::default()
            })
            .await
            .unwrap();
        let (entered, resume) = session.pause_next_state_write();
        session.schedule_state_persist();
        tokio::time::timeout(std::time::Duration::from_secs(3), entered)
            .await
            .expect("the state-only writer did not reach its capture barrier")
            .unwrap();
        session
            .runtime
            .update(RuntimeSettingsUpdate {
                scope_patterns: Some(vec!["late.example.com".into()]),
                ..Default::default()
            })
            .await
            .unwrap();
        session.schedule_state_persist();
        resume.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let state = std::fs::read(super::state_path(session.storage_dir()))
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
                if state.is_some_and(|state| {
                    state["runtime"]["scope_patterns"] == serde_json::json!(["late.example.com"])
                }) && std::sync::Arc::strong_count(&session) == references
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("a state change during the prior write was not checkpointed");
        drop(session);
        drop(registry);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn scheduled_state_write_hands_off_to_a_new_caller_without_losing_its_change() {
        let (root, registry, session) = snapshot_correction_fixture().await;
        let references = std::sync::Arc::strong_count(&session);
        let (entered, resume) = session.pause_next_state_handoff();
        session.schedule_state_persist();
        tokio::time::timeout(std::time::Duration::from_secs(3), entered)
            .await
            .expect("the first writer did not release its scheduler ownership")
            .unwrap();
        assert!(!session
            .state_persist_scheduled
            .load(std::sync::atomic::Ordering::SeqCst));
        session
            .runtime
            .update(RuntimeSettingsUpdate {
                scope_patterns: Some(vec!["handoff.example.com".into()]),
                ..Default::default()
            })
            .await
            .unwrap();
        session.schedule_state_persist();
        assert_eq!(std::sync::Arc::strong_count(&session) - references, 2);
        resume.send(()).unwrap();
        wait_scheduled_scope(&session, references, "handoff.example.com").await;
        drop(session);
        drop(registry);
        let (registry, session) = SessionRegistry::load_or_create(&root, 32, 32).unwrap();
        assert_eq!(
            session.runtime.snapshot().await.scope_patterns,
            vec!["handoff.example.com"]
        );
        drop(session);
        drop(registry);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn scheduled_state_write_releases_ownership_after_error_and_retries_a_later_change() {
        let (root, registry, session) = snapshot_correction_fixture().await;
        let references = std::sync::Arc::strong_count(&session);
        let path = super::state_path(session.storage_dir());
        // An owned fixture directory at the destination makes atomic rename
        // fail, without changing permissions or depending on disk capacity.
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let (entered, resume) = session.pause_next_state_handoff();
        session.schedule_state_persist();
        tokio::time::timeout(std::time::Duration::from_secs(3), entered)
            .await
            .expect("the failed writer did not release its scheduler ownership")
            .unwrap();
        assert!(
            path.is_dir(),
            "the deliberately failing destination remains"
        );
        assert!(!session
            .state_persist_scheduled
            .load(std::sync::atomic::Ordering::SeqCst));
        resume.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while std::sync::Arc::strong_count(&session) != references {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("an unchanged failed write must not spin or retain a worker");
        std::fs::remove_dir(&path).unwrap();
        session
            .runtime
            .update(RuntimeSettingsUpdate {
                scope_patterns: Some(vec!["retry.example.com".into()]),
                ..Default::default()
            })
            .await
            .unwrap();
        session.schedule_state_persist();
        wait_scheduled_scope(&session, references, "retry.example.com").await;
        drop(session);
        drop(registry);
        std::fs::remove_dir_all(root).unwrap();
    }

    async fn wait_scheduled_scope(
        session: &std::sync::Arc<super::SessionContext>,
        references: usize,
        scope: &str,
    ) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let state = std::fs::read(super::state_path(session.storage_dir()))
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
                if state.is_some_and(|state| {
                    state["runtime"]["scope_patterns"] == serde_json::json!([scope])
                }) && std::sync::Arc::strong_count(session) == references
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the latest scheduled state did not persist and release its worker");
    }

    #[tokio::test]
    async fn peer_capture_eligibility_matches_status_after_runtime_and_gate_changes() {
        // An in-memory read-only context avoids journal workers and storage I/O.
        let session = super::SessionContext::from_snapshot_read_only(
            super::default_session_metadata("peer eligibility"),
            std::env::temp_dir().join(format!("sniper-peer-eligibility-{}", Uuid::new_v4())),
            32,
            32,
            super::MAX_PERSISTED_WEBSOCKET_FRAMES_PER_SESSION,
            super::StoredSessionSnapshot {
                scanner_config: ScannerConfig {
                    enabled: false,
                    ..ScannerConfig::default()
                },
                ..super::StoredSessionSnapshot::default()
            },
        );
        assert!(!session.upstream_peer_capture_eligible().await);
        for enabled in [false, true] {
            for http_capture_enabled in [false, true] {
                for revision in [None, Some(0), Some(1), Some(u64::MAX - 1), Some(u64::MAX)] {
                    session
                        .runtime
                        .set_upstream_peer_capture_config(enabled, revision)
                        .await;
                    session
                        .runtime
                        .update(RuntimeSettingsUpdate {
                            http_capture_enabled: Some(http_capture_enabled),
                            ..RuntimeSettingsUpdate::default()
                        })
                        .await
                        .unwrap();
                    let full = session.runtime.snapshot().await;
                    for uncertain in [false, true] {
                        session.upstream_peer_settings.mark_uncertain(uncertain);
                        assert_eq!(
                            session.upstream_peer_capture_eligible().await,
                            crate::upstream_peer_settings::status(&full, uncertain)
                                .effective_enabled
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn saved_http_workspace_write_distinguishes_precommit_and_postrename_failures() {
        let root =
            std::env::temp_dir().join(format!("sniper-json-commit-status-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("workspace.json");
        std::fs::create_dir(&path).unwrap();
        let error = super::write_json_with_commit_status(&path, &serde_json::json!({"revision":1}))
            .err()
            .unwrap();
        assert!(!error.committed);
        assert!(path.is_dir());
        std::fs::remove_dir(&path).unwrap();
        std::fs::write(&path, b"{\"revision\":1}").unwrap();
        let error = super::write_json_finalizing(&path, &serde_json::json!({"revision":2}), |_| {
            anyhow::bail!("injected directory sync failure")
        })
        .err()
        .unwrap();
        assert!(error.committed);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&std::fs::read(&path).unwrap()).unwrap(),
            serde_json::json!({"revision":2})
        );
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }

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
    fn load_session_snapshot_takes_small_components_from_the_state_file() {
        // "state file is newer" is the normal case: a full persist writes
        // snapshot.json first, and persist_state_only writes only state.json.
        // "snapshot is newer" only happens after a build from before the split
        // wrote the whole document, and then the embedded copy has to win.
        for state_file_is_newer in [true, false] {
            let storage_dir =
                std::env::temp_dir().join(format!("sniper-state-file-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&storage_dir).unwrap();

            // write_json fsyncs and renames, so write order is mtime order.
            let write_snapshot = || {
                super::write_json(
                    &super::snapshot_path(&storage_dir),
                    &serde_json::json!({
                        "runtime": { "scope_patterns": ["from-snapshot"] },
                        "transactions": [],
                        "transaction_event_sequence": 42,
                    }),
                )
                .unwrap()
            };
            let write_state = || {
                super::write_json(
                    &super::state_path(&storage_dir),
                    &serde_json::json!({
                        "runtime": { "scope_patterns": ["from-state-file"] },
                        "transaction_event_sequence": 0,
                    }),
                )
                .unwrap()
            };
            if state_file_is_newer {
                write_snapshot();
                write_state();
            } else {
                write_state();
                write_snapshot();
            }

            let loaded = super::load_session_snapshot(&storage_dir, 32, 32).unwrap();
            let expected = if state_file_is_newer {
                "from-state-file"
            } else {
                "from-snapshot"
            };
            assert_eq!(
                loaded.runtime.scope_patterns,
                vec![expected.to_string()],
                "state file newer = {state_file_is_newer}"
            );
            // The big journal-backed sections always come from snapshot.json,
            // never from the state file's empty placeholders.
            assert_eq!(loaded.transaction_event_sequence, 42);

            let _ = std::fs::remove_dir_all(storage_dir);
        }
    }

    #[test]
    fn split_on_line_boundaries_never_cuts_a_record_in_half() {
        // The parallel parse hands each thread a slice of the file. If a boundary
        // landed mid-line, that record would be dropped by one thread and produce
        // a parse error in the other — silently losing captured traffic.
        let bytes = b"aaaa\nbb\ncccccccccc\nd\n\nee\n";
        for parts in 1..=9 {
            let chunks = super::split_on_line_boundaries(bytes, parts);
            assert_eq!(
                chunks.concat(),
                bytes.to_vec(),
                "parts = {parts}: chunks must cover the input exactly once"
            );
            for chunk in &chunks {
                assert!(
                    chunk.is_empty() || chunk.ends_with(b"\n"),
                    "parts = {parts}: every chunk must end on a line boundary"
                );
            }
        }
    }

    #[test]
    fn stale_transaction_metadata_is_ignored_rather_than_trusted() {
        // The metadata file describes bodies by byte offset. If it is allowed to
        // describe a transactions file it was not written against, every offset is
        // wrong and reads return other requests' traffic. It must be checked, not
        // trusted.
        let storage_dir =
            std::env::temp_dir().join(format!("sniper-stale-meta-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&storage_dir).unwrap();
        let make = |path: &str, body: &str| {
            TransactionRecord::http(
                Utc::now(),
                "GET".to_string(),
                "https".to_string(),
                "meta.example:443".to_string(),
                path.to_string(),
                Some(200),
                1,
                MessageRecord {
                    headers: vec![],
                    body_preview: body.to_string(),
                    body_encoding: BodyEncoding::Utf8,
                    body_size: body.len(),
                    decoded_body_size: None,
                    preview_truncated: false,
                    content_type: None,
                    content_decoded: false,
                },
                None,
                vec![],
                None,
                None,
            )
        };

        // A write produces both files, and the metadata is used.
        let first = make("/first", "one");
        super::write_transactions_file_for_test(&storage_dir, &[first.clone()]).unwrap();
        let entries: Vec<_> = super::read_transactions_file_for_test(&storage_dir)
            .unwrap()
            .into_iter()
            .map(|(record, locator)| (record, locator))
            .collect();
        super::write_transactions_meta(
            &storage_dir,
            std::fs::metadata(super::transactions_path(&storage_dir))
                .unwrap()
                .len(),
            &entries,
        )
        .unwrap();
        let from_meta = super::read_transactions_meta(&storage_dir).unwrap();
        assert_eq!(from_meta.len(), 1);
        assert_eq!(from_meta[0].0.path, "/first");

        // Rewriting the transactions file without refreshing the metadata must make
        // the metadata unusable, not silently wrong.
        super::write_transactions_file_for_test(
            &storage_dir,
            &[make("/second", &"y".repeat(500)), first],
        )
        .unwrap();
        std::fs::write(
            super::transactions_meta_path(&storage_dir),
            std::fs::read(super::transactions_meta_path(&storage_dir)).unwrap(),
        )
        .unwrap();
        assert!(
            super::read_transactions_meta(&storage_dir).is_none(),
            "metadata written against a different file must be rejected"
        );

        let _ = std::fs::remove_dir_all(storage_dir);
    }

    #[test]
    fn transaction_locators_point_at_the_right_line_across_parallel_chunks() {
        // Each record is read back by seeking to its recorded offset, so an offset
        // that is off by one line silently returns someone else's traffic. The
        // parallel path hands each thread a slice, and its locators must still be
        // absolute within the whole file.
        let storage_dir =
            std::env::temp_dir().join(format!("sniper-locators-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&storage_dir).unwrap();
        let records: Vec<_> = (0..600)
            .map(|i| {
                TransactionRecord::http(
                    Utc::now(),
                    "GET".to_string(),
                    "https".to_string(),
                    "locators.example:443".to_string(),
                    format!("/record-{i}"),
                    Some(200),
                    1,
                    MessageRecord {
                        headers: vec![],
                        // Vary the length so lines are not uniform.
                        body_preview: "x".repeat(i * 80),
                        body_encoding: BodyEncoding::Utf8,
                        body_size: i * 80,
                        decoded_body_size: None,
                        preview_truncated: false,
                        content_type: None,
                        content_decoded: false,
                    },
                    None,
                    vec![],
                    None,
                    None,
                )
            })
            .collect();
        super::write_transactions_file(&super::transactions_path(&storage_dir), &records).unwrap();

        // Must exceed PARALLEL_TRANSACTION_PARSE_MIN_BYTES so the chunked path runs.
        let file_len = std::fs::metadata(super::transactions_path(&storage_dir))
            .unwrap()
            .len() as usize;
        assert!(
            file_len > super::PARALLEL_TRANSACTION_PARSE_MIN_BYTES,
            "fixture must be big enough to take the parallel path, was {file_len} bytes"
        );

        let located = super::read_transactions_file(&storage_dir).unwrap();
        assert_eq!(located.len(), records.len());
        for (index, (record, locator)) in located.iter().enumerate() {
            assert_eq!(record.path, format!("/record-{index}"));
            let reread = super::read_transaction_at(&storage_dir, *locator)
                .unwrap_or_else(|| panic!("record {index} did not read back at its locator"));
            assert_eq!(reread.id, record.id);
            assert_eq!(reread.path, record.path);
            assert_eq!(reread.request.body_preview, record.request.body_preview);
        }

        let _ = std::fs::remove_dir_all(storage_dir);
    }

    #[test]
    fn transactions_round_trip_through_their_own_file_and_fall_back_to_the_snapshot() {
        let storage_dir =
            std::env::temp_dir().join(format!("sniper-transactions-file-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&storage_dir).unwrap();
        let record = |path: &str| {
            TransactionRecord::http(
                Utc::now(),
                "GET".to_string(),
                "https".to_string(),
                "records.example:443".to_string(),
                path.to_string(),
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
            )
        };

        // A session written before the move keeps its records in snapshot.json.
        let legacy = record("/legacy");
        super::write_json(
            &super::snapshot_path(&storage_dir),
            &serde_json::json!({ "transactions": [legacy] }),
        )
        .unwrap();
        assert!(super::read_transactions_file(&storage_dir).is_none());
        let loaded = super::load_session_snapshot(&storage_dir, 32, 32).unwrap();
        assert_eq!(loaded.transactions.len(), 1);
        assert_eq!(loaded.transactions[0].path, "/legacy");

        // Once the file exists it is authoritative, and survives a round trip.
        let moved: Vec<_> = (0..3).map(|i| record(&format!("/moved-{i}"))).collect();
        super::write_transactions_file(&super::transactions_path(&storage_dir), &moved).unwrap();
        let loaded = super::load_session_snapshot(&storage_dir, 32, 32).unwrap();
        let paths: Vec<_> = loaded
            .transactions
            .iter()
            .map(|record| record.path.clone())
            .collect();
        assert_eq!(paths, vec!["/moved-0", "/moved-1", "/moved-2"]);

        let _ = std::fs::remove_dir_all(storage_dir);
    }

    #[test]
    fn transaction_journal_replay_bytes_counts_the_checkpoint_too() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-journal-replay-bytes-{}",
            uuid::Uuid::new_v4()
        ));
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
            let storage_dir = std::env::temp_dir().join(format!(
                "sniper-workspace-precedence-{}",
                uuid::Uuid::new_v4()
            ));
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

    // `history get --session-id` and search read a session without activating
    // it; its store must read bodies back from disk like an active one.
    #[tokio::test]
    async fn a_session_read_without_activation_serves_its_bodies() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-read-only-bodies-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
        let empty = MessageRecord::from_headers_and_body(&http::HeaderMap::new(), &[], 1024);
        let answer =
            MessageRecord::from_headers_and_body(&http::HeaderMap::new(), b"retained body", 1024);
        let record = TransactionRecord::http(
            Utc::now(),
            "GET".into(),
            "https".into(),
            "example.com".into(),
            "/page".into(),
            Some(200),
            1,
            empty,
            Some(answer),
            Vec::new(),
            None,
            None,
        );
        let id = record.id;
        active.store.insert(record).await;
        active.persist().await.unwrap();

        let read = registry.load_context_read_only(active.id()).unwrap();
        let loaded = read.store.get(id).await.unwrap();
        assert_eq!(
            loaded.response.as_ref().unwrap().body_preview,
            "retained body"
        );

        // A capture that lands in it is persisted at once; the older row keeps
        // its body rather than being written back without one.
        let mut later = loaded.clone();
        later.id = Uuid::new_v4();
        read.store.insert(later).await;
        read.persist().await.unwrap();
        let reloaded = registry.load_context(active.id()).unwrap();
        let kept = reloaded.store.get(id).await.unwrap();
        assert_eq!(kept.response.unwrap().body_preview, "retained body");

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

    #[test]
    fn session_creation_name_validates_trimmed_utf8_bytes() {
        let now = DateTime::parse_from_rfc3339("2026-10-10T12:34:56Z")
            .unwrap()
            .with_timezone(&Utc);
        for name in ["x".repeat(256), "é".repeat(128), "😀".repeat(64)] {
            for raw in [name.clone(), format!(" \t\u{2003}{name}\n ")] {
                super::validate_session_creation_name(Some(&raw)).unwrap();
                assert_eq!(
                    super::normalize_session_name(Some(&raw), now).unwrap(),
                    name
                );
            }
        }
        for name in ["x".repeat(257), "é".repeat(129), "😀".repeat(65)] {
            for raw in [name.clone(), format!(" \t\u{2003}{name}\n ")] {
                let error = super::validate_session_creation_name(Some(&raw)).unwrap_err();
                assert_eq!(error.to_string(), "session name cannot exceed 256 bytes");
                assert!(super::normalize_session_name(Some(&raw), now).is_err());
            }
        }
    }

    #[test]
    fn session_creation_name_preserves_defaults_and_embedded_controls() {
        let now = DateTime::parse_from_rfc3339("2026-10-10T12:34:56Z")
            .unwrap()
            .with_timezone(&Utc);
        let long_blank = " \t\n\u{2003}".repeat(100);
        for name in [
            None,
            Some(""),
            Some(" \t\n\u{2003}"),
            Some(long_blank.as_str()),
        ] {
            super::validate_session_creation_name(name).unwrap();
            assert_eq!(
                super::normalize_session_name(name, now).unwrap(),
                "Session 2026-10-10 12:34"
            );
        }
        for name in ["a\nb", "a\0b", "Review"] {
            let raw = format!(" \u{2003}{name}\t ");
            super::validate_session_creation_name(Some(&raw)).unwrap();
            assert_eq!(
                super::normalize_session_name(Some(&raw), now).unwrap(),
                name
            );
        }
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
    async fn registry_rename_finalization_failure_keeps_visible_metadata_coherent() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-rename-finalize-{}", Uuid::new_v4()));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
        let stale = registry.create_session(Some("Before".to_owned())).unwrap();
        let storage = registry.session_storage_path(stale.id).unwrap();
        registry.fail_next_rename(super::SessionRenameFault::AfterReplacement);
        assert!(registry
            .rename_session(stale.id, "After")
            .unwrap_err()
            .to_string()
            .contains("finalization"));
        let disk: super::SessionRegistrySnapshot =
            serde_json::from_slice(&std::fs::read(&registry.registry_path).unwrap()).unwrap();
        assert_eq!(
            disk.sessions
                .iter()
                .find(|s| s.id == stale.id)
                .unwrap()
                .name,
            "After"
        );
        assert_eq!(
            registry
                .summaries()
                .iter()
                .find(|s| s.id == stale.id)
                .unwrap()
                .name,
            "After"
        );
        registry.update_metadata(stale.clone()).unwrap();
        drop(active);
        drop(registry);
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
        let summary = registry
            .summaries()
            .into_iter()
            .find(|s| s.id == stale.id)
            .unwrap();
        assert_eq!(summary.name, "After");
        assert_eq!(summary.created_at, stale.created_at);
        assert_eq!(registry.session_storage_path(stale.id).unwrap(), storage);
        drop(active);
        drop(registry);
        std::fs::remove_dir_all(data_dir).unwrap();
    }

    #[tokio::test]
    async fn registry_same_name_rename_retries_persistence_after_finalization_failure() {
        let data_dir = std::env::temp_dir().join(format!("sniper-rename-retry-{}", Uuid::new_v4()));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
        registry.fail_next_rename(super::SessionRenameFault::AfterReplacement);
        assert!(registry.rename_session(active.id(), "After").is_err());
        let updated_at = registry.summaries()[0].updated_at;
        registry.fail_next_rename(super::SessionRenameFault::BeforeReplacement);
        assert!(registry
            .rename_session(active.id(), "After")
            .unwrap_err()
            .to_string()
            .contains("before replacement"));
        assert_eq!(registry.summaries()[0].name, "After");
        assert_eq!(registry.summaries()[0].updated_at, updated_at);
        let metadata = registry.rename_session(active.id(), "After").unwrap();
        assert_eq!(metadata.updated_at, updated_at);
        drop(active);
        drop(registry);
        std::fs::remove_dir_all(data_dir).unwrap();
    }

    #[tokio::test]
    async fn registry_rename_session_preserves_storage_and_survives_restart() {
        let data_dir = std::env::temp_dir().join(format!("sniper-rename-{}", Uuid::new_v4()));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
        let before = registry.create_session(Some("Before".to_owned())).unwrap();
        let storage = registry.session_storage_path(before.id).unwrap();
        let snapshot = std::fs::read(storage.join("snapshot.json")).unwrap();

        let renamed = registry
            .rename_session(before.id, "  Review / ../ example.com  ")
            .unwrap();
        assert_eq!(renamed.name, "Review / ../ example.com");
        assert_eq!(renamed.id, before.id);
        assert_eq!(renamed.created_at, before.created_at);
        assert_eq!(renamed.last_opened_at, before.last_opened_at);
        assert!(renamed.updated_at >= before.updated_at);
        assert_eq!(registry.active_session_id(), active.id());
        assert_eq!(registry.session_storage_path(before.id).unwrap(), storage);
        assert_eq!(
            std::fs::read(storage.join("snapshot.json")).unwrap(),
            snapshot
        );
        assert_eq!(std::fs::read_dir(&registry.root_dir).unwrap().count(), 3);
        let unchanged = registry.rename_session(before.id, &renamed.name).unwrap();
        assert_eq!(unchanged.updated_at, renamed.updated_at);
        drop(active);
        drop(registry);

        let (reloaded, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
        let summary = reloaded
            .summaries()
            .into_iter()
            .find(|session| session.id == before.id)
            .unwrap();
        assert_eq!(summary.name, renamed.name);
        assert_eq!(summary.created_at, before.created_at);
        assert_eq!(summary.last_opened_at, before.last_opened_at);
        assert_eq!(summary.updated_at, renamed.updated_at);
        assert!(!summary.active);
        assert_eq!(reloaded.session_storage_path(before.id).unwrap(), storage);
        drop(active);
        drop(reloaded);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn registry_rename_session_validates_trimmed_utf8_names() {
        let data_dir = std::env::temp_dir().join(format!("sniper-rename-name-{}", Uuid::new_v4()));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
        let before = serde_json::to_value(registry.summaries()).unwrap();
        for name in [
            "",
            " \t\n ",
            "embedded\nnewline",
            "nul\0byte",
            "tab\there",
            "del\u{7f}",
        ] {
            let error = registry.rename_session(active.id(), name).unwrap_err();
            assert!(error.to_string().contains("session name"));
        }
        for name in [
            "x".repeat(super::MAX_SESSION_NAME_BYTES + 1),
            "é".repeat(129),
        ] {
            let error = registry.rename_session(active.id(), &name).unwrap_err();
            assert!(error.to_string().contains("256 bytes"));
        }
        assert_eq!(serde_json::to_value(registry.summaries()).unwrap(), before);
        let boundary = "é".repeat(128);
        assert_eq!(
            registry
                .rename_session(active.id(), &format!("  {boundary}  "))
                .unwrap()
                .name,
            boundary
        );
        let error = registry
            .rename_session(Uuid::new_v4(), "Missing")
            .unwrap_err();
        assert!(error.to_string().contains("was not found"));
        drop(active);
        drop(registry);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn registry_rename_session_failed_write_keeps_live_and_saved_metadata() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-rename-failure-{}", Uuid::new_v4()));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
        let before = serde_json::to_value(registry.summaries()).unwrap();
        let backup = registry.registry_path.with_extension("saved");
        std::fs::rename(&registry.registry_path, &backup).unwrap();
        std::fs::create_dir(&registry.registry_path).unwrap();

        let error = registry.rename_session(active.id(), "After").unwrap_err();
        assert!(error.to_string().contains("failed to rename"));
        assert_eq!(serde_json::to_value(registry.summaries()).unwrap(), before);
        assert!(
            !std::fs::read_dir(&registry.root_dir).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains(".tmp-")
            })
        );
        std::fs::remove_dir(&registry.registry_path).unwrap();
        std::fs::rename(backup, &registry.registry_path).unwrap();
        let id = active.id();
        let name = active.summary(true).name;
        drop(active);
        drop(registry);

        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
        assert_eq!(active.id(), id);
        assert_eq!(active.summary(true).name, name);
        drop(active);
        drop(registry);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn registry_rename_session_is_not_reverted_by_stale_snapshot_metadata() {
        let data_dir = std::env::temp_dir().join(format!("sniper-rename-stale-{}", Uuid::new_v4()));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
        let mut stale = registry.create_session(Some("Before".to_owned())).unwrap();
        let renamed = registry.rename_session(stale.id, "After").unwrap();
        let activated = registry.activate_session(stale.id).unwrap();
        stale.request_count = 7;
        registry.update_metadata(stale.clone()).unwrap();
        let summary = registry
            .summaries()
            .into_iter()
            .find(|s| s.id == stale.id)
            .unwrap();
        assert_eq!(summary.name, "After");
        assert_eq!(summary.created_at, stale.created_at);
        assert_eq!(summary.last_opened_at, activated.last_opened_at);
        assert_eq!(summary.updated_at, renamed.updated_at);
        assert_eq!(summary.request_count, 7);
        drop(active);
        drop(registry);
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
        assert!(
            snapshot_path.is_dir(),
            "the workspace save must not touch snapshot.json"
        );

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

    fn quarantine_fixture_tree(
        root: &std::path::Path,
    ) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
        fn visit(
            root: &std::path::Path,
            path: &std::path::Path,
            tree: &mut std::collections::BTreeMap<std::path::PathBuf, Vec<u8>>,
        ) {
            let metadata = std::fs::symlink_metadata(path).unwrap();
            let relative = path.strip_prefix(root).unwrap().to_owned();
            if metadata.file_type().is_symlink() {
                let target = std::fs::read_link(path).unwrap();
                tree.insert(
                    relative,
                    format!("symlink:{}", target.display()).into_bytes(),
                );
            } else if metadata.is_dir() {
                tree.insert(relative, b"directory".to_vec());
                for entry in std::fs::read_dir(path).unwrap() {
                    visit(root, &entry.unwrap().path(), tree);
                }
            } else {
                let mut bytes = b"file:".to_vec();
                bytes.extend(std::fs::read(path).unwrap());
                tree.insert(relative, bytes);
            }
        }
        let mut tree = std::collections::BTreeMap::new();
        visit(root, root, &mut tree);
        tree
    }

    fn assert_quarantine_startup_refused_without_changes(data_dir: &std::path::Path) -> String {
        let before = quarantine_fixture_tree(data_dir);
        let mut last_error = String::new();
        for _ in 0..2 {
            let error = SessionRegistry::load_or_create(data_dir, 32, 32)
                .err()
                .expect("uncertain quarantine must stop startup");
            last_error = format!("{error:#}");
            assert!(
                last_error.contains("session recovery required"),
                "{last_error}"
            );
            assert!(last_error.contains("startup stopped"), "{last_error}");
            assert!(
                last_error.contains("Preserve the entire sessions directory"),
                "{last_error}"
            );
            assert_eq!(quarantine_fixture_tree(data_dir), before);
        }
        last_error
    }

    #[test]
    fn registry_quarantine_live_session_requires_recovery_before_normalization() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-live-quarantine-{}", Uuid::new_v4()));
        let root_dir = data_dir.join(super::SESSIONS_DIR);
        let active = super::default_session_metadata("Active");
        let target = super::default_session_metadata("Interrupted deletion");
        for metadata in [&active, &target] {
            super::persist_session_snapshot(
                &root_dir,
                metadata,
                &super::StoredSessionSnapshot::default(),
            )
            .unwrap();
        }
        let canonical = super::session_dir(&root_dir, target.id);
        let quarantine = super::deleted_session_dir(&root_dir, target.id);
        std::fs::write(
            canonical.join("synthetic-original"),
            b"preserve original bytes",
        )
        .unwrap();
        crate::platform::rename(&canonical, &quarantine).unwrap();
        // Eligible cleanup elsewhere must also wait until all evidence passes
        // preflight; an error must not leave a partially cleaned session root.
        let tombstoned = super::default_session_metadata("Committed deletion");
        let orphan = super::default_session_metadata("Unreferenced deletion");
        for metadata in [&tombstoned, &orphan] {
            super::persist_session_snapshot(
                &root_dir,
                metadata,
                &super::StoredSessionSnapshot::default(),
            )
            .unwrap();
            crate::platform::rename(
                &super::session_dir(&root_dir, metadata.id),
                &super::deleted_session_dir(&root_dir, metadata.id),
            )
            .unwrap();
        }
        let tombstoned_canonical = super::session_dir(&root_dir, tombstoned.id);
        std::fs::create_dir(&tombstoned_canonical).unwrap();
        std::fs::write(
            tombstoned_canonical.join("synthetic-stale"),
            b"preserve before cleanup",
        )
        .unwrap();
        // Missing active_session_id is supported legacy input. Refusal must
        // precede the repaired-registry write as well as destructive cleanup.
        super::write_json(
            &root_dir.join(super::REGISTRY_FILE),
            &serde_json::json!({
                "sessions": [active, target.clone()],
                "deleted_session_ids": [tombstoned.id]
            }),
        )
        .unwrap();
        let error = assert_quarantine_startup_refused_without_changes(&data_dir);
        assert!(error.contains(&target.id.to_string()));
        assert!(error.contains(&canonical.display().to_string()));
        assert!(error.contains(&quarantine.display().to_string()));
        assert!(!canonical.exists());
        assert_eq!(
            std::fs::read(quarantine.join("synthetic-original")).unwrap(),
            b"preserve original bytes"
        );
        std::fs::remove_dir_all(data_dir).unwrap();
    }

    #[tokio::test]
    async fn registry_quarantine_preserves_cached_write_divergence_on_repeated_startup() {
        for mode in ["none", "unrelated", "workspace", "state", "full"] {
            let data_dir = std::env::temp_dir().join(format!(
                "sniper-quarantine-cached-{mode}-{}",
                Uuid::new_v4()
            ));
            let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
            let target = registry
                .create_session(Some("Synthetic target".into()))
                .unwrap();
            let canonical = registry.session_storage_path(target.id).unwrap();
            let record = deletion_test_record(37);
            super::write_transactions_file_for_test(&canonical, &[record.clone()]).unwrap();
            let cached = registry.load_context(target.id).unwrap();
            let original_snapshot = std::fs::read(canonical.join("snapshot.json")).unwrap();
            let original_transactions =
                std::fs::read(canonical.join("transactions.ndjson")).unwrap();
            let quarantine = super::deleted_session_dir(&registry.root_dir, target.id);
            // This is the exact on-disk boundary after a precommit registry
            // error and failed restore; no physical filesystem fault is needed.
            crate::platform::rename(&canonical, &quarantine).unwrap();
            let original_quarantine = quarantine_fixture_tree(&quarantine);
            let save_error = match mode {
                "none" => None,
                "unrelated" => {
                    registry
                        .update_metadata(active.metadata.read().unwrap().clone())
                        .unwrap();
                    None
                }
                "workspace" => cached
                    .persist_workspace_snapshot_locked(WorkspaceStateSnapshot::default())
                    .await
                    .err(),
                "state" => cached.persist_state_only().await.err(),
                "full" => cached.persist().await.err(),
                _ => unreachable!(),
            };
            if matches!(mode, "workspace" | "state" | "full") {
                let error = save_error.expect("cached saves must refuse a missing session root");
                let message = error.to_string();
                assert!(message.contains("was not found"), "{message}");
                assert!(
                    message.contains(&canonical.display().to_string()),
                    "{message}"
                );
            }
            assert!(!canonical.exists());
            assert_eq!(quarantine_fixture_tree(&quarantine), original_quarantine);
            assert_eq!(
                std::fs::read(quarantine.join("snapshot.json")).unwrap(),
                original_snapshot
            );
            assert_eq!(
                std::fs::read(quarantine.join("transactions.ndjson")).unwrap(),
                original_transactions
            );
            assert_eq!(
                super::read_transactions_file_for_test(&quarantine).unwrap()[0]
                    .0
                    .request
                    .body_preview,
                record.request.body_preview
            );
            drop(cached);
            drop(active);
            drop(registry);
            assert_quarantine_startup_refused_without_changes(&data_dir);

            if matches!(mode, "workspace" | "state" | "full") {
                // Older builds or external writers can still leave divergent
                // canonical files. Construct that evidence explicitly instead
                // of requiring current cached saves to resurrect the root.
                std::fs::create_dir(&canonical).unwrap();
                let workspace = WorkspaceStateSnapshot {
                    revision: 7,
                    client_id: Some("synthetic-external-writer".into()),
                    ..WorkspaceStateSnapshot::default()
                };
                if mode == "workspace" {
                    super::write_json(&super::workspace_path(&canonical), &workspace).unwrap();
                } else {
                    let snapshot = super::StoredSessionSnapshot {
                        workspace,
                        scanner_config: crate::scanner::ScannerConfig {
                            enabled: false,
                            ..crate::scanner::ScannerConfig::default()
                        },
                        ..super::StoredSessionSnapshot::default()
                    };
                    let path = if mode == "state" {
                        super::state_path(&canonical)
                    } else {
                        super::write_transactions_file_for_test(
                            &canonical,
                            &[deletion_test_record(38)],
                        )
                        .unwrap();
                        super::snapshot_path(&canonical)
                    };
                    super::write_json(&path, &snapshot).unwrap();
                }
                assert_quarantine_startup_refused_without_changes(&data_dir);
                assert_eq!(quarantine_fixture_tree(&quarantine), original_quarantine);
            }
            std::fs::remove_dir_all(data_dir).unwrap();
        }
    }

    #[test]
    fn registry_quarantine_preserves_multiple_file_and_malformed_evidence() {
        for kind in [
            "multiple",
            "file",
            "bare",
            "empty_nonce",
            "bad_nonce",
            "unknown_owner",
            "partial_owner",
            "malformed_tombstoned",
        ] {
            let data_dir = std::env::temp_dir().join(format!(
                "sniper-quarantine-evidence-{kind}-{}",
                Uuid::new_v4()
            ));
            let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
            let target = registry
                .create_session(Some("Synthetic target".into()))
                .unwrap();
            let canonical = registry.session_storage_path(target.id).unwrap();
            std::fs::write(canonical.join("synthetic-canonical"), b"keep canonical").unwrap();
            let name = match kind {
                "bare" => format!(".deleted-{}", target.id),
                "empty_nonce" => format!(".deleted-{}-", target.id),
                "bad_nonce" | "malformed_tombstoned" => {
                    format!(".deleted-{}-not-a-uuid", target.id)
                }
                "unknown_owner" => ".deleted-not-a-session".into(),
                "partial_owner" => format!(".deleted-{}x-{}", target.id, Uuid::new_v4()),
                _ => format!(".deleted-{}-{}", target.id, Uuid::new_v4()),
            };
            let evidence = registry.root_dir.join(name);
            if kind == "file" {
                std::fs::write(&evidence, b"quarantine file bytes").unwrap();
            } else {
                std::fs::create_dir(&evidence).unwrap();
                std::fs::write(
                    evidence.join("synthetic-original"),
                    b"quarantine original bytes",
                )
                .unwrap();
            }
            if kind == "multiple" {
                let second = super::deleted_session_dir(&registry.root_dir, target.id);
                std::fs::create_dir(&second).unwrap();
                std::fs::write(second.join("synthetic-other"), b"keep second candidate").unwrap();
            }
            if kind == "malformed_tombstoned" {
                let mut snapshot = registry.inner.read().unwrap().clone();
                snapshot.deleted_session_ids.push(target.id);
                super::write_json(&registry.registry_path, &snapshot).unwrap();
            }
            drop(active);
            drop(registry);
            let error = assert_quarantine_startup_refused_without_changes(&data_dir);
            if matches!(kind, "unknown_owner" | "partial_owner") {
                assert!(!error.contains("canonical storage"));
            } else {
                assert!(error.contains(&target.id.to_string()));
            }
            std::fs::remove_dir_all(data_dir).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn registry_quarantine_preserves_symlink_evidence_without_following_it() {
        for dangling in [false, true] {
            let data_dir =
                std::env::temp_dir().join(format!("sniper-quarantine-symlink-{}", Uuid::new_v4()));
            let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
            let target = registry
                .create_session(Some("Synthetic target".into()))
                .unwrap();
            let link_target = data_dir.join("synthetic-link-target");
            if !dangling {
                std::fs::create_dir(&link_target).unwrap();
                std::fs::write(link_target.join("marker"), b"do not follow or remove").unwrap();
            }
            let evidence = super::deleted_session_dir(&registry.root_dir, target.id);
            std::os::unix::fs::symlink(&link_target, &evidence).unwrap();
            drop(active);
            drop(registry);
            assert_quarantine_startup_refused_without_changes(&data_dir);
            assert_eq!(std::fs::read_link(&evidence).unwrap(), link_target);
            std::fs::remove_dir_all(data_dir).unwrap();
        }
    }

    #[test]
    fn registry_quarantine_refuses_missing_corrupt_and_incomplete_registry_before_repair() {
        for kind in ["missing", "corrupt", "incomplete", "directory"] {
            let data_dir = std::env::temp_dir().join(format!(
                "sniper-quarantine-registry-{kind}-{}",
                Uuid::new_v4()
            ));
            let root = data_dir.join(super::SESSIONS_DIR);
            std::fs::create_dir_all(&root).unwrap();
            let id = Uuid::new_v4();
            let evidence = super::deleted_session_dir(&root, id);
            std::fs::create_dir(&evidence).unwrap();
            std::fs::write(evidence.join("synthetic-original"), b"recoverable bytes").unwrap();
            let path = root.join(super::REGISTRY_FILE);
            match kind {
                "missing" => (),
                "corrupt" => std::fs::write(&path, b"{not json").unwrap(),
                "incomplete" => std::fs::write(&path, b"{}").unwrap(),
                "directory" => {
                    std::fs::create_dir(&path).unwrap();
                    std::fs::write(path.join("marker"), b"keep invalid registry directory")
                        .unwrap();
                }
                _ => unreachable!(),
            }
            assert_quarantine_startup_refused_without_changes(&data_dir);
            std::fs::remove_dir_all(data_dir).unwrap();
        }
    }

    #[test]
    fn registry_quarantine_keeps_exact_unreferenced_and_tombstoned_cleanup() {
        for kind in [
            "unreferenced",
            "tombstoned",
            "live_tombstoned",
            "empty_tombstoned",
        ] {
            let data_dir = std::env::temp_dir().join(format!(
                "sniper-quarantine-cleanup-{kind}-{}",
                Uuid::new_v4()
            ));
            let root = data_dir.join(super::SESSIONS_DIR);
            let active = super::default_session_metadata("Active");
            let target = super::default_session_metadata("Deleted");
            super::persist_session_snapshot(
                &root,
                &active,
                &super::StoredSessionSnapshot::default(),
            )
            .unwrap();
            super::persist_session_snapshot(
                &root,
                &target,
                &super::StoredSessionSnapshot::default(),
            )
            .unwrap();
            let canonical = super::session_dir(&root, target.id);
            let evidence = super::deleted_session_dir(&root, target.id);
            crate::platform::rename(&canonical, &evidence).unwrap();
            let mut sessions = if kind == "empty_tombstoned" {
                vec![]
            } else {
                vec![active.clone()]
            };
            if kind == "live_tombstoned" {
                sessions.push(target.clone());
                std::fs::create_dir(&canonical).unwrap();
                std::fs::write(canonical.join("synthetic-stale"), b"committed deletion").unwrap();
            }
            let deleted = if kind == "unreferenced" {
                vec![]
            } else {
                vec![target.id]
            };
            super::write_json(&root.join(super::REGISTRY_FILE), &serde_json::json!({
                "active_session_id": active.id, "sessions": sessions, "deleted_session_ids": deleted
            })).unwrap();
            let (registry, loaded) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
            assert!(registry.contains_session(active.id));
            assert!(!registry.contains_session(target.id));
            assert!(!canonical.exists());
            assert!(!evidence.exists());
            assert!(!registry
                .inner
                .read()
                .unwrap()
                .deleted_session_ids
                .contains(&target.id));
            drop(loaded);
            drop(registry);
            let (registry, loaded) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
            assert!(!registry.contains_session(target.id));
            drop(loaded);
            drop(registry);
            std::fs::remove_dir_all(data_dir).unwrap();
        }
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
    fn delete_commit_failure_preserves_registry_storage_boundary_across_restart() {
        for after_replacement in [false, true] {
            let data_dir =
                std::env::temp_dir().join(format!("sniper-delete-commit-{}", Uuid::new_v4()));
            let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
            let created = registry
                .create_session(Some("Synthetic target".to_owned()))
                .unwrap();
            let storage = registry.session_storage_path(created.id).unwrap();
            let marker_bytes = b"synthetic session data";
            std::fs::write(storage.join("synthetic-marker"), marker_bytes).unwrap();
            let survivor_marker = active.storage_dir().join("synthetic-survivor");
            std::fs::write(&survivor_marker, b"keep").unwrap();
            let disk_before = std::fs::read(&registry.registry_path).unwrap();
            registry.fail_next_delete_write(
                super::SessionDeleteWrite::Commit,
                if after_replacement {
                    super::SessionDeleteFault::AfterReplacement
                } else {
                    super::SessionDeleteFault::BeforeReplacement
                },
            );
            let error = registry.delete_session(created.id).unwrap_err();
            assert!(error.to_string().contains(if after_replacement {
                "finalization"
            } else {
                "before replacement"
            }));
            let quarantines = std::fs::read_dir(&registry.root_dir)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| {
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with(&format!(".deleted-{}-", created.id))
                })
                .collect::<Vec<_>>();
            assert_eq!(registry.contains_session(created.id), !after_replacement);
            if after_replacement {
                assert!(!storage.exists());
                assert_eq!(quarantines.len(), 1);
                assert_eq!(
                    std::fs::read(quarantines[0].join("synthetic-marker")).unwrap(),
                    marker_bytes
                );
                assert!(registry.session_storage_path(created.id).is_err());
                assert!(registry.load_context(created.id).is_err());
                let disk: super::SessionRegistrySnapshot =
                    serde_json::from_slice(&std::fs::read(&registry.registry_path).unwrap())
                        .unwrap();
                assert!(!disk.sessions.iter().any(|session| session.id == created.id));
                assert!(disk.deleted_session_ids.contains(&created.id));
                // A successful unrelated write must not resurrect the target or
                // erase the tombstone while its quarantined data still exists.
                registry
                    .update_metadata(active.metadata.read().unwrap().clone())
                    .unwrap();
                let disk: super::SessionRegistrySnapshot =
                    serde_json::from_slice(&std::fs::read(&registry.registry_path).unwrap())
                        .unwrap();
                assert!(!disk.sessions.iter().any(|session| session.id == created.id));
                assert!(disk.deleted_session_ids.contains(&created.id));
            } else {
                assert_eq!(std::fs::read(&registry.registry_path).unwrap(), disk_before);
                assert_eq!(
                    std::fs::read(storage.join("synthetic-marker")).unwrap(),
                    marker_bytes
                );
                assert!(quarantines.is_empty());
            }
            drop(active);
            drop(registry);
            let (reopened, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
            assert_eq!(reopened.contains_session(created.id), !after_replacement);
            assert_eq!(storage.exists(), !after_replacement);
            assert!(quarantines.iter().all(|path| !path.exists()));
            assert_eq!(std::fs::read(survivor_marker).unwrap(), b"keep");
            drop(active);
            drop(reopened);
            std::fs::remove_dir_all(data_dir).unwrap();
        }
    }

    #[test]
    fn delete_commit_prune_failure_keeps_success_and_visible_snapshot_coherent() {
        for after_replacement in [false, true] {
            let data_dir =
                std::env::temp_dir().join(format!("sniper-delete-prune-fault-{}", Uuid::new_v4()));
            let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
            let created = registry
                .create_session(Some("Synthetic target".to_owned()))
                .unwrap();
            let storage = registry.session_storage_path(created.id).unwrap();
            registry.fail_next_delete_write(
                super::SessionDeleteWrite::Prune,
                if after_replacement {
                    super::SessionDeleteFault::AfterReplacement
                } else {
                    super::SessionDeleteFault::BeforeReplacement
                },
            );
            registry.delete_session(created.id).unwrap();
            assert!(!registry.contains_session(created.id));
            assert!(!storage.exists());
            assert_eq!(
                registry
                    .inner
                    .read()
                    .unwrap()
                    .deleted_session_ids
                    .contains(&created.id),
                !after_replacement
            );
            let disk: super::SessionRegistrySnapshot =
                serde_json::from_slice(&std::fs::read(&registry.registry_path).unwrap()).unwrap();
            assert_eq!(
                disk.deleted_session_ids.contains(&created.id),
                !after_replacement
            );
            registry
                .update_metadata(active.metadata.read().unwrap().clone())
                .unwrap();
            let disk: super::SessionRegistrySnapshot =
                serde_json::from_slice(&std::fs::read(&registry.registry_path).unwrap()).unwrap();
            assert_eq!(
                disk.deleted_session_ids.contains(&created.id),
                !after_replacement
            );
            drop(active);
            drop(registry);
            let (reopened, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
            assert!(!reopened.contains_session(created.id));
            assert!(reopened
                .inner
                .read()
                .unwrap()
                .deleted_session_ids
                .is_empty());
            drop(active);
            drop(reopened);
            std::fs::remove_dir_all(data_dir).unwrap();
        }
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

    #[test]
    fn registry_quarantine_preserves_corrupt_registry_and_legacy_evidence() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-quarantine-corrupt-legacy-{}",
            Uuid::new_v4()
        ));
        let root = data_dir.join(super::SESSIONS_DIR);
        let active = super::default_session_metadata("Active");
        let target = super::default_session_metadata("Interrupted deletion");
        for metadata in [&active, &target] {
            super::persist_session_snapshot(
                &root,
                metadata,
                &super::StoredSessionSnapshot::default(),
            )
            .unwrap();
        }
        let canonical = super::session_dir(&root, target.id);
        let evidence = root.join(format!(".deleted-{}", target.id));
        crate::platform::rename(&canonical, &evidence).unwrap();
        std::fs::write(root.join(super::REGISTRY_FILE), b"{not json").unwrap();
        assert_quarantine_startup_refused_without_changes(&data_dir);
        std::fs::remove_dir_all(data_dir).unwrap();
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

    #[test]
    fn activation_commit_registry_matches_visible_switch_and_same_active_timestamp() {
        for switch in [false, true] {
            for after_replacement in [false, true] {
                let data_dir = std::env::temp_dir()
                    .join(format!("sniper-activation-commit-{}", Uuid::new_v4()));
                let (registry, active) =
                    SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
                let original_id = active.id();
                let target = if switch {
                    registry
                        .create_session(Some("Synthetic target".to_owned()))
                        .unwrap()
                } else {
                    active.metadata.read().unwrap().clone()
                };
                let before = metadata_commit_disk(&registry);
                registry.fail_next_activation(if after_replacement {
                    super::SessionActivationFault::AfterReplacement
                } else {
                    super::SessionActivationFault::BeforeReplacement
                });
                let error = registry.activate_session(target.id).unwrap_err();
                assert!(error.to_string().contains(if after_replacement {
                    "finalization"
                } else {
                    "before replacement"
                }));
                let expected_id = if after_replacement {
                    target.id
                } else {
                    original_id
                };
                let disk = metadata_commit_disk(&registry);
                assert_eq!(disk.active_session_id, expected_id);
                assert_eq!(registry.active_session_id(), expected_id);
                assert_eq!(
                    serde_json::to_value(&*registry.inner.read().unwrap()).unwrap(),
                    serde_json::to_value(&disk).unwrap()
                );
                let last_opened = disk
                    .sessions
                    .iter()
                    .find(|entry| entry.id == target.id)
                    .unwrap()
                    .last_opened_at;
                if after_replacement {
                    assert!(last_opened >= target.last_opened_at);
                } else {
                    assert_eq!(
                        serde_json::to_value(&disk).unwrap(),
                        serde_json::to_value(&before).unwrap()
                    );
                }
                registry
                    .update_metadata(active.metadata.read().unwrap().clone())
                    .unwrap();
                assert_eq!(
                    metadata_commit_disk(&registry).active_session_id,
                    expected_id
                );
                assert_eq!(
                    metadata_commit_disk(&registry)
                        .sessions
                        .iter()
                        .find(|entry| entry.id == target.id)
                        .unwrap()
                        .last_opened_at,
                    last_opened
                );
                drop(active);
                drop(registry);
                let (reopened, active) =
                    SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
                assert_eq!(active.id(), expected_id);
                assert_eq!(reopened.active_session_id(), expected_id);
                drop(active);
                drop(reopened);
                std::fs::remove_dir_all(data_dir).unwrap();
            }
        }
    }

    fn metadata_commit_fault(after_replacement: bool) -> super::SessionMetadataFault {
        if after_replacement {
            super::SessionMetadataFault::AfterReplacement
        } else {
            super::SessionMetadataFault::BeforeReplacement
        }
    }

    fn metadata_commit_disk(registry: &SessionRegistry) -> super::SessionRegistrySnapshot {
        serde_json::from_slice(&std::fs::read(&registry.registry_path).unwrap()).unwrap()
    }

    fn metadata_commit_entry(
        snapshot: &super::SessionRegistrySnapshot,
        id: Uuid,
    ) -> serde_json::Value {
        serde_json::to_value(
            snapshot
                .sessions
                .iter()
                .find(|entry| entry.id == id)
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn metadata_commit_create_preserves_visible_entry_storage_and_names() {
        for after_replacement in [false, true] {
            for name in [None, Some(" \tSynthetic name\n ".to_owned())] {
                let data_dir =
                    std::env::temp_dir().join(format!("sniper-create-commit-{}", Uuid::new_v4()));
                let (registry, active) =
                    SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
                let before = std::fs::read(&registry.registry_path).unwrap();
                registry.fail_next_metadata_write(
                    super::SessionMetadataWrite::Create,
                    metadata_commit_fault(after_replacement),
                );
                let error = registry.create_session(name.clone()).unwrap_err();
                assert!(error.to_string().contains(if after_replacement {
                    "finalization"
                } else {
                    "before replacement"
                }));
                assert_eq!(registry.active_session_id(), active.id());
                let disk = metadata_commit_disk(&registry);
                let created = disk
                    .sessions
                    .iter()
                    .find(|entry| entry.id != active.id())
                    .cloned();
                assert_eq!(created.is_some(), after_replacement);
                assert_eq!(
                    registry.inner.read().unwrap().sessions.len(),
                    1 + usize::from(after_replacement)
                );
                if let Some(created) = created.as_ref() {
                    assert!(registry.contains_session(created.id));
                    assert_eq!(
                        created.name,
                        name.as_deref()
                            .map(str::trim)
                            .map(str::to_owned)
                            .unwrap_or_else(|| format!(
                                "Session {}",
                                created.created_at.format("%Y-%m-%d %H:%M")
                            ))
                    );
                    assert_eq!(created.created_at, created.updated_at);
                    assert_eq!(created.created_at, created.last_opened_at);
                    assert_eq!(
                        metadata_commit_entry(&registry.inner.read().unwrap(), created.id),
                        serde_json::to_value(created).unwrap()
                    );
                    let storage = registry.session_storage_path(created.id).unwrap();
                    assert!(super::snapshot_path(&storage).is_file());
                    std::fs::write(storage.join("synthetic-retained-marker"), b"kept").unwrap();
                    registry
                        .update_metadata(active.metadata.read().unwrap().clone())
                        .unwrap();
                    assert_eq!(
                        metadata_commit_entry(&metadata_commit_disk(&registry), created.id),
                        serde_json::to_value(created).unwrap()
                    );
                } else {
                    assert_eq!(std::fs::read(&registry.registry_path).unwrap(), before);
                    let storage_ids = std::fs::read_dir(&registry.root_dir)
                        .unwrap()
                        .filter_map(|entry| Uuid::parse_str(entry.ok()?.file_name().to_str()?).ok())
                        .collect::<Vec<_>>();
                    assert_eq!(storage_ids, vec![active.id()]);
                }
                assert!(!std::fs::read_dir(&registry.root_dir)
                    .unwrap()
                    .any(|entry| entry
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .contains(".tmp-")));
                let active_id = active.id();
                drop(active);
                drop(registry);
                let (reopened, active) =
                    SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
                assert_eq!(active.id(), active_id);
                assert_eq!(
                    reopened.inner.read().unwrap().sessions.len(),
                    1 + usize::from(after_replacement)
                );
                if let Some(created) = created {
                    assert_eq!(
                        metadata_commit_entry(&reopened.inner.read().unwrap(), created.id),
                        serde_json::to_value(&created).unwrap()
                    );
                    let storage = reopened.session_storage_path(created.id).unwrap();
                    assert_eq!(
                        std::fs::read(storage.join("synthetic-retained-marker")).unwrap(),
                        b"kept"
                    );
                }
                drop(active);
                drop(reopened);
                std::fs::remove_dir_all(data_dir).unwrap();
            }
        }
    }

    #[test]
    fn metadata_commit_update_preserves_visible_fields_across_writes_and_restart() {
        for after_replacement in [false, true] {
            for incoming_is_newer in [false, true] {
                let data_dir =
                    std::env::temp_dir().join(format!("sniper-update-commit-{}", Uuid::new_v4()));
                let (registry, active) =
                    SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
                let mut incoming = registry.create_session(Some("Before".to_owned())).unwrap();
                registry
                    .rename_session(incoming.id, "Registry-owned name")
                    .unwrap();
                registry.activate_session(incoming.id).unwrap();
                registry.activate_session(active.id()).unwrap();
                let existing = registry
                    .inner
                    .read()
                    .unwrap()
                    .sessions
                    .iter()
                    .find(|entry| entry.id == incoming.id)
                    .unwrap()
                    .clone();
                incoming.name = "Stale name".to_owned();
                incoming.created_at -= ChronoDuration::days(1);
                incoming.last_opened_at -= ChronoDuration::days(1);
                incoming.updated_at = existing.updated_at
                    + if incoming_is_newer {
                        ChronoDuration::hours(1)
                    } else {
                        -ChronoDuration::hours(1)
                    };
                incoming.request_count = 42;
                incoming.event_count = 7;
                let mut expected = existing.clone();
                if after_replacement {
                    expected.request_count = incoming.request_count;
                    expected.event_count = incoming.event_count;
                    expected.updated_at = existing.updated_at.max(incoming.updated_at);
                }
                let before = std::fs::read(&registry.registry_path).unwrap();
                registry.fail_next_metadata_write(
                    super::SessionMetadataWrite::Update,
                    metadata_commit_fault(after_replacement),
                );
                let error = registry.update_metadata(incoming).unwrap_err();
                assert!(error.to_string().contains(if after_replacement {
                    "finalization"
                } else {
                    "before replacement"
                }));
                let expected_value = serde_json::to_value(&expected).unwrap();
                assert_eq!(
                    metadata_commit_entry(&registry.inner.read().unwrap(), existing.id),
                    expected_value
                );
                assert_eq!(
                    metadata_commit_entry(&metadata_commit_disk(&registry), existing.id),
                    expected_value
                );
                if !after_replacement {
                    assert_eq!(std::fs::read(&registry.registry_path).unwrap(), before);
                }
                registry
                    .update_metadata(active.metadata.read().unwrap().clone())
                    .unwrap();
                assert_eq!(
                    metadata_commit_entry(&metadata_commit_disk(&registry), existing.id),
                    expected_value
                );
                let active_id = active.id();
                drop(active);
                drop(registry);
                let (reopened, active) =
                    SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
                assert_eq!(active.id(), active_id);
                // The target stays inactive: loading it would legitimately
                // recompute these synthetic counts from its empty snapshot.
                assert_eq!(
                    metadata_commit_entry(&reopened.inner.read().unwrap(), existing.id),
                    expected_value
                );
                drop(active);
                drop(reopened);
                std::fs::remove_dir_all(data_dir).unwrap();
            }
        }
    }

    fn metadata_commit_test_state() -> (std::path::PathBuf, crate::state::AppState) {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-state-metadata-commit-{}", Uuid::new_v4()));
        let state = crate::state::AppState::new(crate::config::AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 32,
            max_transaction_entries: 32,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        })
        .unwrap();
        (data_dir, state)
    }

    #[tokio::test]
    async fn metadata_commit_app_create_keeps_active_identity_on_registry_error() {
        for after_replacement in [false, true] {
            let (data_dir, state) = metadata_commit_test_state();
            let original = state.session().await;
            state.sessions.fail_next_metadata_write(
                super::SessionMetadataWrite::Create,
                metadata_commit_fault(after_replacement),
            );
            let error = state
                .create_session(Some("Synthetic inactive".to_owned()))
                .await
                .unwrap_err();
            assert!(error.to_string().contains(if after_replacement {
                "finalization"
            } else {
                "before replacement"
            }));
            assert!(std::sync::Arc::ptr_eq(&original, &state.session().await));
            assert_eq!(state.sessions.active_session_id(), original.id());
            let sessions = state.list_sessions().await;
            assert_eq!(sessions.len(), 1 + usize::from(after_replacement));
            let created = sessions
                .into_iter()
                .find(|session| session.id != original.id());
            if let Some(created) = created.as_ref() {
                assert!(!created.active);
                assert_eq!(created.name, "Synthetic inactive");
                let loaded = state.session_context_for_id(created.id).await.unwrap();
                assert_eq!(loaded.id(), created.id);
                assert!(super::snapshot_path(loaded.storage_dir()).is_file());
            }
            state.persist_active_session().await.unwrap();
            let config = state.config.clone();
            let active_id = original.id();
            drop(original);
            drop(state);
            let reopened = crate::state::AppState::new(config).unwrap();
            assert_eq!(reopened.active_session_summary().await.id, active_id);
            assert_eq!(
                reopened.sessions.summaries().len(),
                1 + usize::from(after_replacement)
            );
            if let Some(created) = created {
                assert!(reopened.sessions.contains_session(created.id));
                assert_eq!(
                    reopened
                        .session_context_for_id(created.id)
                        .await
                        .unwrap()
                        .summary(false)
                        .name,
                    "Synthetic inactive"
                );
            }
            drop(reopened);
            std::fs::remove_dir_all(data_dir).unwrap();
        }
    }

    #[tokio::test]
    async fn metadata_commit_app_persist_keeps_snapshot_and_reports_registry_error() {
        for after_replacement in [false, true] {
            let (data_dir, state) = metadata_commit_test_state();
            let original = state.session().await;
            original
                .event_log
                .push(
                    crate::event_log::EventLevel::Info,
                    "synthetic",
                    "Saved event",
                    "Synthetic persisted data",
                )
                .await;
            state.sessions.fail_next_metadata_write(
                super::SessionMetadataWrite::Update,
                metadata_commit_fault(after_replacement),
            );
            let error = state.persist_active_session().await.unwrap_err();
            assert!(error.to_string().contains(if after_replacement {
                "finalization"
            } else {
                "before replacement"
            }));
            let expected_count = usize::from(after_replacement);
            assert_eq!(
                metadata_commit_entry(&state.sessions.inner.read().unwrap(), original.id())
                    ["event_count"],
                expected_count
            );
            assert_eq!(
                metadata_commit_entry(&metadata_commit_disk(&state.sessions), original.id())
                    ["event_count"],
                expected_count
            );
            // Snapshot persistence precedes the registry update, so even its
            // precommit failure cannot establish that the whole save was undone.
            let snapshot = super::load_session_snapshot(original.storage_dir(), 32, 32).unwrap();
            assert_eq!(snapshot.event_log.len(), 1);
            state
                .sessions
                .create_session(Some("Unrelated write".to_owned()))
                .unwrap();
            assert_eq!(
                metadata_commit_entry(&metadata_commit_disk(&state.sessions), original.id())
                    ["event_count"],
                expected_count
            );
            let config = state.config.clone();
            let active_id = original.id();
            drop(original);
            drop(state);
            let reopened = crate::state::AppState::new(config).unwrap();
            let active = reopened.session().await;
            assert_eq!(active.id(), active_id);
            let events = active.event_log.snapshot(None).await;
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].message, "Synthetic persisted data");
            assert_eq!(
                metadata_commit_entry(&reopened.sessions.inner.read().unwrap(), active_id)
                    ["event_count"],
                1
            );
            drop(active);
            drop(reopened);
            std::fs::remove_dir_all(data_dir).unwrap();
        }
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
            &mut HashMap::new(),
            &mut false,
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

        assert_eq!(metadata.request_count, 2);
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

    fn deletion_test_record(sequence: u64) -> TransactionRecord {
        let message = |side: &str| {
            let body = format!("fixture {side} body {sequence}");
            MessageRecord::from_headers_and_body(&http::HeaderMap::new(), body.as_bytes(), 1024)
        };
        let mut record = TransactionRecord::http(
            Utc::now(),
            "POST".into(),
            "https".into(),
            "example.com".into(),
            format!("/{sequence}"),
            Some(200),
            1,
            message("request"),
            Some(message("response")),
            vec![],
            None,
            Some(message("original response")),
        );
        record.original_request = Some(message("original request"));
        record.sequence = sequence;
        record
    }

    fn deletion_journal_bytes(entries: &[TransactionJournalEntry]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for entry in entries {
            serde_json::to_writer(&mut bytes, entry).unwrap();
            bytes.push(b'\n');
        }
        bytes
    }

    #[tokio::test]
    async fn deletion_survives_restart_rotation_and_compaction_with_survivor_bodies() {
        for mode in ["active", "rotated", "compacted"] {
            let data_dir = std::env::temp_dir()
                .join(format!("sniper-delete-restart-{mode}-{}", Uuid::new_v4()));
            let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
            let removed = deletion_test_record(1);
            let survivor = deletion_test_record(2);
            let removed_id = removed.id;
            let survivor_id = survivor.id;
            active.store.insert(removed).await;
            active.store.insert(survivor.clone()).await;
            active.persist().await.unwrap();
            let session_id = active.id();
            drop(active);
            let loaded = registry.load_context(session_id).unwrap();
            assert_eq!(loaded.store.delete_ids(&[removed_id]).await.unwrap(), 1);
            if mode == "rotated" {
                let entries = loaded.store.snapshot_for_persistence(None).await.unwrap();
                assert_eq!(entries.len(), 1);
            } else if mode == "compacted" {
                loaded.persist().await.unwrap();
            }
            drop(loaded);
            drop(registry);
            let (registry, loaded) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
            assert_eq!(loaded.store.len().await, 1, "{mode}");
            assert!(loaded.store.get(removed_id).await.is_none(), "{mode}");
            let restored = loaded.store.get(survivor_id).await.unwrap();
            assert_eq!(
                serde_json::to_value(restored).unwrap(),
                serde_json::to_value(&survivor).unwrap(),
                "{mode}"
            );
            let storage_dir = registry.session_storage_path(session_id).unwrap();
            drop(loaded);
            std::fs::remove_file(super::transactions_meta_path(&storage_dir)).unwrap();
            let reloaded = registry.load_context(session_id).unwrap();
            assert!(reloaded.store.get(removed_id).await.is_none(), "{mode}");
            assert_eq!(
                serde_json::to_value(reloaded.store.get(survivor_id).await.unwrap()).unwrap(),
                serde_json::to_value(&survivor).unwrap(),
                "{mode}"
            );
            drop(reloaded);
            drop(registry);
            let _ = std::fs::remove_dir_all(data_dir);
        }
    }

    #[tokio::test]
    async fn deletion_replay_preserves_survivor_annotations_when_metadata_is_rebuilt() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-delete-annotation-restart-{}",
            Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
        let removed = deletion_test_record(1);
        let survivor = deletion_test_record(2);
        let removed_id = removed.id;
        let survivor_id = survivor.id;
        active.store.insert(removed).await;
        active.store.insert(survivor).await;
        active.persist().await.unwrap();
        let session_id = active.id();
        drop(active);
        let loaded = registry.load_context(session_id).unwrap();
        loaded
            .store
            .update_annotations_durable(
                survivor_id,
                Some(Some("green".into())),
                Some(Some("keep this fixture".into())),
            )
            .await
            .unwrap()
            .unwrap();
        let expected = loaded.store.get(survivor_id).await.unwrap();
        loaded.store.delete_ids(&[removed_id]).await.unwrap();
        drop(loaded);
        let loaded = registry.load_context(session_id).unwrap();
        assert_eq!(
            serde_json::to_value(loaded.store.get(survivor_id).await.unwrap()).unwrap(),
            serde_json::to_value(&expected).unwrap()
        );
        let storage_dir = registry.session_storage_path(session_id).unwrap();
        drop(loaded);
        std::fs::remove_file(super::transactions_meta_path(&storage_dir)).unwrap();
        let rebuilt = registry.load_context(session_id).unwrap();
        assert!(rebuilt.store.get(removed_id).await.is_none());
        assert_eq!(
            serde_json::to_value(rebuilt.store.get(survivor_id).await.unwrap()).unwrap(),
            serde_json::to_value(&expected).unwrap()
        );
        drop(rebuilt);
        drop(registry);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn deletion_replay_blocks_checkpoint_duplicates_and_backfill_resurrection() {
        let storage_dir =
            std::env::temp_dir().join(format!("sniper-delete-replay-backfill-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&storage_dir).unwrap();
        let deleted_snapshot = deletion_test_record(3);
        let survivor = deletion_test_record(4);
        let deleted_backfill = deletion_test_record(1);
        let retained_backfill = deletion_test_record(2);
        let unseen_deleted = deletion_test_record(5);
        let deleted_ids = vec![deleted_snapshot.id, deleted_backfill.id, unseen_deleted.id];
        let journal = super::transaction_journal_path(&storage_dir);
        let checkpoint = transaction_journal_checkpoint_path(&journal);
        std::fs::write(
            checkpoint,
            deletion_journal_bytes(&[
                TransactionJournalEntry::Insert {
                    record: deleted_backfill.clone(),
                },
                TransactionJournalEntry::Insert {
                    record: retained_backfill.clone(),
                },
                TransactionJournalEntry::Delete {
                    ids: deleted_ids.clone(),
                },
            ]),
        )
        .unwrap();
        std::fs::write(
            &journal,
            deletion_journal_bytes(&[
                TransactionJournalEntry::Insert {
                    record: deleted_snapshot.clone(),
                },
                TransactionJournalEntry::Insert {
                    record: deleted_backfill,
                },
                TransactionJournalEntry::Insert {
                    record: unseen_deleted,
                },
                TransactionJournalEntry::Update {
                    record: deleted_snapshot.clone(),
                },
            ]),
        )
        .unwrap();
        let mut snapshot = super::StoredSessionSnapshot {
            transactions: vec![survivor.clone(), deleted_snapshot],
            ..Default::default()
        };
        let result =
            super::replay_transaction_journal(&storage_dir, 2, &mut snapshot, false).unwrap();
        assert!(result.mutated_snapshot);
        let retained: HashSet<_> = snapshot
            .transactions
            .iter()
            .map(|record| record.id)
            .collect();
        assert_eq!(retained, HashSet::from([survivor.id, retained_backfill.id]));
        assert!(deleted_ids
            .iter()
            .all(|id| !result.replayed_transaction_ids.contains(id)));
        let _ = std::fs::remove_dir_all(storage_dir);
    }

    #[test]
    fn deletion_replay_ignores_partial_tombstone_without_removing_records() {
        let storage_dir =
            std::env::temp_dir().join(format!("sniper-delete-partial-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&storage_dir).unwrap();
        let record = deletion_test_record(1);
        let mut tombstone = deletion_journal_bytes(&[TransactionJournalEntry::Delete {
            ids: vec![record.id],
        }]);
        tombstone.pop();
        std::fs::write(super::transaction_journal_path(&storage_dir), tombstone).unwrap();
        let mut snapshot = super::StoredSessionSnapshot {
            transactions: vec![record.clone()],
            ..Default::default()
        };
        let result =
            super::replay_transaction_journal(&storage_dir, usize::MAX, &mut snapshot, false)
                .unwrap();
        assert!(!result.mutated_snapshot);
        assert_eq!(snapshot.transactions.len(), 1);
        assert_eq!(snapshot.transactions[0].id, record.id);
        let _ = std::fs::remove_dir_all(storage_dir);
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
        // Records live in transactions.ndjson, not inside snapshot.json.
        assert!(persisted.transactions.is_empty());
        assert_eq!(
            super::read_transactions_file(&storage_dir).unwrap().len(),
            1
        );
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

        // Records live in transactions.ndjson, not inside snapshot.json.
        let disk_transactions = super::read_transactions_file(&storage_dir).unwrap();
        assert_eq!(disk_transactions[0].0.color_tag.as_deref(), Some("green"));

        let reloaded = registry.load_context(active.id()).unwrap();
        let reloaded_records = reloaded.store.snapshot(Some(10)).await;
        assert_eq!(reloaded_records[0].color_tag.as_deref(), Some("green"));
    }

    #[tokio::test]
    async fn registry_replays_every_journal_entry_into_the_snapshot() {
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

        // Nothing is dropped any more, so every journalled record comes back.
        // Order is not the point here — survival is.
        assert_eq!(restored.len(), 4);
        let mut hosts: Vec<_> = restored.iter().map(|r| r.host.as_str()).collect();
        hosts.sort_unstable();
        assert_eq!(
            hosts,
            vec![
                "1.example:443",
                "2.example:443",
                "3.example:443",
                "4.example:443"
            ]
        );
    }

    #[tokio::test]
    async fn registry_backfill_keeps_every_record_in_the_snapshot() {
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
            vec![
                "2.example:443",
                "1.example:443",
                "4.example:443",
                "3.example:443"
            ]
        );
    }

    #[tokio::test]
    async fn registry_applies_a_backfill_annotation_to_the_record_it_names() {
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

        // The record this annotation targets used to be trimmed away, so replay
        // changed nothing and the journal was kept. Nothing is trimmed now: the
        // annotation lands on a live record, the snapshot changes, and the journal
        // is compacted into it.
        assert!(journal_len_before > 0);
        assert_eq!(restored.len(), 2);
        let mut hosts: Vec<_> = restored.iter().map(|r| r.host.as_str()).collect();
        hosts.sort_unstable();
        assert_eq!(hosts, vec!["1.example:443", "2.example:443"]);
        assert_eq!(std::fs::metadata(&journal_path).unwrap().len(), 0);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn registry_replays_the_whole_active_journal() {
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

        // Replay is no longer bounded by a retention cap.
        assert_eq!(restored.len(), 10);
        assert_eq!(restored[0].host, "32.example:443");
        assert_eq!(restored[1].host, "31.example:443");
    }

    #[tokio::test]
    async fn registry_keeps_transactions_beyond_the_old_retention_limit() {
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

        assert_eq!(restored.len(), 8);
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
                "4.example:443",
                "3.example:443",
                "2.example:443",
                "1.example:443"
            ]
        );

        let _ = std::fs::remove_dir_all(data_dir);
    }

    // Passive storage fixtures only: insert synthetic records directly, with no
    // proxy, scanner, listener or network work. The first persist gives the older
    // rows disk locators; the second must copy them alongside the new journal row.
    #[tokio::test]
    async fn legacy_http_limit_does_not_truncate_persistence_or_restart() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-legacy-http-persist-{}", Uuid::new_v4()));
        let (registry, active) =
            SessionRegistry::load_or_create_with_transaction_limit(&data_dir, 2, 2, 2).unwrap();
        let mut expected = Vec::new();
        for sequence in 1..=2 {
            let record = deletion_test_record(sequence);
            let id = record.id;
            active.store.insert(record).await;
            active
                .store
                .update_annotations_durable(
                    id,
                    Some(Some("blue".into())),
                    Some(Some(format!("synthetic note {sequence}"))),
                )
                .await
                .unwrap()
                .unwrap();
            expected.push(active.store.get(id).await.unwrap());
        }
        active.persist().await.unwrap();
        assert!(active.store.snapshot(None).await.iter().all(|record| {
            record.request.body_preview.is_empty()
                && record.response.as_ref().unwrap().body_preview.is_empty()
        }));

        let newest = deletion_test_record(3);
        let newest_id = newest.id;
        active.store.insert(newest).await;
        expected.push(active.store.get(newest_id).await.unwrap());
        let metadata = active.persist().await.unwrap();
        let storage_dir = active.storage_dir().to_path_buf();
        let session_id = active.id();
        assert_eq!(active.store.len().await, 3);
        assert_eq!(active.transaction_journal_replay_bytes(), 0);
        drop(active);
        drop(registry);

        let (registry, loaded) =
            SessionRegistry::load_or_create_with_transaction_limit(&data_dir, 2, 2, 2).unwrap();
        assert_eq!(
            loaded.store.len().await,
            3,
            "restart must keep every HTTP record"
        );
        assert_eq!(metadata.request_count, 3);
        assert_eq!(
            super::read_transactions_file(&storage_dir).unwrap().len(),
            3
        );
        for record in &expected {
            assert_eq!(
                serde_json::to_value(loaded.store.get(record.id).await.unwrap()).unwrap(),
                serde_json::to_value(record).unwrap(),
                "rewritten locators must preserve every body and annotation"
            );
        }
        drop(loaded);
        // Also rebuild the metadata index from the durable body file, rather
        // than letting a correct index hide a truncated or stale body line.
        std::fs::remove_file(super::transactions_meta_path(&storage_dir)).unwrap();
        let rebuilt = registry.load_context(session_id).unwrap();
        assert_eq!(rebuilt.store.len().await, 3);
        for record in &expected {
            assert_eq!(
                serde_json::to_value(rebuilt.store.get(record.id).await.unwrap()).unwrap(),
                serde_json::to_value(record).unwrap()
            );
        }
        drop(rebuilt);
        drop(registry);
        std::fs::remove_dir_all(data_dir).unwrap();
    }

    #[tokio::test]
    async fn legacy_http_limit_does_not_cap_loaded_or_recovered_metadata_counts() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-legacy-http-counts-{}", Uuid::new_v4()));
        // Seed more than the later legacy limit without relying on the fixed
        // persist path, so this independently detects the metadata repair bug.
        let (registry, active) =
            SessionRegistry::load_or_create_with_transaction_limit(&data_dir, 2, 8, 2).unwrap();
        for sequence in 1..=3 {
            active.store.insert(deletion_test_record(sequence)).await;
        }
        active.persist().await.unwrap();
        let session_id = active.id();
        assert_eq!(active.transaction_journal_replay_bytes(), 0);
        drop(active);
        drop(registry);

        let (registry, loaded) =
            SessionRegistry::load_or_create_with_transaction_limit(&data_dir, 2, 2, 2).unwrap();
        assert_eq!(loaded.store.len().await, 3);
        assert_eq!(registry.summaries()[0].request_count, 3);
        let read_only = registry.load_context_read_only(session_id).unwrap();
        assert_eq!(read_only.summary(false).request_count, 3);
        drop(read_only);
        drop(loaded);
        drop(registry);

        // Registry recovery uses the same count helper as ordinary loading.
        std::fs::remove_file(
            data_dir
                .join(super::SESSIONS_DIR)
                .join(super::REGISTRY_FILE),
        )
        .unwrap();
        let (recovered_registry, recovered) =
            SessionRegistry::load_or_create_with_transaction_limit(&data_dir, 2, 2, 2).unwrap();
        assert_eq!(recovered.id(), session_id);
        assert_eq!(recovered.store.len().await, 3);
        assert_eq!(recovered_registry.summaries()[0].request_count, 3);
        drop(recovered);
        drop(recovered_registry);
        std::fs::remove_dir_all(data_dir).unwrap();
    }

    #[tokio::test]
    async fn legacy_http_limit_fix_keeps_websocket_and_event_limits() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-legacy-http-bounded-stores-{}",
            Uuid::new_v4()
        ));
        let (registry, active) =
            SessionRegistry::load_or_create_with_transaction_limit(&data_dir, 2, 1, 2).unwrap();
        for sequence in 1..=3 {
            active
                .websockets
                .open(WebSocketSessionRecord {
                    id: Uuid::new_v4(),
                    sequence,
                    started_at: Utc::now(),
                    closed_at: Some(Utc::now()),
                    duration_ms: Some(0),
                    scheme: "wss".into(),
                    host: "example.com".into(),
                    path: format!("/synthetic-{sequence}"),
                    status: Some(101),
                    request: deletion_test_record(sequence).request,
                    response: None,
                    frames: Vec::new(),
                    notes: Vec::new(),
                })
                .await;
            active
                .event_log
                .push(
                    crate::event_log::EventLevel::Info,
                    "test",
                    "synthetic event",
                    sequence.to_string(),
                )
                .await;
        }
        let metadata = active.persist().await.unwrap();
        assert_eq!(metadata.websocket_count, 2);
        assert_eq!(metadata.event_count, 2);
        drop(active);
        drop(registry);
        let (registry, loaded) =
            SessionRegistry::load_or_create_with_transaction_limit(&data_dir, 2, 1, 2).unwrap();
        let websockets = loaded.websockets.snapshot(None).await;
        assert_eq!(websockets.len(), 2);
        assert_eq!(websockets[0].sequence, 3);
        assert_eq!(websockets[1].sequence, 2);
        assert_eq!(loaded.event_log.snapshot(None).await.len(), 2);
        drop(loaded);
        drop(registry);
        std::fs::remove_dir_all(data_dir).unwrap();
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
    async fn snapshot_correction_fixture() -> (
        std::path::PathBuf,
        SessionRegistry,
        std::sync::Arc<super::SessionContext>,
    ) {
        let root =
            std::env::temp_dir().join(format!("sniper-snapshot-correction-{}", Uuid::new_v4()));
        let (registry, session) = SessionRegistry::load_or_create(&root, 32, 32).unwrap();
        // Restart fixtures exercise persistence only. Replayed synthetic records
        // must bypass the existing optional passive scanner recovery path.
        session
            .scanner
            .update_config(ScannerConfig {
                enabled: false,
                ..ScannerConfig::default()
            })
            .await;
        session.persist_state_only().await.unwrap();
        (root, registry, session)
    }

    #[tokio::test]
    async fn snapshot_publication_preserves_late_mutations_through_second_save_and_restart() {
        for change in [
            "insert",
            "update",
            "annotation",
            "delete",
            "clear",
            "same_id",
            "replace",
        ] {
            let (root, registry, session) = snapshot_correction_fixture().await;
            let record = deletion_test_record(1);
            let id = record.id;
            session.store.insert(record).await;
            session.persist().await.unwrap();
            let (entered, resume) = session.pause_next_snapshot(super::SnapshotTestPhase::Prepared);
            let save = tokio::spawn({
                let session = session.clone();
                async move { session.persist().await }
            });
            entered.await.unwrap();
            let mut expected_id = id;
            let mut expected_body = "fixture request body 1".to_owned();
            match change {
                "insert" => {
                    let next = deletion_test_record(2);
                    expected_id = next.id;
                    expected_body = next.request.body_preview.clone();
                    tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        session.store.insert(next),
                    )
                    .await
                    .expect("bulk snapshot preparation must not hold the mutation lock");
                }
                "update" => {
                    session
                        .store
                        .update_record_durable(id, |record| {
                            record.request.body_preview = "latest full body".into();
                            record.request.body_size = "latest full body".len();
                            record.duration_ms = 77;
                        })
                        .await
                        .unwrap()
                        .unwrap();
                    expected_body = "latest full body".into();
                }
                "annotation" => {
                    session
                        .store
                        .update_annotations_durable_with_client(
                            id,
                            Some(Some("yellow".into())),
                            Some(Some("new note".into())),
                            Some("synthetic-client".into()),
                            Some(3),
                        )
                        .await
                        .unwrap()
                        .unwrap();
                }
                "delete" => {
                    session.store.delete_ids(&[id]).await.unwrap();
                }
                "clear" => {
                    session.store.delete_all().await.unwrap();
                }
                "same_id" => {
                    let mut next = session.store.get(id).await.unwrap();
                    next.request.body_preview = "same ID latest body".into();
                    next.request.body_size = next.request.body_preview.len();
                    expected_body = next.request.body_preview.clone();
                    session.store.insert(next).await;
                }
                "replace" => {
                    let mut next = session.store.get(id).await.unwrap();
                    next.request.body_preview = "replacement body".into();
                    next.request.body_size = next.request.body_preview.len();
                    expected_body = next.request.body_preview.clone();
                    session.store.replace_all(vec![next]).await;
                }
                _ => unreachable!(),
            }
            resume.send(()).unwrap();
            save.await.unwrap().unwrap();
            if change == "delete" || change == "clear" {
                assert!(session.store.get(id).await.is_none(), "{change}");
            } else {
                let current = session.store.get(expected_id).await.unwrap();
                assert_eq!(current.request.body_preview, expected_body, "{change}");
                if change == "update" {
                    assert_eq!(current.duration_ms, 77);
                }
                if change == "annotation" {
                    assert_eq!(current.user_note.as_deref(), Some("new note"));
                }
            }
            session.persist().await.unwrap();
            let storage = session.storage_dir().to_path_buf();
            drop(session);
            drop(registry);
            // The body file is authoritative even when the optional cache is rebuilt.
            std::fs::remove_file(super::transactions_meta_path(&storage)).unwrap();
            let (registry, loaded) = SessionRegistry::load_or_create(&root, 32, 32).unwrap();
            if change == "delete" || change == "clear" {
                assert!(loaded.store.get(id).await.is_none(), "{change}");
            } else {
                let current = loaded.store.get(expected_id).await.unwrap();
                assert_eq!(
                    current.request.body_preview, expected_body,
                    "restart {change}"
                );
                if change == "update" {
                    assert_eq!(current.duration_ms, 77);
                }
                if change == "annotation" {
                    assert_eq!(current.user_note.as_deref(), Some("new note"));
                    assert_eq!(current.color_tag.as_deref(), Some("yellow"));
                    assert_eq!(
                        current.annotation_client_versions.get("synthetic-client"),
                        Some(&3)
                    );
                    assert_eq!(current.annotation_revision, 1);
                }
            }
            drop(loaded);
            drop(registry);
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[tokio::test]
    async fn snapshot_failure_after_publication_keeps_live_locators_and_restart_bodies() {
        for failed_file in ["snapshot.json", "state.json"] {
            let (root, registry, session) = snapshot_correction_fixture().await;
            let first = deletion_test_record(1);
            let first_id = first.id;
            session.store.insert(first).await;
            session.persist().await.unwrap();
            let newest = deletion_test_record(2);
            let newest_id = newest.id;
            session.store.insert(newest).await;
            let failed_path = session.storage_dir().join(failed_file);
            std::fs::remove_file(&failed_path).unwrap();
            std::fs::create_dir(&failed_path).unwrap();
            assert!(session.persist().await.is_err());
            assert_eq!(
                session
                    .store
                    .get(first_id)
                    .await
                    .unwrap()
                    .request
                    .body_preview,
                "fixture request body 1"
            );
            assert_eq!(
                session
                    .store
                    .get(newest_id)
                    .await
                    .unwrap()
                    .request
                    .body_preview,
                "fixture request body 2"
            );
            assert!(session.transaction_journal_replay_bytes() > 0);
            std::fs::remove_dir(failed_path).unwrap();
            drop(session);
            drop(registry);
            let (registry, loaded) = SessionRegistry::load_or_create(&root, 32, 32).unwrap();
            assert_eq!(
                loaded
                    .store
                    .get(first_id)
                    .await
                    .unwrap()
                    .request
                    .body_preview,
                "fixture request body 1"
            );
            assert_eq!(
                loaded
                    .store
                    .get(newest_id)
                    .await
                    .unwrap()
                    .request
                    .body_preview,
                "fixture request body 2"
            );
            drop(loaded);
            drop(registry);
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[tokio::test]
    async fn snapshot_canceled_waiter_keeps_serialization_and_live_metadata() {
        let (root, registry, session) = snapshot_correction_fixture().await;
        session.store.insert(deletion_test_record(1)).await;
        let (entered, resume) = session.pause_next_snapshot(super::SnapshotTestPhase::Prepared);
        let save = tokio::spawn({
            let session = session.clone();
            async move { session.persist().await }
        });
        entered.await.unwrap();
        save.abort();
        assert!(save.await.unwrap_err().is_cancelled());
        session.store.insert(deletion_test_record(2)).await;
        let (next_entered, next_resume) =
            session.pause_next_snapshot(super::SnapshotTestPhase::Prepared);
        let mut next = tokio::spawn({
            let session = session.clone();
            async move { session.persist().await }
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), &mut next)
                .await
                .is_err()
        );
        resume.send(()).unwrap();
        next_entered.await.unwrap();
        assert_eq!(
            session.summary(true).request_count,
            1,
            "the canceled first save must publish its own metadata"
        );
        next_resume.send(()).unwrap();
        next.await.unwrap().unwrap();
        assert_eq!(session.summary(true).request_count, 2);
        assert_eq!(
            session.transaction_compacted_event_sequence(),
            session.store.latest_event_sequence()
        );
        drop(session);
        drop(registry);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn snapshot_publication_blocks_lazy_reads_until_new_offsets_are_installed() {
        let (root, registry, session) = snapshot_correction_fixture().await;
        let first = deletion_test_record(1);
        let id = first.id;
        session.store.insert(first).await;
        session.persist().await.unwrap();
        session.store.insert(deletion_test_record(2)).await;
        let (entered, resume) = session.pause_next_snapshot(super::SnapshotTestPhase::BeforeRename);
        let save = tokio::spawn({
            let session = session.clone();
            async move { session.persist().await }
        });
        entered.await.unwrap();
        let mut read = tokio::spawn({
            let session = session.clone();
            async move { session.store.get(id).await }
        });
        let mut update = tokio::spawn({
            let session = session.clone();
            async move {
                session
                    .store
                    .update_record_durable(id, |row| {
                        row.request.body_preview = "fixture latest body".into();
                        row.request.body_size = row.request.body_preview.len();
                    })
                    .await
            }
        });
        let mut search = tokio::spawn({
            let session = session.clone();
            async move {
                session
                    .store
                    .search_bodies(
                        &crate::store::ListFilters::default(),
                        &crate::store::BodySearchRequest {
                            value: "fixture".into(),
                            sides: crate::store::BodySearchSides::default(),
                            case_sensitive: true,
                            max_matches: 100,
                            byte_budget: 100_000,
                            context_bytes: 20,
                        },
                    )
                    .await
            }
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), &mut read)
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), &mut update)
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), &mut search)
                .await
                .is_err()
        );
        resume.send(()).unwrap();
        save.await.unwrap().unwrap();
        let body = read.await.unwrap().unwrap().request.body_preview;
        assert!(body == "fixture request body 1" || body == "fixture latest body");
        update.await.unwrap().unwrap().unwrap();
        let scanned = search.await.unwrap();
        if scanned.complete {
            assert_eq!(scanned.unsearchable, 0);
            assert!(scanned.transactions.iter().any(|hit| hit.id == id));
        } else {
            // A full edit after candidate capture makes that candidate partial;
            // it must never silently substitute another row's body.
            assert_eq!(scanned.unsearchable, 1);
        }
        let latest = session
            .store
            .search_bodies(
                &crate::store::ListFilters::default(),
                &crate::store::BodySearchRequest {
                    value: "fixture latest body".into(),
                    sides: crate::store::BodySearchSides::default(),
                    case_sensitive: true,
                    max_matches: 100,
                    byte_budget: 100_000,
                    context_bytes: 20,
                },
            )
            .await;
        assert!(latest.complete);
        assert_eq!(latest.unsearchable, 0);
        assert!(latest.transactions.iter().any(|hit| hit.id == id));
        assert_eq!(
            session.store.get(id).await.unwrap().request.body_preview,
            "fixture latest body"
        );
        drop(session);
        drop(registry);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn snapshot_missing_or_mismatched_source_fails_without_publishing_empty_bodies() {
        for missing in [true, false] {
            let (root, registry, session) = snapshot_correction_fixture().await;
            let first = deletion_test_record(1);
            let id = first.id;
            session.store.insert(first).await;
            session.persist().await.unwrap();
            let path = super::transactions_path(session.storage_dir());
            let original = std::fs::read(&path).unwrap();
            if missing {
                std::fs::remove_file(&path).unwrap();
            } else {
                let mut wrong: TransactionRecord =
                    serde_json::from_slice(original.strip_suffix(b"\n").unwrap()).unwrap();
                wrong.id = Uuid::new_v4();
                let mut bytes = serde_json::to_vec(&wrong).unwrap();
                bytes.push(b'\n');
                std::fs::write(&path, bytes).unwrap();
            }
            assert!(session.persist().await.is_err());
            if missing {
                assert!(!path.exists());
            }
            std::fs::write(&path, original).unwrap();
            assert_eq!(
                session.store.get(id).await.unwrap().request.body_preview,
                "fixture request body 1"
            );
            drop(session);
            drop(registry);
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[tokio::test]
    async fn snapshot_unreadable_same_id_insert_blocks_save_without_overwriting_source() {
        for prepared_first in [false, true] {
            for missing in [false, true] {
                let (root, registry, session) = snapshot_correction_fixture().await;
                let original = deletion_test_record(1);
                let id = original.id;
                session.store.insert(original).await;
                session.persist().await.unwrap();
                let pending = if prepared_first {
                    let (entered, resume) =
                        session.pause_next_snapshot(super::SnapshotTestPhase::Prepared);
                    let save = tokio::spawn({
                        let session = session.clone();
                        async move { session.persist().await }
                    });
                    entered.await.unwrap();
                    Some((save, resume))
                } else {
                    None
                };
                let path = super::transactions_path(session.storage_dir());
                let damaged = if missing {
                    std::fs::remove_file(&path).unwrap();
                    None
                } else {
                    let unrelated = deletion_test_record(3);
                    let mut bytes = serde_json::to_vec(&unrelated).unwrap();
                    bytes.push(b'\n');
                    std::fs::write(&path, &bytes).unwrap();
                    Some(bytes)
                };
                let mut replacement = deletion_test_record(2);
                replacement.id = id;
                session.store.insert(replacement).await;
                let result = if let Some((save, resume)) = pending {
                    resume.send(()).unwrap();
                    save.await.unwrap()
                } else {
                    session.persist().await
                };
                assert!(
                    result.is_err(),
                    "unresolved older body must prevent publication"
                );
                assert_eq!(session.store.len().await, 2);
                assert_eq!(
                    session.store.get(id).await.unwrap().request.body_preview,
                    "fixture request body 2"
                );
                match damaged {
                    Some(bytes) => assert_eq!(std::fs::read(&path).unwrap(), bytes),
                    None => assert!(!path.exists()),
                }
                drop(session);
                drop(registry);
                std::fs::remove_dir_all(root).unwrap();
            }
        }
    }

    #[tokio::test]
    async fn snapshot_equal_length_rewrite_has_no_stale_metadata_window() {
        let (root, registry, session) = snapshot_correction_fixture().await;
        let first = deletion_test_record(1);
        let id = first.id;
        session.store.insert(first).await;
        session.persist().await.unwrap();
        let before = std::fs::metadata(super::transactions_path(session.storage_dir()))
            .unwrap()
            .len();
        session
            .store
            .update_record_durable(id, |row| {
                row.request.body_preview = "fixture request body 2".into();
            })
            .await
            .unwrap();
        let (entered, resume) = session.pause_next_snapshot(super::SnapshotTestPhase::Published);
        let save = tokio::spawn({
            let session = session.clone();
            async move { session.persist().await }
        });
        entered.await.unwrap();
        assert_eq!(
            std::fs::metadata(super::transactions_path(session.storage_dir()))
                .unwrap()
                .len(),
            before
        );
        assert!(!super::transactions_meta_path(session.storage_dir()).exists());
        assert_eq!(
            session.store.get(id).await.unwrap().request.body_preview,
            "fixture request body 2"
        );
        let recovered =
            super::load_session_snapshot_read_only(session.storage_dir(), 32, 32).unwrap();
        let row = recovered
            .transactions
            .iter()
            .find(|row| row.id == id)
            .unwrap();
        assert_eq!(
            row.request.body_preview, "fixture request body 2",
            "crash-window load must rebuild from the published body file"
        );
        resume.send(()).unwrap();
        save.await.unwrap().unwrap();
        drop(session);
        drop(registry);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn snapshot_cleanup_failure_does_not_confirm_compaction_or_change_save_contract() {
        let (root, registry, session) = snapshot_correction_fixture().await;
        session.store.insert(deletion_test_record(1)).await;
        session.persist().await.unwrap();
        let old_boundary = session.transaction_compacted_event_sequence();
        session.store.insert(deletion_test_record(2)).await;
        let (entered, resume) =
            session.pause_next_snapshot(super::SnapshotTestPhase::BeforeCleanup);
        let save = tokio::spawn({
            let session = session.clone();
            async move { session.persist().await }
        });
        entered.await.unwrap();
        let checkpoint = transaction_journal_checkpoint_path(&super::transaction_journal_path(
            session.storage_dir(),
        ));
        std::fs::remove_file(&checkpoint).unwrap();
        std::fs::create_dir(&checkpoint).unwrap();
        resume.send(()).unwrap();
        assert!(save.await.unwrap().is_ok());
        assert_eq!(session.transaction_compacted_event_sequence(), old_boundary);
        assert_eq!(session.summary(true).request_count, 2);
        std::fs::remove_dir(checkpoint).unwrap();
        session.persist().await.unwrap();
        assert_eq!(
            session.transaction_compacted_event_sequence(),
            session.store.latest_event_sequence()
        );
        drop(session);
        drop(registry);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn retention_snapshot_cancellation_late_trim_and_cleanup_failure_keep_exact_boundary() {
        let (root, registry, session) = snapshot_correction_fixture().await;
        let mut ids = Vec::new();
        for index in 1..=5 {
            let record = deletion_test_record(index);
            ids.push(record.id);
            session.store.insert(record).await;
        }
        session.persist().await.unwrap();

        // A canceled waiter must not strand an already-persisted trim as pending.
        let first_trim = session
            .store
            .trim_retention(4, &HashSet::new(), 256)
            .await
            .unwrap();
        assert_eq!(first_trim.deleted_ids, vec![ids[0]]);
        assert!(session.store.retention_compaction_pending());
        let (entered, resume) = session.pause_next_snapshot(super::SnapshotTestPhase::Prepared);
        let save = tokio::spawn({
            let session = session.clone();
            async move { session.persist().await }
        });
        entered.await.unwrap();
        save.abort();
        assert!(save.await.unwrap_err().is_cancelled());
        resume.send(()).unwrap();
        drop(session.owned_persist_guard().await);
        assert_eq!(
            session.transaction_compacted_event_sequence(),
            first_trim.event_sequence
        );
        assert!(!session.store.retention_compaction_pending());
        assert!(
            !crate::history_retention::snapshot(&session, false, false, None)
                .await
                .status
                .disk_cleanup_pending
        );

        // The next canceled writer may cover only the trim in its captured plan.
        let captured_trim = session
            .store
            .trim_retention(3, &HashSet::new(), 256)
            .await
            .unwrap();
        assert_eq!(captured_trim.deleted_ids, vec![ids[1]]);
        let (entered, resume) = session.pause_next_snapshot(super::SnapshotTestPhase::Prepared);
        let save = tokio::spawn({
            let session = session.clone();
            async move { session.persist().await }
        });
        entered.await.unwrap();
        save.abort();
        assert!(save.await.unwrap_err().is_cancelled());
        let late_trim = session
            .store
            .trim_retention(2, &HashSet::new(), 256)
            .await
            .unwrap();
        assert_eq!(late_trim.deleted_ids, vec![ids[2]]);
        assert!(late_trim.event_sequence > captured_trim.event_sequence);
        resume.send(()).unwrap();
        drop(session.owned_persist_guard().await);
        assert_eq!(
            session.transaction_compacted_event_sequence(),
            captured_trim.event_sequence
        );
        assert!(session.store.retention_compaction_pending());
        let persisted: super::StoredSessionSnapshot = serde_json::from_slice(
            &std::fs::read(super::snapshot_path(session.storage_dir())).unwrap(),
        )
        .unwrap();
        assert_eq!(
            persisted.transaction_event_sequence,
            captured_trim.event_sequence
        );
        let readonly = registry.load_context_read_only(session.id()).unwrap();
        assert!(!readonly.scanner.get_config().await.enabled);
        assert_eq!(readonly.store.len().await, 2);
        assert!(readonly.store.retention_compaction_pending());
        assert!(
            crate::history_retention::snapshot(&readonly, false, false, None)
                .await
                .status
                .disk_cleanup_pending
        );
        drop(readonly);

        // Body/state publication succeeds, but a failed purge cannot advance
        // either cleanup boundary or claim the retained tombstone was compacted.
        let (entered, resume) =
            session.pause_next_snapshot(super::SnapshotTestPhase::BeforeCleanup);
        let save = tokio::spawn({
            let session = session.clone();
            async move { session.persist().await }
        });
        entered.await.unwrap();
        let checkpoint = transaction_journal_checkpoint_path(&super::transaction_journal_path(
            session.storage_dir(),
        ));
        std::fs::remove_file(&checkpoint).unwrap();
        std::fs::create_dir(&checkpoint).unwrap();
        resume.send(()).unwrap();
        assert!(
            save.await.unwrap().is_ok(),
            "cleanup warnings preserve the save contract"
        );
        assert_eq!(
            session.transaction_compacted_event_sequence(),
            captured_trim.event_sequence
        );
        assert!(session.store.retention_compaction_pending());
        let status = crate::history_retention::snapshot(&session, false, false, None).await;
        assert!(status.status.disk_cleanup_pending);
        assert!(status.status.pending);
        for (index, id) in ids.iter().enumerate() {
            if index < 3 {
                assert!(session.store.get(*id).await.is_none());
            } else {
                assert_eq!(
                    session.store.get(*id).await.unwrap().request.body_preview,
                    format!("fixture request body {}", index + 1)
                );
            }
        }

        std::fs::remove_dir(checkpoint).unwrap();
        session.persist().await.unwrap();
        assert_eq!(
            session.transaction_compacted_event_sequence(),
            late_trim.event_sequence
        );
        assert!(!session.store.retention_compaction_pending());
        drop(session);
        drop(registry);
        let (registry, reloaded) = SessionRegistry::load_or_create(&root, 32, 32).unwrap();
        assert!(!reloaded.scanner.get_config().await.enabled);
        assert_eq!(reloaded.store.len().await, 2);
        assert!(!reloaded.store.retention_compaction_pending());
        for (index, id) in ids.iter().enumerate().skip(3) {
            assert_eq!(
                reloaded.store.get(*id).await.unwrap().request.body_preview,
                format!("fixture request body {}", index + 1)
            );
        }
        drop(reloaded);
        drop(registry);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn snapshot_cancellation_after_rotation_before_dispatch_preserves_checkpoint() {
        let (root, registry, session) = snapshot_correction_fixture().await;
        let record = deletion_test_record(1);
        let id = record.id;
        session.store.insert(record).await;
        let (entered, _resume) = session.pause_next_snapshot_capture();
        let save = tokio::spawn({
            let session = session.clone();
            async move { session.persist().await }
        });
        entered.await.unwrap();
        save.abort();
        assert!(save.await.unwrap_err().is_cancelled());
        assert!(session.transaction_journal_replay_bytes() > 0);
        let next = deletion_test_record(2);
        let next_id = next.id;
        session.store.insert(next).await;
        session.persist().await.unwrap();
        drop(session);
        drop(registry);
        let (registry, loaded) = SessionRegistry::load_or_create(&root, 32, 32).unwrap();
        assert_eq!(
            loaded.store.get(id).await.unwrap().request.body_preview,
            "fixture request body 1"
        );
        assert_eq!(
            loaded
                .store
                .get(next_id)
                .await
                .unwrap()
                .request
                .body_preview,
            "fixture request body 2"
        );
        drop(loaded);
        drop(registry);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn snapshot_duplicate_rows_keep_order_and_distinct_bodies_across_restarts() {
        let (root, mut registry, mut session) = snapshot_correction_fixture().await;
        let mut first = deletion_test_record(1);
        first.user_note = Some("older duplicate note".into());
        first.color_tag = Some("blue".into());
        first.annotation_revision = 8;
        first
            .annotation_client_versions
            .insert("older-client".into(), 4);
        let duplicate_id = first.id;
        let mut second = deletion_test_record(2);
        second.id = duplicate_id;
        let unique = deletion_test_record(3);
        let unique_id = unique.id;
        session.store.insert(first).await;
        session.store.insert(second).await;
        session.store.insert(unique).await;
        session
            .store
            .update_annotations_durable_with_client(
                duplicate_id,
                Some(Some("yellow".into())),
                Some(Some("newest duplicate note".into())),
                Some("newest-client".into()),
                Some(7),
            )
            .await
            .unwrap()
            .unwrap();
        session.persist().await.unwrap();
        let storage = session.storage_dir().to_path_buf();
        let checkpoint =
            transaction_journal_checkpoint_path(&super::transaction_journal_path(&storage));
        std::fs::write(checkpoint, b"").unwrap();
        for _ in 0..3 {
            drop(session);
            drop(registry);
            (registry, session) = SessionRegistry::load_or_create(&root, 32, 32).unwrap();
            let rows = session.store.snapshot(None).await;
            assert_eq!(rows.len(), 3);
            assert_eq!(
                rows.iter().map(|row| row.id).collect::<Vec<_>>(),
                vec![unique_id, duplicate_id, duplicate_id]
            );
            assert_eq!(rows[1].request.body_preview, "fixture request body 2");
            assert_eq!(rows[2].request.body_preview, "fixture request body 1");
            assert_eq!(rows[1].user_note.as_deref(), Some("newest duplicate note"));
            assert_eq!(rows[1].color_tag.as_deref(), Some("yellow"));
            assert_eq!(rows[1].annotation_revision, 1);
            assert_eq!(
                rows[1].annotation_client_versions.get("newest-client"),
                Some(&7)
            );
            assert_eq!(rows[2].user_note.as_deref(), Some("older duplicate note"));
            assert_eq!(rows[2].color_tag.as_deref(), Some("blue"));
            assert_eq!(rows[2].annotation_revision, 8);
            assert_eq!(
                rows[2].annotation_client_versions.get("older-client"),
                Some(&4)
            );
            assert!(!rows[2]
                .annotation_client_versions
                .contains_key("newest-client"));
            assert!(
                rows[0].request.body_preview.is_empty(),
                "unique rows remain lazy"
            );
            assert_eq!(
                session
                    .store
                    .get(duplicate_id)
                    .await
                    .unwrap()
                    .request
                    .body_preview,
                "fixture request body 2"
            );
            session.persist().await.unwrap();
            let disk = super::read_transactions_file(&storage).unwrap();
            assert_eq!(
                disk.iter()
                    .map(|(row, _)| row.request.body_preview.as_str())
                    .collect::<Vec<_>>(),
                vec![
                    "fixture request body 3",
                    "fixture request body 2",
                    "fixture request body 1"
                ]
            );
        }
        drop(session);
        drop(registry);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn snapshot_duplicate_rows_with_nonempty_journals_fail_closed_without_rewriting() {
        for checkpoint in [false, true] {
            let (root, registry, session) = snapshot_correction_fixture().await;
            let first = deletion_test_record(1);
            let id = first.id;
            let mut second = deletion_test_record(2);
            second.id = id;
            session.store.insert(first).await;
            session.store.insert(second).await;
            session.persist().await.unwrap();
            let session_id = session.id();
            let storage = session.storage_dir().to_path_buf();
            drop(session);
            let journal = super::transaction_journal_path(&storage);
            let delta = if checkpoint {
                transaction_journal_checkpoint_path(&journal)
            } else {
                journal
            };
            let bytes =
                deletion_journal_bytes(&[TransactionJournalEntry::Delete { ids: vec![id] }]);
            std::fs::write(&delta, &bytes).unwrap();
            let original = std::fs::read(super::transactions_path(&storage)).unwrap();
            let error = registry
                .load_context(session_id)
                .err()
                .expect("ambiguous journal must be rejected");
            assert!(error.to_string().contains("ambiguous transaction recovery"));
            assert_eq!(
                std::fs::read(super::transactions_path(&storage)).unwrap(),
                original
            );
            assert_eq!(std::fs::read(&delta).unwrap(), bytes);
            drop(registry);
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[tokio::test]
    async fn snapshot_duplicate_row_source_mismatch_fails_without_rewriting() {
        let (root, registry, session) = snapshot_correction_fixture().await;
        let first = deletion_test_record(1);
        let id = first.id;
        let mut second = deletion_test_record(2);
        second.id = id;
        session.store.insert(first).await;
        session.store.insert(second).await;
        session.store.insert(deletion_test_record(3)).await;
        session.persist().await.unwrap();
        let session_id = session.id();
        let storage = session.storage_dir().to_path_buf();
        drop(session);
        let original = std::fs::read(super::transactions_path(&storage)).unwrap();
        let mut meta = super::read_transactions_meta(&storage).unwrap();
        meta[1].1 = meta[0].1;
        super::write_transactions_meta(&storage, original.len() as u64, &meta).unwrap();
        let meta_bytes = std::fs::read(super::transactions_meta_path(&storage)).unwrap();
        assert!(registry.load_context(session_id).is_err());
        assert_eq!(
            std::fs::read(super::transactions_path(&storage)).unwrap(),
            original
        );
        assert_eq!(
            std::fs::read(super::transactions_meta_path(&storage)).unwrap(),
            meta_bytes
        );
        drop(registry);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn a_damaged_body_line_keeps_its_row_without_bodies_and_the_old_file_aside() {
        // A torn write after power loss leaves the file its size; the damaged
        // line is read when a journal replay rewrites the file on load, when
        // the next save does, or when a replayed annotation needs its body.
        // A whole line of another record still aborts the save: see
        // snapshot_missing_or_mismatched_source_fails_without_publishing_empty_bodies.
        for damage in ["torn-on-load", "torn-on-save", "torn-annotated"] {
            let (root, registry, session) = snapshot_correction_fixture().await;
            let mut ids = Vec::new();
            for sequence in 1..=3 {
                let record = deletion_test_record(sequence);
                ids.push(record.id);
                session.store.insert(record).await;
            }
            session.persist().await.unwrap();
            match damage {
                "torn-on-load" => {
                    session.store.insert(deletion_test_record(4)).await;
                }
                "torn-annotated" => {
                    session
                        .store
                        .update_annotations_durable_with_client(
                            ids[1],
                            None,
                            Some(Some("kept note".into())),
                            Some("client".into()),
                            Some(1),
                        )
                        .await
                        .unwrap()
                        .unwrap();
                }
                _ => {}
            }
            let session_id = session.id();
            let storage = session.storage_dir().to_path_buf();
            drop(session);
            let path = super::transactions_path(&storage);
            let meta = super::read_transactions_meta(&storage).unwrap();
            let locator = meta.iter().find(|(row, _)| row.id == ids[1]).unwrap().1;
            let mut before = std::fs::read(&path).unwrap();
            let start = locator.offset as usize;
            before[start..start + 8].copy_from_slice(&[0; 8]);
            std::fs::write(&path, &before).unwrap();

            let session = registry.load_context(session_id).unwrap();
            if damage.ends_with("-on-save") {
                session.persist().await.unwrap();
            }
            let aside: Vec<Vec<u8>> = std::fs::read_dir(&storage)
                .unwrap()
                .map(|entry| entry.unwrap())
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".transactions.ndjson.corrupt-")
                })
                .map(|entry| std::fs::read(entry.path()).unwrap())
                .collect();
            assert_eq!(aside, vec![before], "{damage}");
            drop(session);
            drop(registry);

            let (registry, session) = SessionRegistry::load_or_create(&root, 32, 32).unwrap();
            let kept = session.store.get(ids[1]).await.unwrap();
            assert_eq!(kept.path, "/2", "{damage}");
            assert!(kept.request.body_preview.is_empty(), "{damage}");
            if damage == "torn-annotated" {
                assert_eq!(kept.user_note.as_deref(), Some("kept note"));
            }
            for (index, sequence) in [(0, 1), (2, 3)] {
                assert_eq!(
                    session
                        .store
                        .get(ids[index])
                        .await
                        .unwrap()
                        .request
                        .body_preview,
                    format!("fixture request body {sequence}"),
                    "{damage}"
                );
            }
            drop(session);
            drop(registry);
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[tokio::test]
    async fn snapshot_ambiguous_duplicate_preflight_preserves_all_session_files() {
        fn files(root: &std::path::Path) -> std::collections::BTreeMap<String, Vec<u8>> {
            std::fs::read_dir(root)
                .unwrap()
                .map(|entry| {
                    let entry = entry.unwrap();
                    (
                        entry.file_name().to_string_lossy().into_owned(),
                        std::fs::read(entry.path()).unwrap(),
                    )
                })
                .collect()
        }
        let (root, registry, session) = snapshot_correction_fixture().await;
        let first = deletion_test_record(1);
        let id = first.id;
        let mut second = deletion_test_record(2);
        second.id = id;
        session.store.insert(first).await;
        session.store.insert(second).await;
        session.persist().await.unwrap();
        let session_id = session.id();
        let storage = session.storage_dir().to_path_buf();
        drop(session);
        std::fs::write(
            super::transaction_journal_path(&storage),
            deletion_journal_bytes(&[TransactionJournalEntry::Delete { ids: vec![id] }]),
        )
        .unwrap();
        for path in [
            super::snapshot_path(&storage),
            super::state_path(&storage),
            super::workspace_path(&storage),
        ] {
            std::fs::write(path, b"synthetic invalid JSON").unwrap();
        }
        let before = files(&storage);
        let error = registry.load_context(session_id).err().unwrap();
        assert!(error.to_string().contains("ambiguous transaction recovery"));
        assert_eq!(
            files(&storage),
            before,
            "preflight must precede every writable repair"
        );
        drop(registry);
        std::fs::remove_dir_all(root).unwrap();
    }

    fn overview_record(method: &str, host: &str, path: &str, seconds: i64) -> TransactionRecord {
        let message = MessageRecord {
            headers: Vec::new(),
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };
        TransactionRecord::http(
            DateTime::<Utc>::from_timestamp(1_800_000_000 + seconds, 0).unwrap(),
            method.into(),
            "https".into(),
            host.into(),
            path.into(),
            Some(200),
            1,
            message.clone(),
            Some(message),
            Vec::new(),
            None,
            None,
        )
    }

    fn overview_finding(severity: Severity) -> ScannerFinding {
        ScannerFinding {
            id: Uuid::new_v4(),
            record_id: Uuid::new_v4(),
            found_at: Utc::now(),
            rule_id: String::new(),
            severity,
            category: "test".into(),
            title: "synthetic".into(),
            detail: String::new(),
            evidence: String::new(),
            host: "example.com".into(),
            path: "/".into(),
            location: None,
        }
    }

    #[test]
    fn traffic_overview_ranks_hosts_skips_tunnels_and_counts_what_the_operator_marked() {
        let mut records = vec![
            overview_record("GET", "b.example.com", "/", 1),
            overview_record("GET", "a.example.com", "/", 2),
            overview_record("GET", "b.example.com", "/", 3),
            overview_record("CONNECT", "c.example.com", "", 9),
            overview_record("GET", "", "/", 4),
        ];
        for host in [
            "d.example.com",
            "e.example.com",
            "f.example.com",
            "g.example.com",
        ] {
            records.push(overview_record("GET", host, "/", 5));
        }
        records[0].color_tag = Some("red".into());
        records[1].user_note = Some("token reuse".into());
        // A note Sniper adds itself is not the operator's mark.
        records[2].notes.push("Sent by Active Scan.".into());

        let overview = super::TrafficOverview::from_records(&records);

        let hosts: Vec<_> = overview
            .top_hosts
            .iter()
            .map(|host| (host.host.as_str(), host.requests))
            .collect();
        assert_eq!(
            hosts,
            [
                ("b.example.com", 2),
                ("a.example.com", 1),
                ("d.example.com", 1),
                ("e.example.com", 1),
                ("f.example.com", 1)
            ]
        );
        assert_eq!(
            overview.last_captured_at,
            DateTime::<Utc>::from_timestamp(1_800_000_009, 0)
        );
        assert_eq!(overview.marked_requests, 2);
    }

    #[test]
    fn session_overview_names_scope_pins_rules_scans_and_findings_without_copying_values() {
        let mut snapshot = super::StoredSessionSnapshot::default();
        snapshot.runtime.scope_patterns = vec!["*.example.com".into(), "api.example.net".into()];
        snapshot.runtime.excluded_scope_patterns = vec!["static.example.com".into()];
        let tab = |label: &str, pinned: bool, path: &str| ReplayTabState {
            custom_label: label.into(),
            pinned,
            base_request: Some(EditableRequest {
                scheme: "https".into(),
                host: "api.example.com".into(),
                method: "POST".into(),
                path: path.into(),
                headers: Vec::new(),
                body: "secret=value".into(),
                body_encoding: BodyEncoding::Utf8,
                preview_truncated: false,
            }),
            ..Default::default()
        };
        snapshot.workspace.replay.tabs = vec![
            tab("Login bypass", true, "/login"),
            tab("", true, "/v1/orders?token=abc#top"),
            tab("Scratch", false, "/"),
        ];
        let rule =
            |description: &str, enabled: bool, target: MatchReplaceTarget| MatchReplaceRule {
                id: Uuid::new_v4(),
                enabled,
                description: description.into(),
                scope: MatchReplaceScope::Request,
                target,
                search: "Bearer secret".into(),
                replace: "Bearer other".into(),
                regex: false,
                case_sensitive: false,
            };
        snapshot.match_replace_rules = vec![
            rule("Strip CSP", true, MatchReplaceTarget::HeaderName),
            rule("", true, MatchReplaceTarget::HeaderValue),
            rule("Off", false, MatchReplaceTarget::Body),
        ];
        let at =
            |seconds: i64| DateTime::<Utc>::from_timestamp(1_800_000_000 + seconds, 0).unwrap();
        snapshot.template_scans.jobs = vec![
            crate::templates::scan::ScanJob {
                status: "completed".into(),
                started_at: at(10),
                targets: vec![
                    "https://app.example.com".into(),
                    "https://api.example.com".into(),
                ],
                matched: 2,
                ..Default::default()
            },
            crate::templates::scan::ScanJob {
                status: "completed".into(),
                auto: true,
                started_at: at(30),
                targets: vec!["https://www.example.com".into()],
                ..Default::default()
            },
        ];
        snapshot.recon.jobs = vec![crate::recon::ReconJob {
            id: Uuid::new_v4(),
            target_url: "https://app.example.com/".into(),
            status: "completed".into(),
            started_at: at(20),
            finished_at: None,
            sources: Vec::new(),
            error: None,
        }];
        snapshot.scanner_findings = vec![
            overview_finding(Severity::High),
            overview_finding(Severity::Low),
            overview_finding(Severity::Low),
        ];

        let overview = super::SessionOverview::new(super::TrafficOverview::default(), &snapshot);

        assert_eq!(overview.scope, ["*.example.com", "api.example.net"]);
        assert_eq!(overview.excluded_scope, ["static.example.com"]);
        assert_eq!(
            overview.pinned_replays,
            ["Login bypass", "POST api.example.com/v1/orders"]
        );
        assert_eq!(overview.pinned_replay_count, 2);
        assert_eq!(
            overview.replace_rules,
            ["Strip CSP", "Request header value rule"]
        );
        assert_eq!(overview.replace_rule_count, 2);
        let activity: Vec<_> = overview
            .activity
            .iter()
            .map(|entry| (entry.kind.as_str(), entry.target.as_str(), entry.matched))
            .collect();
        assert_eq!(
            activity,
            [
                ("auto scan", "https://www.example.com", Some(0)),
                ("recon", "https://app.example.com/", None),
                ("manual scan", "https://app.example.com +1", Some(2)),
            ]
        );
        assert_eq!(
            overview.findings,
            super::SeverityCounts {
                high: 1,
                low: 2,
                ..Default::default()
            }
        );
        // Nothing from a request or a rule's text reaches the registry.
        let stored = serde_json::to_string(&overview).unwrap();
        for value in ["token=abc", "secret=value", "Bearer"] {
            assert!(!stored.contains(value), "{value} leaked into the overview");
        }

        let mut metadata = super::default_session_metadata("overview");
        assert!(super::update_metadata_counts_from_snapshot(
            &mut metadata,
            &snapshot,
            10,
            10
        ));
        assert_eq!(metadata.overview, overview);
        assert!(!super::update_metadata_counts_from_snapshot(
            &mut metadata,
            &snapshot,
            10,
            10
        ));
    }

    #[tokio::test]
    async fn ordinary_state_save_keeps_inactive_scope_overview_after_restart() {
        let (root, state) = metadata_commit_test_state();
        let session = state.session().await;
        let id = session.id();
        let other = state
            .create_session(Some("Scope control".into()))
            .await
            .unwrap();
        assert_ne!(id, other.id);
        session
            .runtime
            .update(RuntimeSettingsUpdate {
                scope_patterns: Some(vec!["example.com".into()]),
                excluded_scope_patterns: Some(vec!["static.example.com".into()]),
                ..Default::default()
            })
            .await
            .unwrap();
        {
            let _guard = session.mutation_guard().await;
            state
                .persist_session_state_mutation_locked(&session)
                .await
                .unwrap();
        }
        let saved: super::StoredSessionSnapshot = serde_json::from_slice(
            &std::fs::read(super::state_path(session.storage_dir())).unwrap(),
        )
        .unwrap();
        assert_eq!(saved.runtime.scope_patterns, ["example.com"]);
        let config = state.config.clone();
        drop(session);
        drop(state);
        let restarted = crate::state::AppState::new(config).unwrap();
        // List before opening/reading the inactive context; a loaded overlay
        // would conceal stale registry metadata.
        let listed = restarted.list_session_listings().await;
        let inactive = listed.iter().find(|item| item.summary.id == id).unwrap();
        assert!(!inactive.summary.active);
        assert_eq!(inactive.overview.scope, ["example.com"]);
        assert_eq!(inactive.overview.excluded_scope, ["static.example.com"]);
        assert_eq!(inactive.summary.request_count, 0);
        assert_eq!(restarted.active_session_summary().await.id, other.id);
        let loaded = restarted.read_session_context_for_id(id).await.unwrap();
        assert_eq!(loaded.overview().await, inactive.overview);
        drop(loaded);
        drop(restarted);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn ordinary_state_save_keeps_cleared_findings_overview_after_restart() {
        let (root, state) = metadata_commit_test_state();
        let session = state.session().await;
        session
            .scanner
            .update_config(ScannerConfig {
                enabled: false,
                ..ScannerConfig::default()
            })
            .await;
        // Stored synthetic findings only: never invoke a scanner or capture.
        session
            .scanner
            .replace_all(vec![overview_finding(Severity::High)])
            .await;
        state.persist_active_session().await.unwrap();
        let id = session.id();
        let other = state
            .create_session(Some("Finding control".into()))
            .await
            .unwrap();
        assert_eq!(session.overview().await.findings.high, 1);
        session.scanner.clear().await;
        {
            let _guard = session.mutation_guard().await;
            state
                .persist_session_state_mutation_locked(&session)
                .await
                .unwrap();
        }
        let saved: super::StoredSessionSnapshot = serde_json::from_slice(
            &std::fs::read(super::state_path(session.storage_dir())).unwrap(),
        )
        .unwrap();
        assert!(saved.scanner_findings.is_empty());
        let config = state.config.clone();
        drop(session);
        drop(state);
        let restarted = crate::state::AppState::new(config).unwrap();
        let listed = restarted.list_session_listings().await;
        let inactive = listed.iter().find(|item| item.summary.id == id).unwrap();
        assert!(!inactive.summary.active);
        assert_eq!(inactive.overview.findings, super::SeverityCounts::default());
        assert_eq!(inactive.summary.request_count, 0);
        assert_eq!(restarted.active_session_summary().await.id, other.id);
        let loaded = restarted.read_session_context_for_id(id).await.unwrap();
        assert_eq!(loaded.scanner.count().await, 0);
        drop(loaded);
        drop(restarted);
        std::fs::remove_dir_all(root).unwrap();
    }

    fn ordinary_state_save_traffic_files(
        storage: &std::path::Path,
    ) -> Vec<Option<(Vec<u8>, std::time::SystemTime)>> {
        [
            "snapshot.json",
            "transactions.ndjson",
            "transactions.meta.ndjson",
            "transactions.journal",
            "transactions.journal.checkpoint",
            "websockets.journal",
        ]
        .iter()
        .map(|name| match std::fs::read(storage.join(name)) {
            Ok(bytes) => Some((
                bytes,
                std::fs::metadata(storage.join(name))
                    .unwrap()
                    .modified()
                    .unwrap(),
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("cannot read synthetic traffic file {name}: {error}"),
        })
        .collect()
    }

    #[tokio::test]
    async fn ordinary_state_save_preserves_full_save_traffic_without_reading_bodies() {
        let (root, registry, session) = snapshot_correction_fixture().await;
        let mut first = overview_record("GET", "first.example.com", "/", 1);
        first.user_note = Some("Synthetic marked row".into());
        first.request.body_preview = "synthetic retained body".into();
        first.request.body_size = first.request.body_preview.len();
        session.store.insert(first).await;
        let mut before = session.persist().await.unwrap();
        // A nonzero cached WebSocket count must survive without starting a
        // transport or replacing the count from this empty state-only snapshot.
        before.websocket_count = 3;
        session.replace_metadata(before.clone());
        registry.update_metadata(before.clone()).unwrap();
        // Later live traffic must not become a partial new traffic snapshot
        // just because an unrelated state component was saved.
        session
            .store
            .insert(overview_record("GET", "later.example.com", "/", 2))
            .await;
        assert_eq!(session.store.len().await, 2);
        let files = ordinary_state_save_traffic_files(session.storage_dir());
        assert!(files[0].is_some() && files[1].is_some());
        let body_path = super::transactions_path(session.storage_dir());
        let held_body = session
            .storage_dir()
            .join("synthetic-held-transactions.ndjson");
        std::fs::rename(&body_path, &held_body).unwrap();
        // A full rewrite or lazy body read cannot use this path. The state-only
        // save must succeed without touching it, not fall back to empty bodies.
        std::fs::create_dir(&body_path).unwrap();
        session
            .runtime
            .update(RuntimeSettingsUpdate {
                scope_patterns: Some(vec!["example.com".into()]),
                ..Default::default()
            })
            .await
            .unwrap();
        let after = {
            let _guard = session.mutation_guard().await;
            session.persist_state_mutation_locked().await.unwrap()
        };
        assert!(body_path.is_dir());
        assert_eq!(
            std::fs::read(&held_body).unwrap(),
            files[1].as_ref().unwrap().0.clone()
        );
        std::fs::remove_dir(&body_path).unwrap();
        std::fs::rename(&held_body, &body_path).unwrap();
        assert_eq!(
            ordinary_state_save_traffic_files(session.storage_dir()),
            files
        );
        assert_eq!(after.request_count, before.request_count);
        assert_eq!(after.websocket_count, before.websocket_count);
        assert_eq!(after.overview.top_hosts, before.overview.top_hosts);
        assert_eq!(
            after.overview.last_captured_at,
            before.overview.last_captured_at
        );
        assert_eq!(
            after.overview.marked_requests,
            before.overview.marked_requests
        );
        assert_eq!(after.overview.scope, ["example.com"]);
        assert_eq!(after.name, before.name);
        assert_eq!(after.created_at, before.created_at);
        assert_eq!(after.last_opened_at, before.last_opened_at);
        drop(session);
        drop(registry);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn ordinary_state_save_failed_write_does_not_publish_overview() {
        let (root, registry, session) = snapshot_correction_fixture().await;
        session
            .store
            .insert(overview_record("GET", "example.com", "/", 1))
            .await;
        registry
            .update_metadata(session.persist().await.unwrap())
            .unwrap();
        let before = session.metadata.read().unwrap().clone();
        let registry_before = std::fs::read(&registry.registry_path).unwrap();
        let files = ordinary_state_save_traffic_files(session.storage_dir());
        let path = super::state_path(session.storage_dir());
        let held_state = session.storage_dir().join("synthetic-held-state.json");
        let bytes = std::fs::read(&path).unwrap();
        std::fs::rename(&path, &held_state).unwrap();
        std::fs::create_dir(&path).unwrap();
        session
            .runtime
            .update(RuntimeSettingsUpdate {
                scope_patterns: Some(vec!["example.com".into()]),
                ..Default::default()
            })
            .await
            .unwrap();
        {
            let _guard = session.mutation_guard().await;
            assert!(session.persist_state_mutation_locked().await.is_err());
        }
        assert_eq!(
            serde_json::to_value(&*session.metadata.read().unwrap()).unwrap(),
            serde_json::to_value(&before).unwrap()
        );
        assert_eq!(
            std::fs::read(&registry.registry_path).unwrap(),
            registry_before
        );
        assert_eq!(std::fs::read(&held_state).unwrap(), bytes);
        assert_eq!(
            ordinary_state_save_traffic_files(session.storage_dir()),
            files
        );
        std::fs::remove_dir(&path).unwrap();
        std::fs::rename(&held_state, &path).unwrap();
        let retry = {
            let _guard = session.mutation_guard().await;
            session.persist_state_mutation_locked().await.unwrap()
        };
        assert_eq!(retry.overview.scope, ["example.com"]);
        registry.update_metadata(retry).unwrap();
        drop(session);
        drop(registry);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn ordinary_state_save_reports_registry_failures_after_state_publication() {
        for after_replacement in [false, true] {
            let (root, state) = metadata_commit_test_state();
            let session = state.session().await;
            session
                .runtime
                .update(RuntimeSettingsUpdate {
                    scope_patterns: Some(vec!["example.com".into()]),
                    ..Default::default()
                })
                .await
                .unwrap();
            state.sessions.fail_next_metadata_write(
                super::SessionMetadataWrite::Update,
                metadata_commit_fault(after_replacement),
            );
            let error = {
                let _guard = session.mutation_guard().await;
                state
                    .persist_session_state_mutation_locked(&session)
                    .await
                    .unwrap_err()
            };
            assert!(error.to_string().contains(if after_replacement {
                "finalization"
            } else {
                "before replacement"
            }));
            // State persistence precedes registry publication; an error must
            // not be reported as success or misrepresented as a full rollback.
            let saved: super::StoredSessionSnapshot = serde_json::from_slice(
                &std::fs::read(super::state_path(session.storage_dir())).unwrap(),
            )
            .unwrap();
            assert_eq!(saved.runtime.scope_patterns, ["example.com"]);
            assert_eq!(
                session.metadata.read().unwrap().overview.scope,
                ["example.com"]
            );
            let expected = if after_replacement {
                vec!["example.com"]
            } else {
                Vec::new()
            };
            let listed = state.sessions.listings();
            assert_eq!(listed[0].overview.scope, expected);
            let disk = metadata_commit_disk(&state.sessions);
            assert_eq!(
                metadata_commit_entry(&disk, session.id())["overview"]["scope"],
                serde_json::json!(expected)
            );
            drop(session);
            drop(state);
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[tokio::test]
    async fn ordinary_state_save_bounds_state_overview_and_omits_request_values() {
        let (root, registry, session) = snapshot_correction_fixture().await;
        session
            .runtime
            .update(RuntimeSettingsUpdate {
                scope_patterns: Some((0..10).map(|n| format!("host-{n}.example.com")).collect()),
                excluded_scope_patterns: Some(
                    (0..10).map(|n| format!("skip-{n}.example.com")).collect(),
                ),
                ..Default::default()
            })
            .await
            .unwrap();
        let mut workspace = session.workspace.snapshot().await;
        workspace.replay.tabs = (0..7)
            .map(|n| ReplayTabState {
                id: format!("synthetic-{n}"),
                pinned: true,
                base_request: Some(EditableRequest {
                    scheme: "https".into(),
                    host: "example.com".into(),
                    method: "GET".into(),
                    path: format!("/{}?synthetic-query-value", "x".repeat(100)),
                    headers: Vec::new(),
                    body: "synthetic-body-value".into(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                }),
                ..Default::default()
            })
            .collect();
        session.workspace.replace_snapshot(workspace).await;
        session
            .match_replace
            .replace_all(
                (0..7)
                    .map(|_| MatchReplaceRule {
                        id: Uuid::new_v4(),
                        enabled: true,
                        description: "Rule ".repeat(30),
                        scope: MatchReplaceScope::Request,
                        target: MatchReplaceTarget::Body,
                        search: "synthetic-search-value".into(),
                        replace: "synthetic-replacement-value".into(),
                        regex: false,
                        case_sensitive: false,
                    })
                    .collect(),
            )
            .await;
        session
            .scanner
            .replace_all(vec![
                overview_finding(Severity::High),
                overview_finding(Severity::Low),
            ])
            .await;
        let metadata = {
            let _guard = session.mutation_guard().await;
            session.persist_state_mutation_locked().await.unwrap()
        };
        let overview = &metadata.overview;
        assert_eq!((overview.scope.len(), overview.scope_count), (8, 10));
        assert_eq!(
            (overview.excluded_scope.len(), overview.excluded_scope_count),
            (8, 10)
        );
        assert_eq!(
            (overview.pinned_replays.len(), overview.pinned_replay_count),
            (5, 7)
        );
        assert_eq!(
            (overview.replace_rules.len(), overview.replace_rule_count),
            (5, 7)
        );
        assert!(overview
            .pinned_replays
            .iter()
            .chain(&overview.replace_rules)
            .all(|label| label.chars().count() <= 80));
        assert_eq!(overview.findings.high, 1);
        assert_eq!(overview.findings.low, 1);
        let json = serde_json::to_string(&metadata).unwrap();
        for omitted in [
            "synthetic-query-value",
            "synthetic-body-value",
            "synthetic-search-value",
            "synthetic-replacement-value",
        ] {
            assert!(
                !json.contains(omitted),
                "request/rule value entered registry metadata"
            );
        }
        registry.update_metadata(metadata).unwrap();
        drop(session);
        drop(registry);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn directory_bytes_adds_up_files_below_a_session_folder() {
        let root = std::env::temp_dir().join(format!("sniper-overview-size-{}", Uuid::new_v4()));
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::fs::write(root.join("a"), [0u8; 100]).unwrap();
        std::fs::write(root.join("nested").join("b"), [0u8; 23]).unwrap();
        assert_eq!(super::directory_bytes(&root), 123);
        assert_eq!(super::directory_bytes(&root.join("missing")), 0);
        std::fs::remove_dir_all(root).unwrap();
    }
}
