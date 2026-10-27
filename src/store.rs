use std::{
    collections::{HashMap, HashSet},
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
};

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, oneshot, Mutex as AsyncMutex, Notify, OwnedMutexGuard, RwLock};
use tracing::warn;
use uuid::Uuid;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use regex::{Regex, RegexBuilder};

use crate::model::{
    compact_annotation_client_versions_for_insert, BodyEncoding, MessageRecord, TrafficKind,
    TransactionRecord, TransactionSummary,
};

#[derive(Clone, Debug, Default)]
pub struct ListFilters {
    pub query: Option<String>,
    /// UI history opts in; legacy CLI and destructive selections remain metadata-only.
    pub search_headers: bool,
    pub method: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub before_sequence: Option<u64>,
    pub sort_key: Option<String>,
    pub sort_direction: Option<String>,
    pub scope_patterns: Vec<String>,
    pub excluded_scope_patterns: Vec<String>,
    pub in_scope_only: bool,
    pub hide_connect: bool,
    pub hide_without_responses: bool,
    pub only_parameterized: bool,
    pub only_notes: bool,
    pub status_classes: Option<Vec<String>>,
    pub mime_types: Option<Vec<String>>,
    pub hidden_extensions: Vec<String>,
    pub host: Option<String>,
    pub status: Option<u16>,
    pub status_range: Option<String>,
    pub since: Option<String>,
    pub mime: Option<String>,
    pub port: Option<String>,
    pub color_tags: Vec<String>,
    pub advanced_search: Option<String>,
    pub advanced_regex: bool,
    pub advanced_case_sensitive: bool,
    pub advanced_negative: bool,
}

/// Destructive selections must never inherit the listing API's forgiving
/// defaults: an ignored or empty criterion could otherwise select everything.
pub fn validate_delete_filters(filters: &ListFilters) -> Result<(), String> {
    if filters.search_headers
        || filters.limit.is_some_and(|limit| limit != 0)
        || filters.offset.is_some()
        || filters.before_sequence.is_some()
        || filters.sort_key.is_some()
        || filters.sort_direction.is_some()
        || !filters.scope_patterns.is_empty()
        || !filters.excluded_scope_patterns.is_empty()
        || filters.in_scope_only
        || filters.hide_connect
        || filters.hide_without_responses
        || filters.only_parameterized
        || filters.only_notes
        || filters.status_classes.is_some()
        || filters.mime_types.is_some()
        || !filters.hidden_extensions.is_empty()
        || filters.port.is_some()
        || !filters.color_tags.is_empty()
        || filters.advanced_search.is_some()
        || filters.advanced_regex
        || filters.advanced_case_sensitive
        || filters.advanced_negative
    {
        return Err("unsupported deletion filter; use query, method, host, status, status_range, since, or mime".to_string());
    }
    let criteria = [
        ("query", filters.query.as_deref()),
        ("method", filters.method.as_deref()),
        ("host", filters.host.as_deref()),
        ("status_range", filters.status_range.as_deref()),
        ("since", filters.since.as_deref()),
        ("mime", filters.mime.as_deref()),
    ];
    for (name, value) in criteria {
        if value.is_some_and(|value| value.trim().is_empty()) {
            return Err(format!("{name} must not be blank"));
        }
    }
    if filters.status.is_none() && criteria.iter().all(|(_, value)| value.is_none()) {
        return Err("at least one deletion filter is required".to_string());
    }
    if filters.status.is_some() && filters.status_range.is_some() {
        return Err("status and status_range cannot be combined".to_string());
    }
    if filters
        .status
        .is_some_and(|status| !(100..=599).contains(&status))
    {
        return Err("status must be between 100 and 599".to_string());
    }
    if let Some(range) = filters.status_range.as_deref() {
        let valid = match parse_status_range(range) {
            Some(StatusPredicate::Class(_)) => true,
            Some(StatusPredicate::Range(lo, hi)) => {
                (100..=599).contains(&lo) && (100..=599).contains(&hi)
            }
            _ => false,
        };
        if !valid {
            return Err(
                "status_range must be a class such as 4xx or an ordered range within 100-599"
                    .to_string(),
            );
        }
    }
    if filters
        .since
        .as_deref()
        .is_some_and(|since| parse_since(since).is_none())
    {
        return Err("since must be a valid date, RFC3339 timestamp, or nonnegative relative duration such as 30m".to_string());
    }
    Ok(())
}

/// What a body search may look at. The URL and headers are held in memory, so
/// including them costs nothing; bodies come off disk and are what the byte
/// budget governs. The URL is here so one search answers "did this value cross
/// the wire at all" without a second pass through the metadata query.
#[derive(Clone, Copy, Debug)]
pub struct BodySearchSides {
    pub url: bool,
    pub request_body: bool,
    pub response_body: bool,
    pub headers: bool,
}

impl Default for BodySearchSides {
    fn default() -> Self {
        Self {
            url: true,
            request_body: true,
            response_body: true,
            headers: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct BodySearchRequest {
    pub value: String,
    pub sides: BodySearchSides,
    pub case_sensitive: bool,
    /// Stop after this many matches. Reported through `complete`.
    pub max_matches: usize,
    /// Stop after reading this many body bytes. Reported through `complete`.
    pub byte_budget: u64,
    pub context_bytes: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct BodySearchMatch {
    pub side: &'static str,
    /// Byte offset of the match inside that side, not inside the file.
    pub offset: usize,
    pub context: String,
}

/// One transaction and every place in it the value turned up. Grouped because
/// the question is almost always "which requests", and a flat list of
/// occurrences makes the caller count distinct ids to answer it.
#[derive(Clone, Debug, Serialize)]
pub struct BodySearchHit {
    pub id: Uuid,
    pub sequence: u64,
    // Carried so a caller can say which request matched without fetching each
    // record again — the round trip the search exists to remove.
    pub method: String,
    pub host: String,
    pub path: String,
    pub matches: Vec<BodySearchMatch>,
}

/// A search answers "where is this value" and, just as importantly, "how much did
/// you actually look at". Without the second half an agent reads an exhausted
/// budget as proof the value is absent.
#[derive(Clone, Debug, Serialize)]
pub struct BodySearchOutcome {
    pub transactions: Vec<BodySearchHit>,
    /// Occurrences across all transactions; what `max_matches` caps.
    pub match_count: usize,
    pub records_considered: usize,
    pub records_scanned: usize,
    pub bytes_scanned: u64,
    /// True only when every candidate was searched: nothing cut the scan short
    /// and nothing was unreadable. "No matches" is an answer only when this is.
    pub complete: bool,
    /// Which limit ended the scan early — `max_matches`, `byte_budget` or
    /// `scan_failed` — so the caller knows what to raise rather than guessing.
    pub stopped_by: Option<&'static str>,
    /// Records whose bodies could not be read back, so their absence from the
    /// matches proves nothing.
    pub unsearchable: usize,
}

impl BodySearchOutcome {
    fn stop(&mut self, reason: &'static str) {
        self.complete = false;
        self.stopped_by.get_or_insert(reason);
    }
}

#[derive(Clone, Debug)]
pub struct TransactionListPage {
    pub items: Vec<TransactionSummary>,
    pub total: usize,
    pub filtered_total: Option<usize>,
    pub hidden_connect_total: Option<usize>,
    pub offset: usize,
    pub limit: usize,
    pub has_more: bool,
}

#[derive(Clone, Debug)]
pub struct SiteMapRecord {
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub path: String,
    pub status: Option<u16>,
    pub note_count: usize,
    pub is_websocket: bool,
}

pub struct TransactionStore {
    // Sequence numbers may be reused after reloading a trimmed/cleared store.
    // Saved-data cursors expire when the underlying store is reconstructed.
    saved_cursor_generation: Uuid,
    inner: Arc<RwLock<StoreInner>>,
    insert_lock: Arc<AsyncMutex<()>>,
    events: broadcast::Sender<TransactionEvent>,
    retention_events: broadcast::Sender<TransactionRetentionEvent>,
    in_progress: Arc<InProgressTransactions>,
    retention_trim_sequence: AtomicU64,
    retention_compacted_sequence: AtomicU64,
    journal_tx: Option<mpsc::Sender<TransactionJournalCommand>>,
    // Set only when startup proves no journal writer ever became ready.
    journal_start_failed: bool,
    /// Session directory, so a record whose bodies were dropped can be read back
    /// out of transactions.ndjson. Derived from the journal path.
    storage_dir: Option<PathBuf>,
    /// `storage_dir` is only where bodies are read back: the store of a session
    /// read without activation keeps no journal, so persisting it confirms no
    /// rotation, as a store without a directory never did.
    read_only_bodies: bool,
    /// Libraries read from retained scripts and pages; see `LibraryCaches`.
    library_versions: Mutex<LibraryCaches>,
    /// The last whole-history map, serialized; see `cached_service_map`.
    service_map_result: Mutex<Option<CachedServiceMap>>,
    max_entries: Option<usize>,
    next_sequence: AtomicU64,
    next_event_sequence: AtomicU64,
    #[cfg(test)]
    before_transaction_event_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

/// A persistence plan binds its records to the journal and file versions from
/// which they were captured. A later live mutation must never adopt its bodies.
#[derive(Debug)]
pub struct TransactionPersistenceSnapshot {
    entries: Vec<(TransactionRecord, Option<crate::session::BodyLocator>)>,
    body_generations: HashMap<Uuid, Uuid>,
    file_generation: Uuid,
    complete_capture: bool,
    pub latest_event_sequence: u64,
    pub journal_rotation_confirmed: bool,
}

impl std::ops::Deref for TransactionPersistenceSnapshot {
    type Target = [(TransactionRecord, Option<crate::session::BodyLocator>)];

    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

impl IntoIterator for TransactionPersistenceSnapshot {
    type Item = (TransactionRecord, Option<crate::session::BodyLocator>);
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

/// Metadata-only ownership of provisional records. The synchronous mutex is
/// never held across an await, filesystem operation, or callback.
#[derive(Default)]
struct InProgressTransactions {
    leases: Mutex<HashMap<Uuid, HashSet<Uuid>>>,
    notify: Arc<Notify>,
}

impl InProgressTransactions {
    fn register(self: &Arc<Self>, id: Uuid) -> InProgressTransactionGuard {
        let token = Uuid::new_v4();
        self.leases
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(id)
            .or_default()
            .insert(token);
        InProgressTransactionGuard {
            registry: Arc::clone(self),
            id,
            token,
        }
    }

    fn release(&self, id: Uuid, token: Uuid) {
        let mut leases = self
            .leases
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let remove = leases
            .get_mut(&id)
            .is_some_and(|tokens| tokens.remove(&token) && tokens.is_empty());
        if remove {
            leases.remove(&id);
        }
        drop(leases);
        if remove {
            self.notify.notify_one();
        }
    }
}

/// A single non-cloneable lease. Dropping it only releases its own token and
/// wakes the cleanup worker; it never touches records or performs persistence.
#[must_use = "hold this guard through the provisional record's final update"]
pub struct InProgressTransactionGuard {
    registry: Arc<InProgressTransactions>,
    id: Uuid,
    token: Uuid,
}

impl Drop for InProgressTransactionGuard {
    fn drop(&mut self) {
        self.registry.release(self.id, self.token);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransactionRetentionEvent {
    /// Existing manual-delete and legacy-cap invalidation behavior.
    Gap,
    Deleted {
        ids: Vec<Uuid>,
        generation: Uuid,
        event_sequence: u64,
    },
}

pub(crate) struct RetentionStatusDetails {
    pub total_count: usize,
    pub protected_count: usize,
    pub all_records_protected: bool,
    pub identity_conflict: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionTrimOutcome {
    pub deleted_ids: Vec<Uuid>,
    pub current_count: usize,
    pub protected_count: usize,
    pub event_sequence: u64,
    /// Bytes the deleted rows still occupy in `transactions.ndjson`, which only
    /// a snapshot rewrite reclaims. Rows not yet snapshotted count nothing.
    pub reclaimable_bytes: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TransactionInsertOutcome {
    journal_fallback_required: bool,
}

impl TransactionInsertOutcome {
    /// True when the journal could not take this record, so rewriting the full
    /// session snapshot is the only way to make it durable.
    ///
    /// A retention trim deliberately does NOT ask for a snapshot: journal replay
    /// applies the same retention cap (`trim_transaction_replay_state`), so a
    /// trimmed record cannot come back. Treating a trim as a snapshot trigger
    /// meant that once a session reached `max_transaction_entries` — where every
    /// insert trims — the whole 1.35 GB document was rewritten every
    /// `PERSIST_DEBOUNCE`. Journal size drives compaction instead; see
    /// `AppConfig::transaction_journal_compact_bytes`.
    pub fn immediate_snapshot_required(self) -> bool {
        self.journal_fallback_required
    }
}

#[derive(Clone, Debug)]
pub struct AnnotationUpdate {
    pub summary: TransactionSummary,
    pub previous_color_tag: Option<String>,
    pub previous_user_note: Option<String>,
    pub applied_color_tag: Option<String>,
    pub applied_user_note: Option<String>,
}

#[derive(Clone, Debug)]
pub struct TransactionEvent {
    pub event_sequence: u64,
    pub summary: TransactionSummary,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum TransactionJournalEntry {
    Insert {
        record: TransactionRecord,
    },
    Update {
        record: TransactionRecord,
    },
    Delete {
        ids: Vec<Uuid>,
    },
    Annotation {
        id: Uuid,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        color_tag: Option<NullableStringPatch>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user_note: Option<NullableStringPatch>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        annotation_revision: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        previous_annotation_revision: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        annotation_client_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        annotation_client_version: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        previous_color_tag: Option<NullableStringPatch>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        previous_user_note: Option<NullableStringPatch>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NullableStringPatch {
    Set(String),
    Clear,
}

#[derive(Serialize)]
struct TransactionJournalInsert<'a> {
    #[serde(rename = "type")]
    entry_type: &'static str,
    record: &'a TransactionRecord,
}

enum TransactionJournalCommand {
    Append {
        line: Vec<u8>,
        ack: Option<oneshot::Sender<io::Result<()>>>,
    },
    Rotate {
        ack: mpsc::Sender<io::Result<()>>,
    },
    #[cfg(test)]
    StopForTest {
        ack: mpsc::Sender<()>,
    },
}

/// A private publication fence, unrelated to persisted rows or evidence tokens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ServiceMapMetadataEpoch(Uuid);

struct StoreInner {
    /// Oldest to newest. New captures append, queries iterate in reverse.
    entries: Vec<TransactionRecord>,
    summaries: Vec<CachedSummary>,
    // Parallel to entries, including duplicate IDs. Only annotations retain a token.
    body_generations: Vec<Uuid>,
    // Displaced lazy rows whose saved bodies could not be recovered. Their
    // ordering rows remain present, but no compaction may silently erase them.
    unresolved_body_generations: HashSet<Uuid>,
    // Changed only after publishing a replacement transactions file.
    file_generation: Uuid,
    // Changes under the metadata mutation lock, before event publication. Pure
    // append, annotations and body-file changes preserve the projected rows.
    service_map_metadata_epoch: Uuid,
    // Annotations change filtered map membership without changing evidence.
    service_map_annotation_epoch: Uuid,
    /// Changes only when rows are removed or replaced, which moves the rows a
    /// whole-history map reads by index; updates and appends keep it.
    service_map_structure_epoch: Uuid,
    by_id: HashMap<Uuid, usize>,
    /// Where a record's line sits in transactions.ndjson, for records whose bodies
    /// were dropped after loading. Bodies are read back through this rather than
    /// kept resident: they are ~90% of a record and the history list never needs
    /// them (`ListFilters` has no body search and `summary()` reads only sizes).
    locators: HashMap<Uuid, crate::session::BodyLocator>,
}

/// Drops the body text a record carries, leaving sizes, headers and metadata.
/// Only safe for a record that has a locator, so the text can be read back.
/// Whether any of a record's messages still holds its body in memory. A record
/// loaded from `transactions.meta.ndjson` has none of them; one replayed from the
/// journal has all of it.
fn transaction_carries_bodies(record: &TransactionRecord) -> bool {
    if !record.request.body_preview.is_empty() {
        return true;
    }
    [
        record.response.as_ref(),
        record.original_request.as_ref(),
        record.original_response.as_ref(),
    ]
    .into_iter()
    .flatten()
    .any(|message| !message.body_preview.is_empty())
}

pub(crate) fn strip_transaction_bodies(record: &mut TransactionRecord) {
    record.request.body_preview = String::new();
    for message in [
        record.response.as_mut(),
        record.original_request.as_mut(),
        record.original_response.as_mut(),
    ]
    .into_iter()
    .flatten()
    {
        message.body_preview = String::new();
    }
}

/// Leaves a record's bodies to disk when its persisted line is current.
fn keep_located_bodies_on_disk(
    records: &mut [TransactionRecord],
    locators: &mut HashMap<Uuid, crate::session::BodyLocator>,
    replayed_ids: &HashSet<Uuid>,
) {
    for id in replayed_ids {
        locators.remove(id);
    }
    for record in records.iter_mut() {
        if !locators.contains_key(&record.id) {
            continue;
        }
        if transaction_carries_bodies(record) {
            // It has a locator, so a copy of it was persisted, yet it still
            // holds its bodies: it came back from an Update entry in the
            // journal, which means memory is the newer copy. Reading it from
            // the stale line would serve the pre-update record, and copying
            // that line on the next persist would discard the update for good.
            locators.remove(&record.id);
        } else {
            strip_transaction_bodies(record);
        }
    }
}

/// The caller holds `inner` through the complete disk read. Mutation callers
/// propagate failure before invoking their edit closure or appending a journal.
fn rehydrate_checked(
    record: &TransactionRecord,
    inner: &StoreInner,
    storage_dir: Option<&Path>,
) -> io::Result<TransactionRecord> {
    let Some(locator) = inner.locators.get(&record.id).copied() else {
        return Ok(record.clone());
    };
    let storage_dir = storage_dir.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "transaction body storage is unavailable",
        )
    })?;
    let mut full = crate::session::read_transaction_at(storage_dir, locator).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "transaction body could not be read",
        )
    })?;
    if full.id != record.id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "transaction body locator points to a different record",
        ));
    }
    full.notes = record.notes.clone();
    full.color_tag = record.color_tag.clone();
    full.user_note = record.user_note.clone();
    full.annotation_revision = record.annotation_revision;
    full.annotation_client_versions = record.annotation_client_versions.clone();
    Ok(full)
}

#[derive(Debug)]
pub(crate) struct ServiceMapPacketRead {
    pub(crate) bytes: Vec<u8>,
    fence: Option<ServiceMapPacketFence>,
}
#[derive(Debug)]
struct ServiceMapPacketFence {
    located: Option<(crate::session::BodyLocator, Uuid)>,
    unresolved: bool,
}

// Resolve the full row token rather than UUID: older retained duplicates can
// only use their own resident preview, never the newest row's disk locator.
fn service_map_row_index(
    inner: &StoreInner,
    key: &crate::service_map::EvidenceKey,
) -> Result<usize, &'static str> {
    let index = inner
        .entries
        .binary_search_by_key(&key.sequence, |record| record.sequence)
        .map_err(|_| "record_missing")?;
    if inner.entries[index].id != key.record_id {
        return Err("record_missing");
    }
    if inner.body_generations[index] != key.revision {
        return Err("record_changed");
    }
    Ok(index)
}

/// Notes the newest icon row of each origin. It runs before the display
/// filter, which hides `ico` and `png` rows by default, so an origin keeps its
/// icon whatever the map shows.
fn note_favicon(
    favicons: &mut std::collections::BTreeMap<String, String>,
    record: &TransactionRecord,
    evidence: impl FnOnce() -> String,
) {
    if let Some(origin) = crate::service_map::favicon_origin(record) {
        favicons.entry(origin).or_insert_with(evidence);
    }
}

fn service_map_body_row_index(
    inner: &StoreInner,
    key: &crate::service_map::EvidenceKey,
) -> Result<usize, &'static str> {
    let index = service_map_row_index(inner, key)?;
    if inner.unresolved_body_generations.contains(&key.revision) {
        return Err("body_identity_unverifiable");
    }
    Ok(index)
}

fn validate_service_map_body_locator(
    inner: &StoreInner,
    key: &crate::service_map::EvidenceKey,
    file_generation: Uuid,
    locator: crate::session::BodyLocator,
) -> Result<(), &'static str> {
    let index = service_map_body_row_index(inner, key)?;
    if inner.file_generation != file_generation
        || inner.by_id.get(&key.record_id) != Some(&index)
        || inner.locators.get(&key.record_id) != Some(&locator)
    {
        return Err("body_identity_unverifiable");
    }
    Ok(())
}

/// A path without its fragment, split from its query string.
fn path_and_query(path: &str) -> (&str, Option<&str>) {
    let path = path.split('#').next().unwrap_or("");
    match path.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (path, None),
    }
}

/// A row for a parameter read: its query, and its request body or, when the
/// row still owns one, the locator to read it from.
fn parameter_row(
    inner: &StoreInner,
    index: usize,
    session_id: Uuid,
    generation: Uuid,
    query: Option<&str>,
) -> crate::service_map_parameters::ParameterRow {
    let record = &inner.entries[index];
    let locator = (inner.by_id.get(&record.id) == Some(&index))
        .then(|| inner.locators.get(&record.id).copied())
        .flatten();
    crate::service_map_parameters::ParameterRow {
        key: crate::service_map::EvidenceKey {
            session_id,
            generation,
            sequence: record.sequence,
            revision: inner.body_generations[index],
            record_id: record.id,
        },
        query: query.map(str::to_string),
        content_type: record.request.content_type.clone(),
        // Only a body's start is parsed (`ParameterTally::add_row`), so only
        // that much of an unsaved one is copied.
        body: (locator.is_none() && record.request.body_encoding == BodyEncoding::Utf8).then(
            || {
                let body = &record.request.body_preview;
                let mut end = body
                    .len()
                    .min(crate::service_map_parameters::MAX_BODY_BYTES);
                while !body.is_char_boundary(end) {
                    end -= 1;
                }
                body[..end].to_string()
            },
        ),
        locator,
    }
}

/// A parameter row's request body: held in memory, or read from its locator
/// while `budget` lasts. None when the budget did not cover it; empty when it
/// cannot be shown to be this row's UTF-8 body.
fn parameter_body(
    inner: &RwLock<StoreInner>,
    file: Option<&mut fs::File>,
    file_generation: Uuid,
    budget: &mut usize,
    row: &mut crate::service_map_parameters::ParameterRow,
) -> Option<String> {
    match (row.body.take(), row.locator, file) {
        (Some(body), _, _) => Some(body),
        (None, Some(locator), Some(_)) if locator.len as usize > *budget => None,
        (None, Some(locator), Some(file)) => {
            *budget -= locator.len as usize;
            let current = validate_service_map_body_locator(
                &inner.blocking_read(),
                &row.key,
                file_generation,
                locator,
            );
            Some(
                current
                    .ok()
                    .and_then(|_| {
                        crate::service_map_parameters::read_request_body(
                            file,
                            locator,
                            row.key.record_id,
                        )
                    })
                    .unwrap_or_default(),
            )
        }
        _ => Some(String::new()),
    }
}

#[cfg(test)]
type ServiceMapBodyReadHook = Arc<dyn Fn(&str) + Send + Sync>;

/// Libraries already read by row revision, and detections by bounded body
/// content and kind. URL and size cannot identify a response across captures.
#[derive(Default)]
struct LibraryCaches {
    rows: HashMap<(Uuid, Uuid), Vec<crate::service_map_libraries::Detection>>,
    bodies: HashMap<
        (crate::service_map_libraries::Kind, [u8; 32]),
        Vec<crate::service_map_libraries::Detection>,
    >,
}

impl LibraryCaches {
    // ponytail: forget everything at a cap rather than track recency.
    fn trim(&mut self) {
        if self.rows.len() > 100_000 || self.bodies.len() > 100_000 {
            *self = Self::default();
        }
    }
}

/// Body reads one map may make; a row past it waits for a later map.
#[derive(Default)]
struct LibraryBudget {
    reads: usize,
    bytes: usize,
    exhausted: bool,
}

/// The libraries a script or page row declares when read before (`Ok`); or,
/// within the budget, how to read them (`Err`); None when the row declares
/// nothing to read, or must wait for a later map.
fn library_lookup(
    inner: &StoreInner,
    caches: &mut LibraryCaches,
    row: &crate::service_map::ServiceMapRow,
    budget: &mut LibraryBudget,
) -> Option<Result<Vec<crate::service_map_libraries::Detection>, PendingLibrary>> {
    use crate::{
        service_map::EvidenceKey,
        service_map_body::BodySource,
        service_map_libraries::{kind, MAX_BYTES_PER_MAP, MAX_READS, MAX_ROW_BYTES},
    };
    let body_kind = kind(row)?;
    let key = EvidenceKey::parse(&row.evidence_id)?;
    let row_key = (key.record_id, key.revision);
    if let Some(found) = caches.rows.get(&row_key) {
        return Some(Ok(found.clone()));
    }
    let index = service_map_body_row_index(inner, &key).ok()?;
    let record = &inner.entries[index];
    let response = record.response.as_ref()?;
    if BodySource::from_text_record(record).is_err() {
        caches.rows.insert(row_key, Vec::new());
        return Some(Ok(Vec::new()));
    }
    let locator = (inner.by_id.get(&record.id) == Some(&index))
        .then(|| inner.locators.get(&record.id).copied())
        .flatten();
    let size = locator.map_or(response.body_preview.len().min(MAX_ROW_BYTES), |l| {
        l.len as usize
    });
    if budget.reads >= MAX_READS || budget.bytes + size > MAX_BYTES_PER_MAP {
        budget.exhausted = true;
        return None;
    }
    budget.reads += 1;
    budget.bytes += size;
    let source = match locator {
        Some(locator) => LibrarySource::Retained(locator, inner.file_generation),
        None => {
            let mut end = response.body_preview.len().min(MAX_ROW_BYTES);
            while !response.body_preview.is_char_boundary(end) {
                end -= 1;
            }
            if response.body_encoding == crate::model::BodyEncoding::Base64 {
                // Whole base64 quanta only, so the copy still decodes.
                end -= end % 4;
            }
            LibrarySource::Resident(
                response.body_preview[..end].to_string(),
                response.body_encoding.clone(),
            )
        }
    };
    Some(Err(PendingLibrary {
        key,
        kind: body_kind,
        url: format!("{}{}", row.origin, record.path),
        source,
    }))
}

#[derive(Debug)]
pub(crate) enum ServiceMapStreamError {
    HistoryChanged,
    ScopeWorkLimit,
}

const SERVICE_MAP_CHUNK: usize = 8_192;

/// Where the rows a whole-history read has yet to fold end, after rows were
/// removed: at the oldest row of its last chunk that is still retained, found
/// by ID and body generation. Nothing read yet starts again from the newest.
fn resume_below(inner: &StoreInner, read: &[(Uuid, Uuid)]) -> Option<usize> {
    if read.is_empty() {
        return Some(inner.entries.len());
    }
    read.iter().find_map(|&(id, generation)| {
        inner
            .by_id
            .get(&id)
            .copied()
            .filter(|&index| inner.body_generations.get(index) == Some(&generation))
    })
}

/// The last whole-history map, serialized, and the history it was built from.
struct CachedServiceMap {
    key: String,
    token: (Uuid, Uuid, usize),
    built: std::time::Instant,
    cost: std::time::Duration,
    /// Every script and page body was read; otherwise rebuild for the rest.
    complete: bool,
    bytes: bytes::Bytes,
}

fn merge_libraries(
    found: &mut Vec<crate::service_map_libraries::Detection>,
    more: Vec<crate::service_map_libraries::Detection>,
) {
    for detection in more {
        crate::service_map_libraries::merge(found, detection);
    }
}

/// A script or page row to scan after the store lock is released.
struct PendingLibrary {
    key: crate::service_map::EvidenceKey,
    kind: crate::service_map_libraries::Kind,
    url: String,
    source: LibrarySource,
}

enum LibrarySource {
    /// A copy of a body still in memory, as stored.
    Resident(String, crate::model::BodyEncoding),
    /// Where a retained body sits in transactions.ndjson, and in which file.
    Retained(crate::session::BodyLocator, Uuid),
}

#[derive(Clone, Debug)]
struct CachedSummary {
    summary: TransactionSummary,
    method_upper: String,
    host_lower: String,
    content_type_lower: String,
    path_lower: String,
    path_extension: Option<String>,
    port: Option<String>,
    mime: &'static str,
    total_bytes: usize,
    is_tls: bool,
    quick_haystack: String,
    advanced_haystack: String,
    advanced_haystack_lower: String,
    header_haystack: String,
    header_haystack_lower: String,
}

impl CachedSummary {
    fn new(mut summary: TransactionSummary) -> Self {
        let method_upper = summary.method.to_ascii_uppercase();
        let host_lower = summary.host.to_ascii_lowercase();
        let content_type_lower = summary
            .content_type
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase();
        let path_extension = extract_path_extension(&summary.path);
        let path_lower = summary.path.to_ascii_lowercase();
        let port = effective_summary_port(&summary);
        let mime = infer_summary_mime(&summary);
        let total_bytes = summary_total_bytes(&summary);
        let is_tls = is_tls_summary(&summary);
        let quick_haystack = format!(
            "{} {} {} {} {} {} {} {} {} {} {} {}",
            summary.id,
            summary.sequence,
            summary.method,
            summary.host,
            summary.path,
            summary
                .status
                .map(|status| status.to_string())
                .unwrap_or_default(),
            summary.content_type.as_deref().unwrap_or(""),
            mime,
            total_bytes,
            format_size(total_bytes),
            summary.started_at.to_rfc3339(),
            summary.started_at.format("%b %d, %H:%M:%S"),
        )
        .to_ascii_lowercase();
        let advanced_haystack = format!(
            "{} {} {} {}",
            summary.host,
            summary.method,
            summary.path,
            summary.content_type.as_deref().unwrap_or("")
        );
        let advanced_haystack_lower = advanced_haystack.to_ascii_lowercase();
        let header_haystack = std::mem::take(&mut summary.header_search_text);
        let header_haystack_lower = header_haystack.to_ascii_lowercase();

        Self {
            summary,
            method_upper,
            host_lower,
            content_type_lower,
            path_lower,
            path_extension,
            port,
            mime,
            total_bytes,
            is_tls,
            quick_haystack,
            advanced_haystack,
            advanced_haystack_lower,
            header_haystack,
            header_haystack_lower,
        }
    }

    fn list_summary(&self, search_headers: bool) -> TransactionSummary {
        let mut summary = self.summary.clone();
        if search_headers {
            // Keep default CLI/selection payloads and allocations metadata-only.
            summary.header_search_text = self.header_haystack.clone();
        }
        summary
    }
}

impl StoreInner {
    fn from_newest_first(records: Vec<TransactionRecord>) -> Self {
        Self::from_oldest_first(records.into_iter().rev().collect())
    }

    fn from_oldest_first(mut entries: Vec<TransactionRecord>) -> Self {
        normalize_storage_sequences(&mut entries);
        let mut summaries = Vec::with_capacity(entries.len());
        let mut by_id = HashMap::with_capacity(entries.len());
        for (index, record) in entries.iter().enumerate() {
            summaries.push(CachedSummary::new(record.summary()));
            by_id.insert(record.id, index);
        }
        let body_generations = entries.iter().map(|_| Uuid::new_v4()).collect();
        Self {
            entries,
            summaries,
            body_generations,
            unresolved_body_generations: HashSet::new(),
            file_generation: Uuid::new_v4(),
            service_map_metadata_epoch: Uuid::new_v4(),
            service_map_annotation_epoch: Uuid::new_v4(),
            service_map_structure_epoch: Uuid::new_v4(),
            by_id,
            locators: HashMap::new(),
        }
    }

    fn require_resolved_bodies(&self) -> io::Result<()> {
        if self.unresolved_body_generations.is_empty() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cannot save snapshot while a preserved transaction body dependency is unresolved",
            ))
        }
    }

    fn push(&mut self, record: TransactionRecord, summary: TransactionSummary) {
        let index = self.entries.len();
        self.by_id.insert(record.id, index);
        // Reusing an ID creates a new full record, never a view of the old body.
        self.locators.remove(&record.id);
        self.body_generations.push(Uuid::new_v4());
        self.entries.push(record);
        self.summaries.push(CachedSummary::new(summary));
    }

    fn trim_to_max_entries(&mut self, max_entries: usize) -> bool {
        if max_entries == 0 {
            let trimmed =
                !self.entries.is_empty() || !self.summaries.is_empty() || !self.by_id.is_empty();
            self.entries.clear();
            self.summaries.clear();
            self.body_generations.clear();
            self.unresolved_body_generations.clear();
            self.by_id.clear();
            self.locators.clear();
            if trimmed {
                self.service_map_metadata_epoch = Uuid::new_v4();
                self.service_map_structure_epoch = Uuid::new_v4();
            }
            return trimmed;
        }

        if self.entries.len() <= max_entries {
            return false;
        }

        let remove_count = self.entries.len().saturating_sub(max_entries);
        self.entries.drain(0..remove_count);
        self.summaries.drain(0..remove_count);
        for generation in self.body_generations.drain(0..remove_count) {
            self.unresolved_body_generations.remove(&generation);
        }
        self.by_id = self
            .entries
            .iter()
            .enumerate()
            .map(|(index, record)| (record.id, index))
            .collect();
        self.locators.retain(|id, _| self.by_id.contains_key(id));
        self.service_map_metadata_epoch = Uuid::new_v4();
        self.service_map_structure_epoch = Uuid::new_v4();
        true
    }
}

impl TransactionStore {
    pub fn saved_cursor_generation(&self) -> Uuid {
        self.saved_cursor_generation
    }

    pub fn new() -> Self {
        Self::from_records(Vec::new())
    }

    pub fn from_records(records: Vec<TransactionRecord>) -> Self {
        Self::from_records_with_max_entries(records, None)
    }

    pub fn from_records_with_max_entries(
        records: Vec<TransactionRecord>,
        max_entries: Option<usize>,
    ) -> Self {
        Self::from_records_with_max_entries_and_event_sequence(records, max_entries, 0)
    }

    pub fn from_records_with_max_entries_and_event_sequence(
        records: Vec<TransactionRecord>,
        max_entries: Option<usize>,
        latest_event_sequence: u64,
    ) -> Self {
        let (events, _) = broadcast::channel(256);
        let (retention_events, _) = broadcast::channel(64);
        let mut inner = StoreInner::from_newest_first(records);
        if let Some(max_entries) = max_entries {
            inner.trim_to_max_entries(max_entries);
        }
        // Resume sequence from the highest existing number.
        let max_seq = inner.entries.iter().map(|r| r.sequence).max().unwrap_or(0);
        Self {
            saved_cursor_generation: Uuid::new_v4(),
            inner: Arc::new(RwLock::new(inner)),
            insert_lock: Arc::new(AsyncMutex::new(())),
            events,
            retention_events,
            in_progress: Arc::new(InProgressTransactions::default()),
            retention_trim_sequence: AtomicU64::new(0),
            retention_compacted_sequence: AtomicU64::new(0),
            journal_tx: None,
            journal_start_failed: false,
            storage_dir: None,
            read_only_bodies: false,
            library_versions: Mutex::new(LibraryCaches::default()),
            service_map_result: Mutex::new(None),
            max_entries,
            next_sequence: AtomicU64::new(max_seq + 1),
            next_event_sequence: AtomicU64::new(max_seq.max(latest_event_sequence) + 1),
            #[cfg(test)]
            before_transaction_event_hook: Mutex::new(None),
        }
    }

    pub fn from_records_with_journal(
        records: Vec<TransactionRecord>,
        journal_path: PathBuf,
        max_entries: Option<usize>,
    ) -> Self {
        Self::from_records_with_journal_and_event_sequence(records, journal_path, max_entries, 0)
    }

    /// Builds a store that keeps bodies on disk for every record with a locator.
    ///
    /// A record the journal replayed is deliberately given no locator: the journal
    /// holds a newer version than the line in transactions.ndjson, so reading that
    /// line back would serve stale traffic. Those keep their bodies in memory until
    /// the next compaction writes them out, which the journal size bounds.
    pub fn from_located_records_with_journal(
        mut records: Vec<TransactionRecord>,
        mut locators: HashMap<Uuid, crate::session::BodyLocator>,
        replayed_ids: &HashSet<Uuid>,
        journal_path: PathBuf,
        latest_event_sequence: u64,
    ) -> Self {
        keep_located_bodies_on_disk(&mut records, &mut locators, replayed_ids);
        // No cap: captured traffic is kept. Bodies live on disk, so what a record
        // costs resident no longer scales with its response size.
        let store = Self::from_records_with_journal_and_event_sequence(
            records,
            journal_path,
            None,
            latest_event_sequence,
        );
        store
            .inner
            .try_write()
            .expect("new store is not shared yet")
            .locators = locators;
        store
    }

    /// The store of a session read without being activated: bodies are read
    /// back from disk by their locators, as in a writable store, but there is
    /// no journal. It used to drop the locators, so every body it served was
    /// empty (`history get --session-id` showed none, and a search reported
    /// complete with no match), and a capture that landed in it and persisted
    /// wrote its older rows back without their bodies.
    pub fn from_located_records_read_only(
        mut records: Vec<TransactionRecord>,
        mut locators: HashMap<Uuid, crate::session::BodyLocator>,
        replayed_ids: &HashSet<Uuid>,
        storage_dir: PathBuf,
        latest_event_sequence: u64,
    ) -> Self {
        keep_located_bodies_on_disk(&mut records, &mut locators, replayed_ids);
        let mut store = Self::from_records_with_max_entries_and_event_sequence(
            records,
            None,
            latest_event_sequence,
        );
        store.storage_dir = Some(storage_dir);
        store.read_only_bodies = true;
        store
            .inner
            .try_write()
            .expect("new store is not shared yet")
            .locators = locators;
        store
    }

    pub fn from_records_with_journal_and_event_sequence(
        records: Vec<TransactionRecord>,
        journal_path: PathBuf,
        max_entries: Option<usize>,
        latest_event_sequence: u64,
    ) -> Self {
        let mut store = Self::from_records_with_max_entries_and_event_sequence(
            records,
            max_entries,
            latest_event_sequence,
        );
        store.storage_dir = journal_path.parent().map(Path::to_path_buf);
        store.journal_tx = start_transaction_journal_writer(journal_path);
        store.journal_start_failed = store.journal_tx.is_none();
        store
    }

    pub async fn insert(&self, record: TransactionRecord) -> TransactionInsertOutcome {
        let _insert_guard = self.insert_lock.lock().await;
        self.insert_locked(record).await
    }

    /// Registers protection and inserts under the same mutation lock. If this
    /// future is cancelled, its unreturned lease is released synchronously.
    pub async fn insert_in_progress(
        &self,
        record: TransactionRecord,
    ) -> (TransactionInsertOutcome, InProgressTransactionGuard) {
        let _insert_guard = self.insert_lock.lock().await;
        let guard = self.in_progress.register(record.id);
        (self.insert_locked(record).await, guard)
    }

    async fn insert_locked(&self, mut record: TransactionRecord) -> TransactionInsertOutcome {
        record.sequence = self.next_sequence.fetch_add(1, Ordering::Relaxed);
        let journal_fallback_required = match &self.journal_tx {
            Some(tx) => match encode_transaction_insert_journal_line(&record) {
                Some(line) => {
                    if let Err(error) = append_transaction_journal(tx, line).await {
                        warn!(
                            ?error,
                            "failed to append transaction insert journal entry before storing; record will rely on full snapshot persistence"
                        );
                        true
                    } else {
                        false
                    }
                }
                None => {
                    warn!(
                        "failed to encode transaction insert journal entry before storing; record will rely on full snapshot persistence"
                    );
                    true
                }
            },
            None => true,
        };
        let summary = record.summary();
        let mut inner = self.inner.write().await;
        if let Some(&index) = inner.by_id.get(&record.id) {
            inner.service_map_metadata_epoch = Uuid::new_v4();
            // Duplicate IDs remain separate ordering rows. Before moving the
            // authoritative ID to the new row, keep the old row self-contained.
            if inner.locators.contains_key(&record.id) {
                match rehydrate_checked(&inner.entries[index], &inner, self.storage_dir.as_deref())
                {
                    Ok(full) => inner.entries[index] = full,
                    Err(error) => {
                        let generation = inner.body_generations[index];
                        inner.unresolved_body_generations.insert(generation);
                        warn!(?error, record_id = %record.id, "could not preserve older duplicate transaction body; snapshot persistence is blocked")
                    }
                }
            }
        }
        inner.push(record, summary.clone());
        let mut retention_trimmed = false;
        if let Some(max_entries) = self.max_entries {
            retention_trimmed = inner.trim_to_max_entries(max_entries);
        }
        drop(inner);
        self.publish_transaction_event(summary);
        if retention_trimmed {
            let _ = self.retention_events.send(TransactionRetentionEvent::Gap);
        }
        self.in_progress.notify.notify_one();
        TransactionInsertOutcome {
            journal_fallback_required,
        }
    }

    pub async fn len(&self) -> usize {
        self.inner.read().await.entries.len()
    }

    /// Commit a tombstone before touching memory. A missing id invalidates the
    /// whole selection, including ids that belong to another session or a stale
    /// preview. Keeping the journal mandatory avoids lossy snapshot rollback.
    pub async fn delete_ids(&self, ids: &[Uuid]) -> io::Result<usize> {
        let _mutation_guard = self.insert_lock.lock().await;
        self.delete_ids_locked(ids).await
    }

    /// Resolve and check the reviewed selection while capture/update mutations
    /// are excluded, so a changing response cannot invalidate it between the
    /// token check and the durable deletion.
    pub async fn delete_selection(
        &self,
        selection: &crate::history_selection::HistorySelection,
    ) -> io::Result<(usize, Vec<Uuid>)> {
        let _mutation_guard = self.insert_lock.lock().await;
        selection
            .validate(true)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let rows = selection
            .resolve(self)
            .await
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        if selection.selection_token.as_ref().is_some_and(|token| {
            *token != crate::history_selection::selection_token(selection.session_id, &rows)
        }) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "selection changed since preview; nothing deleted",
            ));
        }
        let ids: Vec<_> = rows.iter().map(|row| row.id).collect();
        if ids.is_empty() {
            return Ok((0, ids));
        }
        Ok((self.delete_ids_locked(&ids).await?, ids))
    }

    pub async fn delete_all(&self) -> io::Result<usize> {
        let _mutation_guard = self.insert_lock.lock().await;
        let ids: Vec<_> = self
            .inner
            .read()
            .await
            .entries
            .iter()
            .map(|record| record.id)
            .collect();
        if ids.is_empty() {
            return Ok(0);
        }
        self.delete_ids_locked(&ids).await
    }

    async fn delete_ids_locked(&self, ids: &[Uuid]) -> io::Result<usize> {
        self.delete_ids_locked_with_event(ids, false).await
    }

    async fn delete_ids_locked_with_event(
        &self,
        ids: &[Uuid],
        automatic_retention: bool,
    ) -> io::Result<usize> {
        if ids.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "at least one transaction id is required",
            ));
        }
        let mut selected = HashSet::with_capacity(ids.len());
        let ids: Vec<_> = ids
            .iter()
            .copied()
            .filter(|id| selected.insert(*id))
            .collect();
        {
            let inner = self.inner.read().await;
            if ids.iter().any(|id| !inner.by_id.contains_key(id)) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "one or more transaction ids are not in this session",
                ));
            }
        }
        let tx = self.journal_tx.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "transaction journal writer is not available",
            )
        })?;
        let line =
            encode_transaction_journal_line(&TransactionJournalEntry::Delete { ids: ids.clone() })
                .ok_or_else(|| {
                    io::Error::other("failed to encode transaction deletion journal entry")
                })?;
        // InvalidInput is reserved for selection checks before an append. Even
        // that OS error can follow a written tombstone (for example at fsync),
        // so callers must treat every append/ack failure as uncertain persistence.
        append_transaction_journal(tx, line)
            .await
            .map_err(io::Error::other)?;

        let mut inner = self.inner.write().await;
        let mut removed_generations = Vec::new();
        let retained_generations = inner
            .entries
            .iter()
            .zip(&inner.body_generations)
            .filter_map(|(record, generation)| {
                if selected.contains(&record.id) {
                    removed_generations.push(*generation);
                    None
                } else {
                    Some(*generation)
                }
            })
            .collect();
        for generation in removed_generations {
            inner.unresolved_body_generations.remove(&generation);
        }
        inner
            .entries
            .retain(|record| !selected.contains(&record.id));
        inner.body_generations = retained_generations;
        inner
            .summaries
            .retain(|cached| !selected.contains(&cached.summary.id));
        inner.locators.retain(|id, _| !selected.contains(id));
        inner.by_id = inner
            .entries
            .iter()
            .enumerate()
            .map(|(index, record)| (record.id, index))
            .collect();
        inner.service_map_metadata_epoch = Uuid::new_v4();
        inner.service_map_structure_epoch = Uuid::new_v4();
        drop(inner);
        let event_sequence = self.next_event_sequence.fetch_add(1, Ordering::Relaxed);
        let event = if automatic_retention {
            self.retention_trim_sequence
                .fetch_max(event_sequence, Ordering::Release);
            TransactionRetentionEvent::Deleted {
                ids,
                generation: self.saved_cursor_generation,
                event_sequence,
            }
        } else {
            TransactionRetentionEvent::Gap
        };
        let _ = self.retention_events.send(event);
        Ok(selected.len())
    }

    pub async fn is_empty(&self) -> bool {
        self.inner.read().await.entries.is_empty()
    }

    pub async fn list(&self, filters: &ListFilters) -> Vec<TransactionSummary> {
        self.list_page(filters).await.items
    }

    pub async fn list_page(&self, filters: &ListFilters) -> TransactionListPage {
        let query = filters
            .query
            .as_ref()
            .map(|value| value.to_ascii_lowercase());
        let method = filters
            .method
            .as_ref()
            .map(|value| value.to_ascii_uppercase());
        let host = filters
            .host
            .as_ref()
            .map(|value| value.to_ascii_lowercase());
        let since_dt = filters.since.as_deref().and_then(parse_history_since);
        let status_pred = filters
            .status
            .map(StatusPredicate::Exact)
            .or_else(|| filters.status_range.as_deref().and_then(parse_status_range));
        let mime = filters
            .mime
            .as_ref()
            .map(|value| value.to_ascii_lowercase());
        let limit = filters.limit.unwrap_or(5000);
        let offset = filters.offset.unwrap_or(0);
        let before_sequence = if can_stream_descending_index_order(filters) {
            filters.before_sequence
        } else {
            None
        };
        let advanced_matcher = AdvancedSearchMatcher::new(filters);

        let inner = self.inner.read().await;
        let summaries = &inner.summaries;
        let total = summaries.len();

        if can_stream_index_order(filters) {
            let descending = !matches!(filters.sort_direction.as_deref(), Some("asc"));
            let scan_end = if descending {
                newest_scan_end(summaries, before_sequence)
            } else {
                summaries.len()
            };
            let mut matched_count = 0usize;
            let mut hidden_connect_count = 0usize;
            let mut exhausted = true;
            let mut items = if limit == 0 {
                Vec::new()
            } else {
                Vec::with_capacity(limit.min(total.saturating_sub(offset)))
            };
            let stop_after = if limit == 0 {
                None
            } else {
                Some(offset.saturating_add(limit).saturating_add(1))
            };

            let iter: Box<dyn Iterator<Item = &CachedSummary> + '_> = if descending {
                Box::new(summaries[..scan_end].iter().rev())
            } else {
                Box::new(summaries.iter())
            };
            for cached in iter {
                if filters.hide_connect
                    && cached.summary.method == "CONNECT"
                    && matches_filters(
                        cached,
                        query.as_deref(),
                        method.as_deref(),
                        host.as_deref(),
                        status_pred.as_ref(),
                        since_dt.as_ref(),
                        mime.as_deref(),
                        None,
                        filters,
                        advanced_matcher.as_ref(),
                        false,
                    )
                {
                    hidden_connect_count += 1;
                }
                if !matches_filters(
                    cached,
                    query.as_deref(),
                    method.as_deref(),
                    host.as_deref(),
                    status_pred.as_ref(),
                    since_dt.as_ref(),
                    mime.as_deref(),
                    None,
                    filters,
                    advanced_matcher.as_ref(),
                    filters.hide_connect,
                ) {
                    continue;
                }

                let matched_index = matched_count;
                matched_count += 1;
                if matched_index >= offset && (limit == 0 || items.len() < limit) {
                    items.push(cached.list_summary(filters.search_headers));
                }
                if stop_after.is_some_and(|threshold| matched_count >= threshold) {
                    exhausted = false;
                    break;
                }
            }
            let has_more = limit != 0 && matched_count > offset.saturating_add(items.len());

            return TransactionListPage {
                has_more,
                items,
                total,
                filtered_total: (exhausted && before_sequence.is_none()).then_some(matched_count),
                hidden_connect_total: (filters.hide_connect
                    && exhausted
                    && before_sequence.is_none())
                .then_some(hidden_connect_count),
                offset,
                limit,
            };
        }

        let mut hidden_connect_count = 0usize;
        let mut filtered = Vec::new();
        for cached in summaries.iter().rev() {
            if filters.hide_connect
                && before_sequence.is_none()
                && cached.summary.method == "CONNECT"
                && matches_filters(
                    cached,
                    query.as_deref(),
                    method.as_deref(),
                    host.as_deref(),
                    status_pred.as_ref(),
                    since_dt.as_ref(),
                    mime.as_deref(),
                    before_sequence,
                    filters,
                    advanced_matcher.as_ref(),
                    false,
                )
            {
                hidden_connect_count += 1;
            }
            if matches_filters(
                cached,
                query.as_deref(),
                method.as_deref(),
                host.as_deref(),
                status_pred.as_ref(),
                since_dt.as_ref(),
                mime.as_deref(),
                before_sequence,
                filters,
                advanced_matcher.as_ref(),
                filters.hide_connect,
            ) {
                filtered.push(cached);
            }
        }
        let filtered_total = filtered.len();

        sort_filtered_records(&mut filtered, filters);

        let items: Vec<TransactionSummary> = if limit == 0 {
            // limit=0 means unlimited
            filtered
                .into_iter()
                .skip(offset)
                .map(|cached| cached.list_summary(filters.search_headers))
                .collect()
        } else {
            filtered
                .into_iter()
                .skip(offset)
                .take(limit)
                .map(|cached| cached.list_summary(filters.search_headers))
                .collect()
        };

        TransactionListPage {
            has_more: limit != 0 && offset.saturating_add(items.len()) < filtered_total,
            items,
            total,
            filtered_total: before_sequence.is_none().then_some(filtered_total),
            hidden_connect_total: (filters.hide_connect && before_sequence.is_none())
                .then_some(hidden_connect_count),
            offset,
            limit,
        }
    }

    /// Capture row-exact metadata while one read lock fixes membership, order and
    /// revisions. Never clone a full transaction or rehydrate a body here.
    #[cfg(test)]
    pub(crate) async fn service_map_snapshot(
        &self,
        session_id: Uuid,
        max_records: usize,
    ) -> crate::service_map::MetadataSnapshot {
        self.service_map_snapshot_for_catalog(
            session_id,
            max_records,
            crate::service_map_technology::CatalogVersion::V1,
        )
        .await
    }

    #[cfg(test)]
    pub(crate) async fn service_map_snapshot_for_catalog(
        &self,
        session_id: Uuid,
        max_records: usize,
        catalog: crate::service_map_technology::CatalogVersion,
    ) -> crate::service_map::MetadataSnapshot {
        let inner = self.inner.read().await;
        self.service_map_snapshot_locked(
            &inner,
            session_id,
            max_records,
            catalog,
            &ListFilters::default(),
        )
    }

    /// Call only in a blocking worker. The fence and projection share one read
    /// lock, which is released before aggregation or response serialization.
    pub(crate) fn service_map_snapshot_blocking_for_catalog(
        &self,
        session_id: Uuid,
        max_records: usize,
        catalog: crate::service_map_technology::CatalogVersion,
        filters: &ListFilters,
    ) -> (
        crate::service_map::MetadataSnapshot,
        ServiceMapMetadataEpoch,
    ) {
        let inner = self.inner.blocking_read();
        let epoch = ServiceMapMetadataEpoch(inner.service_map_metadata_epoch);
        let mut snapshot =
            self.service_map_snapshot_locked(&inner, session_id, max_records, catalog, filters);
        let pending = self.cached_library_versions(&inner, &mut snapshot);
        drop(inner);
        self.read_library_versions(&mut snapshot, pending);
        (snapshot, epoch)
    }

    /// Fills in the libraries each script and page row declares: from the cache
    /// when read before, otherwise copied or located within this map's budget,
    /// to read after the lock is released. Later maps read the rest.
    fn cached_library_versions(
        &self,
        inner: &StoreInner,
        snapshot: &mut crate::service_map::MetadataSnapshot,
    ) -> Vec<(usize, PendingLibrary)> {
        let mut caches = self.library_caches();
        caches.trim();
        let mut budget = LibraryBudget::default();
        let mut pending = Vec::new();
        for (row_index, row) in snapshot.rows.iter_mut().enumerate() {
            match library_lookup(inner, &mut caches, row, &mut budget) {
                Some(Ok(found)) => merge_libraries(&mut row.libraries, found),
                Some(Err(item)) => pending.push((row_index, item)),
                None => {}
            }
        }
        pending
    }

    fn read_library_versions(
        &self,
        snapshot: &mut crate::service_map::MetadataSnapshot,
        pending: Vec<(usize, PendingLibrary)>,
    ) {
        if pending.is_empty() {
            return;
        }
        let mut file = self.transactions_file();
        for (row_index, item) in pending {
            if let Some(found) = self.read_library(&mut file, item) {
                merge_libraries(&mut snapshot.rows[row_index].libraries, found);
            }
        }
    }

    /// Scans a copied or retained body without the store lock. A retained row
    /// must still own its locator in this file, as for a body inspection.
    fn read_library(
        &self,
        file: &mut Option<fs::File>,
        item: PendingLibrary,
    ) -> Option<Vec<crate::service_map_libraries::Detection>> {
        use crate::service_map_libraries::{detect, drop_library_source_map, read_body, scan_text};
        use rsa::sha2::{Digest, Sha256};
        let body = match item.source {
            LibrarySource::Resident(body, encoding) => scan_text(body, encoding)?,
            LibrarySource::Retained(locator, file_generation) => {
                let file = file.as_mut()?;
                validate_service_map_body_locator(
                    &self.inner.blocking_read(),
                    &item.key,
                    file_generation,
                    locator,
                )
                .ok()?;
                read_body(file, locator, item.key.record_id)?
            }
        };
        // Hash only the budgeted scan text, after validating and reading this
        // row's own body. Repeated content skips detection, never verification.
        let body_key = (item.kind, Sha256::digest(body.as_bytes()).into());
        let cached = self.library_caches().bodies.get(&body_key).cloned();
        let mut found = cached.unwrap_or_else(|| {
            let found = detect(&body, item.kind);
            self.library_caches().bodies.insert(body_key, found.clone());
            found
        });
        // This suppression depends on the file name, not just its contents.
        drop_library_source_map(&mut found, &item.url);
        self.library_caches()
            .rows
            .insert((item.key.record_id, item.key.revision), found.clone());
        Some(found)
    }

    fn library_caches(&self) -> std::sync::MutexGuard<'_, LibraryCaches> {
        self.library_versions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn transactions_file(&self) -> Option<fs::File> {
        self.storage_dir
            .as_ref()
            .and_then(|dir| fs::File::open(dir.join("transactions.ndjson")).ok())
    }

    /// Discover admissible page origins before charging for bodies. Scripts
    /// usually follow their page in capture order, so a newest-first fold has
    /// not seen that page yet. Matching the canonical Referer against scope
    /// would also lose the captured host spelling used for IDNs and IPv6.
    fn service_map_scoped_origins(
        &self,
        (mut structure, mut next): (Uuid, usize),
        scope: &mut crate::service_map::BoundedScope,
        origin_filter: Option<&String>,
        filters: &ListFilters,
        advanced_matcher: Option<&AdvancedSearchMatcher>,
    ) -> Result<HashSet<String>, ServiceMapStreamError> {
        use crate::service_map::{request_target, MAX_ORIGINS};
        let mut origins = HashSet::new();
        let mut read = Vec::new();
        while next > 0 {
            let inner = self.inner.blocking_read();
            if inner.service_map_structure_epoch != structure {
                next = resume_below(&inner, &read).ok_or(ServiceMapStreamError::HistoryChanged)?;
                structure = inner.service_map_structure_epoch;
            }
            let from = next.saturating_sub(SERVICE_MAP_CHUNK);
            for index in (from..next).rev() {
                let record = &inner.entries[index];
                if record.method == "CONNECT"
                    || !matches_filters(
                        &inner.summaries[index],
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        filters,
                        advanced_matcher,
                        false,
                    )
                {
                    continue;
                }
                // These are the same admission checks as row projection and
                // MapBuilder, without headers, body copies or derived clues.
                let Some((target, _)) = request_target(record) else {
                    continue;
                };
                if !scope
                    .contains(&record.host)
                    .map_err(|_| ServiceMapStreamError::ScopeWorkLimit)?
                {
                    continue;
                }
                let origin = target.origin().ascii_serialization();
                if origin_filter.is_some_and(|only| only != &origin) {
                    continue;
                }
                origins.insert(origin);
                if origins.len() == MAX_ORIGINS {
                    return Ok(origins);
                }
            }
            read.clear();
            read.extend(
                (from..next).map(|index| (inner.entries[index].id, inner.body_generations[index])),
            );
            next = from;
        }
        Ok(origins)
    }

    /// The map over every retained row, newest first. Rows are folded as they
    /// are projected, so none are kept, and the store lock is held a chunk at a
    /// time, so captures continue while a large session is read. Appends and
    /// updates during the read wait for the next map. Retention at its limit
    /// removes a row with every capture, which moves the rows not yet read, so
    /// the read continues below the oldest row it read that is still retained;
    /// only losing all of its last chunk ends it as HistoryChanged. The flag says
    /// whether every script and page body was read, or some wait for a later map.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn service_map_all_rows_blocking(
        &self,
        session_id: Uuid,
        catalog: crate::service_map_technology::CatalogVersion,
        filters: &ListFilters,
        in_scope_only: bool,
        origin_filter: Option<String>,
        include: &[String],
        exclude: &[String],
    ) -> Result<(crate::service_map::ServiceMap, bool), ServiceMapStreamError> {
        use crate::service_map::{
            evidence_id, library_page, project_record, project_record_for_catalog, BoundedScope,
            MapBuilder, MetadataSnapshot,
        };
        let mut scope = BoundedScope::new(include, exclude)
            .map_err(|_| ServiceMapStreamError::ScopeWorkLimit)?;
        let advanced_matcher = AdvancedSearchMatcher::new(filters);
        // A one-origin map reads only that origin's bodies: the builder leaves
        // every other row out, so reading theirs would spend the read budget on
        // nothing, and a large session could leave the origin's own pages unread.
        let only = origin_filter.clone();
        let mut builder = MapBuilder::new(in_scope_only, origin_filter);
        let (mut structure, retained, first, last) = {
            let inner = self.inner.blocking_read();
            (
                inner.service_map_structure_epoch,
                inner.entries.len(),
                inner.entries.first().map(|r| r.started_at),
                inner.entries.last().map(|r| r.started_at),
            )
        };
        let mut meta = MetadataSnapshot {
            generation: self.saved_cursor_generation,
            captured_at: chrono::Utc::now(),
            first_retained_started_at: first,
            last_retained_started_at: last,
            oldest_considered_at: None,
            latest_considered_at: None,
            retained_rows: retained,
            considered_rows: 0,
            non_http_rows: 0,
            filtered_rows: 0,
            omitted_rows: 0,
            stopped_by: Default::default(),
            rows: Vec::new(),
            favicons: Default::default(),
        };
        let scoped_origins = in_scope_only
            .then(|| {
                self.service_map_scoped_origins(
                    (structure, retained),
                    &mut scope,
                    only.as_ref(),
                    filters,
                    advanced_matcher.as_ref(),
                )
            })
            .transpose()?;
        let mut budget = LibraryBudget::default();
        let mut pending = Vec::new();
        let mut next = retained;
        // The last chunk's rows, oldest first, by ID and body generation.
        let mut read = Vec::new();
        while next > 0 {
            let inner = self.inner.blocking_read();
            if inner.service_map_structure_epoch != structure {
                next = resume_below(&inner, &read).ok_or(ServiceMapStreamError::HistoryChanged)?;
                structure = inner.service_map_structure_epoch;
            }
            let mut caches = self.library_caches();
            caches.trim();
            let from = next.saturating_sub(SERVICE_MAP_CHUNK);
            for index in (from..next).rev() {
                let record = &inner.entries[index];
                meta.considered_rows += 1;
                meta.oldest_considered_at = Some(
                    meta.oldest_considered_at
                        .map_or(record.started_at, |time| time.min(record.started_at)),
                );
                meta.latest_considered_at = Some(
                    meta.latest_considered_at
                        .map_or(record.started_at, |time| time.max(record.started_at)),
                );
                if record.method == "CONNECT" {
                    meta.non_http_rows += 1;
                    continue;
                }
                note_favicon(&mut meta.favicons, record, || {
                    evidence_id(
                        session_id,
                        self.saved_cursor_generation,
                        inner.body_generations[index],
                        record,
                    )
                });
                if !matches_filters(
                    &inner.summaries[index],
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    filters,
                    advanced_matcher.as_ref(),
                    false,
                ) {
                    meta.filtered_rows += 1;
                    continue;
                }
                let id = evidence_id(
                    session_id,
                    self.saved_cursor_generation,
                    inner.body_generations[index],
                    record,
                );
                let row = match catalog {
                    crate::service_map_technology::CatalogVersion::V1 => project_record(record, id),
                    crate::service_map_technology::CatalogVersion::V2 => {
                        project_record_for_catalog(record, id, catalog)
                    }
                };
                let Some(mut row) = row else {
                    meta.omitted_rows += 1;
                    meta.stopped_by
                        .insert("unsupported_or_oversized_metadata".into());
                    continue;
                };
                let in_scope = scope
                    .contains(&row.scope_host)
                    .map_err(|_| ServiceMapStreamError::ScopeWorkLimit)?;
                // Charge only for included origins or assets their pages took
                // from elsewhere. Excluded pages cannot use a read that would
                // then be discarded, starving older included pages forever.
                let page = library_page(&row);
                let wanted = builder.wants_page(page.as_ref())
                    && scoped_origins.as_ref().is_none_or(|origins| {
                        page.as_ref().is_some_and(|page| origins.contains(page))
                    });
                let included = (!in_scope_only || in_scope)
                    && only.as_ref().is_none_or(|origin| *origin == row.origin)
                    && scoped_origins
                        .as_ref()
                        .is_none_or(|origins| origins.contains(&row.origin));
                let lookup = if included || wanted {
                    library_lookup(&inner, &mut caches, &row, &mut budget)
                } else {
                    None
                };
                let waiting = match lookup {
                    Some(Ok(found)) => {
                        merge_libraries(&mut row.libraries, found);
                        None
                    }
                    Some(Err(item)) => Some((
                        item,
                        page,
                        row.origin.clone(),
                        row.evidence_id.clone(),
                        std::mem::take(&mut row.libraries),
                    )),
                    None => None,
                };
                if builder.add(row, in_scope) || wanted {
                    pending.extend(waiting);
                }
            }
            read.clear();
            read.extend(
                (from..next).map(|index| (inner.entries[index].id, inner.body_generations[index])),
            );
            next = from;
        }
        let mut file = self.transactions_file();
        for (item, page, origin, evidence, mut found) in pending {
            if let Some(more) = self.read_library(&mut file, item) {
                merge_libraries(&mut found, more);
            }
            builder.add_libraries(page, origin, found, evidence);
        }
        Ok((
            builder.finish(session_id, meta, retained.max(1)),
            !budget.exhausted,
        ))
    }

    /// A whole-history map from the last read with the same key, when history
    /// is unchanged since, or when that read is recent: a large session is
    /// rebuilt no more often than four times its build time, at least every
    /// 1.2 seconds' poll, unless the caller asks for a fresh map. Retention at
    /// its limit removes a row with every capture, so a recent map is served
    /// whatever changed, and shows rows removed since until the next.
    pub(crate) fn cached_service_map(&self, key: &str, fresh: bool) -> Option<bytes::Bytes> {
        let token = self.service_map_history_token();
        let cache = self
            .service_map_result
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let cached = cache.as_ref().filter(|cached| cached.key == key)?;
        let unchanged = cached.complete && cached.token == token;
        let recent = !fresh
            && cached.built.elapsed()
                < (cached.cost * 4).max(std::time::Duration::from_millis(1_200));
        (unchanged || recent).then(|| cached.bytes.clone())
    }

    pub(crate) fn store_service_map(
        &self,
        key: String,
        token: (Uuid, Uuid, usize),
        cost: std::time::Duration,
        complete: bool,
        bytes: bytes::Bytes,
    ) {
        *self
            .service_map_result
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(CachedServiceMap {
            key,
            token,
            built: std::time::Instant::now(),
            cost,
            complete,
            bytes,
        });
    }

    /// What a whole-history map was built from: an update or removal changes
    /// metadata epoch, an annotation edit its own epoch, and an append the row
    /// count. Evidence and bounded-map publication ignore annotation-only edits.
    pub(crate) fn service_map_history_token(&self) -> (Uuid, Uuid, usize) {
        let inner = self.inner.blocking_read();
        (
            inner.service_map_metadata_epoch,
            inner.service_map_annotation_epoch,
            inner.entries.len(),
        )
    }

    pub(crate) async fn service_map_metadata_epoch_matches(
        &self,
        epoch: ServiceMapMetadataEpoch,
    ) -> bool {
        self.inner.read().await.service_map_metadata_epoch == epoch.0
    }

    fn service_map_snapshot_locked(
        &self,
        inner: &StoreInner,
        session_id: Uuid,
        max_records: usize,
        catalog: crate::service_map_technology::CatalogVersion,
        filters: &ListFilters,
    ) -> crate::service_map::MetadataSnapshot {
        use crate::service_map::{
            evidence_id, project_record, project_record_for_catalog, MetadataSnapshot,
            MAX_METADATA_BYTES,
        };
        // The display filter is HTTP history's own row matcher, so the map hides
        // exactly the rows History would hide; scope stays with `in_scope_only`.
        let advanced_matcher = AdvancedSearchMatcher::new(filters);
        let mut snapshot = MetadataSnapshot {
            generation: self.saved_cursor_generation,
            captured_at: chrono::Utc::now(),
            first_retained_started_at: inner.entries.first().map(|r| r.started_at),
            last_retained_started_at: inner.entries.last().map(|r| r.started_at),
            oldest_considered_at: None,
            latest_considered_at: None,
            retained_rows: inner.entries.len(),
            considered_rows: 0,
            non_http_rows: 0,
            filtered_rows: 0,
            omitted_rows: 0,
            stopped_by: Default::default(),
            rows: Vec::new(),
            favicons: Default::default(),
        };
        let mut bytes = 0usize;
        for ((record, revision), cached) in inner
            .entries
            .iter()
            .zip(&inner.body_generations)
            .zip(&inner.summaries)
            .rev()
        {
            if snapshot.considered_rows >= max_records {
                snapshot.stopped_by.insert("max_records".into());
                break;
            }
            snapshot.considered_rows += 1;
            snapshot.oldest_considered_at = Some(
                snapshot
                    .oldest_considered_at
                    .map_or(record.started_at, |time| time.min(record.started_at)),
            );
            snapshot.latest_considered_at = Some(
                snapshot
                    .latest_considered_at
                    .map_or(record.started_at, |time| time.max(record.started_at)),
            );
            if record.method == "CONNECT" {
                snapshot.non_http_rows += 1;
                continue;
            }
            note_favicon(&mut snapshot.favicons, record, || {
                evidence_id(session_id, self.saved_cursor_generation, *revision, record)
            });
            if !matches_filters(
                cached,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                filters,
                advanced_matcher.as_ref(),
                false,
            ) {
                snapshot.filtered_rows += 1;
                continue;
            }
            let id = evidence_id(session_id, self.saved_cursor_generation, *revision, record);
            let row = match catalog {
                crate::service_map_technology::CatalogVersion::V1 => project_record(record, id),
                crate::service_map_technology::CatalogVersion::V2 => {
                    project_record_for_catalog(record, id, catalog)
                }
            };
            let Some(row) = row else {
                snapshot.omitted_rows += 1;
                snapshot
                    .stopped_by
                    .insert("unsupported_or_oversized_metadata".into());
                continue;
            };
            // Serialization measures only the safe projection, never bodies or
            // raw headers. Bound cumulative memory even for high-cardinality paths.
            bytes = bytes.saturating_add(
                serde_json::to_vec(&row).map_or(MAX_METADATA_BYTES + 1, |v| v.len()),
            );
            if bytes > MAX_METADATA_BYTES {
                snapshot.stopped_by.insert("metadata_bytes".into());
                snapshot.omitted_rows += 1;
                break;
            }
            snapshot.rows.push(row);
        }
        snapshot
    }

    pub(crate) async fn service_map_evidence(
        &self,
        session_id: Uuid,
        id: &str,
    ) -> crate::service_map::ServiceMapEvidence {
        self.service_map_evidence_with_socket_peer(session_id, id, false)
            .await
    }

    pub(crate) async fn service_map_evidence_with_socket_peer(
        &self,
        session_id: Uuid,
        id: &str,
        include_socket_peer: bool,
    ) -> crate::service_map::ServiceMapEvidence {
        self.service_map_evidence_for_catalog(
            session_id,
            id,
            include_socket_peer,
            crate::service_map_technology::CatalogVersion::V1,
        )
        .await
    }

    pub(crate) async fn service_map_evidence_for_catalog(
        &self,
        session_id: Uuid,
        id: &str,
        include_socket_peer: bool,
        catalog: crate::service_map_technology::CatalogVersion,
    ) -> crate::service_map::ServiceMapEvidence {
        use crate::service_map::{project_record_for_catalog, EvidenceKey, ServiceMapEvidence};
        let missing = |reason| ServiceMapEvidence::missing(session_id, id.into(), reason);
        let Some(key) = EvidenceKey::parse(id) else {
            return missing("invalid_evidence_id");
        };
        if key.session_id != session_id {
            return missing("session_mismatch");
        }
        if key.generation != self.saved_cursor_generation {
            return missing("stale_generation");
        }
        let inner = self.inner.read().await;
        // UUID lookup deliberately cannot resolve this: retained legacy rows may
        // share an ID and get(id) selects the latest one.
        let Ok(index) = inner
            .entries
            .binary_search_by_key(&key.sequence, |record| record.sequence)
        else {
            return missing("record_missing");
        };
        let record = &inner.entries[index];
        if record.id != key.record_id {
            return missing("record_missing");
        }
        if inner.body_generations[index] != key.revision {
            return missing("record_changed");
        }
        match project_record_for_catalog(record, id.into(), catalog) {
            Some(row) => {
                let mut evidence = ServiceMapEvidence::found(session_id, row);
                if include_socket_peer {
                    evidence.socket_peer =
                        Some(crate::service_map::ServiceMapSocketPeerEvidence::from_record(record));
                }
                evidence
            }
            None => missing("metadata_unavailable"),
        }
    }

    /// Explicit retained peer equality. There is no body/locator dependency,
    /// global peer index, traffic hydration, or ordinary-map projection here.
    pub async fn service_map_socket_peer_matches(
        &self,
        session_id: Uuid,
        id: &str,
        in_scope_only: bool,
        max_records: usize,
        include: &[String],
        exclude: &[String],
    ) -> crate::service_map_peer_matches::ServiceMapSocketPeerMatches {
        self.service_map_socket_peer_matches_impl(
            session_id,
            id,
            in_scope_only,
            max_records,
            include,
            exclude,
            #[cfg(test)]
            None,
        )
        .await
    }

    async fn service_map_socket_peer_matches_impl(
        &self,
        session_id: Uuid,
        id: &str,
        in_scope_only: bool,
        max_records: usize,
        include: &[String],
        exclude: &[String],
        #[cfg(test)] hook: Option<ServiceMapBodyReadHook>,
    ) -> crate::service_map_peer_matches::ServiceMapSocketPeerMatches {
        use crate::service_map_peer_matches::{
            canonical_evidence_key, inspect_retained, ServiceMapSocketPeerMatches,
        };
        let max_records = max_records.clamp(1, crate::service_map::MAX_RECORDS);
        let missing = |reason| {
            ServiceMapSocketPeerMatches::missing(
                session_id,
                id.into(),
                in_scope_only,
                max_records,
                reason,
            )
        };
        let Some(key) = canonical_evidence_key(id) else {
            return missing("invalid_evidence_id");
        };
        if key.session_id != session_id {
            return missing("session_mismatch");
        }
        if key.generation != self.saved_cursor_generation {
            return missing("stale_generation");
        }
        if !crate::scope::PreparedScope::within_limits(
            include,
            exclude,
            crate::service_map_peer_matches::MAX_SCOPE_PATTERN_ENTRIES,
            crate::service_map_peer_matches::MAX_SCOPE_PATTERN_BYTES,
        ) {
            return missing("scope_work_limit");
        }
        let generation = self.saved_cursor_generation;
        let inner = Arc::clone(&self.inner);
        let evidence_id = id.to_owned();
        let include = include.to_vec();
        let exclude = exclude.to_vec();
        // Bounded CPU work runs off the async executor. One read lock fixes row
        // membership and revisions. Nonmatching rows cause no string copies.
        let task = tokio::task::spawn_blocking(move || {
            // Scope lists are bounded by runtime settings. Normalize once off
            // lock; dense include/exclude lists must not allocate per row/pattern.
            let Some(prepared_scope) = crate::scope::PreparedScope::try_new(
                &include,
                &exclude,
                crate::service_map_peer_matches::MAX_SCOPE_PATTERN_ENTRIES,
                crate::service_map_peer_matches::MAX_SCOPE_PATTERN_BYTES,
            ) else {
                return ServiceMapSocketPeerMatches::missing(
                    session_id,
                    evidence_id,
                    in_scope_only,
                    max_records,
                    "scope_work_limit",
                );
            };
            drop(include);
            drop(exclude);
            let result = {
                let locked = inner.blocking_read();
                let source = match service_map_row_index(&locked, &key) {
                    Ok(index) => &locked.entries[index],
                    Err(reason) => {
                        return ServiceMapSocketPeerMatches::missing(
                            session_id,
                            evidence_id,
                            in_scope_only,
                            max_records,
                            reason,
                        )
                    }
                };
                inspect_retained(
                    session_id,
                    generation,
                    &evidence_id,
                    source,
                    locked
                        .entries
                        .iter()
                        .zip(locked.body_generations.iter().copied())
                        .rev(),
                    max_records,
                    in_scope_only,
                    &prepared_scope,
                )
            };
            #[cfg(test)]
            if let Some(hook) = &hook {
                hook("after_snapshot");
            }
            match service_map_row_index(&inner.blocking_read(), &key) {
                Ok(_) => result,
                Err(reason) => ServiceMapSocketPeerMatches::missing(
                    session_id,
                    evidence_id,
                    in_scope_only,
                    max_records,
                    reason,
                ),
            }
        });
        task.await
            .unwrap_or_else(|_| missing("peer_inspection_failed"))
    }

    /// Metadata-only exact-row inspection. Body storage is deliberately absent
    /// from both acquisition and publication checks, even for duplicate UUIDs.
    pub async fn service_map_link_declarations(
        &self,
        session_id: Uuid,
        id: &str,
    ) -> crate::service_map_links::ServiceMapLinkDeclarations {
        self.service_map_link_declarations_impl(
            session_id,
            id,
            #[cfg(test)]
            None,
        )
        .await
    }

    pub(crate) async fn service_map_link_source_status(
        &self,
        session_id: Uuid,
        id: &str,
    ) -> Result<(), &'static str> {
        let key = crate::service_map::EvidenceKey::parse(id).ok_or("invalid_evidence_id")?;
        if key.session_id != session_id {
            return Err("session_mismatch");
        }
        if key.generation != self.saved_cursor_generation {
            return Err("stale_generation");
        }
        let inner = self.inner.read().await;
        service_map_row_index(&inner, &key).map(|_| ())
    }

    async fn service_map_link_declarations_impl(
        &self,
        session_id: Uuid,
        id: &str,
        #[cfg(test)] hook: Option<ServiceMapBodyReadHook>,
    ) -> crate::service_map_links::ServiceMapLinkDeclarations {
        use crate::{
            service_map::EvidenceKey,
            service_map_links::{self, LinkSource, ServiceMapLinkDeclarations},
        };
        let missing = |reason| ServiceMapLinkDeclarations::missing(session_id, id.into(), reason);
        let Some(key) = EvidenceKey::parse(id) else {
            return missing("invalid_evidence_id");
        };
        if key.session_id != session_id {
            return missing("session_mismatch");
        }
        if key.generation != self.saved_cursor_generation {
            return missing("stale_generation");
        }
        let source = {
            let inner = self.inner.read().await;
            let index = match service_map_row_index(&inner, &key) {
                Ok(index) => index,
                Err(reason) => return missing(reason),
            };
            match LinkSource::from_record(&inner.entries[index]) {
                Ok(source) => source,
                Err("unsupported_source_context") => {
                    return ServiceMapLinkDeclarations::unsupported(session_id, id.into())
                }
                Err(reason) => return missing(reason),
            }
        };
        let inner = Arc::clone(&self.inner);
        let evidence_id = id.to_owned();
        let task = tokio::task::spawn_blocking(move || {
            #[cfg(test)]
            if let Some(hook) = &hook {
                hook("before_scan");
            }
            let result = service_map_links::inspect_source(session_id, evidence_id.clone(), source);
            #[cfg(test)]
            if let Some(hook) = &hook {
                hook("after_scan");
            }
            // Revisions change for full record mutations; annotation-only edits
            // remain valid. No body locator ambiguity can invalidate headers.
            match service_map_row_index(&inner.blocking_read(), &key) {
                Ok(_) => result,
                Err(reason) => ServiceMapLinkDeclarations::missing(session_id, evidence_id, reason),
            }
        });
        task.await
            .unwrap_or_else(|_| missing("link_inspection_failed"))
    }

    /// Opt-in, exact-token reads of a retained response preview. No generic
    /// transaction lookup, body decoding, or full record hydration is allowed.
    pub async fn service_map_body_references(
        &self,
        session_id: Uuid,
        id: &str,
    ) -> crate::service_map_body::ServiceMapBodyReferences {
        self.service_map_body_references_impl(
            session_id,
            id,
            #[cfg(test)]
            None,
        )
        .await
    }

    async fn service_map_body_references_impl(
        &self,
        session_id: Uuid,
        id: &str,
        #[cfg(test)] hook: Option<ServiceMapBodyReadHook>,
    ) -> crate::service_map_body::ServiceMapBodyReferences {
        use crate::service_map_body::{self, BodySource, ServiceMapBodyReferences};
        self.service_map_retained_preview(
            session_id,
            id,
            BodySource::from_record,
            service_map_body::scan_preview,
            ServiceMapBodyReferences::missing,
            ServiceMapBodyReferences::unsupported,
            #[cfg(test)]
            hook,
        )
        .await
    }

    /// The icon a map named by evidence: the row's whole retained body, when it
    /// is still that icon row and its bytes are a raster image.
    pub async fn service_map_favicon(
        &self,
        session_id: Uuid,
        id: &str,
    ) -> Option<(&'static str, Vec<u8>)> {
        let key = crate::service_map::EvidenceKey::parse(id)?;
        if key.session_id != session_id || key.generation != self.saved_cursor_generation {
            return None;
        }
        let record = {
            let inner = self.inner.read().await;
            let index = service_map_body_row_index(&inner, &key).ok()?;
            let record = &inner.entries[index];
            crate::service_map::favicon_origin(record)?;
            self.rehydrate(record, &inner)
        };
        let bytes = record.response?.body_bytes();
        crate::service_map::favicon_type(&bytes).map(|kind| (kind, bytes))
    }

    /// A separate opt-in operation; default metadata and body-reference reads
    /// never invoke the HTML parser or enrich their existing output.
    pub async fn service_map_html_generators(
        &self,
        session_id: Uuid,
        id: &str,
    ) -> crate::service_map_html::ServiceMapHtmlGenerators {
        self.service_map_html_generators_impl(
            session_id,
            id,
            #[cfg(test)]
            None,
        )
        .await
    }

    async fn service_map_html_generators_impl(
        &self,
        session_id: Uuid,
        id: &str,
        #[cfg(test)] hook: Option<ServiceMapBodyReadHook>,
    ) -> crate::service_map_html::ServiceMapHtmlGenerators {
        use crate::{
            service_map_body::BodySource,
            service_map_html::{self, ServiceMapHtmlGenerators},
        };
        self.service_map_retained_preview(
            session_id,
            id,
            BodySource::from_html_record,
            service_map_html::scan_preview,
            ServiceMapHtmlGenerators::missing,
            ServiceMapHtmlGenerators::unsupported,
            #[cfg(test)]
            hook,
        )
        .await
    }

    /// Read only the selected exact row's packet pair. The permit belongs to
    /// actual blocking work, not its cancellable async caller.
    pub(crate) async fn service_map_packet_source_status(
        &self,
        session_id: Uuid,
        id: &str,
        read: &ServiceMapPacketRead,
    ) -> Result<(), &'static str> {
        let key = crate::service_map::EvidenceKey::parse(id).ok_or("invalid_evidence_id")?;
        if key.session_id != session_id {
            return Err("session_mismatch");
        }
        if key.generation != self.saved_cursor_generation {
            return Err("stale_generation");
        }
        let current = self.inner.read().await;
        service_map_row_index(&current, &key)?;
        if let Some(fence) = &read.fence {
            if current.unresolved_body_generations.contains(&key.revision) != fence.unresolved {
                return Err("body_identity_unverifiable");
            }
            if let Some((locator, generation)) = fence.located {
                validate_service_map_body_locator(&current, &key, generation, locator)?;
            }
        }
        Ok(())
    }

    pub(crate) async fn service_map_packet(
        &self,
        session_id: Uuid,
        id: &str,
        variant: crate::service_map_packet::PacketVariant,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> ServiceMapPacketRead {
        self.service_map_packet_inner(
            session_id,
            id,
            variant,
            permit,
            #[cfg(test)]
            None,
        )
        .await
    }

    async fn service_map_packet_inner(
        &self,
        session_id: Uuid,
        id: &str,
        variant: crate::service_map_packet::PacketVariant,
        permit: tokio::sync::OwnedSemaphorePermit,
        #[cfg(test)] hook: Option<ServiceMapBodyReadHook>,
    ) -> ServiceMapPacketRead {
        use crate::{
            service_map::EvidenceKey,
            service_map_packet::{encode_record, read_pair, unavailable, MAX_SERIALIZED_ROW_BYTES},
        };
        let missing = |reason| ServiceMapPacketRead {
            bytes: unavailable(session_id, id, variant, reason),
            fence: None,
        };
        let Some(key) = EvidenceKey::parse(id) else {
            return missing("invalid_evidence_id");
        };
        if key.session_id != session_id {
            return missing("session_mismatch");
        }
        if key.generation != self.saved_cursor_generation {
            return missing("stale_generation");
        }
        let inner = Arc::clone(&self.inner);
        let storage_dir = self.storage_dir.clone();
        let evidence_id = id.to_owned();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let missing = |reason| ServiceMapPacketRead {
                bytes: unavailable(session_id, &evidence_id, variant, reason),
                fence: None,
            };
            #[cfg(test)]
            if let Some(hook) = &hook {
                hook("started");
            }
            let (located, unresolved, resident) = {
                let current = inner.blocking_read();
                let index = match service_map_row_index(&current, &key) {
                    Ok(index) => index,
                    Err(reason) => return missing(reason),
                };
                let unresolved = current.unresolved_body_generations.contains(&key.revision);
                let located = if unresolved {
                    None
                } else {
                    (current.by_id.get(&key.record_id) == Some(&index))
                        .then(|| current.locators.get(&key.record_id).copied())
                        .flatten()
                        .map(|locator| (locator, current.file_generation))
                };
                if located
                    .is_some_and(|(locator, _)| locator.len as usize > MAX_SERIALIZED_ROW_BYTES)
                {
                    return missing("serialized_row_limit");
                }
                let resident = located.is_none().then(|| {
                    encode_record(
                        session_id,
                        &evidence_id,
                        variant,
                        &current.entries[index],
                        None,
                        unresolved.then_some("body_identity_unverifiable"),
                    )
                });
                (located, unresolved, resident)
            };
            let disk = if let Some((locator, generation)) = located {
                let file = storage_dir
                    .as_ref()
                    .ok_or("body_storage_unavailable")
                    .and_then(|dir| {
                        fs::File::open(dir.join("transactions.ndjson"))
                            .map_err(|_| "body_storage_unavailable")
                    });
                match file {
                    Ok(file) => {
                        #[cfg(test)]
                        if let Some(hook) = &hook {
                            hook("after_open");
                        }
                        if let Err(reason) = validate_service_map_body_locator(
                            &inner.blocking_read(),
                            &key,
                            generation,
                            locator,
                        ) {
                            return missing(reason);
                        }
                        Some(read_pair(file, locator, variant))
                    }
                    Err(reason) => Some(Err(reason)),
                }
            } else {
                None
            };
            #[cfg(test)]
            if let Some(hook) = &hook {
                hook("before_publish");
            }
            let current = inner.blocking_read();
            let index = match service_map_row_index(&current, &key) {
                Ok(index) => index,
                Err(reason) => return missing(reason),
            };
            if current.unresolved_body_generations.contains(&key.revision) != unresolved {
                return missing("body_identity_unverifiable");
            }
            if let Some((locator, generation)) = located {
                if let Err(reason) =
                    validate_service_map_body_locator(&current, &key, generation, locator)
                {
                    return missing(reason);
                }
            }
            let result = match disk {
                Some(Ok(pair)) => encode_record(
                    session_id,
                    &evidence_id,
                    variant,
                    &current.entries[index],
                    Some(&pair),
                    None,
                ),
                Some(Err(reason @ ("serialized_row_limit" | "body_identity_unverifiable"))) => {
                    Err(reason)
                }
                Some(Err(reason)) => encode_record(
                    session_id,
                    &evidence_id,
                    variant,
                    &current.entries[index],
                    None,
                    Some(reason),
                ),
                None => resident.expect("resident packet or disk locator"),
            };
            match result {
                Ok(bytes) => ServiceMapPacketRead {
                    bytes,
                    fence: Some(ServiceMapPacketFence {
                        located,
                        unresolved,
                    }),
                },
                Err(reason) => missing(reason),
            }
        })
        .await
        .unwrap_or_else(|_| missing("packet_read_failed"))
    }

    // Keep inspection inside the read fence. Returning an unfenced preview to
    // callers would permit evidence to escape after retention or file replacement.
    async fn service_map_retained_preview<R: Send + 'static>(
        &self,
        session_id: Uuid,
        id: &str,
        source_from_record: fn(
            &TransactionRecord,
        )
            -> Result<crate::service_map_body::BodySource, &'static str>,
        scan_preview: fn(
            Uuid,
            String,
            crate::service_map_body::BodySource,
            crate::service_map_body::RetainedPreview,
        ) -> R,
        missing_result: fn(Uuid, String, &str) -> R,
        unsupported_result: fn(Uuid, String, &str) -> R,
        #[cfg(test)] hook: Option<ServiceMapBodyReadHook>,
    ) -> R {
        use crate::{
            service_map::EvidenceKey,
            service_map_body::{read_preview, RetainedPreview, MAX_SERIALIZED_ROW_BYTES},
        };
        let missing = |reason| missing_result(session_id, id.into(), reason);
        let Some(key) = EvidenceKey::parse(id) else {
            return missing("invalid_evidence_id");
        };
        if key.session_id != session_id {
            return missing("session_mismatch");
        }
        if key.generation != self.saved_cursor_generation {
            return missing("stale_generation");
        }
        let (source, resident, located) = {
            let inner = self.inner.read().await;
            let index = match service_map_body_row_index(&inner, &key) {
                Ok(index) => index,
                Err(reason) => return missing(reason),
            };
            let record = &inner.entries[index];
            let source = match source_from_record(record) {
                Ok(source) => source,
                Err("response_unavailable") => return missing("response_unavailable"),
                Err(reason) => return unsupported_result(session_id, id.into(), reason),
            };
            let locator = (inner.by_id.get(&record.id) == Some(&index))
                .then(|| inner.locators.get(&record.id).copied())
                .flatten();
            match locator {
                Some(locator) => {
                    if locator.len as usize > MAX_SERIALIZED_ROW_BYTES {
                        return missing("serialized_row_limit");
                    }
                    (source, None, Some((locator, inner.file_generation)))
                }
                None => {
                    let preview = RetainedPreview::from_str(
                        &record
                            .response
                            .as_ref()
                            .expect("supported response")
                            .body_preview,
                    );
                    (source, Some(preview), None)
                }
            }
        };
        let inner = Arc::clone(&self.inner);
        let storage_dir = self.storage_dir.clone();
        let evidence_id = id.to_owned();
        let task = tokio::task::spawn_blocking(move || {
            let missing = |reason| missing_result(session_id, evidence_id.clone(), reason);
            let preview = if let Some((locator, file_generation)) = located {
                let Some(storage_dir) = storage_dir else {
                    return missing("body_storage_unavailable");
                };
                // Opening before the generation check gives us a stable inode.
                // Publication renames and adopts locators under the write lock:
                // either this handle and captured offsets agree, or we reject.
                let file = match fs::File::open(storage_dir.join("transactions.ndjson")) {
                    Ok(file) => file,
                    Err(_) => return missing("body_storage_unavailable"),
                };
                #[cfg(test)]
                if let Some(hook) = &hook {
                    hook("after_open");
                }
                if let Err(reason) = validate_service_map_body_locator(
                    &inner.blocking_read(),
                    &key,
                    file_generation,
                    locator,
                ) {
                    return missing(reason);
                }
                // All file I/O and JSON parsing happen without a store lock.
                read_preview(file, locator, key.record_id, &source)
            } else {
                Ok(resident.expect("resident preview or locator"))
            };
            #[cfg(test)]
            if let Some(hook) = &hook {
                hook("before_scan");
            }
            let result = match preview {
                Ok(preview) => scan_preview(session_id, evidence_id.clone(), source, preview),
                Err(reason) => missing(reason),
            };
            #[cfg(test)]
            if let Some(hook) = &hook {
                hook("after_scan");
            }
            // Never publish evidence after deletion, retention, full mutation,
            // duplicate displacement, or a transactions-file replacement.
            let current = inner.blocking_read();
            let validity = match located {
                Some((locator, file_generation)) => {
                    validate_service_map_body_locator(&current, &key, file_generation, locator)
                }
                None => service_map_body_row_index(&current, &key).map(|_| ()),
            };
            match validity {
                Ok(()) => result,
                Err(reason) => missing(reason),
            }
        });
        task.await.unwrap_or_else(|_| missing("body_scan_failed"))
    }

    /// The parameters one endpoint was called with, from its newest retained
    /// rows. Queries come from row metadata; bodies are read here, on request,
    /// never to build the map.
    pub async fn service_map_parameters(
        &self,
        session_id: Uuid,
        origin: &str,
        method: &str,
        path: &str,
    ) -> crate::service_map_parameters::EndpointParameters {
        use crate::service_map_parameters::{
            EndpointParameters, ParameterTally, MAX_ROWS, MAX_TOTAL_BODY_BYTES,
        };
        let mut result =
            EndpointParameters::new(session_id, origin.into(), method.into(), path.into());
        let mut rows = Vec::new();
        let file_generation = {
            let inner = self.inner.read().await;
            for (index, record) in inner.entries.iter().enumerate().rev() {
                let (record_path, query) = path_and_query(&record.path);
                if record.method != method
                    || record_path != path
                    || crate::service_map::canonical_origin(&format!(
                        "{}://{}",
                        record.scheme, record.host
                    ))
                    .as_deref()
                        != Some(origin)
                {
                    continue;
                }
                if rows.len() == MAX_ROWS {
                    result.more_rows = true;
                    break;
                }
                rows.push(parameter_row(
                    &inner,
                    index,
                    session_id,
                    self.saved_cursor_generation,
                    query,
                ));
            }
            inner.file_generation
        };
        let inner = Arc::clone(&self.inner);
        let storage_dir = self.storage_dir.clone();
        let task = tokio::task::spawn_blocking(move || {
            // All file I/O and parsing happen without a store lock; each row
            // must still own its locator in this file, as for a body inspection.
            let mut file =
                storage_dir.and_then(|dir| fs::File::open(dir.join("transactions.ndjson")).ok());
            let mut tally = ParameterTally::default();
            let (mut read, mut budget, mut unread) = (0, MAX_TOTAL_BODY_BYTES, 0);
            for mut row in rows {
                let body = parameter_body(
                    &inner,
                    file.as_mut(),
                    file_generation,
                    &mut budget,
                    &mut row,
                );
                unread += usize::from(body.is_none());
                tally.add_row(
                    row.query.as_deref(),
                    row.content_type.as_deref(),
                    body.as_deref().unwrap_or(""),
                );
                read += 1;
            }
            (tally.finish(), read, unread)
        });
        match task.await {
            Ok(((parameters, omitted), read, unread)) => {
                result.parameters = parameters;
                result.omitted_parameters = omitted;
                result.rows = read;
                result.unread_bodies = unread;
            }
            Err(_) => {
                result.available = false;
                result.reasons = vec!["parameter_read_failed".into()];
            }
        }
        result
    }

    /// One origin's API in OpenAPI (`service_map_openapi`), from every retained
    /// row of it. Parameters come from each operation's newest rows, within the
    /// same body budget as one endpoint's parameters.
    pub async fn service_map_openapi(
        &self,
        session_id: Uuid,
        origin: &str,
    ) -> Option<serde_json::Value> {
        use crate::service_map_openapi::{
            document, media_type, operation_path, static_path, Operation, MAX_OPERATIONS,
            MAX_ROWS_PER_OPERATION, METHODS,
        };
        use crate::service_map_parameters::{ParameterTally, MAX_TOTAL_BODY_BYTES};
        let inner = Arc::clone(&self.inner);
        let storage_dir = self.storage_dir.clone();
        let generation = self.saved_cursor_generation;
        let origin = origin.to_string();
        let task = tokio::task::spawn_blocking(move || {
            let mut found: std::collections::BTreeMap<(String, String), (Operation, Vec<_>)> =
                Default::default();
            let mut omitted = std::collections::BTreeSet::new();
            let mut static_requests = 0;
            let mut held = 0;
            // ponytail: one read-locked pass over the history; read it in
            // chunks as the map does if exporting a huge session stalls capture.
            let file_generation = {
                let inner = inner.blocking_read();
                let mut same_origin = HashMap::new();
                for (index, record) in inner.entries.iter().enumerate().rev() {
                    let method = record.method.to_ascii_lowercase();
                    let (path, query) = path_and_query(&record.path);
                    if !METHODS.contains(&method.as_str())
                        || !path.starts_with('/')
                        || !*same_origin
                            .entry((record.scheme.as_str(), record.host.as_str()))
                            .or_insert_with(|| {
                                crate::service_map::canonical_origin(&format!(
                                    "{}://{}",
                                    record.scheme, record.host
                                ))
                                .as_deref()
                                    == Some(origin.as_str())
                            })
                    {
                        continue;
                    }
                    // Never in the document, so never taking an API's place
                    // under the cap: 500 images used to leave it empty.
                    if static_path(path) {
                        static_requests += 1;
                        continue;
                    }
                    let key = (operation_path(path), method);
                    if found.len() == MAX_OPERATIONS && !found.contains_key(&key) {
                        omitted.insert(key);
                        continue;
                    }
                    let (operation, rows) = found.entry(key).or_default();
                    // Rows are read newest first.
                    operation.newest.get_or_insert((record.sequence, record.id));
                    operation.requests += 1;
                    if let Some(status) = record.status.filter(|status| (100..600).contains(status))
                    {
                        let types = operation.responses.entry(status).or_default();
                        types.extend(
                            record
                                .response
                                .as_ref()
                                .and_then(|response| response.content_type.as_deref())
                                .and_then(media_type),
                        );
                    }
                    if record.request.body_size > 0 {
                        let request_type = record.request.content_type.as_deref();
                        operation
                            .request_types
                            .extend(request_type.and_then(media_type));
                    }
                    operation
                        .auth
                        .extend(crate::service_map_auth::detect(record));
                    if rows.len() < MAX_ROWS_PER_OPERATION {
                        let mut row = parameter_row(&inner, index, session_id, generation, query);
                        // Unsaved bodies held for the read share its budget,
                        // so thousands of them cannot pile up in memory.
                        held += row.body.as_ref().map_or(0, String::len);
                        if held > MAX_TOTAL_BODY_BYTES {
                            row.body = None;
                        }
                        rows.push(row);
                    }
                }
                inner.file_generation
            };
            let mut file =
                storage_dir.and_then(|dir| fs::File::open(dir.join("transactions.ndjson")).ok());
            let mut budget = MAX_TOTAL_BODY_BYTES;
            let operations = found
                .into_iter()
                .map(|(key, (mut operation, rows))| {
                    let mut tally = ParameterTally::named_only();
                    for mut row in rows {
                        let body = parameter_body(
                            &inner,
                            file.as_mut(),
                            file_generation,
                            &mut budget,
                            &mut row,
                        );
                        tally.add_row(
                            row.query.as_deref(),
                            row.content_type.as_deref(),
                            body.as_deref().unwrap_or(""),
                        );
                    }
                    operation.json_types = tally.json_types();
                    let (parameters, omitted_parameters) = tally.finish();
                    operation.parameters = parameters;
                    operation.parameter_cap_truncated = omitted_parameters > 0;
                    (key, operation)
                })
                .collect();
            document(&origin, &operations, omitted.len(), static_requests)
        });
        task.await.ok()
    }

    /// What the records in memory say about the session, read in place.
    pub async fn traffic_overview(&self) -> crate::session::TrafficOverview {
        let inner = self.inner.read().await;
        crate::session::TrafficOverview::from_records(inner.entries.iter())
    }

    pub async fn site_map_records(&self) -> Vec<SiteMapRecord> {
        let inner = self.inner.read().await;
        inner
            .entries
            .iter()
            .filter(|record| record.method != "CONNECT" && !record.host.is_empty())
            .map(|record| SiteMapRecord {
                started_at: record.started_at,
                method: record.method.clone(),
                scheme: record.scheme.clone(),
                host: record.host.clone(),
                path: record.path.clone(),
                status: record.status,
                note_count: record.notes.len() + usize::from(record.user_note.is_some()),
                is_websocket: record.is_websocket(),
            })
            .collect()
    }

    pub async fn get(&self, id: Uuid) -> Option<TransactionRecord> {
        let inner = self.inner.read().await;
        let index = *inner.by_id.get(&id)?;
        let record = inner.entries.get(index)?;
        // This is the one caller that needs the body text, so it is where a record
        // whose bodies live on disk gets them back.
        Some(self.rehydrate(record, &inner))
    }

    /// Calls `visit` with every retained record and its bodies, oldest first.
    /// Reading every body back is file I/O far too long to hold a runtime worker
    /// that proxy tasks share, so it runs on a blocking thread. Also returns how
    /// many records were skipped because their bodies could not be read; None
    /// if the walk itself failed.
    pub async fn visit_records<T: Send + 'static>(
        &self,
        mut accumulator: T,
        visit: impl Fn(&mut T, &TransactionRecord) + Send + 'static,
    ) -> Option<(T, usize)> {
        let ids: Vec<Uuid> = {
            let inner = self.inner.read().await;
            inner.entries.iter().map(|record| record.id).collect()
        };
        let storage_dir = self.storage_dir.clone();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut unreadable = 0;
            for id in ids {
                // By ID, not position: a trim meanwhile shifts every later row.
                let record = {
                    let inner = inner.blocking_read();
                    let Some(&index) = inner.by_id.get(&id) else {
                        continue;
                    };
                    let generation = inner.body_generations[index];
                    if inner.unresolved_body_generations.contains(&generation) {
                        None
                    } else {
                        rehydrate_checked(&inner.entries[index], &inner, storage_dir.as_deref())
                            .ok()
                    }
                };
                match record {
                    Some(record) => visit(&mut accumulator, &record),
                    None => unreadable += 1,
                }
            }
            (accumulator, unreadable)
        })
        .await
        .ok()
    }

    pub async fn snapshot(&self, limit: Option<usize>) -> Vec<TransactionRecord> {
        let inner = self.inner.read().await;
        snapshot_entries(&inner, limit)
    }

    /// Search request/response bodies and headers for a literal value.
    ///
    /// Bodies are not held in memory and are not in the metadata haystack that
    /// `query` searches, so this is the only way to ask whether a value ever
    /// crossed the wire. Candidates are narrowed with the ordinary filters first,
    /// then their locators are read in file order — one forward pass rather than a
    /// seek per record. No index is built: a locator map is already maintained for
    /// every record, and an index would be a second copy to keep correct through
    /// rewrites, trims and session switches.
    pub async fn search_bodies(
        &self,
        filters: &ListFilters,
        request: &BodySearchRequest,
    ) -> BodySearchOutcome {
        let needle = if request.case_sensitive {
            request.value.clone()
        } else {
            request.value.to_ascii_lowercase()
        };
        let mut outcome = BodySearchOutcome {
            transactions: Vec::new(),
            match_count: 0,
            records_considered: 0,
            records_scanned: 0,
            bytes_scanned: 0,
            complete: true,
            stopped_by: None,
            unsearchable: 0,
        };
        if needle.is_empty() {
            return outcome;
        }

        // Keep the original row identity as well as ordering hints. An ID may
        // occur more than once, so resolving every candidate through by_id would
        // scan the newest duplicate repeatedly and omit older bodies.
        struct Candidate {
            id: Uuid,
            index: usize,
            body_generation: Uuid,
            sort_offset: u64,
        }
        let candidates: Vec<Candidate> = {
            let inner = self.inner.read().await;
            let query = filters
                .query
                .as_ref()
                .map(|value| value.to_ascii_lowercase());
            let method = filters
                .method
                .as_ref()
                .map(|value| value.to_ascii_uppercase());
            let host = filters
                .host
                .as_ref()
                .map(|value| value.to_ascii_lowercase());
            let since_dt = filters.since.as_deref().and_then(parse_since);
            let status_pred = filters
                .status
                .map(StatusPredicate::Exact)
                .or_else(|| filters.status_range.as_deref().and_then(parse_status_range));
            let mime = filters
                .mime
                .as_ref()
                .map(|value| value.to_ascii_lowercase());
            let advanced_matcher = AdvancedSearchMatcher::new(filters);
            inner
                .summaries
                .iter()
                .enumerate()
                .filter(|(_, cached)| {
                    matches_filters(
                        cached,
                        query.as_deref(),
                        method.as_deref(),
                        host.as_deref(),
                        status_pred.as_ref(),
                        since_dt.as_ref(),
                        mime.as_deref(),
                        None,
                        filters,
                        advanced_matcher.as_ref(),
                        filters.hide_connect,
                    )
                })
                .map(|(index, cached)| {
                    let id = cached.summary.id;
                    Candidate {
                        id,
                        index,
                        body_generation: inner.body_generations[index],
                        sort_offset: if inner.by_id.get(&id) == Some(&index) {
                            inner.locators.get(&id).map_or(0, |locator| locator.offset)
                        } else {
                            0
                        },
                    }
                })
                .collect()
        };
        outcome.records_considered = candidates.len();

        // The reads are blocking file I/O over as much as the byte budget allows,
        // which is far too long to hold a runtime worker that proxy tasks share.
        let storage_dir = self.storage_dir.clone();
        let inner = Arc::clone(&self.inner);
        let request = request.clone();
        let scan = tokio::task::spawn_blocking(move || {
            // File order, so the pass over transactions.ndjson only moves forward.
            let mut ordered = candidates;
            ordered.sort_by_key(|candidate| candidate.sort_offset);
            for candidate in ordered {
                if outcome.match_count >= request.max_matches {
                    outcome.stop("max_matches");
                    break;
                }
                if outcome.bytes_scanned >= request.byte_budget {
                    outcome.stop("byte_budget");
                    break;
                }
                let record = {
                    let inner = inner.blocking_read();
                    let current = inner.entries.get(candidate.index).filter(|record| {
                        record.id == candidate.id
                            && inner.body_generations.get(candidate.index)
                                == Some(&candidate.body_generation)
                            && !inner
                                .unresolved_body_generations
                                .contains(&candidate.body_generation)
                    });
                    match current.and_then(|record| {
                        if inner.by_id.get(&candidate.id) == Some(&candidate.index) {
                            rehydrate_checked(record, &inner, storage_dir.as_deref()).ok()
                        } else {
                            // An older duplicate owns its resident body, never
                            // the locator belonging to the newest same-ID row.
                            Some(record.clone())
                        }
                    }) {
                        Some(record) => record,
                        None => {
                            outcome.unsearchable += 1;
                            continue;
                        }
                    }
                };
                outcome.records_scanned += 1;
                outcome.bytes_scanned = outcome
                    .bytes_scanned
                    .saturating_add(record.request.body_size as u64)
                    .saturating_add(
                        record
                            .response
                            .as_ref()
                            .map(|message| message.body_size as u64)
                            .unwrap_or(0),
                    );
                collect_record_matches(&record, record.sequence, &needle, &request, &mut outcome);
            }
            if outcome.unsearchable > 0 {
                outcome.complete = false;
            }
            // Scanned in file order for the disk; reported in capture order for
            // the reader.
            outcome.transactions.sort_by_key(|hit| hit.sequence);
            outcome
        });
        scan.await.unwrap_or_else(|error| {
            warn!(?error, "body search scan did not finish");
            BodySearchOutcome {
                transactions: Vec::new(),
                match_count: 0,
                records_considered: 0,
                records_scanned: 0,
                bytes_scanned: 0,
                complete: false,
                stopped_by: Some("scan_failed"),
                unsearchable: 0,
            }
        })
    }

    /// Puts the body text back on a record whose bodies were dropped after loading.
    /// The in-memory copy carries the current annotations, which may be ahead of
    /// what is on disk, so those are kept and only the bodies come from the file.
    fn rehydrate(&self, record: &TransactionRecord, inner: &StoreInner) -> TransactionRecord {
        rehydrate_checked(record, inner, self.storage_dir.as_deref()).unwrap_or_else(|error| {
            warn!(?error, record_id = %record.id, "could not read transaction bodies back from disk");
            record.clone()
        })
    }

    /// Drain any detached persistence worker before changing the session's
    /// directory lifetime. Acquire after the session persistence guard.
    pub(crate) async fn owned_persistence_mutation_guard(&self) -> OwnedMutexGuard<()> {
        Arc::clone(&self.insert_lock).lock_owned().await
    }

    /// Records, body locations and the exact journal boundary captured together.
    /// The writer can stream existing bodies without materializing the history.
    pub async fn snapshot_for_persistence(
        &self,
        limit: Option<usize>,
    ) -> io::Result<TransactionPersistenceSnapshot> {
        let mut _insert_guard = self.owned_persistence_mutation_guard().await;
        let inner = self.inner.read().await;
        inner.require_resolved_bodies()?;
        let journal_rotation_confirmed = match &self.journal_tx {
            Some(tx) => match rotate_transaction_journal(tx) {
                Ok(()) => self.storage_dir.is_some(),
                Err(JournalRotationError::SendDisconnected) => {
                    if let Some(storage_dir) = &self.storage_dir {
                        // A failed send proves no receiver can still append. An
                        // absent acknowledgement proves no such thing.
                        _insert_guard =
                            rotate_stopped_transaction_journal(storage_dir, _insert_guard).await?;
                        true
                    } else {
                        false
                    }
                }
                Err(JournalRotationError::AckLost) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "transaction journal rotation acknowledgement was lost",
                    ));
                }
                Err(JournalRotationError::Writer(error)) => return Err(error),
            },
            None if self.journal_start_failed && self.storage_dir.is_some() => {
                _insert_guard = rotate_stopped_transaction_journal(
                    self.storage_dir.as_ref().unwrap(),
                    _insert_guard,
                )
                .await?;
                true
            }
            None if self.storage_dir.is_some() && !self.read_only_bodies => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "transaction journal rotation cannot be confirmed",
                ));
            }
            None => false,
        };
        let mut entries = Vec::new();
        let mut body_generations = HashMap::new();
        for index in (0..inner.entries.len())
            .rev()
            .take(limit.unwrap_or(usize::MAX))
        {
            let record = &inner.entries[index];
            body_generations
                .entry(record.id)
                .or_insert(inner.body_generations[index]);
            let locator = (inner.by_id.get(&record.id) == Some(&index))
                .then(|| inner.locators.get(&record.id).copied())
                .flatten();
            entries.push((record.clone(), locator));
        }
        Ok(TransactionPersistenceSnapshot {
            complete_capture: entries.len() == inner.entries.len(),
            entries,
            body_generations,
            file_generation: inner.file_generation,
            latest_event_sequence: self.latest_event_sequence(),
            journal_rotation_confirmed,
        })
    }

    pub async fn update_annotations(
        &self,
        id: Uuid,
        color_tag: Option<Option<String>>,
        user_note: Option<Option<String>>,
    ) -> Option<AnnotationUpdate> {
        match self
            .update_annotations_with_journal_mode(id, color_tag, user_note, None, None, false)
            .await
        {
            Ok(update) => update,
            Err(error) => {
                warn!(
                    ?error,
                    "failed to append transaction annotation journal entry before storing"
                );
                None
            }
        }
    }

    pub async fn update_record(
        &self,
        id: Uuid,
        update: impl FnOnce(&mut TransactionRecord),
    ) -> Option<TransactionSummary> {
        match self
            .update_record_with_journal_mode(id, update, false)
            .await
        {
            Ok(summary) => summary,
            Err(error) => {
                warn!(
                    ?error,
                    "failed to append transaction update journal entry before storing"
                );
                None
            }
        }
    }

    pub async fn update_record_durable(
        &self,
        id: Uuid,
        update: impl FnOnce(&mut TransactionRecord),
    ) -> io::Result<Option<TransactionSummary>> {
        self.update_record_with_journal_mode(id, update, true).await
    }

    async fn update_record_with_journal_mode(
        &self,
        id: Uuid,
        update: impl FnOnce(&mut TransactionRecord),
        require_journal_append: bool,
    ) -> io::Result<Option<TransactionSummary>> {
        let _mutation_guard = self.insert_lock.lock().await;
        let mut updated_record = {
            let inner = self.inner.read().await;
            let Some(index) = inner.by_id.get(&id).copied() else {
                return Ok(None);
            };
            let Some(record) = inner.entries.get(index) else {
                return Ok(None);
            };
            // Pull the bodies back off disk before mutating. Once this record is
            // updated the line on disk no longer matches it, so its locator has to
            // go — and with no locator the writer serialises whatever is in memory,
            // which has to be the whole record by then. Without this the update
            // survives only in memory and the journal.
            rehydrate_checked(record, &inner, self.storage_dir.as_deref())?
        };
        update(&mut updated_record);
        updated_record.id = id;
        if let Some(tx) = &self.journal_tx {
            if let Some(line) = encode_transaction_journal_line(&TransactionJournalEntry::Update {
                record: updated_record.clone(),
            }) {
                if let Err(error) = append_transaction_journal(tx, line).await {
                    if require_journal_append {
                        return Err(error);
                    }
                    warn!(
                        ?error,
                        "failed to append transaction update journal entry before storing"
                    );
                }
            } else if require_journal_append {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "failed to encode transaction update journal entry",
                ));
            }
        } else if require_journal_append {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "transaction journal writer is not available",
            ));
        }
        let summary = updated_record.summary();
        let mut inner = self.inner.write().await;
        let Some(index) = inner.by_id.get(&id).copied() else {
            return Ok(None);
        };
        if index >= inner.entries.len() {
            return Ok(None);
        }
        inner.entries[index] = updated_record;
        inner.service_map_metadata_epoch = Uuid::new_v4();
        inner.body_generations[index] = Uuid::new_v4();
        inner.summaries[index] = CachedSummary::new(summary.clone());
        // Memory is now newer than the line on disk. Leaving the locator in place
        // makes the next persist copy that stale line byte for byte and throw this
        // update away — silently, because the bodies it carries still look right.
        // Symmetric with from_located_records_with_journal, which drops locators
        // for records it replayed from the journal for the same reason.
        inner.locators.remove(&id);
        drop(inner);
        self.publish_transaction_event(summary.clone());
        Ok(Some(summary))
    }

    pub async fn update_annotations_durable(
        &self,
        id: Uuid,
        color_tag: Option<Option<String>>,
        user_note: Option<Option<String>>,
    ) -> io::Result<Option<AnnotationUpdate>> {
        self.update_annotations_with_journal_mode(id, color_tag, user_note, None, None, true)
            .await
    }

    pub async fn update_annotations_durable_with_client(
        &self,
        id: Uuid,
        color_tag: Option<Option<String>>,
        user_note: Option<Option<String>>,
        client_id: Option<String>,
        client_version: Option<u64>,
    ) -> io::Result<Option<AnnotationUpdate>> {
        self.update_annotations_with_journal_mode(
            id,
            color_tag,
            user_note,
            client_id,
            client_version,
            true,
        )
        .await
    }

    async fn update_annotations_with_journal_mode(
        &self,
        id: Uuid,
        color_tag: Option<Option<String>>,
        user_note: Option<Option<String>>,
        client_id: Option<String>,
        client_version: Option<u64>,
        require_journal_append: bool,
    ) -> io::Result<Option<AnnotationUpdate>> {
        let color_patch = nullable_string_patch(color_tag.as_ref());
        let note_patch = nullable_string_patch(user_note.as_ref());
        let has_annotation_patch = color_patch.is_some() || note_patch.is_some();
        let annotation_client_id = client_id.unwrap_or_default();
        let annotation_client_version = client_version.unwrap_or(0);
        let has_client_clock = !annotation_client_id.is_empty() && annotation_client_version > 0;
        let _mutation_guard = self.insert_lock.lock().await;
        let (previous_color_tag, previous_user_note, previous_annotation_revision) = {
            let inner = self.inner.read().await;
            let Some(index) = inner.by_id.get(&id).copied() else {
                return Ok(None);
            };
            let Some(record) = inner.entries.get(index) else {
                return Ok(None);
            };
            if has_client_clock
                && record
                    .annotation_client_versions
                    .get(&annotation_client_id)
                    .is_some_and(|seen_version| annotation_client_version <= *seen_version)
            {
                let summary = record.summary();
                return Ok(Some(AnnotationUpdate {
                    summary,
                    previous_color_tag: record.color_tag.clone(),
                    previous_user_note: record.user_note.clone(),
                    applied_color_tag: record.color_tag.clone(),
                    applied_user_note: record.user_note.clone(),
                }));
            }
            (
                record.color_tag.clone(),
                record.user_note.clone(),
                record.annotation_revision,
            )
        };
        let next_annotation_revision = if has_annotation_patch {
            previous_annotation_revision.saturating_add(1).max(1)
        } else {
            previous_annotation_revision
        };
        if has_annotation_patch {
            if let Some(tx) = &self.journal_tx {
                if let Some(line) =
                    encode_transaction_journal_line(&TransactionJournalEntry::Annotation {
                        id,
                        color_tag: color_patch,
                        user_note: note_patch,
                        annotation_revision: Some(next_annotation_revision),
                        previous_annotation_revision: Some(previous_annotation_revision),
                        annotation_client_id: has_client_clock
                            .then(|| annotation_client_id.clone()),
                        annotation_client_version: has_client_clock
                            .then_some(annotation_client_version),
                        previous_color_tag: Some(nullable_string_value_patch(
                            previous_color_tag.clone(),
                        )),
                        previous_user_note: Some(nullable_string_value_patch(
                            previous_user_note.clone(),
                        )),
                    })
                {
                    if let Err(error) = append_transaction_journal(tx, line).await {
                        if require_journal_append {
                            return Err(error);
                        }
                        warn!(
                            ?error,
                            "failed to append transaction annotation journal entry before storing"
                        );
                    }
                } else if require_journal_append {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "failed to encode transaction annotation journal entry",
                    ));
                }
            } else if require_journal_append {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "transaction journal writer is not available",
                ));
            }
        }
        let mut inner = self.inner.write().await;
        let Some(index) = inner.by_id.get(&id).copied() else {
            return Ok(None);
        };
        let Some(record) = inner.entries.get_mut(index) else {
            return Ok(None);
        };
        if let Some(tag) = color_tag {
            record.color_tag = tag;
        }
        if let Some(note) = user_note {
            record.user_note = note;
        }
        if has_annotation_patch {
            record.annotation_revision = next_annotation_revision;
            if has_client_clock {
                compact_annotation_client_versions_for_insert(
                    &mut record.annotation_client_versions,
                    &annotation_client_id,
                );
                record
                    .annotation_client_versions
                    .insert(annotation_client_id, annotation_client_version);
            }
        }
        let summary = record.summary();
        let applied_color_tag = record.color_tag.clone();
        let applied_user_note = record.user_note.clone();
        inner.summaries[index] = CachedSummary::new(summary.clone());
        if has_annotation_patch {
            inner.service_map_annotation_epoch = Uuid::new_v4();
        }
        drop(inner);
        if has_annotation_patch {
            self.publish_transaction_event(summary.clone());
        }
        Ok(Some(AnnotationUpdate {
            summary,
            previous_color_tag,
            previous_user_note,
            applied_color_tag,
            applied_user_note,
        }))
    }

    pub async fn restore_annotations_if_current(
        &self,
        id: Uuid,
        expected_color_tag: Option<String>,
        expected_user_note: Option<String>,
        previous_color_tag: Option<String>,
        previous_user_note: Option<String>,
    ) -> io::Result<bool> {
        let _mutation_guard = self.insert_lock.lock().await;
        let previous_annotation_revision = {
            let inner = self.inner.read().await;
            let Some(index) = inner.by_id.get(&id).copied() else {
                return Ok(false);
            };
            let Some(record) = inner.entries.get(index) else {
                return Ok(false);
            };
            if record.color_tag != expected_color_tag || record.user_note != expected_user_note {
                return Ok(false);
            }
            record.annotation_revision
        };
        let next_annotation_revision = previous_annotation_revision.saturating_add(1).max(1);
        let mut journal_error = None;
        if let Some(tx) = &self.journal_tx {
            let line = encode_transaction_journal_line(&TransactionJournalEntry::Annotation {
                id,
                color_tag: Some(nullable_string_value_patch(previous_color_tag.clone())),
                user_note: Some(nullable_string_value_patch(previous_user_note.clone())),
                annotation_revision: Some(next_annotation_revision),
                previous_annotation_revision: Some(previous_annotation_revision),
                annotation_client_id: None,
                annotation_client_version: None,
                previous_color_tag: Some(nullable_string_value_patch(expected_color_tag.clone())),
                previous_user_note: Some(nullable_string_value_patch(expected_user_note.clone())),
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "failed to encode transaction annotation rollback journal entry",
                )
            });
            match line {
                Ok(line) => {
                    if let Err(error) = append_transaction_journal(tx, line).await {
                        journal_error = Some(error);
                    }
                }
                Err(error) => {
                    journal_error = Some(error);
                }
            }
        }
        if let Some(error) = journal_error {
            return Err(error);
        }
        let mut inner = self.inner.write().await;
        let Some(index) = inner.by_id.get(&id).copied() else {
            return Ok(false);
        };
        let Some(record) = inner.entries.get_mut(index) else {
            return Ok(false);
        };
        record.color_tag = previous_color_tag;
        record.user_note = previous_user_note;
        record.annotation_revision = next_annotation_revision;
        let summary = record.summary();
        inner.summaries[index] = CachedSummary::new(summary.clone());
        inner.service_map_annotation_epoch = Uuid::new_v4();
        drop(inner);
        self.publish_transaction_event(summary);
        Ok(true)
    }

    pub async fn replace_all(&self, records: Vec<TransactionRecord>) {
        let _mutation_guard = self.insert_lock.lock().await;
        let mut inner = StoreInner::from_newest_first(records);
        if let Some(max_entries) = self.max_entries {
            inner.trim_to_max_entries(max_entries);
        }
        let max_seq = inner.entries.iter().map(|r| r.sequence).max().unwrap_or(0);
        let mut current = self.inner.write().await;
        // Replacing memory does not replace the file; preserve its publication guard.
        inner.file_generation = current.file_generation;
        *current = inner;
        drop(current);
        self.next_sequence.store(max_seq + 1, Ordering::Relaxed);
        let mut current = self.next_event_sequence.load(Ordering::Relaxed);
        loop {
            let next = current
                .checked_add(1)
                .expect("transaction event sequence exhausted")
                .max(max_seq + 1);
            match self.next_event_sequence.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<TransactionEvent> {
        self.events.subscribe()
    }

    pub fn subscribe_retention(&self) -> broadcast::Receiver<TransactionRetentionEvent> {
        self.retention_events.subscribe()
    }

    /// Publish the prepared file and its offsets as one reader-visible change.
    /// Call from a blocking worker. The closure must perform only the atomic
    /// rename: successful rename cannot be followed by a fallible adoption step.
    pub(crate) fn publish_persistence_snapshot(
        &self,
        snapshot: &TransactionPersistenceSnapshot,
        mut locators: HashMap<Uuid, crate::session::BodyLocator>,
        rename: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        let mut inner = self.inner.blocking_write();
        // A duplicate insertion may have discovered a missing dependency after
        // this plan was prepared. Do not publish over the only recovery source.
        inner.require_resolved_bodies()?;
        if !snapshot.complete_capture {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a partial transaction snapshot cannot replace the complete file",
            ));
        }
        if inner.file_generation != snapshot.file_generation {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "transaction snapshot source file changed before publication",
            ));
        }
        if self.storage_dir.is_some()
            && !self.read_only_bodies
            && !snapshot.journal_rotation_confirmed
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "transaction snapshot journal boundary is not confirmed",
            ));
        }
        // Precompute every decision before rename. New full records keep their
        // resident bodies; annotation-only edits retain their generation and data.
        locators.retain(|id, _| {
            inner.by_id.get(id).is_some_and(|&index| {
                snapshot.body_generations.get(id) == inner.body_generations.get(index)
            })
        });
        let next_file_generation = Uuid::new_v4();
        rename()?;
        for index in 0..inner.entries.len() {
            let id = inner.entries[index].id;
            if locators.contains_key(&id) && inner.by_id.get(&id) == Some(&index) {
                strip_transaction_bodies(&mut inner.entries[index]);
            }
        }
        inner.locators = locators;
        inner.file_generation = next_file_generation;
        Ok(())
    }

    /// Single-worker notification with a retained permit. Register a waiter
    /// before checking work so an insert or final lease release cannot be lost.
    pub fn retention_notify(&self) -> Arc<Notify> {
        Arc::clone(&self.in_progress.notify)
    }

    pub fn notify_retention_work(&self) {
        self.in_progress.notify.notify_one();
    }

    fn protected_existing_ids(
        &self,
        inner: &StoreInner,
        saved_source_ids: &HashSet<Uuid>,
    ) -> HashSet<Uuid> {
        let leases = self
            .in_progress
            .leases
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        saved_source_ids
            .iter()
            .chain(leases.keys())
            .filter(|id| inner.by_id.contains_key(id))
            .copied()
            .collect()
    }

    /// Counts only metadata; dangling references and duplicate lease owners do
    /// not inflate the number of protected existing UUIDs.
    pub async fn retention_status(&self, saved_source_ids: &HashSet<Uuid>) -> (usize, usize) {
        let _mutation_guard = self.insert_lock.lock().await;
        let inner = self.inner.read().await;
        (
            inner.entries.len(),
            self.protected_existing_ids(&inner, saved_source_ids).len(),
        )
    }

    /// UUID tombstones are indivisible. Distinguish protected records from a
    /// malformed duplicate-ID group whose removal would overshoot the target.
    pub(crate) async fn retention_status_details(
        &self,
        saved_source_ids: &HashSet<Uuid>,
        target: Option<usize>,
    ) -> RetentionStatusDetails {
        let _mutation_guard = self.insert_lock.lock().await;
        let inner = self.inner.read().await;
        let protected = self.protected_existing_ids(&inner, saved_source_ids);
        let all_records_protected = inner.by_id.keys().all(|id| protected.contains(id));
        let excess = target.map_or(0, |target| inner.entries.len().saturating_sub(target));
        let identity_conflict =
            if excess == 0 || all_records_protected || inner.by_id.len() == inner.entries.len() {
                false
            } else {
                let mut counts = HashMap::<Uuid, usize>::new();
                for record in &inner.entries {
                    if !protected.contains(&record.id) {
                        *counts.entry(record.id).or_default() += 1;
                    }
                }
                !counts.values().any(|count| *count <= excess)
            };
        RetentionStatusDetails {
            total_count: inner.entries.len(),
            protected_count: protected.len(),
            all_records_protected,
            identity_conflict,
        }
    }

    /// Durably removes one bounded chunk of oldest eligible excess records.
    /// Saved-source protection must be stabilized by the caller's workspace
    /// mutation guard. Provisional insertion and tombstone selection are atomic
    /// with respect to each other under the store mutation lock.
    pub async fn trim_retention(
        &self,
        max_entries: usize,
        saved_source_ids: &HashSet<Uuid>,
        chunk_size: usize,
    ) -> io::Result<RetentionTrimOutcome> {
        const MAX_TOMBSTONE_IDS: usize = 1024;
        let _mutation_guard = self.insert_lock.lock().await;
        let (ids, reclaimable_bytes) = {
            let inner = self.inner.read().await;
            let protected = self.protected_existing_ids(&inner, saved_source_ids);
            let mut remaining = inner.entries.len().saturating_sub(max_entries);
            let limit = chunk_size.min(MAX_TOMBSTONE_IDS);
            let mut ids = Vec::new();
            let mut seen = HashSet::new();
            // Preserve existing insertion/UUID behavior. A UUID tombstone can
            // cover multiple rows; never remove more rows than the excess.
            let occurrences = if inner.by_id.len() == inner.entries.len() {
                None
            } else {
                let mut counts = HashMap::<Uuid, usize>::new();
                for record in &inner.entries {
                    *counts.entry(record.id).or_default() += 1;
                }
                Some(counts)
            };
            for record in &inner.entries {
                if remaining == 0 || ids.len() == limit {
                    break;
                }
                if protected.contains(&record.id) || !seen.insert(record.id) {
                    continue;
                }
                let count = occurrences.as_ref().map_or(1, |counts| counts[&record.id]);
                if count <= remaining {
                    ids.push(record.id);
                    remaining -= count;
                }
            }
            let bytes = ids
                .iter()
                .filter_map(|id| inner.locators.get(id))
                .map(|locator| u64::from(locator.len))
                .sum();
            (ids, bytes)
        };
        if !ids.is_empty() {
            self.delete_ids_locked_with_event(&ids, true).await?;
        }
        let inner = self.inner.read().await;
        Ok(RetentionTrimOutcome {
            deleted_ids: ids,
            current_count: inner.entries.len(),
            protected_count: self.protected_existing_ids(&inner, saved_source_ids).len(),
            event_sequence: self.latest_event_sequence(),
            reclaimable_bytes,
        })
    }

    /// Restores pending work when journal replay was applied but compaction
    /// could not finish. The boundary is the replayed mutation event sequence.
    pub fn mark_retention_compaction_pending(&self, event_sequence: u64) {
        self.retention_trim_sequence
            .fetch_max(event_sequence, Ordering::Release);
    }

    pub fn retention_compaction_pending(&self) -> bool {
        self.retention_trim_sequence.load(Ordering::Acquire)
            > self.retention_compacted_sequence.load(Ordering::Acquire)
    }

    /// Called inside the owned snapshot worker after confirmed journal rotation,
    /// body/state publication, and checkpoint cleanup, using the captured boundary.
    /// A later trim remains pending even when an older snapshot finishes last.
    pub(crate) fn mark_retention_compacted(&self, event_sequence: u64) {
        self.retention_compacted_sequence
            .fetch_max(event_sequence, Ordering::Release);
    }

    // Synthetic fixtures may install a file written outside the production
    // publisher. Production callers must always use the versioned barrier above.
    #[cfg(test)]
    pub async fn adopt_written_locators(
        &self,
        mut locators: HashMap<Uuid, crate::session::BodyLocator>,
    ) {
        let mut inner = self.inner.write().await;
        locators.retain(|id, _| inner.by_id.contains_key(id));
        for record in inner.entries.iter_mut() {
            if locators.contains_key(&record.id) {
                strip_transaction_bodies(record);
            }
        }
        inner.locators = locators;
        inner.file_generation = Uuid::new_v4();
    }

    #[cfg(test)]
    pub(crate) fn persistence_mutation_locked_for_test(&self) -> bool {
        self.insert_lock.try_lock().is_err()
    }

    #[cfg(test)]
    pub(crate) fn disconnect_journal_writer_for_test(&mut self) -> io::Result<()> {
        if let Some(tx) = self.journal_tx.take() {
            let (ack, finished) = mpsc::channel();
            if tx
                .send(TransactionJournalCommand::StopForTest { ack })
                .is_ok()
            {
                finished.recv().map_err(io::Error::other)?;
            }
        }
        let (tx, rx) = mpsc::channel();
        drop(rx);
        self.journal_tx = Some(tx);
        self.journal_start_failed = false;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) async fn set_body_locator_for_test(
        &self,
        id: Uuid,
        locator: crate::session::BodyLocator,
    ) {
        self.inner.write().await.locators.insert(id, locator);
    }

    pub fn latest_sequence(&self) -> u64 {
        self.next_sequence.load(Ordering::Relaxed).saturating_sub(1)
    }

    pub fn latest_event_sequence(&self) -> u64 {
        self.next_event_sequence
            .load(Ordering::Relaxed)
            .saturating_sub(1)
    }

    fn publish_transaction_event(&self, summary: TransactionSummary) {
        #[cfg(test)]
        {
            let hook = self.before_transaction_event_hook.lock().unwrap().take();
            if let Some(hook) = hook {
                hook();
            }
        }
        let event = TransactionEvent {
            event_sequence: self.next_event_sequence.fetch_add(1, Ordering::Relaxed),
            summary,
        };
        let _ = self.events.send(event);
    }
}

impl Default for TransactionStore {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn normalize_storage_sequences(entries: &mut [TransactionRecord]) {
    let has_unadvanceable_sequence = entries.iter().any(|record| record.sequence == u64::MAX);
    let needs_repair = has_unadvanceable_sequence
        || entries
            .iter()
            .try_fold(0u64, |previous, record| {
                (record.sequence > previous).then_some(record.sequence)
            })
            .is_none();
    if !needs_repair {
        return;
    }

    for (index, record) in entries.iter_mut().enumerate() {
        record.sequence = (index as u64).saturating_add(1);
    }
}

fn can_stream_index_order(filters: &ListFilters) -> bool {
    let key = normalized_transaction_sort_key(filters);
    let direction = normalized_transaction_sort_direction(filters);
    key == "index" && (direction == "asc" || direction == "desc")
}

fn can_stream_descending_index_order(filters: &ListFilters) -> bool {
    let key = normalized_transaction_sort_key(filters);
    let direction = normalized_transaction_sort_direction(filters);
    key == "index" && direction == "desc"
}

fn normalized_transaction_sort_key(filters: &ListFilters) -> &str {
    filters
        .sort_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("index")
}

fn normalized_transaction_sort_direction(filters: &ListFilters) -> &str {
    filters
        .sort_direction
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("desc")
}

fn newest_scan_end(summaries: &[CachedSummary], before_sequence: Option<u64>) -> usize {
    before_sequence
        .map(|before| summaries.partition_point(|cached| cached.summary.sequence < before))
        .unwrap_or(summaries.len())
}

fn snapshot_entries(inner: &StoreInner, limit: Option<usize>) -> Vec<TransactionRecord> {
    match limit {
        Some(n) => inner.entries.iter().rev().take(n).cloned().collect(),
        None => inner.entries.iter().rev().cloned().collect(),
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

fn open_private_append_file(path: &Path) -> io::Result<fs::File> {
    let created = !path.exists();
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(path)?;
    tighten_private_file(path)?;
    if created {
        if let Some(parent) = path.parent() {
            sync_directory(parent)?;
        }
    }
    Ok(file)
}

fn open_private_truncate_file(path: &Path) -> io::Result<fs::File> {
    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(path)?;
    tighten_private_file(path)?;
    Ok(file)
}

#[cfg(unix)]
fn tighten_private_file(path: &Path) -> io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn tighten_private_file(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn start_transaction_journal_writer(
    journal_path: PathBuf,
) -> Option<mpsc::Sender<TransactionJournalCommand>> {
    let (tx, rx) = mpsc::channel::<TransactionJournalCommand>();
    let (ready_tx, ready_rx) = mpsc::sync_channel::<io::Result<()>>(1);
    let spawn_result = thread::Builder::new()
        .name("sniper-transaction-journal".to_string())
        .spawn(move || {
            if let Some(parent) = journal_path.parent() {
                if let Err(error) = create_private_dir_all(parent) {
                    warn!(?error, path = %parent.display(), "failed to create transaction journal directory");
                    let _ = ready_tx.send(Err(error));
                    return;
                }
            }

            let file = match open_private_append_file(&journal_path) {
                Ok(file) => file,
                Err(error) => {
                    warn!(?error, path = %journal_path.display(), "failed to open transaction journal");
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
                    TransactionJournalCommand::Append { line, ack } => {
                        let result = file
                            .write_all(&line)
                            .and_then(|()| file.flush())
                            .and_then(|()| file.sync_data());
                        let failed = result.is_err();
                        if let Err(error) = &result {
                            warn!(?error, path = %journal_path.display(), "failed to append transaction journal entry");
                        }
                        #[cfg(windows)]
                        drop(file);
                        if let Some(ack) = ack {
                            let _ = ack.send(result);
                        }
                        if failed {
                            return;
                        }
                    }
                    #[cfg(test)]
                    TransactionJournalCommand::StopForTest { ack } => {
                        drop(file);
                        let _ = ack.send(());
                        return;
                    }
                    TransactionJournalCommand::Rotate { ack } => {
                        let result = rotate_transaction_journal_file(&mut file, &journal_path);
                        if let Err(error) = &result {
                            warn!(?error, path = %journal_path.display(), "failed to rotate transaction journal");
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
                    "transaction journal writer stopped before startup completed"
                );
                None
            }
        },
        Err(error) => {
            warn!(?error, "failed to spawn transaction journal writer");
            None
        }
    }
}

#[derive(Debug)]
enum JournalRotationError {
    SendDisconnected,
    AckLost,
    Writer(io::Error),
}

fn rotate_transaction_journal(
    tx: &mpsc::Sender<TransactionJournalCommand>,
) -> Result<(), JournalRotationError> {
    let (ack, rx) = mpsc::channel();
    tx.send(TransactionJournalCommand::Rotate { ack })
        .map_err(|_| JournalRotationError::SendDisconnected)?;
    rx.recv()
        .map_err(|_| JournalRotationError::AckLost)?
        .map_err(JournalRotationError::Writer)
}

async fn append_transaction_journal(
    tx: &mpsc::Sender<TransactionJournalCommand>,
    line: Vec<u8>,
) -> io::Result<()> {
    let (ack, rx) = oneshot::channel();
    tx.send(TransactionJournalCommand::Append {
        line,
        ack: Some(ack),
    })
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            "transaction journal writer stopped",
        )
    })?;
    rx.await.map_err(|_| {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            "transaction journal writer stopped",
        )
    })?
}

async fn rotate_stopped_transaction_journal(
    storage_dir: &Path,
    mutation_guard: OwnedMutexGuard<()>,
) -> io::Result<OwnedMutexGuard<()>> {
    let path = storage_dir.join("transactions.journal");
    tokio::task::spawn_blocking(move || {
        // A cancelled async waiter must not let another mutation or rotation
        // enter while this worker still owns the journal files.
        let mut file = open_private_append_file(&path)?;
        rotate_transaction_journal_file(&mut file, &path)?;
        Ok(mutation_guard)
    })
    .await
    .map_err(io::Error::other)?
}

fn rotate_transaction_journal_file(file: &mut fs::File, journal_path: &Path) -> io::Result<()> {
    file.flush()?;
    let active = match fs::read(journal_path) {
        Ok(active) => active,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error),
    };

    if !active.is_empty() {
        let checkpoint_path = transaction_journal_checkpoint_path(journal_path);
        merge_transaction_journal_checkpoint(&checkpoint_path, &active)?;
    }

    crate::platform::truncate_journal(file, journal_path)
}

fn merge_transaction_journal_checkpoint(checkpoint_path: &Path, active: &[u8]) -> io::Result<()> {
    if let Some(parent) = checkpoint_path.parent() {
        create_private_dir_all(parent)?;
    }

    let mut checkpoint = match fs::read(checkpoint_path) {
        Ok(checkpoint) => checkpoint,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error),
    };
    if !checkpoint.is_empty() && !checkpoint.ends_with(b"\n") {
        checkpoint.push(b'\n');
    }
    checkpoint.extend_from_slice(active);

    let file_name = checkpoint_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("transactions.journal.checkpoint");
    let tmp_path = checkpoint_path.with_file_name(format!(".{file_name}.tmp-{}", Uuid::new_v4()));
    let write_result = (|| -> io::Result<()> {
        let mut tmp = open_private_truncate_file(&tmp_path)?;
        tmp.write_all(&checkpoint)?;
        tmp.sync_all()?;
        drop(tmp);
        crate::platform::rename(&tmp_path, checkpoint_path)?;
        tighten_private_file(checkpoint_path)?;
        if let Some(parent) = checkpoint_path.parent() {
            sync_directory(parent)?;
        }
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    write_result
}

fn sync_directory(path: &Path) -> io::Result<()> {
    crate::platform::sync_directory(path)
}

pub(crate) fn transaction_journal_checkpoint_path(journal_path: &Path) -> PathBuf {
    let file_name = journal_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("transactions.journal");
    journal_path.with_file_name(format!("{file_name}.checkpoint"))
}

fn encode_transaction_insert_journal_line(record: &TransactionRecord) -> Option<Vec<u8>> {
    let entry = TransactionJournalInsert {
        entry_type: "insert",
        record,
    };
    encode_transaction_journal_line(&entry)
}

fn encode_transaction_journal_line(entry: &impl Serialize) -> Option<Vec<u8>> {
    match serde_json::to_vec(entry) {
        Ok(mut line) => {
            line.push(b'\n');
            Some(line)
        }
        Err(error) => {
            warn!(?error, "failed to encode transaction journal entry");
            None
        }
    }
}

fn nullable_string_patch(value: Option<&Option<String>>) -> Option<NullableStringPatch> {
    value.map(|patch| match patch {
        Some(value) => NullableStringPatch::Set(value.clone()),
        None => NullableStringPatch::Clear,
    })
}

fn nullable_string_value_patch(value: Option<String>) -> NullableStringPatch {
    match value {
        Some(value) => NullableStringPatch::Set(value),
        None => NullableStringPatch::Clear,
    }
}

#[derive(Clone, Debug)]
enum StatusPredicate {
    Exact(u16),
    Range(u16, u16),
    Class(u16), // e.g. 4 means 4xx (400-499)
}

impl StatusPredicate {
    fn matches(&self, status: Option<u16>) -> bool {
        let Some(s) = status else { return false };
        match self {
            StatusPredicate::Exact(v) => s == *v,
            StatusPredicate::Range(lo, hi) => s >= *lo && s <= *hi,
            StatusPredicate::Class(c) => s / 100 == *c,
        }
    }
}

fn parse_status_range(input: &str) -> Option<StatusPredicate> {
    let trimmed = input.trim();
    // "4xx", "5xx", etc.
    if trimmed.len() == 3 && trimmed.ends_with("xx") {
        let class = trimmed[..1].parse::<u16>().ok()?;
        if (1..=5).contains(&class) {
            return Some(StatusPredicate::Class(class));
        }
    }
    // "200-299"
    if let Some((lo_str, hi_str)) = trimmed.split_once('-') {
        let lo = lo_str.trim().parse::<u16>().ok()?;
        let hi = hi_str.trim().parse::<u16>().ok()?;
        if lo <= hi {
            return Some(StatusPredicate::Range(lo, hi));
        }
    }
    None
}

pub(crate) fn parse_history_since(input: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    // History queries have always required positive relative durations.
    parse_since_with_minimum(input, 1)
}

fn parse_since(input: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    parse_since_with_minimum(input, 0)
}

fn parse_since_with_minimum(
    input: &str,
    minimum_relative_amount: i64,
) -> Option<chrono::DateTime<chrono::Utc>> {
    let trimmed = input.trim();
    // Relative: "1h", "30m", "2d", "7d"
    for (unit, seconds_per_unit) in [('h', 3600_i64), ('m', 60), ('d', 86400), ('s', 1)] {
        if let Some(rest) = trimmed.strip_suffix(unit) {
            if rest.is_empty() || !rest.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            let amount: i64 = rest.parse().ok()?;
            if amount < minimum_relative_amount {
                return None;
            }
            let duration = chrono::Duration::try_seconds(amount.checked_mul(seconds_per_unit)?)?;
            return chrono::Utc::now().checked_sub_signed(duration);
        }
    }
    // Absolute: "2024-01-01" or "2024-01-01T12:00:00Z"
    if let Ok(dt) = chrono::NaiveDate::parse_from_str(trimmed, "%Y-%m-%d") {
        let datetime = dt.and_hms_opt(0, 0, 0)?;
        return Some(chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(
            datetime,
            chrono::Utc,
        ));
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(trimmed) {
        return Some(dt.with_timezone(&chrono::Utc));
    }
    None
}

/// Pull the searchable text out of one message. A Base64 body is decoded first:
/// searching the Base64 itself would match nothing a person ever sent.
fn searchable_body(message: &MessageRecord) -> Option<String> {
    match message.body_encoding {
        BodyEncoding::Utf8 => Some(message.body_preview.clone()),
        BodyEncoding::Base64 => {
            use base64::Engine as _;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(message.body_preview.as_bytes())
                .ok()?;
            Some(String::from_utf8_lossy(&bytes).into_owned())
        }
    }
}

fn header_block(message: &MessageRecord) -> String {
    message
        .headers
        .iter()
        .map(|header| format!("{}: {}", header.name, header.value))
        .collect::<Vec<_>>()
        .join("\n")
}

/// A window of `width` bytes either side of the match, widened to char
/// boundaries: slicing inside a multi-byte character panics, and bodies are
/// not ASCII. The trailing width is counted from the end of the match, so the
/// matched value itself is never what gets cut off.
fn match_context(haystack: &str, at: usize, len: usize, width: usize) -> String {
    let mut start = at.saturating_sub(width);
    while !haystack.is_char_boundary(start) {
        start -= 1;
    }
    let mut end = at
        .saturating_add(len)
        .saturating_add(width)
        .min(haystack.len());
    while !haystack.is_char_boundary(end) {
        end += 1;
    }
    haystack[start..end].to_string()
}

fn push_matches(
    haystack: &str,
    side: &'static str,
    needle: &str,
    request: &BodySearchRequest,
    found: &mut Vec<BodySearchMatch>,
    outcome: &mut BodySearchOutcome,
) {
    let subject = if request.case_sensitive {
        haystack.to_string()
    } else {
        haystack.to_ascii_lowercase()
    };
    let mut from = 0usize;
    while let Some(offset) = subject[from..].find(needle) {
        let at = from + offset;
        if outcome.match_count >= request.max_matches {
            outcome.stop("max_matches");
            return;
        }
        found.push(BodySearchMatch {
            side,
            offset: at,
            context: match_context(haystack, at, needle.len(), request.context_bytes),
        });
        outcome.match_count += 1;
        from = at + needle.len().max(1);
        if from >= subject.len() {
            break;
        }
    }
}

fn collect_record_matches(
    record: &TransactionRecord,
    sequence: u64,
    needle: &str,
    request: &BodySearchRequest,
    outcome: &mut BodySearchOutcome,
) {
    let mut found = Vec::new();
    let mut search = |haystack: &str, side: &'static str| {
        push_matches(haystack, side, needle, request, &mut found, outcome)
    };
    if request.sides.url {
        search(&record.path, "url");
    }
    if request.sides.headers {
        search(&header_block(&record.request), "request-headers");
        if let Some(response) = record.response.as_ref() {
            search(&header_block(response), "response-headers");
        }
    }
    if request.sides.request_body {
        if let Some(body) = searchable_body(&record.request) {
            search(&body, "request-body");
        }
    }
    if request.sides.response_body {
        if let Some(body) = record.response.as_ref().and_then(searchable_body) {
            search(&body, "response-body");
        }
    }
    if !found.is_empty() {
        outcome.transactions.push(BodySearchHit {
            id: record.id,
            sequence,
            method: record.method.clone(),
            host: record.host.clone(),
            path: record.path.clone(),
            matches: found,
        });
    }
}

fn matches_filters(
    cached: &CachedSummary,
    query: Option<&str>,
    method: Option<&str>,
    host: Option<&str>,
    status_pred: Option<&StatusPredicate>,
    since: Option<&chrono::DateTime<chrono::Utc>>,
    mime: Option<&str>,
    before_sequence: Option<u64>,
    filters: &ListFilters,
    advanced_matcher: Option<&AdvancedSearchMatcher>,
    hide_connect: bool,
) -> bool {
    let summary = &cached.summary;

    if let Some(before) = before_sequence {
        if summary.sequence >= before {
            return false;
        }
    }

    if let Some(m) = method {
        if cached.method_upper != m {
            return false;
        }
    }

    if let Some(h) = host {
        if !cached.host_lower.contains(h) {
            return false;
        }
    }

    if let Some(pred) = status_pred {
        if !pred.matches(summary.status) {
            return false;
        }
    }

    if let Some(since_dt) = since {
        if summary.started_at < *since_dt {
            return false;
        }
    }

    if let Some(mime_filter) = mime {
        if !cached.content_type_lower.contains(mime_filter) {
            return false;
        }
    }

    if filters.in_scope_only
        && !crate::scope::is_host_in_scope(
            &summary.host,
            &filters.scope_patterns,
            &filters.excluded_scope_patterns,
        )
    {
        return false;
    }

    if hide_connect && summary.method == "CONNECT" {
        return false;
    }

    if filters.hide_without_responses && !summary.has_response {
        return false;
    }

    if filters.only_parameterized && !summary.path.contains('?') {
        return false;
    }

    if filters.only_notes && visible_note_count(summary) == 0 {
        return false;
    }

    if !matches_status_classes(summary.status, filters.status_classes.as_deref()) {
        return false;
    }

    if !matches_mime_types(cached.mime, filters.mime_types.as_deref()) {
        return false;
    }

    if cached.mime != "websocket"
        && !matches_hidden_extensions(cached.path_extension.as_deref(), &filters.hidden_extensions)
    {
        return false;
    }

    if !matches_port_filter(cached.port.as_deref(), filters.port.as_deref()) {
        return false;
    }

    if !matches_color_tags(summary.color_tag.as_deref(), &filters.color_tags) {
        return false;
    }

    if let Some(matcher) = advanced_matcher {
        if !matcher.matches(cached, filters.search_headers) {
            return false;
        }
    }

    let Some(value) = query else { return true };
    cached.quick_haystack.contains(value)
        || (filters.search_headers && cached.header_haystack_lower.contains(value))
}

fn sort_filtered_records(records: &mut [&CachedSummary], filters: &ListFilters) {
    let key = normalized_transaction_sort_key(filters);
    let direction = normalized_transaction_sort_direction(filters);
    let ascending = direction == "asc";

    match key {
        "index" => records.sort_by(|left, right| compare_sequence(left, right)),
        "host" => records.sort_by(|left, right| {
            left.host_lower
                .cmp(&right.host_lower)
                .then_with(|| compare_sequence(left, right))
        }),
        "method" => records.sort_by(|left, right| {
            left.method_upper
                .cmp(&right.method_upper)
                .then_with(|| compare_sequence(left, right))
        }),
        "path" => records.sort_by(|left, right| {
            left.path_lower
                .cmp(&right.path_lower)
                .then_with(|| compare_sequence(left, right))
        }),
        "status" => records.sort_by(|left, right| {
            left.summary
                .status
                .unwrap_or(0)
                .cmp(&right.summary.status.unwrap_or(0))
                .then_with(|| compare_sequence(left, right))
        }),
        "length" => records.sort_by(|left, right| {
            left.total_bytes
                .cmp(&right.total_bytes)
                .then_with(|| compare_sequence(left, right))
        }),
        "mime" => records.sort_by(|left, right| {
            left.mime
                .cmp(right.mime)
                .then_with(|| compare_sequence(left, right))
        }),
        "notes" => records.sort_by(|left, right| {
            visible_note_count(&left.summary)
                .cmp(&visible_note_count(&right.summary))
                .then_with(|| compare_sequence(left, right))
        }),
        "tls" => records.sort_by(|left, right| {
            left.is_tls
                .cmp(&right.is_tls)
                .then_with(|| compare_sequence(left, right))
        }),
        "edited" => records.sort_by(|left, right| {
            left.summary
                .has_match_replace
                .cmp(&right.summary.has_match_replace)
                .then_with(|| compare_sequence(left, right))
        }),
        "started_at" => records.sort_by(|left, right| compare_started_at(left, right)),
        _ => records.sort_by(|left, right| compare_started_at(left, right)),
    }

    if !ascending {
        records.reverse();
    }
}

fn visible_note_count(summary: &TransactionSummary) -> usize {
    summary.note_count + usize::from(summary.has_user_note)
}

fn compare_sequence(left: &CachedSummary, right: &CachedSummary) -> std::cmp::Ordering {
    left.summary.sequence.cmp(&right.summary.sequence)
}

fn compare_started_at(left: &CachedSummary, right: &CachedSummary) -> std::cmp::Ordering {
    left.summary
        .started_at
        .cmp(&right.summary.started_at)
        .then_with(|| compare_sequence(left, right))
}

fn infer_summary_mime(summary: &TransactionSummary) -> &'static str {
    if summary.is_websocket {
        return "websocket";
    }
    let content_type = summary
        .content_type
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    if content_type.contains("html") {
        return "html";
    }
    if content_type.contains("javascript") || content_type.contains("ecmascript") {
        return "script";
    }
    if content_type.contains("css") {
        return "css";
    }
    if content_type.contains("json") {
        return "json";
    }
    if content_type.contains("image") {
        return "image";
    }
    if let Some(extension) = extract_path_extension(&summary.path) {
        match extension.as_str() {
            "js" => return "script",
            "css" => return "css",
            "json" => return "json",
            "html" => return "html",
            "png" | "jpg" | "jpeg" | "gif" | "svg" | "ico" => return "image",
            _ => {}
        }
    }
    "other"
}

fn summary_total_bytes(summary: &TransactionSummary) -> usize {
    summary.request_bytes + summary.response_bytes
}

fn is_tls_summary(summary: &TransactionSummary) -> bool {
    matches!(summary.kind, TrafficKind::Tunnel) || summary.scheme == "https"
}

fn matches_status_classes(status: Option<u16>, classes: Option<&[String]>) -> bool {
    let Some(classes) = classes else {
        return true;
    };

    let class = match status {
        Some(value) if (200..300).contains(&value) => "success",
        Some(value) if (300..400).contains(&value) => "redirect",
        Some(value) if (400..500).contains(&value) => "client_error",
        Some(value) if (500..600).contains(&value) => "server_error",
        _ => "other",
    };
    classes.iter().any(|value| value == class)
}

fn matches_mime_types(mime: &str, mime_types: Option<&[String]>) -> bool {
    let Some(mime_types) = mime_types else {
        return true;
    };
    mime_types.iter().any(|value| value == mime)
}

fn matches_hidden_extensions(extension: Option<&str>, hidden_extensions: &[String]) -> bool {
    if hidden_extensions.is_empty() {
        return true;
    }
    let Some(extension) = extension else {
        return true;
    };
    !hidden_extensions
        .iter()
        .any(|value| value.as_str() == extension)
}

fn matches_port_filter(actual: Option<&str>, port: Option<&str>) -> bool {
    let Some(expected) = port.filter(|value| !value.is_empty()) else {
        return true;
    };
    actual.unwrap_or("") == expected
}

fn effective_summary_port(summary: &TransactionSummary) -> Option<String> {
    extract_host_port(&summary.host)
        .map(str::to_string)
        .or_else(|| default_port_for_scheme(&summary.scheme).map(str::to_string))
}

fn default_port_for_scheme(scheme: &str) -> Option<&'static str> {
    match scheme.to_ascii_lowercase().as_str() {
        "http" | "ws" => Some("80"),
        "https" | "wss" => Some("443"),
        _ => None,
    }
}

fn matches_color_tags(color_tag: Option<&str>, color_tags: &[String]) -> bool {
    if color_tags.is_empty() {
        return true;
    }
    color_tag
        .map(|tag| color_tags.iter().any(|value| value == tag))
        .unwrap_or(false)
}

fn extract_path_extension(path: &str) -> Option<String> {
    let clean = path.split('?').next().unwrap_or(path);
    let (_, extension) = clean.rsplit_once('.')?;
    if extension.is_empty() || !extension.chars().all(|ch| ch.is_ascii_alphanumeric()) {
        return None;
    }
    Some(extension.to_ascii_lowercase())
}

fn extract_host_port(host: &str) -> Option<&str> {
    let trimmed = host.trim();
    if let Some(rest) = trimmed.strip_prefix('[') {
        let end = rest.find(']')?;
        return rest[end + 1..]
            .strip_prefix(':')
            .filter(|port| !port.is_empty());
    }
    if trimmed.matches(':').count() == 1 {
        return trimmed
            .split_once(':')
            .map(|(_, port)| port)
            .filter(|port| !port.is_empty());
    }
    None
}

fn format_size(bytes: usize) -> String {
    if bytes == 0 {
        return "0 B".to_string();
    }

    let units = ["B", "KB", "MB", "GB"];
    let mut size = bytes as f64;
    let mut index = 0;
    while size >= 1024.0 && index < units.len() - 1 {
        size /= 1024.0;
        index += 1;
    }
    let precision = if size >= 10.0 || index == 0 { 0 } else { 1 };
    // The UI uses toFixed, which rounds positive ties up. Rust's formatter
    // rounds ties to even, so round first to keep displayed-size queries equal.
    // One-decimal values are below 10 GB, making size * 10 exact for byte counts.
    let factor = if precision == 0 { 1.0 } else { 10.0 };
    let size = (size * factor).round() / factor;
    format!("{size:.precision$} {}", units[index])
}

enum AdvancedSearchMatcher {
    Plain {
        needle: String,
        case_sensitive: bool,
        negative: bool,
    },
    Regex {
        regex: Regex,
        negative: bool,
    },
    Always(bool),
}

impl AdvancedSearchMatcher {
    fn new(filters: &ListFilters) -> Option<Self> {
        let term = filters.advanced_search.as_deref()?.trim();
        if term.is_empty() {
            return None;
        }

        if filters.advanced_regex {
            return Some(
                RegexBuilder::new(term)
                    .case_insensitive(!filters.advanced_case_sensitive)
                    .build()
                    .map(|regex| Self::Regex {
                        regex,
                        negative: filters.advanced_negative,
                    })
                    .unwrap_or(Self::Always(!filters.advanced_negative)),
            );
        }

        Some(Self::Plain {
            needle: if filters.advanced_case_sensitive {
                term.to_string()
            } else {
                term.to_ascii_lowercase()
            },
            case_sensitive: filters.advanced_case_sensitive,
            negative: filters.advanced_negative,
        })
    }

    fn matches(&self, cached: &CachedSummary, search_headers: bool) -> bool {
        match self {
            Self::Plain {
                needle,
                case_sensitive,
                negative,
            } => {
                let matched = if *case_sensitive {
                    cached.advanced_haystack.contains(needle)
                        || (search_headers && cached.header_haystack.contains(needle))
                } else {
                    cached.advanced_haystack_lower.contains(needle)
                        || (search_headers && cached.header_haystack_lower.contains(needle))
                };
                if *negative {
                    !matched
                } else {
                    matched
                }
            }
            Self::Regex { regex, negative } => {
                let matched = regex.is_match(&cached.advanced_haystack)
                    || (search_headers
                        && !cached.header_haystack.is_empty()
                        && regex.is_match(&cached.header_haystack));
                if *negative {
                    !matched
                } else {
                    matched
                }
            }
            Self::Always(value) => *value,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use chrono::{Duration, Utc};

    use super::*;
    use crate::model::{BodyEncoding, HeaderRecord, MessageRecord, TransactionRecord};

    fn test_record(host: &str) -> TransactionRecord {
        test_record_with_scheme(host, "https")
    }

    fn test_record_with_scheme(host: &str, scheme: &str) -> TransactionRecord {
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
            Utc::now(),
            "GET".into(),
            scheme.into(),
            host.into(),
            "/".into(),
            Some(200),
            1,
            message.clone(),
            Some(message),
            Vec::new(),
            None,
            None,
        )
    }

    #[test]
    fn history_size_format_matches_ui_rounding_and_unit_boundaries() {
        for (bytes, expected) in [
            (0, "0 B"),
            (512, "512 B"),
            (1023, "1023 B"),
            (1024, "1.0 KB"),
            (1279, "1.2 KB"),
            (1280, "1.3 KB"),
            (1281, "1.3 KB"),
            (10239, "10.0 KB"),
            (10240, "10 KB"),
            (10751, "10 KB"),
            (10752, "11 KB"),
            (10753, "11 KB"),
            (1048575, "1024 KB"),
            (1048576, "1.0 MB"),
            (1310720, "1.3 MB"),
            (11010048, "11 MB"),
            (1073741824, "1.0 GB"),
            (1342177280, "1.3 GB"),
        ] {
            assert_eq!(format_size(bytes), expected, "{bytes} bytes");
        }
    }

    #[test]
    fn history_size_search_matches_displayed_half_unit_values() {
        for (bytes, displayed) in [(1280, "1.3 KB"), (10752, "11 KB"), (512, "512 B")] {
            let mut summary = test_record("example.com").summary();
            summary.request_bytes = bytes;
            summary.response_bytes = 0;
            let cached = CachedSummary::new(summary);
            assert!(matches_filters(
                &cached,
                Some(&displayed.to_ascii_lowercase()),
                None,
                None,
                None,
                None,
                None,
                None,
                &ListFilters::default(),
                None,
                false,
            ));
        }
    }

    #[test]
    fn history_since_parser_rejects_nonpositive_and_unusable_cutoffs() {
        for since in [
            "+1h",
            "9223372036854775807h",
            "9223372036854775807s",
            "999999999d",
            "-1h",
            "0s",
            "00m",
            "000h",
            "0d",
            "1.5h",
            "2026-02-30",
            " ",
        ] {
            assert!(parse_history_since(since).is_none(), "{since}");
        }
    }

    #[test]
    fn history_since_parser_retains_cutoffs_for_valid_inputs() {
        let old = chrono::DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut summary = test_record("example.com").summary();
        summary.started_at = old;
        let cached = CachedSummary::new(summary);
        for since in ["1h", "30m", "2d", "60s", " 1h ", "01h", "2026-01-01"] {
            let cutoff = parse_history_since(since).expect(since);
            assert!(!matches_filters(
                &cached,
                None,
                None,
                None,
                None,
                Some(&cutoff),
                None,
                None,
                &ListFilters::default(),
                None,
                false,
            ));
        }
        let midnight = parse_history_since("2026-01-01").unwrap();
        assert_eq!(parse_history_since("2026-01-01T00:00:00Z"), Some(midnight));
        assert_eq!(
            parse_history_since("2026-01-01T05:30:00+05:30"),
            Some(midnight)
        );
        // Keep the pre-existing parser contract for callers outside history reads.
        assert!(parse_since("0s").is_some());
    }

    mod service_map_body_tests {
        use super::*;
        use crate::service_map::{evidence_id, EvidenceKey};
        use crate::service_map_body::{ServiceMapBodyReferences, MAX_SERIALIZED_ROW_BYTES};
        use std::time::Duration as WaitDuration;

        fn body_record(body: &str, sequence: u64) -> TransactionRecord {
            let mut record = test_record("source.example.com");
            record.sequence = sequence;
            let response = record.response.as_mut().unwrap();
            response.content_type = Some("text/html".into());
            response.body_preview = body.into();
            response.body_size = body.len();
            record
        }

        async fn fixture_store(
            records: &[TransactionRecord],
            lazy: bool,
        ) -> (Arc<TransactionStore>, PathBuf) {
            let dir = std::env::temp_dir().join(format!("sniper-passive-body-{}", Uuid::new_v4()));
            fs::create_dir_all(&dir).unwrap();
            let store = Arc::new(TransactionStore::from_records_with_journal(
                records.iter().rev().cloned().collect(),
                dir.join("transactions.journal"),
                None,
            ));
            if lazy {
                let locators = crate::session::write_transactions_file_for_test_returning_locators(
                    &dir, records,
                )
                .unwrap();
                store.adopt_written_locators(locators).await;
            }
            (store, dir)
        }

        async fn token(store: &TransactionStore, session: Uuid, sequence: u64) -> String {
            let inner = store.inner.read().await;
            let index = inner
                .entries
                .binary_search_by_key(&sequence, |r| r.sequence)
                .unwrap();
            evidence_id(
                session,
                store.saved_cursor_generation,
                inner.body_generations[index],
                &inner.entries[index],
            )
        }

        async fn packet(
            store: &TransactionStore,
            session: Uuid,
            id: &str,
            variant: crate::service_map_packet::PacketVariant,
        ) -> serde_json::Value {
            let permit = Arc::new(tokio::sync::Semaphore::new(1))
                .acquire_owned()
                .await
                .unwrap();
            let read = store.service_map_packet(session, id, variant, permit).await;
            serde_json::from_slice(&read.bytes).unwrap()
        }

        #[tokio::test]
        async fn exact_packet_pairs_current_and_original_on_resident_and_disk_without_private_fields(
        ) {
            use crate::service_map_packet::PacketVariant::{Current, Original};
            for lazy in [false, true] {
                let mut record = body_record("current response", 9_007_199_254_740_993);
                record.host = "example.com:443".into();
                record.http_version = Some("HTTP/2.0".into());
                record.original_request = Some(record.request.clone());
                record.original_method = Some("PUT".into());
                record.original_path = Some("/before".into());
                record.original_response = record.response.clone();
                record.original_response.as_mut().unwrap().body_preview = "before response".into();
                record.original_response.as_mut().unwrap().body_size = "before response".len();
                record.notes = vec!["private system note".into()];
                record.user_note = Some("private manual note".into());
                let (store, dir) = fixture_store(&[record.clone()], lazy).await;
                let session = Uuid::new_v4();
                let id = token(&store, session, record.sequence).await;
                let current = packet(&store, session, &id, Current).await;
                assert_eq!(current["source"]["sequence"], "9007199254740993");
                assert_eq!(
                    current["request"]["message"]["authority"],
                    "example.com:443"
                );
                assert_eq!(current["request"]["message"]["body"]["body_preview"], "");
                assert_eq!(
                    current["response"]["message"]["body"]["body_preview"],
                    "current response"
                );
                assert!(current["response"]["message"]["http_version"].is_null());
                let original = packet(&store, session, &id, Original).await;
                assert_eq!(original["request"]["message"]["method"], "PUT");
                assert_eq!(
                    original["response"]["message"]["body"]["body_preview"],
                    "before response"
                );
                assert!(original["request"]["message"]["authority"].is_null());
                assert!(original["response"]["message"]["status_code"].is_null());
                assert!(!current.to_string().contains("private"));
                store
                    .update_annotations(record.id, None, Some(Some("later private note".into())))
                    .await
                    .unwrap();
                assert_eq!(
                    packet(&store, session, &id, Current).await["available"],
                    true
                );
                drop(store);
                fs::remove_dir_all(dir).unwrap();
            }
        }

        #[tokio::test]
        async fn exact_packet_missing_disk_keeps_headers_and_proven_decoded_empty_not_unknown_body()
        {
            use crate::service_map_packet::PacketVariant::Current;
            let mut record = body_record("response content", 1);
            record.request.content_decoded = true;
            record.request.decoded_body_size = Some(0);
            record.request.body_size = 20;
            record
                .response
                .as_mut()
                .unwrap()
                .headers
                .push(HeaderRecord {
                    name: "Server".into(),
                    value: "example".into(),
                });
            let (store, dir) = fixture_store(&[record], true).await;
            let session = Uuid::new_v4();
            let id = token(&store, session, 1).await;
            fs::remove_file(dir.join("transactions.ndjson")).unwrap();
            let result = packet(&store, session, &id, Current).await;
            assert_eq!(result["available"], true);
            assert_eq!(result["request"]["message"]["body"]["available"], true);
            assert_eq!(result["request"]["message"]["body"]["body_preview"], "");
            assert_eq!(
                result["response"]["message"]["headers"][0]["value"],
                "example"
            );
            assert_eq!(
                result["response"]["message"]["body"]["reason"],
                "body_storage_unavailable"
            );
            assert!(result["response"]["message"]["body"]["body_preview"].is_null());
            drop(store);
            fs::remove_dir_all(dir).unwrap();
        }

        #[tokio::test]
        async fn exact_packet_duplicate_uuid_never_borrows_newer_body() {
            use crate::service_map_packet::PacketVariant::Current;
            for lazy in [false, true] {
                let first = body_record("older", 1);
                let mut second = body_record("newer", 2);
                second.id = first.id;
                let (store, dir) = fixture_store(&[first, second], lazy).await;
                let session = Uuid::new_v4();
                let id = token(&store, session, 1).await;
                let result = packet(&store, session, &id, Current).await;
                assert_eq!(result["available"], true);
                let body = &result["response"]["message"]["body"];
                if lazy {
                    assert_eq!(body["available"], false);
                    assert!(body["body_preview"].is_null());
                } else {
                    assert_eq!(body["body_preview"], "older");
                }
                let key = EvidenceKey::parse(&id).unwrap();
                store
                    .inner
                    .write()
                    .await
                    .unresolved_body_generations
                    .insert(key.revision);
                assert_eq!(
                    packet(&store, session, &id, Current).await["response"]["message"]["body"]
                        ["reason"],
                    "body_identity_unverifiable"
                );
                drop(store);
                fs::remove_dir_all(dir).unwrap();
            }
        }

        #[tokio::test]
        async fn exact_packet_rejects_invalid_session_generation_and_revised_keys() {
            use crate::service_map_packet::PacketVariant::Current;
            let record = body_record("retained", 1);
            let (store, dir) = fixture_store(&[record.clone()], false).await;
            let session = Uuid::new_v4();
            let id = token(&store, session, 1).await;
            assert_eq!(
                packet(&store, session, "bad", Current).await["reason"],
                "invalid_evidence_id"
            );
            assert_eq!(
                packet(&store, Uuid::new_v4(), &id, Current).await["reason"],
                "session_mismatch"
            );
            let replacement = TransactionStore::from_records(vec![record.clone()]);
            assert_eq!(
                packet(&replacement, session, &id, Current).await["reason"],
                "stale_generation"
            );
            store
                .update_record(record.id, |row| row.path = "/changed".into())
                .await
                .unwrap();
            let result = packet(&store, session, &id, Current).await;
            assert_eq!(result["reason"], "record_changed");
            assert!(result["request"].is_null() && result["response"].is_null());
            drop(store);
            fs::remove_dir_all(dir).unwrap();
        }

        #[tokio::test]
        async fn exact_packet_disk_limits_identity_and_missing_preview_are_distinct() {
            use crate::service_map_packet::PacketVariant::Current;
            for case in [
                "oversized",
                "wrong_id",
                "wrong_sequence",
                "malformed",
                "invalid_utf8",
                "missing_preview",
            ] {
                let record = body_record("retained response", 1);
                let (store, dir) = fixture_store(&[record.clone()], true).await;
                let session = Uuid::new_v4();
                let id = token(&store, session, 1).await;
                let mut value = serde_json::to_value(&record).unwrap();
                match case {
                    "wrong_id" => value["id"] = serde_json::json!(Uuid::new_v4()),
                    "wrong_sequence" => value["sequence"] = serde_json::json!(2),
                    "missing_preview" => {
                        value["response"]
                            .as_object_mut()
                            .unwrap()
                            .remove("body_preview");
                    }
                    _ => {}
                }
                let bytes = match case {
                    "malformed" => b"{".to_vec(),
                    "invalid_utf8" => b"{\"ignored\":\"\xff\"}".to_vec(),
                    _ => serde_json::to_vec(&value).unwrap(),
                };
                fs::write(dir.join("transactions.ndjson"), &bytes).unwrap();
                store
                    .set_body_locator_for_test(
                        record.id,
                        crate::session::BodyLocator {
                            offset: 0,
                            len: if case == "oversized" {
                                (MAX_SERIALIZED_ROW_BYTES + 1) as u32
                            } else {
                                bytes.len() as u32
                            },
                        },
                    )
                    .await;
                let result = packet(&store, session, &id, Current).await;
                match case {
                    "oversized" => {
                        assert_eq!(result["reason"], "serialized_row_limit");
                        assert!(result["request"].is_null());
                    }
                    "wrong_id" | "wrong_sequence" => {
                        assert_eq!(result["reason"], "body_identity_unverifiable");
                        assert!(result["response"].is_null());
                    }
                    "missing_preview" => assert_eq!(
                        result["response"]["message"]["body"]["reason"],
                        "retained_preview_unavailable"
                    ),
                    _ => assert_eq!(
                        result["response"]["message"]["body"]["reason"],
                        "malformed_retained_row"
                    ),
                }
                drop(store);
                fs::remove_dir_all(dir).unwrap();
            }
        }

        #[tokio::test]
        async fn exact_packet_worker_and_late_publication_fences_reject_record_and_file_changes() {
            use crate::service_map_packet::PacketVariant::Current;
            for mutation in ["record", "file", "delete"] {
                let record = body_record("retained", 1);
                let (store, dir) = fixture_store(&[record.clone()], true).await;
                let session = Uuid::new_v4();
                let id = token(&store, session, 1).await;
                let permit = Arc::new(tokio::sync::Semaphore::new(1))
                    .acquire_owned()
                    .await
                    .unwrap();
                let read = store
                    .service_map_packet(session, &id, Current, permit)
                    .await;
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&read.bytes).unwrap()["available"],
                    true
                );
                match mutation {
                    "record" => {
                        store
                            .update_record(record.id, |row| row.path = "/changed".into())
                            .await
                            .unwrap();
                    }
                    "file" => {
                        let locators =
                            crate::session::write_transactions_file_for_test_returning_locators(
                                &dir,
                                &[record],
                            )
                            .unwrap();
                        store.adopt_written_locators(locators).await;
                    }
                    "delete" => {
                        store.inner.write().await.entries.clear();
                    }
                    _ => unreachable!(),
                }
                assert!(
                    store
                        .service_map_packet_source_status(session, &id, &read)
                        .await
                        .is_err(),
                    "{mutation}"
                );
                drop(store);
                fs::remove_dir_all(dir).unwrap();
            }
            let record = body_record("retained", 1);
            let (store, dir) = fixture_store(&[record.clone()], true).await;
            let session = Uuid::new_v4();
            let id = token(&store, session, 1).await;
            let (hook, ready, release) = barrier("after_open");
            let worker_store = store.clone();
            let worker_id = id.clone();
            let task = tokio::spawn(async move {
                let permit = Arc::new(tokio::sync::Semaphore::new(1))
                    .acquire_owned()
                    .await
                    .unwrap();
                worker_store
                    .service_map_packet_inner(session, &worker_id, Current, permit, Some(hook))
                    .await
            });
            ready.await.unwrap();
            let locators = crate::session::write_transactions_file_for_test_returning_locators(
                &dir,
                &[record],
            )
            .unwrap();
            store.adopt_written_locators(locators).await;
            release.send(()).unwrap();
            let result: serde_json::Value =
                serde_json::from_slice(&task.await.unwrap().bytes).unwrap();
            assert_eq!(result["reason"], "body_identity_unverifiable");
            assert!(result["response"].is_null());
            drop(store);
            fs::remove_dir_all(dir).unwrap();
        }

        #[tokio::test]
        async fn exact_packet_dropped_owner_keeps_running_worker_permit_until_exit() {
            let record = body_record("retained", 1);
            let (store, dir) = fixture_store(&[record], false).await;
            let session = Uuid::new_v4();
            let id = token(&store, session, 1).await;
            let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let (hook, ready, release) = barrier("started");
            let worker = store.clone();
            let task = tokio::spawn(async move {
                worker
                    .service_map_packet_inner(
                        session,
                        &id,
                        crate::service_map_packet::PacketVariant::Current,
                        permit,
                        Some(hook),
                    )
                    .await
            });
            ready.await.unwrap();
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            assert!(semaphore.clone().try_acquire_owned().is_err());
            release.send(()).unwrap();
            let permit = tokio::time::timeout(WaitDuration::from_secs(5), semaphore.acquire())
                .await
                .unwrap()
                .unwrap();
            drop(permit);
            drop(store);
            fs::remove_dir_all(dir).unwrap();
        }

        #[tokio::test]
        async fn exact_socket_peer_reads_remain_metadata_only_with_missing_body_storage() {
            use crate::model::{ObservedSocketPeer, ObservedSocketPeerRoute};
            let mut record = body_record("retained synthetic body", 1);
            record.observed_socket_peer = Some(ObservedSocketPeer::from_remote_addr(
                record.started_at,
                ObservedSocketPeerRoute::HttpProxy,
                Some("198.51.100.7:8080".parse().unwrap()),
            ));
            let (store, dir) = fixture_store(&[record.clone()], true).await;
            let session = Uuid::new_v4();
            let id = token(&store, session, 1).await;
            fs::remove_file(dir.join("transactions.ndjson")).unwrap();
            let evidence = store
                .service_map_evidence_with_socket_peer(session, &id, true)
                .await;
            assert!(evidence.available);
            let observation = evidence.socket_peer.unwrap().observation.unwrap();
            assert_eq!(observation.address.unwrap().ip.to_string(), "198.51.100.7");
            assert!(store.inner.read().await.entries[0]
                .response
                .as_ref()
                .unwrap()
                .body_preview
                .is_empty());
            crate::session::write_transactions_file_for_test_returning_locators(
                &dir,
                &[record.clone()],
            )
            .unwrap();
            assert!(store
                .update_record(record.id, |row| row.path = "/changed".into())
                .await
                .is_some());
            let stale = store
                .service_map_evidence_with_socket_peer(session, &id, true)
                .await;
            assert!(!stale.available);
            assert!(stale.socket_peer.is_none());
            drop(store);
            fs::remove_dir_all(dir).unwrap();
        }

        fn barrier(
            stage: &'static str,
        ) -> (
            ServiceMapBodyReadHook,
            oneshot::Receiver<()>,
            mpsc::Sender<()>,
        ) {
            let (ready, started) = oneshot::channel();
            let ready = Mutex::new(Some(ready));
            let (release, wait) = mpsc::channel();
            let wait = Mutex::new(wait);
            let hook = Arc::new(move |current: &str| {
                if current == stage {
                    ready.lock().unwrap().take().unwrap().send(()).unwrap();
                    wait.lock()
                        .unwrap()
                        .recv_timeout(WaitDuration::from_secs(10))
                        .unwrap();
                }
            });
            (hook, started, release)
        }

        fn paused_read(
            store: Arc<TransactionStore>,
            session: Uuid,
            token: String,
            hook: ServiceMapBodyReadHook,
        ) -> tokio::task::JoinHandle<ServiceMapBodyReferences> {
            tokio::spawn(async move {
                store
                    .service_map_body_references_impl(session, &token, Some(hook))
                    .await
            })
        }

        #[tokio::test]
        async fn explicit_body_read_distinguishes_resident_and_lazy_duplicate_rows() {
            let first = body_record("https://older.example.com/private?secret=one ", 1);
            let mut second = body_record("https://newer.example.com/private?secret=two ", 2);
            second.id = first.id;
            let (store, dir) = fixture_store(&[first, second], false).await;
            let snapshot = store.snapshot_for_persistence(None).await.unwrap();
            let staged = dir.join("replacement");
            fs::create_dir_all(&staged).unwrap();
            // The fixture writer uses last-wins UUID locators, so give it
            // oldest-first rows. Production streaming uses newest-first and
            // first-wins locators; both must select the same authoritative row.
            let records: Vec<_> = snapshot
                .iter()
                .rev()
                .map(|(record, _)| record.clone())
                .collect();
            let locators = crate::session::write_transactions_file_for_test_returning_locators(
                &staged, &records,
            )
            .unwrap();
            let publisher = store.clone();
            let destination = dir.join("transactions.ndjson");
            tokio::task::spawn_blocking(move || {
                publisher.publish_persistence_snapshot(&snapshot, locators, || {
                    crate::platform::rename(&staged.join("transactions.ndjson"), &destination)
                })
            })
            .await
            .unwrap()
            .unwrap();
            let session = Uuid::new_v4();
            let older_token = token(&store, session, 1).await;
            let newer_token = token(&store, session, 2).await;
            let older = store
                .service_map_body_references(session, &older_token)
                .await;
            let newer = store
                .service_map_body_references(session, &newer_token)
                .await;
            assert_eq!(
                older.references[0].target_origin,
                "https://older.example.com"
            );
            assert_eq!(
                newer.references[0].target_origin,
                "https://newer.example.com"
            );
            let inner = store.inner.read().await;
            assert!(!inner.entries[0]
                .response
                .as_ref()
                .unwrap()
                .body_preview
                .is_empty());
            assert!(inner.entries[1]
                .response
                .as_ref()
                .unwrap()
                .body_preview
                .is_empty());
            drop(inner);
            drop(store);
            fs::remove_dir_all(dir).unwrap();
        }

        #[tokio::test]
        async fn explicit_body_read_rejects_invalid_session_generation_and_revision_tokens() {
            let record = body_record("https://example.com/ ", 1);
            let (store, dir) = fixture_store(&[record.clone()], false).await;
            let session = Uuid::new_v4();
            let id = token(&store, session, 1).await;
            assert_eq!(
                store
                    .service_map_body_references(session, "bad")
                    .await
                    .reasons,
                ["invalid_evidence_id"]
            );
            assert_eq!(
                store
                    .service_map_body_references(Uuid::new_v4(), &id)
                    .await
                    .reasons,
                ["session_mismatch"]
            );
            let replacement = TransactionStore::from_records(vec![record.clone()]);
            assert_eq!(
                replacement
                    .service_map_body_references(session, &id)
                    .await
                    .reasons,
                ["stale_generation"]
            );
            store
                .update_record(record.id, |r| {
                    r.response.as_mut().unwrap().body_preview =
                        "https://changed.example.com/ ".into()
                })
                .await
                .unwrap();
            assert_eq!(
                store
                    .service_map_body_references(session, &id)
                    .await
                    .reasons,
                ["record_changed"]
            );
            drop(store);
            fs::remove_dir_all(dir).unwrap();
        }

        #[tokio::test]
        async fn explicit_body_read_fails_closed_for_oversized_wrong_missing_and_malformed_disk_rows(
        ) {
            for case in [
                "oversized",
                "wrong_locator",
                "missing_file",
                "malformed_json",
                "malformed_utf8",
                "wrong_sequence",
                "missing_preview",
            ] {
                let first = body_record("https://first.example.com/ ", 1);
                let second = body_record("https://second.example.com/ ", 2);
                let (store, dir) = fixture_store(&[first.clone(), second.clone()], true).await;
                let session = Uuid::new_v4();
                let id = token(&store, session, 1).await;
                let expected = match case {
                    "oversized" => {
                        store
                            .set_body_locator_for_test(
                                first.id,
                                crate::session::BodyLocator {
                                    offset: u64::MAX,
                                    len: (MAX_SERIALIZED_ROW_BYTES + 1) as u32,
                                },
                            )
                            .await;
                        "serialized_row_limit"
                    }
                    "wrong_locator" => {
                        let locator = store.inner.read().await.locators[&second.id];
                        store.set_body_locator_for_test(first.id, locator).await;
                        "body_identity_unverifiable"
                    }
                    "missing_file" => {
                        fs::remove_file(dir.join("transactions.ndjson")).unwrap();
                        "body_storage_unavailable"
                    }
                    case => {
                        let mut value = serde_json::to_value(&first).unwrap();
                        let bytes = match case {
                            "malformed_json" => b"{not json}".to_vec(),
                            "malformed_utf8" => {
                                // Put invalid UTF-8 in an ignored request field:
                                // malformed bytes must not bypass the projection.
                                let mut bytes = serde_json::to_vec(&first).unwrap();
                                let needle = b"\"body_preview\":\"\"";
                                let start = bytes
                                    .windows(needle.len())
                                    .position(|part| part == needle)
                                    .unwrap();
                                bytes.insert(start + needle.len() - 1, 0xff);
                                bytes
                            }
                            "wrong_sequence" => {
                                value["sequence"] = 0.into();
                                serde_json::to_vec(&value).unwrap()
                            }
                            "missing_preview" => {
                                value["response"]
                                    .as_object_mut()
                                    .unwrap()
                                    .remove("body_preview");
                                serde_json::to_vec(&value).unwrap()
                            }
                            _ => unreachable!(),
                        };
                        fs::write(dir.join("transactions.ndjson"), &bytes).unwrap();
                        store
                            .set_body_locator_for_test(
                                first.id,
                                crate::session::BodyLocator {
                                    offset: 0,
                                    len: bytes.len() as u32,
                                },
                            )
                            .await;
                        match case {
                            "wrong_sequence" => "body_identity_unverifiable",
                            "missing_preview" => "retained_preview_unavailable",
                            _ => "malformed_retained_row",
                        }
                    }
                };
                let result = store.service_map_body_references(session, &id).await;
                assert!(!result.available, "{case}");
                assert!(result.references.is_empty(), "{case}");
                assert_eq!(result.reasons, [expected], "{case}");
                // The normal map and metadata evidence remain independent of
                // body storage, including missing/corrupt files and bad locators.
                assert_eq!(store.service_map_snapshot(session, 10).await.rows.len(), 2);
                assert!(store.service_map_evidence(session, &id).await.available);
                drop(store);
                fs::remove_dir_all(dir).unwrap();
            }
        }

        #[tokio::test]
        async fn explicit_body_read_rejects_unresolved_and_nonresident_older_duplicate() {
            let first = body_record("https://older.example.com/ ", 1);
            let mut second = body_record("https://newer.example.com/ ", 2);
            second.id = first.id;
            // A legacy-loaded older duplicate has no authoritative locator.
            let (store, dir) = fixture_store(&[first, second], true).await;
            let session = Uuid::new_v4();
            let id = token(&store, session, 1).await;
            assert_eq!(
                store
                    .service_map_body_references(session, &id)
                    .await
                    .reasons,
                ["retained_preview_unavailable"]
            );
            let key = EvidenceKey::parse(&id).unwrap();
            store
                .inner
                .write()
                .await
                .unresolved_body_generations
                .insert(key.revision);
            assert_eq!(
                store
                    .service_map_body_references(session, &id)
                    .await
                    .reasons,
                ["body_identity_unverifiable"]
            );
            drop(store);
            fs::remove_dir_all(dir).unwrap();
        }

        #[tokio::test]
        async fn explicit_body_read_resident_and_lazy_reject_deletion_retention_and_mutation_races()
        {
            for lazy in [false, true] {
                for mutation in ["delete", "retention", "body"] {
                    let first = body_record("https://before.example.com/ ", 1);
                    let (store, dir) = fixture_store(&[first.clone()], lazy).await;
                    let session = Uuid::new_v4();
                    let id = token(&store, session, 1).await;
                    let (hook, started, release) = barrier("after_scan");
                    let reading = paused_read(store.clone(), session, id, hook);
                    tokio::time::timeout(WaitDuration::from_secs(10), started)
                        .await
                        .unwrap()
                        .unwrap();
                    // If the reader held the store lock during file/scan work,
                    // these real mutations would deadlock at this barrier.
                    let expected = match mutation {
                        "delete" => {
                            assert_eq!(store.delete_ids(&[first.id]).await.unwrap(), 1);
                            "record_missing"
                        }
                        "retention" => {
                            assert_eq!(
                                store
                                    .trim_retention(0, &HashSet::new(), 10)
                                    .await
                                    .unwrap()
                                    .deleted_ids,
                                [first.id]
                            );
                            "record_missing"
                        }
                        _ => {
                            store
                                .update_record(first.id, |r| {
                                    r.response.as_mut().unwrap().body_preview =
                                        "https://after.example.com/ ".into()
                                })
                                .await
                                .unwrap();
                            "record_changed"
                        }
                    };
                    release.send(()).unwrap();
                    let result = reading.await.unwrap();
                    assert!(!result.available, "{lazy} {mutation}");
                    assert_eq!(result.reasons, [expected], "{lazy} {mutation}");
                    drop(store);
                    fs::remove_dir_all(dir).unwrap();
                }
            }
        }

        #[tokio::test]
        async fn explicit_body_read_annotations_keep_evidence_valid_during_scan() {
            for lazy in [false, true] {
                let record = body_record("https://example.com/ ", 1);
                let (store, dir) = fixture_store(&[record.clone()], lazy).await;
                let session = Uuid::new_v4();
                let id = token(&store, session, 1).await;
                let (hook, started, release) = barrier("after_scan");
                let reading = paused_read(store.clone(), session, id, hook);
                started.await.unwrap();
                store
                    .update_annotations(record.id, None, Some(Some("note".into())))
                    .await
                    .unwrap();
                release.send(()).unwrap();
                assert!(reading.await.unwrap().complete);
                drop(store);
                fs::remove_dir_all(dir).unwrap();
            }
        }

        #[tokio::test]
        async fn explicit_body_read_rejects_atomic_publication_before_and_after_disk_scan() {
            for stage in ["after_open", "after_scan"] {
                let record = body_record("https://example.com/ ", 1);
                let (store, dir) = fixture_store(&[record.clone()], true).await;
                let session = Uuid::new_v4();
                let id = token(&store, session, 1).await;
                let snapshot = store.snapshot_for_persistence(None).await.unwrap();
                let staged = dir.join("replacement");
                fs::create_dir_all(&staged).unwrap();
                let locators = crate::session::write_transactions_file_for_test_returning_locators(
                    &staged,
                    &[record],
                )
                .unwrap();
                let (hook, started, release) = barrier(stage);
                let reading = paused_read(store.clone(), session, id.clone(), hook);
                started.await.unwrap();
                let publisher = store.clone();
                let destination = dir.join("transactions.ndjson");
                tokio::task::spawn_blocking(move || {
                    publisher.publish_persistence_snapshot(&snapshot, locators, || {
                        crate::platform::rename(&staged.join("transactions.ndjson"), &destination)
                    })
                })
                .await
                .unwrap()
                .unwrap();
                release.send(()).unwrap();
                let result = reading.await.unwrap();
                assert_eq!(result.reasons, ["body_identity_unverifiable"], "{stage}");
                assert!(result.references.is_empty());
                // A fresh explicit read uses the adopted locator/file generation.
                assert!(
                    store
                        .service_map_body_references(session, &id)
                        .await
                        .complete
                );
                drop(store);
                fs::remove_dir_all(dir).unwrap();
            }
        }

        #[tokio::test]
        async fn explicit_body_read_rejects_base64_from_invalid_utf8_capture() {
            let mut record = body_record("", 1);
            let mut headers = http::HeaderMap::new();
            headers.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("text/html"),
            );
            record.response = Some(MessageRecord::from_headers_and_body(
                &headers,
                &[0xff, 0xfe, 0xfd],
                100,
            ));
            assert_eq!(
                record.response.as_ref().unwrap().body_encoding,
                BodyEncoding::Base64
            );
            let (store, dir) = fixture_store(&[record], false).await;
            let session = Uuid::new_v4();
            let id = token(&store, session, 1).await;
            let result = store.service_map_body_references(session, &id).await;
            assert_eq!(result.status, "unsupported");
            assert_eq!(result.reasons, ["unsupported_body_encoding"]);
            assert!(!result.available);
            drop(store);
            fs::remove_dir_all(dir).unwrap();
        }
        fn paused_html_read(
            store: Arc<TransactionStore>,
            session: Uuid,
            token: String,
            hook: ServiceMapBodyReadHook,
        ) -> tokio::task::JoinHandle<crate::service_map_html::ServiceMapHtmlGenerators> {
            tokio::spawn(async move {
                store
                    .service_map_html_generators_impl(session, &token, Some(hook))
                    .await
            })
        }

        fn peer_record(host: &str, sequence: u64, address: &str) -> TransactionRecord {
            let mut row = body_record("PRIVATE_RESPONSE_BODY", sequence);
            row.host = host.into();
            row.path = "/PRIVATE_PATH?token=PRIVATE_QUERY".into();
            row.observed_socket_peer = Some(crate::model::ObservedSocketPeer::from_remote_addr(
                row.started_at + chrono::Duration::milliseconds(sequence as i64),
                crate::model::ObservedSocketPeerRoute::Direct,
                Some(address.parse().unwrap()),
            ));
            row
        }

        #[tokio::test]
        async fn peer_matches_compare_typed_family_route_port_and_diagnostic_buckets() {
            use crate::model::{ObservedSocketPeerReason, ObservedSocketPeerRoute, TrafficKind};
            let source = peer_record("source.example.com", 1, "198.51.100.7:443");
            let mut rows = vec![
                source.clone(),
                peer_record("other.example.com", 2, "198.51.100.7:443"),
            ];
            for (seq, address) in [
                (3, "198.51.100.8:443"),
                (4, "198.51.100.7:8443"),
                (5, "[::ffff:198.51.100.7]:443"),
            ] {
                rows.push(peer_record("different.example.com", seq, address));
            }
            for (seq, route) in [
                (6, ObservedSocketPeerRoute::HttpProxy),
                (7, ObservedSocketPeerRoute::SocksProxy),
                (8, ObservedSocketPeerRoute::Unknown),
            ] {
                let mut row = source.clone();
                row.sequence = seq;
                row.id = Uuid::new_v4();
                row.observed_socket_peer.as_mut().unwrap().route = route;
                rows.push(row);
            }
            let mut row = source.clone();
            row.sequence = 9;
            row.observed_socket_peer = None;
            rows.push(row);
            let mut row = source.clone();
            row.sequence = 10;
            row.observed_socket_peer.as_mut().unwrap().address = None;
            row.observed_socket_peer.as_mut().unwrap().reason =
                Some(ObservedSocketPeerReason::RemoteAddrUnavailable);
            rows.push(row);
            let mut row = source.clone();
            row.sequence = 11;
            row.observed_socket_peer.as_mut().unwrap().reason =
                Some(ObservedSocketPeerReason::RemoteAddrUnavailable);
            rows.push(row);
            let mut row = source.clone();
            row.sequence = 12;
            row.kind = TrafficKind::Tunnel;
            rows.push(row);
            let mut row = source.clone();
            row.sequence = 13;
            row.method = "CONNECT".into();
            rows.push(row);
            let mut row = source.clone();
            row.sequence = 14;
            row.status = Some(101);
            rows.push(row);
            let mut row = source.clone();
            row.sequence = 15;
            row.host = "user:PRIVATE_CREDENTIAL@example.com".into();
            rows.push(row);
            let (store, dir) = fixture_store(&rows, false).await;
            let session = Uuid::new_v4();
            let id = token(&store, session, 1).await;
            let result = store
                .service_map_socket_peer_matches(session, &id, false, 100, &[], &[])
                .await;
            assert!(result.available && !result.complete);
            assert_eq!(result.counts.matching_rows, 1);
            assert_eq!(result.counts.different_peer_rows, 3);
            assert_eq!(result.counts.non_direct_rows, 3);
            assert_eq!(result.counts.not_recorded_rows, 1);
            assert_eq!(result.counts.unavailable_observation_rows, 1);
            assert_eq!(result.counts.invalid_observation_rows, 1);
            assert_eq!(result.counts.non_http_rows, 3);
            assert_eq!(result.counts.invalid_metadata_rows, 1);
            assert_eq!(result.reasons, ["invalid_metadata"]);
            assert_eq!(result.origins[0].origin, "https://other.example.com");
            assert!(result.validate_response(session, &id, false, 100));
            let text = serde_json::to_string(&result).unwrap();
            for secret in [
                "PRIVATE_RESPONSE_BODY",
                "PRIVATE_PATH",
                "PRIVATE_QUERY",
                "PRIVATE_CREDENTIAL",
            ] {
                assert!(!text.contains(secret));
            }
            let map = crate::service_map::build(
                session,
                store.service_map_snapshot(session, 100).await,
                100,
                false,
                None,
                &[],
                &[],
            );
            let ordinary = serde_json::to_string(&map).unwrap();
            assert!(!ordinary.contains("198.51.100.7") && !ordinary.contains("socket_peer"));
            drop(store);
            fs::remove_dir_all(dir).unwrap();
        }

        #[tokio::test]
        async fn peer_matches_reject_unusable_seed_addresses_and_source_contexts() {
            use crate::model::{ObservedSocketPeerReason, ObservedSocketPeerRoute};
            for address in [
                "0.0.0.0:443",
                "0.1.2.3:443",
                "169.254.1.2:443",
                "224.1.2.3:443",
                "255.255.255.255:443",
                "240.0.0.1:443",
                "198.51.100.7:0",
                "[::]:443",
                "[ff02::1]:443",
                "[fe80::1]:443",
                "[::ffff:169.254.1.2]:443",
                "[::ffff:0.1.2.3]:443",
                "[::ffff:224.1.2.3]:443",
            ] {
                let row = peer_record("example.com", 1, address);
                let store = TransactionStore::from_records(vec![row]);
                let session = Uuid::new_v4();
                let id = token(&store, session, 1).await;
                let result = store
                    .service_map_socket_peer_matches(session, &id, false, 10, &[], &[])
                    .await;
                assert_eq!(result.reasons, ["invalid_observation"], "{address}");
                assert!(
                    result.peer.is_none() && result.source.is_none() && result.origins.is_empty()
                );
                assert!(result.validate_response(session, &id, false, 10));
            }
            for reason in [
                "observation_not_recorded",
                "observation_unavailable",
                "non_direct_observation",
                "unsupported_source_context",
                "metadata_unavailable",
            ] {
                let mut row = peer_record("example.com", 1, "198.51.100.7:443");
                match reason {
                    "observation_not_recorded" => row.observed_socket_peer = None,
                    "observation_unavailable" => {
                        let o = row.observed_socket_peer.as_mut().unwrap();
                        o.address = None;
                        o.reason = Some(ObservedSocketPeerReason::RemoteAddrUnavailable);
                    }
                    "non_direct_observation" => {
                        row.observed_socket_peer.as_mut().unwrap().route =
                            ObservedSocketPeerRoute::Unknown
                    }
                    "unsupported_source_context" => row.status = Some(101),
                    _ => row.host = "x".repeat(513),
                }
                let store = TransactionStore::from_records(vec![row]);
                let session = Uuid::new_v4();
                let id = token(&store, session, 1).await;
                let result = store
                    .service_map_socket_peer_matches(session, &id, false, 10, &[], &[])
                    .await;
                assert_eq!(result.reasons, [reason]);
                assert!(result.validate_response(session, &id, false, 10));
            }
        }

        #[tokio::test]
        async fn peer_matches_duplicate_tokens_missing_bodies_and_reopened_generations() {
            let first = peer_record("older.example.com", 1, "[::ffff:198.51.100.7]:443");
            let mut second = peer_record("newer.example.com", 2, "[::ffff:198.51.100.7]:443");
            second.id = first.id;
            let (store, dir) = fixture_store(&[first.clone(), second.clone()], true).await;
            let session = Uuid::new_v4();
            let first_token = token(&store, session, 1).await;
            let second_token = token(&store, session, 2).await;
            fs::remove_file(dir.join("transactions.ndjson")).unwrap();
            {
                let mut inner = store.inner.write().await;
                for id in [&first_token, &second_token] {
                    inner
                        .unresolved_body_generations
                        .insert(EvidenceKey::parse(id).unwrap().revision);
                }
            }
            for (seed, sample) in [(&first_token, &second_token), (&second_token, &first_token)] {
                let result = store
                    .service_map_socket_peer_matches(session, seed, false, 10, &[], &[])
                    .await;
                assert!(result.available && result.complete);
                assert_eq!(result.origins[0].samples[0].evidence_id, *sample);
                assert!(result.validate_response(session, seed, false, 10));
            }
            let reopened = TransactionStore::from_records(vec![second, first]);
            assert_eq!(
                reopened
                    .service_map_socket_peer_matches(session, &first_token, false, 10, &[], &[])
                    .await
                    .reasons,
                ["stale_generation"]
            );
            assert_eq!(
                store
                    .service_map_socket_peer_matches(
                        Uuid::new_v4(),
                        &first_token,
                        false,
                        10,
                        &[],
                        &[]
                    )
                    .await
                    .reasons,
                ["session_mismatch"]
            );
            assert_eq!(
                store
                    .service_map_socket_peer_matches(session, "bad", false, 10, &[], &[])
                    .await
                    .reasons,
                ["invalid_evidence_id"]
            );
            drop(store);
            fs::remove_dir_all(dir).unwrap();
        }

        #[tokio::test]
        async fn peer_matches_scope_uses_original_authority_and_discloses_seed_outside_window() {
            let rows = [
                peer_record("0x7f000001", 1, "127.0.0.1:443"),
                peer_record("outside.example.com", 2, "127.0.0.1:443"),
                peer_record("0x7f000001", 3, "127.0.0.1:443"),
            ];
            let (store, dir) = fixture_store(&rows, false).await;
            let session = Uuid::new_v4();
            let id = token(&store, session, 1).await;
            let include = vec!["0x7f000001".into()];
            let result = store
                .service_map_socket_peer_matches(session, &id, true, 2, &include, &[])
                .await;
            assert!(result.available && !result.complete);
            assert!(!result.source.as_ref().unwrap().in_window);
            assert_eq!(result.source.as_ref().unwrap().origin, "https://127.0.0.1");
            assert_eq!(result.counts.scope_excluded_rows, 1);
            assert_eq!(result.counts.matching_rows, 1);
            assert_eq!(result.reasons, ["max_records", "source_outside_window"]);
            assert!(result.validate_response(session, &id, true, 2));
            let mut normalized = peer_record("127.0.0.1", 4, "127.0.0.1:443");
            normalized.id = Uuid::new_v4();
            store.insert(normalized).await;
            let all = store
                .service_map_socket_peer_matches(session, &id, false, 10, &include, &[])
                .await;
            let canonical_group = all
                .origins
                .iter()
                .find(|g| g.origin == "https://127.0.0.1")
                .unwrap();
            assert!(
                canonical_group.in_scope,
                "group scope is OR across original authorities"
            );
            assert_eq!(canonical_group.matching_rows, 2);
            assert!(all.validate_response(session, &id, false, 10));
            let excluded = store
                .service_map_socket_peer_matches(session, &id, true, 2, &[], &include)
                .await;
            assert_eq!(excluded.reasons, ["source_out_of_scope"]);
            assert!(excluded.peer.is_none());
            drop(store);
            fs::remove_dir_all(dir).unwrap();
        }

        #[tokio::test]
        async fn peer_matches_snapshot_fences_source_changes_without_body_identity_checks() {
            for mutation in ["delete", "retention", "peer", "path"] {
                let row = peer_record("example.com", 1, "198.51.100.7:443");
                let (store, dir) = fixture_store(&[row.clone()], false).await;
                let session = Uuid::new_v4();
                let id = token(&store, session, 1).await;
                let (hook, started, release) = barrier("after_snapshot");
                let reading_store = store.clone();
                let reading_id = id.clone();
                let reading = tokio::spawn(async move {
                    reading_store
                        .service_map_socket_peer_matches_impl(
                            session,
                            &reading_id,
                            false,
                            10,
                            &[],
                            &[],
                            Some(hook),
                        )
                        .await
                });
                tokio::time::timeout(WaitDuration::from_secs(10), started)
                    .await
                    .unwrap()
                    .unwrap();
                let expected = match mutation {
                    "delete" => {
                        store.delete_ids(&[row.id]).await.unwrap();
                        "record_missing"
                    }
                    "retention" => {
                        store.trim_retention(0, &HashSet::new(), 10).await.unwrap();
                        "record_missing"
                    }
                    "peer" => {
                        store
                            .update_record(row.id, |r| r.observed_socket_peer = None)
                            .await
                            .unwrap();
                        "record_changed"
                    }
                    _ => {
                        store
                            .update_record(row.id, |r| r.path = "/changed".into())
                            .await
                            .unwrap();
                        "record_changed"
                    }
                };
                release.send(()).unwrap();
                let result = reading.await.unwrap();
                assert_eq!(result.reasons, [expected]);
                assert!(result.peer.is_none() && result.origins.is_empty());
                assert_eq!(result.counts, Default::default());
                drop(store);
                fs::remove_dir_all(dir).unwrap();
            }
        }

        #[tokio::test]
        async fn peer_matches_caps_count_rows_without_unbounded_origin_sets() {
            for long_host in [false, true] {
                let mut rows = vec![peer_record("source.example.com", 1, "198.51.100.7:443")];
                for index in 0..500 {
                    let host = if long_host {
                        format!(
                            "{}.{}.{}.n{index}.example.com",
                            "a".repeat(63),
                            "b".repeat(63),
                            "c".repeat(63)
                        )
                    } else {
                        format!("n{index}.example.com")
                    };
                    for _ in 0..if long_host { 5 } else { 1 } {
                        rows.push(peer_record(
                            &host,
                            rows.len() as u64 + 1,
                            "198.51.100.7:443",
                        ));
                    }
                }
                let store = TransactionStore::from_records(rows.into_iter().rev().collect());
                let session = Uuid::new_v4();
                let id = token(&store, session, 1).await;
                let result = store
                    .service_map_socket_peer_matches(session, &id, false, 10_000, &[], &[])
                    .await;
                assert_eq!(
                    result.counts.matching_rows,
                    if long_host { 2500 } else { 500 }
                );
                assert!(result.counts.omitted_matching_rows > 0);
                assert!(result.origins.len() <= 100);
                assert!(result.origins.iter().all(|g| g.samples.len() <= 3));
                assert!(result.reasons.iter().any(|r| r
                    == if long_host {
                        "projection_byte_limit"
                    } else {
                        "origin_group_limit"
                    }));
                assert!(
                    serde_json::to_vec(&result).unwrap().len()
                        <= crate::service_map_peer_matches::MAX_PROJECTION_BYTES
                );
                assert!(result.validate_response(session, &id, false, 10_000));
            }
        }

        #[tokio::test]
        async fn peer_matches_high_cardinality_lock_duration_is_measured_with_bounded_work() {
            const ROWS: usize = 1000;
            let mut rows = Vec::new();
            for index in 0..ROWS {
                let mut row = peer_record(
                    &format!("n{index}.example.com"),
                    index as u64 + 1,
                    "198.51.100.7:443",
                );
                row.response.as_mut().unwrap().headers = vec![
                    HeaderRecord {
                        name: "X-Private".into(),
                        value: "H".repeat(4096)
                    };
                    8
                ];
                row.path = "/PRIVATE_OVERSIZED_PATH".repeat(1000);
                rows.push(row);
            }
            let store = TransactionStore::from_records(rows.into_iter().rev().collect());
            let session = Uuid::new_v4();
            let id = token(&store, session, 1).await;
            let prepared_scope = crate::scope::PreparedScope::new(&[], &[]);
            let locked = store.inner.read().await;
            let started = std::time::Instant::now();
            let result = crate::service_map_peer_matches::inspect_retained(
                session,
                store.saved_cursor_generation,
                &id,
                &locked.entries[0],
                locked
                    .entries
                    .iter()
                    .zip(locked.body_generations.iter().copied())
                    .rev(),
                500,
                false,
                &prepared_scope,
            );
            let lock_duration = started.elapsed();
            drop(locked);
            let serialized = serde_json::to_vec(&result).unwrap();
            eprintln!("recorded peer snapshot: retained_rows={ROWS}, considered_rows={}, matching_rows={}, returned_groups={}, exact_samples={}, projected_bytes={}, measured_read_lock_duration={lock_duration:?}, retained_header_bytes={}",result.snapshot.as_ref().unwrap().considered_rows,result.counts.matching_rows,result.origins.len(),result.counts.sample_rows,serialized.len(),ROWS*8*4096);
            assert_eq!(result.snapshot.as_ref().unwrap().considered_rows, 500);
            assert_eq!(result.counts.matching_rows, 500);
            assert_eq!(result.origins.len(), 100);
            assert_eq!(result.counts.sample_rows, 100);
            assert!(result.validate_response(session, &id, false, 500));
            assert!(serialized.len() <= crate::service_map_peer_matches::MAX_PROJECTION_BYTES);
        }

        #[tokio::test]
        async fn peer_matches_response_validator_rejects_inconsistent_or_unbound_results() {
            let rows = [
                peer_record("source.example.com", 1, "198.51.100.7:443"),
                peer_record("other.example.com", 2, "198.51.100.7:443"),
            ];
            let (store, dir) = fixture_store(&rows, false).await;
            let session = Uuid::new_v4();
            let id = token(&store, session, 1).await;
            let result = store
                .service_map_socket_peer_matches(session, &id, false, 10, &[], &[])
                .await;
            assert!(result.validate_response(session, &id, false, 10));
            for change in 0..10 {
                let mut changed = result.clone();
                match change {
                    0 => changed.counts.matching_rows = usize::MAX,
                    1 => changed.origins[0].samples[0].evidence_id = id.clone(),
                    2 => changed.source.as_mut().unwrap().in_window = false,
                    3 => {
                        changed.origins[0].origin =
                            "https://user:PRIVATE@example.com/path?token=PRIVATE".into()
                    }
                    4 => {
                        changed.peer.as_mut().unwrap().route =
                            crate::model::ObservedSocketPeerRoute::HttpProxy
                    }
                    5 => changed.snapshot.as_mut().unwrap().generation = Uuid::new_v4(),
                    6 => changed.origins[0].samples[0].sequence = "02".into(),
                    7 => changed.origins[0].omitted_samples = 1,
                    8 => changed.reasons = vec!["PRIVATE_ERROR".into()],
                    _ => {
                        let duplicate = changed.origins[0].samples[0].clone();
                        changed.origins[0].samples.push(duplicate);
                    }
                }
                assert!(
                    !changed.validate_response(session, &id, false, 10),
                    "case={change}"
                );
            }
            drop(store);
            fs::remove_dir_all(dir).unwrap();
        }

        #[tokio::test]
        async fn peer_matches_reject_noncanonical_tokens_and_impossible_window_extrema() {
            let rows = [
                peer_record("source.example.com", 10, "198.51.100.7:443"),
                peer_record("other.example.com", 11, "198.51.100.7:443"),
            ];
            let store = TransactionStore::from_records(rows.into_iter().rev().collect());
            let session = Uuid::new_v4();
            let id = token(&store, session, 10).await;
            let result = store
                .service_map_socket_peer_matches(session, &id, false, 10, &[], &[])
                .await;
            assert!(result.validate_response(session, &id, false, 10));
            for field in [1, 2, 4, 5] {
                for uppercase in [false, true] {
                    let mut fields: Vec<String> = id.split('.').map(str::to_owned).collect();
                    fields[field] = if uppercase {
                        fields[field].to_uppercase()
                    } else {
                        fields[field].replace('-', "")
                    };
                    let alias = fields.join(".");
                    if alias == id {
                        continue;
                    }
                    assert!(!crate::service_map_peer_matches::is_canonical_evidence_id(
                        &alias
                    ));
                    let rejected = store
                        .service_map_socket_peer_matches(session, &alias, false, 10, &[], &[])
                        .await;
                    assert_eq!(rejected.reasons, ["invalid_evidence_id"]);
                }
            }
            let mut alias = result.clone();
            let sample = &mut alias.origins[0].samples[0];
            let mut fields: Vec<String> =
                sample.evidence_id.split('.').map(str::to_owned).collect();
            fields[4] = fields[4].replace('-', "");
            sample.evidence_id = fields.join(".");
            assert!(!alias.validate_response(session, &id, false, 10));
            let mut padded: Vec<String> = id.split('.').map(str::to_owned).collect();
            padded[3].insert(0, '0');
            assert!(!crate::service_map_peer_matches::is_canonical_evidence_id(
                &padded.join(".")
            ));
            for extra_unknown_row in [false, true] {
                let mut changed = result.clone();
                let window = changed.snapshot.as_mut().unwrap();
                window.oldest_considered_sequence = Some("1".into());
                window.latest_considered_sequence = Some("100".into());
                if extra_unknown_row {
                    window.considered_rows += 1;
                    window.retained_rows += 1;
                    changed.counts.different_peer_rows += 1;
                }
                assert!(!changed.validate_response(session, &id, false, 10));
            }
            let single = TransactionStore::from_records(vec![peer_record(
                "source.example.com",
                10,
                "198.51.100.7:443",
            )]);
            let single_id = token(&single, session, 10).await;
            let mut result = single
                .service_map_socket_peer_matches(session, &single_id, false, 10, &[], &[])
                .await;
            assert!(result.validate_response(session, &single_id, false, 10));
            result.snapshot.as_mut().unwrap().oldest_considered_sequence = Some("1".into());
            assert!(!result.validate_response(session, &single_id, false, 10));
        }

        #[tokio::test]
        async fn peer_matches_validator_requires_truthful_projection_and_sample_limits() {
            let mut rows = vec![peer_record("source.example.com", 1, "198.51.100.7:443")];
            for index in 0..100 {
                let host = format!(
                    "{}.{}.n{index:03}.example.com",
                    "a".repeat(63),
                    "b".repeat(30)
                );
                for _ in 0..5 {
                    rows.push(peer_record(
                        &host,
                        rows.len() as u64 + 1,
                        "198.51.100.7:443",
                    ));
                }
            }
            let store = TransactionStore::from_records(rows.into_iter().rev().collect());
            let session = Uuid::new_v4();
            let id = token(&store, session, 1).await;
            let result = store
                .service_map_socket_peer_matches(session, &id, false, 10_000, &[], &[])
                .await;
            assert!(result.validate_response(session, &id, false, 10_000));
            assert!(result
                .origins
                .iter()
                .any(|g| g.samples.len() < 3 && g.omitted_samples > 0));
            for reason in ["projection_byte_limit", "sample_limit"] {
                let mut changed = result.clone();
                changed.reasons.retain(|r| r != reason);
                assert!(
                    !changed.validate_response(session, &id, false, 10_000),
                    "missing {reason}"
                );
            }
            // A group omission may justify the byte reason, but cannot hide a
            // sample omission when one more fixed-size sample still fits.
            let mut impossible_sample = result.clone();
            let full_group = impossible_sample
                .origins
                .iter_mut()
                .find(|group| group.samples.len() == 3)
                .unwrap();
            full_group.samples.pop();
            full_group.omitted_samples += 1;
            impossible_sample.counts.sample_rows -= 1;
            impossible_sample.counts.omitted_sample_rows += 1;
            assert!(!impossible_sample.validate_response(session, &id, false, 10_000));
            let small = TransactionStore::from_records(vec![
                peer_record("other.example.com", 2, "198.51.100.7:443"),
                peer_record("source.example.com", 1, "198.51.100.7:443"),
            ]);
            let small_id = token(&small, session, 1).await;
            let mut impossible = small
                .service_map_socket_peer_matches(session, &small_id, false, 10, &[], &[])
                .await;
            impossible.complete = false;
            impossible.reasons = vec!["projection_byte_limit".into()];
            impossible.origins[0].samples.clear();
            impossible.origins[0].omitted_samples = 1;
            impossible.counts.sample_rows = 0;
            impossible.counts.omitted_sample_rows = 1;
            assert!(!impossible.validate_response(session, &small_id, false, 10));
            let time_rows = (1..=5)
                .map(|seq| {
                    peer_record(
                        if seq == 1 {
                            "source.example.com"
                        } else {
                            "other.example.com"
                        },
                        seq,
                        "198.51.100.7:443",
                    )
                })
                .rev()
                .collect();
            let times = TransactionStore::from_records(time_rows);
            let times_id = token(&times, session, 1).await;
            let mut result = times
                .service_map_socket_peer_matches(session, &times_id, false, 10, &[], &[])
                .await;
            assert!(result.validate_response(session, &times_id, false, 10));
            assert_eq!(result.origins[0].omitted_samples, 1);
            result.origins[0].first_observed_at -= chrono::Duration::days(1);
            result.origins[0].last_observed_at += chrono::Duration::days(1);
            assert!(!result.validate_response(session, &times_id, false, 10));
        }

        #[tokio::test]
        async fn peer_matches_fifty_thousand_rows_measure_bounded_metadata_scan() {
            const ROWS: usize = 50_000;
            for distribution in ["same_origin", "distinct_origins", "different_peer"] {
                let rows = (0..ROWS)
                    .map(|index| {
                        let host = if distribution == "distinct_origins" {
                            format!("n{index}.example.com")
                        } else {
                            "same.example.com".into()
                        };
                        let mut row = peer_record(
                            &host,
                            index as u64 + 1,
                            if distribution == "different_peer" && index > 0 {
                                "198.51.100.8:443"
                            } else {
                                "198.51.100.7:443"
                            },
                        );
                        row.path = "/".into();
                        row.response.as_mut().unwrap().body_preview.clear();
                        row.response.as_mut().unwrap().body_size = 0;
                        row
                    })
                    .rev()
                    .collect();
                let store = TransactionStore::from_records(rows);
                let session = Uuid::new_v4();
                let id = token(&store, session, 1).await;
                let prepared_scope = crate::scope::PreparedScope::new(&[], &[]);
                for max_records in [10_000, ROWS] {
                    let locked = store.inner.read().await;
                    let started = std::time::Instant::now();
                    let result = crate::service_map_peer_matches::inspect_retained(
                        session,
                        store.saved_cursor_generation,
                        &id,
                        &locked.entries[0],
                        locked
                            .entries
                            .iter()
                            .zip(locked.body_generations.iter().copied())
                            .rev(),
                        max_records,
                        false,
                        &prepared_scope,
                    );
                    let lock_duration = started.elapsed();
                    drop(locked);
                    let bytes = serde_json::to_vec(&result).unwrap().len();
                    eprintln!("recorded peer microbenchmark: distribution={distribution}, retained_rows={ROWS}, considered_rows={max_records}, matching_rows={}, groups={}, samples={}, projected_bytes={bytes}, measured_read_lock_duration={lock_duration:?}", result.counts.matching_rows, result.origins.len(), result.counts.sample_rows);
                    assert_eq!(
                        result.snapshot.as_ref().unwrap().considered_rows,
                        max_records
                    );
                    assert_eq!(
                        result.counts.matching_rows,
                        if distribution == "different_peer" {
                            0
                        } else {
                            max_records - usize::from(max_records == ROWS)
                        }
                    );
                    assert!(result.validate_response(session, &id, false, max_records));
                    assert!(result.origins.len() <= 100 && result.counts.sample_rows <= 300);
                    assert!(bytes <= crate::service_map_peer_matches::MAX_PROJECTION_BYTES);
                }
            }
        }

        #[tokio::test]
        async fn peer_matches_dense_scope_measures_preparation_outside_snapshot_lock() {
            const ROWS: usize = 50_000;
            let rows = (0..ROWS)
                .map(|index| {
                    let mut row = peer_record(
                        &format!("n{index}.example.com"),
                        index as u64 + 1,
                        "198.51.100.7:443",
                    );
                    row.path = "/".into();
                    row.response.as_mut().unwrap().body_preview.clear();
                    row.response.as_mut().unwrap().body_size = 0;
                    row
                })
                .rev()
                .collect();
            let store = TransactionStore::from_records(rows);
            let session = Uuid::new_v4();
            let id = token(&store, session, 1).await;
            for shape in ["short_exact", "long_exact", "wildcard"] {
                let mut include = (0..499)
                    .map(|i| match shape {
                        "long_exact" => format!("include-{i}.{}.example.com", "a".repeat(470)),
                        "wildcard" => format!("*never-included-{i}*"),
                        _ => format!("include-{i}.unmatched.example.com"),
                    })
                    .collect::<Vec<_>>();
                include.push("*.example.com".into());
                let exclude = (0..500)
                    .map(|i| match shape {
                        "long_exact" => format!("exclude-{i}.{}.example.com", "b".repeat(470)),
                        "wildcard" => format!("*never-excluded-{i}*"),
                        _ => format!("exclude-{i}.unmatched.example.com"),
                    })
                    .collect::<Vec<_>>();
                assert!(include
                    .iter()
                    .chain(exclude.iter())
                    .all(|pattern| pattern.len() <= 512));
                let prepared_at = std::time::Instant::now();
                let prepared_scope = crate::scope::PreparedScope::new(&include, &exclude);
                let preparation = prepared_at.elapsed();
                for max_records in [10_000, ROWS] {
                    let locked = store.inner.read().await;
                    let started = std::time::Instant::now();
                    let result = crate::service_map_peer_matches::inspect_retained(
                        session,
                        store.saved_cursor_generation,
                        &id,
                        &locked.entries[0],
                        locked
                            .entries
                            .iter()
                            .zip(locked.body_generations.iter().copied())
                            .rev(),
                        max_records,
                        true,
                        &prepared_scope,
                    );
                    let lock_duration = started.elapsed();
                    drop(locked);
                    let bytes = serde_json::to_vec(&result).unwrap().len();
                    eprintln!("recorded peer dense-scope microbenchmark: shape={shape}, include=500, exclude=500, retained_rows={ROWS}, considered_rows={max_records}, matching_rows={}, preparation_outside_lock={preparation:?}, measured_read_lock_duration={lock_duration:?}, projected_bytes={bytes}",result.counts.matching_rows);
                    if shape == "wildcard" {
                        assert_eq!(result.reasons, ["scope_work_limit"]);
                        assert!(
                            !result.available
                                && result.source.is_none()
                                && result.peer.is_none()
                                && result.snapshot.is_none()
                        );
                        assert!(result.origins.is_empty());
                        assert_eq!(
                            result.counts,
                            crate::service_map_peer_matches::SocketPeerMatchCounts::default()
                        );
                    } else {
                        assert_eq!(
                            result.counts.matching_rows,
                            max_records - usize::from(max_records == ROWS)
                        );
                        assert!(
                            result.source.as_ref().unwrap().in_scope
                                && result.origins.iter().all(|group| group.in_scope)
                        );
                    }
                    assert!(result.validate_response(session, &id, true, max_records));
                    assert!(bytes <= crate::service_map_peer_matches::MAX_PROJECTION_BYTES);
                }
            }
        }

        #[tokio::test]
        async fn peer_matches_scope_work_limit_discards_all_partial_metadata() {
            let host = format!(
                "{}.{}.{}.{}.example.com",
                "a".repeat(63),
                "a".repeat(63),
                "a".repeat(63),
                "a".repeat(63)
            );
            let rows = (1..=50_000)
                .map(|sequence| {
                    let mut row = peer_record(&host, sequence, "198.51.100.7:443");
                    row.response.as_mut().unwrap().body_preview.clear();
                    row.response.as_mut().unwrap().body_size = 0;
                    row
                })
                .rev()
                .collect();
            let store = TransactionStore::from_records(rows);
            let session = Uuid::new_v4();
            let id = token(&store, session, 1).await;
            let include = vec!["*.example.com".into(); 500];
            let exclude = (0..500)
                .map(|i| format!("{}z{i}*", "*a".repeat(240)))
                .collect::<Vec<_>>();
            let prepared =
                crate::scope::PreparedScope::try_new(&include, &exclude, 500, 512).unwrap();
            for max_records in [10_000, 50_000] {
                for scope_only in [false, true] {
                    let locked = store.inner.read().await;
                    let started = std::time::Instant::now();
                    let result = crate::service_map_peer_matches::inspect_retained(
                        session,
                        store.saved_cursor_generation,
                        &id,
                        &locked.entries[0],
                        locked
                            .entries
                            .iter()
                            .zip(locked.body_generations.iter().copied())
                            .rev(),
                        max_records,
                        scope_only,
                        &prepared,
                    );
                    let elapsed = started.elapsed();
                    drop(locked);
                    eprintln!("recorded peer long-glob work-bound microbenchmark: patterns500+500, host_bytes={}, rows={max_records}, scope_only={scope_only}, read_lock={elapsed:?}",host.len());
                    assert_eq!(result.reasons, ["scope_work_limit"]);
                    assert!(
                        !result.available
                            && result.peer.is_none()
                            && result.source.is_none()
                            && result.snapshot.is_none()
                            && result.origins.is_empty()
                    );
                    assert_eq!(
                        result.counts,
                        crate::service_map_peer_matches::SocketPeerMatchCounts::default()
                    );
                    assert!(result.validate_response(session, &id, scope_only, max_records));
                    let json = serde_json::to_string(&result).unwrap();
                    assert!(
                        !json.contains(&host)
                            && !json.contains("198.51.100.7")
                            && !json.contains("PRIVATE")
                    );
                }
            }
            for (include, exclude) in [
                (vec!["*".into(); 501], vec![]),
                (vec![], vec!["x".repeat(513)]),
            ] {
                let result = store
                    .service_map_socket_peer_matches(session, &id, false, 10, &include, &exclude)
                    .await;
                assert_eq!(result.reasons, ["scope_work_limit"]);
                assert!(result.validate_response(session, &id, false, 10));
            }
        }

        fn link_record(origin: &str, sequence: u64) -> TransactionRecord {
            let mut record = body_record("SYNTHETIC_PRIVATE_BODY", sequence);
            record.response.as_mut().unwrap().headers = vec![crate::model::HeaderRecord {
                name: "Link".into(),
                value: format!("<{origin}/private?token=HIDDEN>; rel=service-doc"),
            }];
            record
        }

        fn paused_link_read(
            store: Arc<TransactionStore>,
            session: Uuid,
            token: String,
            hook: ServiceMapBodyReadHook,
        ) -> tokio::task::JoinHandle<crate::service_map_links::ServiceMapLinkDeclarations> {
            tokio::spawn(async move {
                store
                    .service_map_link_declarations_impl(session, &token, Some(hook))
                    .await
            })
        }

        #[tokio::test]
        async fn link_declarations_distinguish_resident_lazy_and_ambiguous_duplicate_metadata() {
            for lazy in [false, true] {
                let first = link_record("https://older.example.com", 1);
                let mut second = link_record("https://newer.example.com", 2);
                second.id = first.id;
                second.method = "HEAD".into();
                let (store, dir) = fixture_store(&[first, second], lazy).await;
                let session = Uuid::new_v4();
                let first_token = token(&store, session, 1).await;
                let second_token = token(&store, session, 2).await;
                // Header identity survives both absent body files and known
                // ambiguous UUID-only body locators for either exact row.
                if lazy {
                    fs::remove_file(dir.join("transactions.ndjson")).unwrap();
                }
                {
                    let mut inner = store.inner.write().await;
                    for id in [&first_token, &second_token] {
                        inner
                            .unresolved_body_generations
                            .insert(EvidenceKey::parse(id).unwrap().revision);
                    }
                }
                for (id, origin, method) in [
                    (&first_token, "https://older.example.com", "GET"),
                    (&second_token, "https://newer.example.com", "HEAD"),
                ] {
                    let result = store.service_map_link_declarations(session, id).await;
                    assert!(result.available && result.complete, "lazy={lazy}");
                    assert_eq!(result.observations[0].target_origin, origin);
                    assert_eq!(result.source_method.as_deref(), Some(method));
                    assert_eq!(result.retained_header_count, Some(1));
                    assert!(store
                        .service_map_link_source_status(session, id)
                        .await
                        .is_ok());
                }
                drop(store);
                fs::remove_dir_all(dir).unwrap();
            }
        }

        #[tokio::test]
        async fn link_declarations_reject_invalid_session_generation_row_and_revision_tokens() {
            let first = link_record("https://example.com", 1);
            let (store, dir) = fixture_store(&[first.clone()], false).await;
            let session = Uuid::new_v4();
            let id = token(&store, session, 1).await;
            assert_eq!(
                store
                    .service_map_link_declarations(session, "bad")
                    .await
                    .reasons,
                ["invalid_evidence_id"]
            );
            assert_eq!(
                store
                    .service_map_link_declarations(Uuid::new_v4(), &id)
                    .await
                    .reasons,
                ["session_mismatch"]
            );
            let replacement = TransactionStore::from_records(vec![first.clone()]);
            assert_eq!(
                replacement
                    .service_map_link_declarations(session, &id)
                    .await
                    .reasons,
                ["stale_generation"]
            );
            let key = EvidenceKey::parse(&id).unwrap();
            let wrong_id = format!(
                "v1.{}.{}.{}.{}.{}",
                session,
                key.generation,
                key.sequence,
                key.revision,
                Uuid::new_v4()
            );
            assert_eq!(
                store
                    .service_map_link_declarations(session, &wrong_id)
                    .await
                    .reasons,
                ["record_missing"]
            );
            store
                .update_record(first.id, |row| {
                    row.response.as_mut().unwrap().headers.clear()
                })
                .await
                .unwrap();
            assert_eq!(
                store
                    .service_map_link_declarations(session, &id)
                    .await
                    .reasons,
                ["record_changed"]
            );
            assert_eq!(
                store.service_map_link_source_status(session, &id).await,
                Err("record_changed")
            );
            drop(store);
            fs::remove_dir_all(dir).unwrap();
        }

        #[tokio::test]
        async fn link_declarations_fence_mutation_deletion_and_retention_before_and_after_scan() {
            for lazy in [false, true] {
                for stage in ["before_scan", "after_scan"] {
                    for mutation in ["delete", "retention", "headers", "body"] {
                        let first = link_record("https://example.com", 1);
                        let (store, dir) = fixture_store(&[first.clone()], lazy).await;
                        let session = Uuid::new_v4();
                        let id = token(&store, session, 1).await;
                        let before = store.service_map_link_declarations(session, &id).await;
                        assert!(before.complete && before.observations.len() == 1);
                        let (hook, started, release) = barrier(stage);
                        let reading = paused_link_read(store.clone(), session, id, hook);
                        tokio::time::timeout(WaitDuration::from_secs(10), started)
                            .await
                            .unwrap()
                            .unwrap();
                        let expected = match mutation {
                            "delete" => {
                                assert_eq!(store.delete_ids(&[first.id]).await.unwrap(), 1);
                                "record_missing"
                            }
                            "retention" => {
                                assert_eq!(
                                    store
                                        .trim_retention(0, &HashSet::new(), 10)
                                        .await
                                        .unwrap()
                                        .deleted_ids,
                                    [first.id]
                                );
                                "record_missing"
                            }
                            "headers" => {
                                store
                                    .update_record(first.id, |row| {
                                        row.response.as_mut().unwrap().headers.clear()
                                    })
                                    .await
                                    .unwrap();
                                "record_changed"
                            }
                            _ => {
                                store
                                    .update_record(first.id, |row| {
                                        row.response.as_mut().unwrap().body_preview =
                                            "changed".into()
                                    })
                                    .await
                                    .unwrap();
                                "record_changed"
                            }
                        };
                        release.send(()).unwrap();
                        let result = reading.await.unwrap();
                        assert!(
                            !result.available && !result.complete,
                            "{lazy} {stage} {mutation}"
                        );
                        assert_eq!(result.reasons, [expected]);
                        assert!(result.observations.is_empty());
                        assert_eq!(
                            result.counts,
                            crate::service_map_links::ServiceMapLinkCounts::default()
                        );
                        assert!(
                            result.source_origin.is_none()
                                && result.retained_header_count.is_none()
                        );
                        drop(store);
                        fs::remove_dir_all(dir).unwrap();
                    }
                }
            }
        }

        #[tokio::test]
        async fn link_declarations_ignore_annotation_and_body_file_generation_changes() {
            for stage in ["before_scan", "after_scan"] {
                let first = link_record("https://example.com", 1);
                let (store, dir) = fixture_store(&[first.clone()], true).await;
                let session = Uuid::new_v4();
                let id = token(&store, session, 1).await;
                let (hook, started, release) = barrier(stage);
                let reading = paused_link_read(store.clone(), session, id, hook);
                started.await.unwrap();
                store
                    .update_annotations(first.id, None, Some(Some("note".into())))
                    .await
                    .unwrap();
                // The retained metadata row does not change during body-file
                // publication. No file/locator state belongs in this read fence.
                let snapshot = store.snapshot_for_persistence(None).await.unwrap();
                let staged = dir.join("replacement");
                fs::create_dir_all(&staged).unwrap();
                let locators = crate::session::write_transactions_file_for_test_returning_locators(
                    &staged,
                    &[first],
                )
                .unwrap();
                let publisher = store.clone();
                let destination = dir.join("transactions.ndjson");
                tokio::task::spawn_blocking(move || {
                    publisher.publish_persistence_snapshot(&snapshot, locators, || {
                        crate::platform::rename(&staged.join("transactions.ndjson"), &destination)
                    })
                })
                .await
                .unwrap()
                .unwrap();
                fs::remove_file(dir.join("transactions.ndjson")).unwrap();
                release.send(()).unwrap();
                let result = reading.await.unwrap();
                assert!(result.complete && result.available);
                assert_eq!(result.observations.len(), 1);
                drop(store);
                fs::remove_dir_all(dir).unwrap();
            }
        }

        #[tokio::test]
        async fn link_declarations_worker_failure_has_fixed_empty_envelope() {
            let record = link_record("https://example.com", 1);
            let (store, dir) = fixture_store(&[record], false).await;
            let session = Uuid::new_v4();
            let id = token(&store, session, 1).await;
            let hook: ServiceMapBodyReadHook = Arc::new(|_| panic!("synthetic worker failure"));
            let result = store
                .service_map_link_declarations_impl(session, &id, Some(hook))
                .await;
            assert_eq!(result.reasons, ["link_inspection_failed"]);
            assert!(!result.available && result.observations.is_empty());
            assert_eq!(
                result.counts,
                crate::service_map_links::ServiceMapLinkCounts::default()
            );
            drop(store);
            fs::remove_dir_all(dir).unwrap();
        }

        #[tokio::test]
        async fn html_generator_read_distinguishes_resident_and_lazy_duplicate_rows() {
            let first = body_record(
                "<html><head><meta name='generator' content='WordPress 6.8.1'></head>",
                1,
            );
            let mut second = body_record(
                "<html><head><meta name='generator' content='Drupal 11.0'></head>",
                2,
            );
            second.id = first.id;
            let (store, dir) = fixture_store(&[first, second], false).await;
            let snapshot = store.snapshot_for_persistence(None).await.unwrap();
            let staged = dir.join("replacement");
            fs::create_dir_all(&staged).unwrap();
            // The fixture writer uses last-wins UUID locators, so give it
            // oldest-first rows. Production streaming uses newest-first and
            // first-wins locators; both must select the same authoritative row.
            let records: Vec<_> = snapshot
                .iter()
                .rev()
                .map(|(record, _)| record.clone())
                .collect();
            let locators = crate::session::write_transactions_file_for_test_returning_locators(
                &staged, &records,
            )
            .unwrap();
            let publisher = store.clone();
            let destination = dir.join("transactions.ndjson");
            tokio::task::spawn_blocking(move || {
                publisher.publish_persistence_snapshot(&snapshot, locators, || {
                    crate::platform::rename(&staged.join("transactions.ndjson"), &destination)
                })
            })
            .await
            .unwrap()
            .unwrap();
            let session = Uuid::new_v4();
            let older_token = token(&store, session, 1).await;
            let newer_token = token(&store, session, 2).await;
            let older = store
                .service_map_html_generators(session, &older_token)
                .await;
            let newer = store
                .service_map_html_generators(session, &newer_token)
                .await;
            assert_eq!(older.observations[0].product_id, "wordpress");
            assert_eq!(newer.observations[0].product_id, "drupal");
            let inner = store.inner.read().await;
            assert!(!inner.entries[0]
                .response
                .as_ref()
                .unwrap()
                .body_preview
                .is_empty());
            assert!(inner.entries[1]
                .response
                .as_ref()
                .unwrap()
                .body_preview
                .is_empty());
            drop(inner);
            drop(store);
            fs::remove_dir_all(dir).unwrap();
        }

        #[tokio::test]
        async fn html_generator_read_rejects_invalid_session_generation_and_revision_tokens() {
            let record = body_record(
                "<html><head><meta name='generator' content='Drupal 11.0'></head>",
                1,
            );
            let (store, dir) = fixture_store(&[record.clone()], false).await;
            let session = Uuid::new_v4();
            let id = token(&store, session, 1).await;
            assert_eq!(
                store
                    .service_map_html_generators(session, "bad")
                    .await
                    .reasons,
                ["invalid_evidence_id"]
            );
            assert_eq!(
                store
                    .service_map_html_generators(Uuid::new_v4(), &id)
                    .await
                    .reasons,
                ["session_mismatch"]
            );
            let replacement = TransactionStore::from_records(vec![record.clone()]);
            assert_eq!(
                replacement
                    .service_map_html_generators(session, &id)
                    .await
                    .reasons,
                ["stale_generation"]
            );
            store
                .update_record(record.id, |r| {
                    r.response.as_mut().unwrap().body_preview =
                        "https://changed.example.com/ ".into()
                })
                .await
                .unwrap();
            assert_eq!(
                store
                    .service_map_html_generators(session, &id)
                    .await
                    .reasons,
                ["record_changed"]
            );
            drop(store);
            fs::remove_dir_all(dir).unwrap();
        }

        #[tokio::test]
        async fn html_generator_read_fails_closed_for_oversized_wrong_missing_and_malformed_disk_rows(
        ) {
            for case in [
                "oversized",
                "wrong_locator",
                "missing_file",
                "malformed_json",
                "malformed_utf8",
                "wrong_sequence",
                "missing_preview",
            ] {
                let first = body_record(
                    "<html><head><meta name='generator' content='Drupal 11.0'></head>",
                    1,
                );
                let second = body_record(
                    "<html><head><meta name='generator' content='Drupal 11.0'></head>",
                    2,
                );
                let (store, dir) = fixture_store(&[first.clone(), second.clone()], true).await;
                let session = Uuid::new_v4();
                let id = token(&store, session, 1).await;
                let expected = match case {
                    "oversized" => {
                        store
                            .set_body_locator_for_test(
                                first.id,
                                crate::session::BodyLocator {
                                    offset: u64::MAX,
                                    len: (MAX_SERIALIZED_ROW_BYTES + 1) as u32,
                                },
                            )
                            .await;
                        "serialized_row_limit"
                    }
                    "wrong_locator" => {
                        let locator = store.inner.read().await.locators[&second.id];
                        store.set_body_locator_for_test(first.id, locator).await;
                        "body_identity_unverifiable"
                    }
                    "missing_file" => {
                        fs::remove_file(dir.join("transactions.ndjson")).unwrap();
                        "body_storage_unavailable"
                    }
                    case => {
                        let mut value = serde_json::to_value(&first).unwrap();
                        let bytes = match case {
                            "malformed_json" => b"{not json}".to_vec(),
                            "malformed_utf8" => {
                                // Put invalid UTF-8 in an ignored request field:
                                // malformed bytes must not bypass the projection.
                                let mut bytes = serde_json::to_vec(&first).unwrap();
                                let needle = b"\"body_preview\":\"\"";
                                let start = bytes
                                    .windows(needle.len())
                                    .position(|part| part == needle)
                                    .unwrap();
                                bytes.insert(start + needle.len() - 1, 0xff);
                                bytes
                            }
                            "wrong_sequence" => {
                                value["sequence"] = 0.into();
                                serde_json::to_vec(&value).unwrap()
                            }
                            "missing_preview" => {
                                value["response"]
                                    .as_object_mut()
                                    .unwrap()
                                    .remove("body_preview");
                                serde_json::to_vec(&value).unwrap()
                            }
                            _ => unreachable!(),
                        };
                        fs::write(dir.join("transactions.ndjson"), &bytes).unwrap();
                        store
                            .set_body_locator_for_test(
                                first.id,
                                crate::session::BodyLocator {
                                    offset: 0,
                                    len: bytes.len() as u32,
                                },
                            )
                            .await;
                        match case {
                            "wrong_sequence" => "body_identity_unverifiable",
                            "missing_preview" => "retained_preview_unavailable",
                            _ => "malformed_retained_row",
                        }
                    }
                };
                let result = store.service_map_html_generators(session, &id).await;
                assert!(!result.available, "{case}");
                assert!(result.observations.is_empty(), "{case}");
                assert_eq!(result.reasons, [expected], "{case}");
                // The normal map and metadata evidence remain independent of
                // body storage, including missing/corrupt files and bad locators.
                assert_eq!(store.service_map_snapshot(session, 10).await.rows.len(), 2);
                assert!(store.service_map_evidence(session, &id).await.available);
                drop(store);
                fs::remove_dir_all(dir).unwrap();
            }
        }

        #[tokio::test]
        async fn html_generator_read_rejects_unresolved_and_nonresident_older_duplicate() {
            let first = body_record(
                "<html><head><meta name='generator' content='WordPress 6.8.1'></head>",
                1,
            );
            let mut second = body_record(
                "<html><head><meta name='generator' content='Drupal 11.0'></head>",
                2,
            );
            second.id = first.id;
            // A legacy-loaded older duplicate has no authoritative locator.
            let (store, dir) = fixture_store(&[first, second], true).await;
            let session = Uuid::new_v4();
            let id = token(&store, session, 1).await;
            assert_eq!(
                store
                    .service_map_html_generators(session, &id)
                    .await
                    .reasons,
                ["retained_preview_unavailable"]
            );
            let key = EvidenceKey::parse(&id).unwrap();
            store
                .inner
                .write()
                .await
                .unresolved_body_generations
                .insert(key.revision);
            assert_eq!(
                store
                    .service_map_html_generators(session, &id)
                    .await
                    .reasons,
                ["body_identity_unverifiable"]
            );
            drop(store);
            fs::remove_dir_all(dir).unwrap();
        }

        #[tokio::test]
        async fn html_generator_read_resident_and_lazy_reject_deletion_retention_and_mutation_races(
        ) {
            for lazy in [false, true] {
                for mutation in ["delete", "retention", "body"] {
                    let first = body_record(
                        "<html><head><meta name='generator' content='Drupal 11.0'></head>",
                        1,
                    );
                    let (store, dir) = fixture_store(&[first.clone()], lazy).await;
                    let session = Uuid::new_v4();
                    let id = token(&store, session, 1).await;
                    let (hook, started, release) = barrier("after_scan");
                    let reading = paused_html_read(store.clone(), session, id, hook);
                    tokio::time::timeout(WaitDuration::from_secs(10), started)
                        .await
                        .unwrap()
                        .unwrap();
                    // If the reader held the store lock during file/scan work,
                    // these real mutations would deadlock at this barrier.
                    let expected = match mutation {
                        "delete" => {
                            assert_eq!(store.delete_ids(&[first.id]).await.unwrap(), 1);
                            "record_missing"
                        }
                        "retention" => {
                            assert_eq!(
                                store
                                    .trim_retention(0, &HashSet::new(), 10)
                                    .await
                                    .unwrap()
                                    .deleted_ids,
                                [first.id]
                            );
                            "record_missing"
                        }
                        _ => {
                            store
                                .update_record(first.id, |r| {
                                    r.response.as_mut().unwrap().body_preview =
                                        "https://after.example.com/ ".into()
                                })
                                .await
                                .unwrap();
                            "record_changed"
                        }
                    };
                    release.send(()).unwrap();
                    let result = reading.await.unwrap();
                    assert!(!result.available, "{lazy} {mutation}");
                    assert_eq!(result.reasons, [expected], "{lazy} {mutation}");
                    drop(store);
                    fs::remove_dir_all(dir).unwrap();
                }
            }
        }

        #[tokio::test]
        async fn html_generator_read_annotations_keep_evidence_valid_during_scan() {
            for lazy in [false, true] {
                let record = body_record(
                    "<html><head><meta name='generator' content='Drupal 11.0'></head>",
                    1,
                );
                let (store, dir) = fixture_store(&[record.clone()], lazy).await;
                let session = Uuid::new_v4();
                let id = token(&store, session, 1).await;
                let (hook, started, release) = barrier("after_scan");
                let reading = paused_html_read(store.clone(), session, id, hook);
                started.await.unwrap();
                store
                    .update_annotations(record.id, None, Some(Some("note".into())))
                    .await
                    .unwrap();
                release.send(()).unwrap();
                assert!(reading.await.unwrap().complete);
                drop(store);
                fs::remove_dir_all(dir).unwrap();
            }
        }

        #[tokio::test]
        async fn html_generator_read_rejects_atomic_publication_before_and_after_disk_scan() {
            for stage in ["after_open", "after_scan"] {
                let record = body_record(
                    "<html><head><meta name='generator' content='Drupal 11.0'></head>",
                    1,
                );
                let (store, dir) = fixture_store(&[record.clone()], true).await;
                let session = Uuid::new_v4();
                let id = token(&store, session, 1).await;
                let snapshot = store.snapshot_for_persistence(None).await.unwrap();
                let staged = dir.join("replacement");
                fs::create_dir_all(&staged).unwrap();
                let locators = crate::session::write_transactions_file_for_test_returning_locators(
                    &staged,
                    &[record],
                )
                .unwrap();
                let (hook, started, release) = barrier(stage);
                let reading = paused_html_read(store.clone(), session, id.clone(), hook);
                started.await.unwrap();
                let publisher = store.clone();
                let destination = dir.join("transactions.ndjson");
                tokio::task::spawn_blocking(move || {
                    publisher.publish_persistence_snapshot(&snapshot, locators, || {
                        crate::platform::rename(&staged.join("transactions.ndjson"), &destination)
                    })
                })
                .await
                .unwrap()
                .unwrap();
                release.send(()).unwrap();
                let result = reading.await.unwrap();
                assert_eq!(result.reasons, ["body_identity_unverifiable"], "{stage}");
                assert!(result.observations.is_empty());
                // A fresh explicit read uses the adopted locator/file generation.
                assert!(
                    store
                        .service_map_html_generators(session, &id)
                        .await
                        .complete
                );
                drop(store);
                fs::remove_dir_all(dir).unwrap();
            }
        }

        #[tokio::test]
        async fn html_generator_read_rejects_base64_from_invalid_utf8_capture() {
            let mut record = body_record("", 1);
            let mut headers = http::HeaderMap::new();
            headers.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("text/html"),
            );
            record.response = Some(MessageRecord::from_headers_and_body(
                &headers,
                &[0xff, 0xfe, 0xfd],
                100,
            ));
            assert_eq!(
                record.response.as_ref().unwrap().body_encoding,
                BodyEncoding::Base64
            );
            let (store, dir) = fixture_store(&[record], false).await;
            let session = Uuid::new_v4();
            let id = token(&store, session, 1).await;
            let result = store.service_map_html_generators(session, &id).await;
            assert_eq!(result.status, "unsupported");
            assert_eq!(result.reasons, ["unsupported_body_encoding"]);
            assert!(!result.available);
            drop(store);
            fs::remove_dir_all(dir).unwrap();
        }
    }

    mod retention_tests {
        use super::*;
        use futures_util::{poll, FutureExt};
        use std::panic::{catch_unwind, AssertUnwindSafe};

        fn records(count: usize) -> Vec<TransactionRecord> {
            (0..count)
                .map(|index| {
                    let mut record = test_record("example.com");
                    record.path = format!("/{index}");
                    record.sequence = index as u64 + 1;
                    record
                })
                .collect()
        }

        fn journal_store(records: Vec<TransactionRecord>) -> (TransactionStore, PathBuf) {
            let path =
                std::env::temp_dir().join(format!("sniper-retention-store-{}", Uuid::new_v4()));
            let store = TransactionStore::from_records_with_journal(
                records.into_iter().rev().collect(),
                path.join("transactions.journal"),
                None,
            );
            (store, path)
        }

        #[tokio::test]
        async fn retention_oldest_eligible_holes_deduplicated_protection_and_target() {
            let records = records(7);
            let ids: Vec<_> = records.iter().map(|record| record.id).collect();
            let (store, path) = journal_store(records);
            let lease = store.in_progress.register(ids[2]);
            let saved = HashSet::from([ids[0], ids[2], ids[5], Uuid::new_v4()]);
            assert_eq!(store.retention_status(&saved).await, (7, 3));
            let outcome = store.trim_retention(4, &saved, 10).await.unwrap();
            assert_eq!(outcome.deleted_ids, vec![ids[1], ids[3], ids[4]]);
            assert_eq!((outcome.current_count, outcome.protected_count), (4, 3));
            assert!(store.get(ids[6]).await.is_some());
            let outcome = store.trim_retention(1, &saved, 10).await.unwrap();
            assert_eq!(outcome.deleted_ids, vec![ids[6]]);
            assert_eq!((outcome.current_count, outcome.protected_count), (3, 3));
            let outcome = store.trim_retention(1, &saved, 10).await.unwrap();
            assert!(outcome.deleted_ids.is_empty());
            drop(lease);
            drop(store);
            fs::remove_dir_all(path).unwrap();
        }

        #[tokio::test]
        async fn retention_chunks_and_zero_work_do_not_append_or_publish() {
            let (store, path) = journal_store(records(6));
            let mut events = store.subscribe_retention();
            let initial_sequence = store.latest_event_sequence();
            let no_work = store.trim_retention(6, &HashSet::new(), 2).await.unwrap();
            assert!(no_work.deleted_ids.is_empty());
            assert_eq!(no_work.event_sequence, initial_sequence);
            assert!(!store.retention_compaction_pending());
            let zero_chunk = store.trim_retention(1, &HashSet::new(), 0).await.unwrap();
            assert!(zero_chunk.deleted_ids.is_empty());
            assert!(events.try_recv().is_err());
            assert_eq!(
                fs::metadata(path.join("transactions.journal"))
                    .unwrap()
                    .len(),
                0
            );
            let first = store.trim_retention(1, &HashSet::new(), 2).await.unwrap();
            assert_eq!(first.deleted_ids.len(), 2);
            assert_eq!(first.current_count, 4);
            assert_eq!(first.event_sequence, initial_sequence + 1);
            let second = store.trim_retention(1, &HashSet::new(), 2).await.unwrap();
            assert_eq!(second.deleted_ids.len(), 2);
            assert_eq!(second.current_count, 2);
            store.mark_retention_compacted(first.event_sequence);
            assert!(store.retention_compaction_pending());
            store.mark_retention_compacted(second.event_sequence);
            assert!(!store.retention_compaction_pending());
            drop(store);
            fs::remove_dir_all(path).unwrap();
        }

        // The retention worker rewrites the session only when trims free enough
        // of transactions.ndjson; a row that lives only in the journal frees none.
        #[tokio::test]
        async fn retention_trims_report_the_snapshotted_bytes_they_free() {
            let records = records(3);
            let ids: Vec<_> = records.iter().map(|record| record.id).collect();
            let (store, path) = journal_store(records);
            store
                .adopt_written_locators(HashMap::from([(
                    ids[0],
                    crate::session::BodyLocator {
                        offset: 0,
                        len: 700,
                    },
                )]))
                .await;
            let outcome = store.trim_retention(1, &HashSet::new(), 10).await.unwrap();
            assert_eq!(outcome.deleted_ids, vec![ids[0], ids[1]]);
            assert_eq!(outcome.reclaimable_bytes, 700);
            drop(store);
            fs::remove_dir_all(path).unwrap();
        }

        #[tokio::test]
        async fn retention_tombstone_ids_are_hard_bounded() {
            let (store, path) = journal_store(records(1030));
            let outcome = store
                .trim_retention(1, &HashSet::new(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(outcome.deleted_ids.len(), 1024);
            assert_eq!(outcome.current_count, 6);
            drop(store);
            fs::remove_dir_all(path).unwrap();
        }

        #[tokio::test]
        async fn retention_duplicate_leases_release_only_owned_token_and_notify_last() {
            let record = test_record("example.com");
            let id = record.id;
            let store = TransactionStore::from_records(vec![record]);
            let first = store.in_progress.register(id);
            let second = store.in_progress.register(id);
            let first_token = first.token;
            let notify = store.retention_notify();
            drop(second);
            assert_eq!(store.retention_status(&HashSet::new()).await, (1, 1));
            assert!(notify.notified().now_or_never().is_none());
            store.in_progress.release(id, Uuid::new_v4());
            assert_eq!(store.retention_status(&HashSet::from([id])).await, (1, 1));
            drop(first);
            assert!(notify.notified().now_or_never().is_some());
            assert_eq!(store.retention_status(&HashSet::new()).await, (1, 0));
            store.in_progress.release(id, first_token);
            store.in_progress.release(Uuid::new_v4(), first_token);
            assert!(notify.notified().now_or_never().is_none());
        }

        #[tokio::test]
        async fn retention_in_progress_insert_and_cleanup_are_atomic() {
            let record = test_record("example.com");
            let id = record.id;
            let mut store = TransactionStore::new();
            let (tx, rx) = mpsc::channel();
            store.journal_tx = Some(tx);
            let mut insertion = Box::pin(store.insert_in_progress(record));
            assert!(poll!(&mut insertion).is_pending());
            let TransactionJournalCommand::Append { ack: Some(ack), .. } = rx.try_recv().unwrap()
            else {
                panic!("expected provisional append");
            };
            let saved = HashSet::new();
            let mut cleanup = Box::pin(store.trim_retention(0, &saved, 10));
            assert!(poll!(&mut cleanup).is_pending());
            assert_eq!(store.len().await, 0);
            ack.send(Ok(())).unwrap();
            let (outcome, guard) = insertion.await;
            assert!(!outcome.immediate_snapshot_required());
            let cleanup = cleanup.await.unwrap();
            assert!(cleanup.deleted_ids.is_empty());
            assert_eq!((cleanup.current_count, cleanup.protected_count), (1, 1));
            assert_eq!(store.get(id).await.unwrap().id, id);
            assert!(rx.try_recv().is_err());
            drop(guard);
            assert_eq!(store.retention_status(&saved).await, (1, 0));
        }

        #[tokio::test]
        async fn retention_cancelled_insertion_and_owner_panic_release_their_leases() {
            let record = test_record("example.com");
            let id = record.id;
            let mut store = TransactionStore::new();
            let (tx, rx) = mpsc::channel();
            store.journal_tx = Some(tx);
            let mut insertion = Box::pin(store.insert_in_progress(record));
            assert!(poll!(&mut insertion).is_pending());
            let command = rx.try_recv().unwrap();
            assert!(store.in_progress.leases.lock().unwrap().contains_key(&id));
            drop(insertion);
            drop(command);
            assert!(store.in_progress.leases.lock().unwrap().is_empty());
            assert_eq!(store.len().await, 0);
            let result = catch_unwind(AssertUnwindSafe(|| {
                let _guard = store.in_progress.register(id);
                panic!("synthetic owner panic");
            }));
            assert!(result.is_err());
            assert!(store.in_progress.leases.lock().unwrap().is_empty());
        }

        #[tokio::test]
        async fn retention_insert_fallback_and_cancelled_owner_keep_then_release_protection() {
            let store = Arc::new(TransactionStore::new());
            let record = test_record("example.com");
            let id = record.id;
            let notify = store.retention_notify();
            let (ready_tx, ready_rx) = oneshot::channel();
            let owner = {
                let store = Arc::clone(&store);
                tokio::spawn(async move {
                    let (outcome, _guard) = store.insert_in_progress(record).await;
                    assert!(outcome.immediate_snapshot_required());
                    // Controlled stand-in for the completion/persistence scope.
                    ready_tx.send(()).unwrap();
                    std::future::pending::<()>().await;
                })
            };
            ready_rx.await.unwrap();
            assert!(notify.notified().now_or_never().is_some());
            assert_eq!(store.retention_status(&HashSet::new()).await, (1, 1));
            assert!(store
                .trim_retention(0, &HashSet::new(), 10)
                .await
                .unwrap()
                .deleted_ids
                .is_empty());
            owner.abort();
            assert!(owner.await.unwrap_err().is_cancelled());
            assert!(notify.notified().now_or_never().is_some());
            assert_eq!(store.retention_status(&HashSet::new()).await, (1, 0));
            assert!(store.get(id).await.is_some());
        }

        #[tokio::test]
        async fn retention_manual_clear_and_absent_update_do_not_resurrect_on_drop() {
            let (store, path) = journal_store(Vec::new());
            let record = test_record("example.com");
            let id = record.id;
            let (_, guard) = store.insert_in_progress(record).await;
            let mut events = store.subscribe_retention();
            assert_eq!(store.delete_all().await.unwrap(), 1);
            assert!(matches!(
                events.try_recv().unwrap(),
                TransactionRetentionEvent::Gap
            ));
            assert!(store
                .update_record_durable(id, |_| panic!("absent update called"))
                .await
                .unwrap()
                .is_none());
            assert_eq!(store.retention_status(&HashSet::from([id])).await, (0, 0));
            drop(guard);
            assert_eq!(store.len().await, 0);
            assert!(store.in_progress.leases.lock().unwrap().is_empty());
            assert!(events.try_recv().is_err());
            drop(store);
            fs::remove_dir_all(path).unwrap();
        }

        #[tokio::test]
        async fn retention_waits_for_durable_ack_before_memory_event_or_compaction_flag() {
            let rows = records(2);
            let first_id = rows[0].id;
            let mut store = TransactionStore::from_records(rows.into_iter().rev().collect());
            let (tx, rx) = mpsc::channel();
            store.journal_tx = Some(tx);
            let mut events = store.subscribe_retention();
            let sequence = store.latest_event_sequence();
            let saved = HashSet::new();
            let mut cleanup = Box::pin(store.trim_retention(1, &saved, 10));
            assert!(poll!(&mut cleanup).is_pending());
            let TransactionJournalCommand::Append {
                line,
                ack: Some(ack),
            } = rx.try_recv().unwrap()
            else {
                panic!("expected acknowledged tombstone");
            };
            let entry: TransactionJournalEntry = serde_json::from_slice(&line).unwrap();
            assert!(
                matches!(entry, TransactionJournalEntry::Delete { ids } if ids == vec![first_id])
            );
            assert_eq!(store.len().await, 2);
            assert!(store.get(first_id).await.is_some());
            assert_eq!(store.latest_event_sequence(), sequence);
            assert!(!store.retention_compaction_pending());
            assert!(events.try_recv().is_err());
            ack.send(Ok(())).unwrap();
            let outcome = cleanup.await.unwrap();
            assert_eq!(outcome.deleted_ids, vec![first_id]);
            assert_eq!(outcome.event_sequence, sequence + 1);
            assert_eq!(outcome.current_count, 1);
            assert!(store.retention_compaction_pending());
            assert_eq!(
                events.try_recv().unwrap(),
                TransactionRetentionEvent::Deleted {
                    ids: vec![first_id],
                    generation: store.saved_cursor_generation(),
                    event_sequence: sequence + 1,
                }
            );
            assert!(events.try_recv().is_err());
        }

        #[tokio::test]
        async fn retention_failed_or_lost_ack_keeps_memory_and_event_boundary() {
            for lose_ack in [false, true] {
                let rows = records(2);
                let mut store = TransactionStore::from_records(rows.into_iter().rev().collect());
                let (tx, rx) = mpsc::channel();
                store.journal_tx = Some(tx);
                let before = serde_json::to_value(store.snapshot(None).await).unwrap();
                let sequence = store.latest_event_sequence();
                let mut events = store.subscribe_retention();
                let saved = HashSet::new();
                let mut cleanup = Box::pin(store.trim_retention(1, &saved, 10));
                assert!(poll!(&mut cleanup).is_pending());
                let TransactionJournalCommand::Append { ack: Some(ack), .. } =
                    rx.try_recv().unwrap()
                else {
                    panic!("expected acknowledged tombstone");
                };
                if lose_ack {
                    drop(ack);
                } else {
                    ack.send(Err(io::Error::other("synthetic fsync failure")))
                        .unwrap();
                }
                assert!(cleanup.await.is_err());
                assert_eq!(
                    serde_json::to_value(store.snapshot(None).await).unwrap(),
                    before
                );
                assert_eq!(store.latest_event_sequence(), sequence);
                assert!(!store.retention_compaction_pending());
                assert!(events.try_recv().is_err());
            }
        }

        #[tokio::test]
        async fn retention_deletion_only_restart_preserves_survivor_bodies_after_ack_or_failure() {
            for fail_ack in [false, true] {
                let path = std::env::temp_dir()
                    .join(format!("sniper-retention-restart-{}", Uuid::new_v4()));
                let (registry, session) =
                    crate::session::SessionRegistry::load_or_create(&path, 32, 32).unwrap();
                session
                    .scanner
                    .update_config(crate::scanner::ScannerConfig {
                        enabled: false,
                        ..crate::scanner::ScannerConfig::default()
                    })
                    .await;
                let mut rows = records(3);
                for (index, record) in rows.iter_mut().enumerate() {
                    record.request.body_preview = format!("synthetic body {index}");
                    record.request.body_size = record.request.body_preview.len();
                    session.store.insert(record.clone()).await;
                }
                session.persist().await.unwrap();
                let journal_path = session.storage_dir().join("transactions.journal");
                // The baseline is fully compacted before deletion. Restart
                // replays only tombstones, never inserts or scanner recovery.
                assert_eq!(fs::metadata(&journal_path).unwrap().len(), 0);
                let protected_id = rows[0].id;
                let survivor_body = rows[0].request.body_preview.clone();
                drop(session);
                drop(registry);
                let mut store = TransactionStore::from_records(rows.into_iter().rev().collect());
                let (tx, rx) = mpsc::channel();
                store.journal_tx = Some(tx);
                let saved = HashSet::from([protected_id]);
                let mut cleanup = Box::pin(store.trim_retention(1, &saved, 10));
                assert!(poll!(&mut cleanup).is_pending());
                let TransactionJournalCommand::Append {
                    line,
                    ack: Some(ack),
                } = rx.try_recv().unwrap()
                else {
                    panic!("expected acknowledged tombstone");
                };
                let mut journal = OpenOptions::new().append(true).open(&journal_path).unwrap();
                journal.write_all(&line).unwrap();
                journal.flush().unwrap();
                journal.sync_all().unwrap();
                drop(journal);
                if fail_ack {
                    ack.send(Err(io::Error::other("synthetic acknowledgement failure")))
                        .unwrap();
                    assert!(cleanup.await.is_err());
                    assert_eq!(store.len().await, 3);
                } else {
                    ack.send(Ok(())).unwrap();
                    assert_eq!(cleanup.await.unwrap().current_count, 1);
                }
                drop(store);
                let (registry, reloaded) =
                    crate::session::SessionRegistry::load_or_create(&path, 32, 32).unwrap();
                assert!(!reloaded.scanner.get_config().await.enabled);
                assert_eq!(reloaded.store.len().await, 1);
                assert_eq!(
                    reloaded
                        .store
                        .get(protected_id)
                        .await
                        .unwrap()
                        .request
                        .body_preview,
                    survivor_body
                );
                assert_eq!(fs::metadata(&journal_path).unwrap().len(), 0);
                drop(reloaded);
                drop(registry);
                fs::remove_dir_all(path).unwrap();
            }
        }

        #[tokio::test]
        async fn retention_keeps_duplicate_uuid_insertion_semantics_and_counts_once() {
            let record = test_record("example.com");
            let id = record.id;
            let (store, path) = journal_store(Vec::new());
            let (_, first) = store.insert_in_progress(record.clone()).await;
            let (_, second) = store.insert_in_progress(record).await;
            assert_eq!(store.len().await, 2);
            assert_eq!(store.retention_status(&HashSet::from([id])).await, (2, 1));
            drop(first);
            assert_eq!(store.retention_status(&HashSet::new()).await, (2, 1));
            assert!(store
                .trim_retention(0, &HashSet::new(), 10)
                .await
                .unwrap()
                .deleted_ids
                .is_empty());
            drop(second);
            let outcome = store.trim_retention(0, &HashSet::new(), 10).await.unwrap();
            assert_eq!(outcome.deleted_ids, vec![id]);
            assert_eq!(outcome.current_count, 0);
            drop(store);
            fs::remove_dir_all(path).unwrap();
        }
    }

    fn history_header_record() -> TransactionRecord {
        let mut record = test_record("example.com");
        record.request.headers = vec![
            HeaderRecord {
                name: "Authorization".into(),
                value: "Bearer ExampleCredential".into(),
            },
            HeaderRecord {
                name: "X-Example-Request".into(),
                value: "RequestValue".into(),
            },
        ];
        let mut response = record.request.clone();
        response.headers = vec![
            HeaderRecord {
                name: "Server".into(),
                value: "ExampleServer/1.25".into(),
            },
            HeaderRecord {
                name: "Set-Cookie".into(),
                value: "first=One".into(),
            },
            HeaderRecord {
                name: "Set-Cookie".into(),
                value: "second=Two".into(),
            },
            HeaderRecord {
                name: "Location".into(),
                value: "/example-target".into(),
            },
        ];
        record.response = Some(response);
        record
    }

    #[tokio::test]
    async fn history_header_search_matches_names_values_duplicates_and_combined_filters() {
        let store = TransactionStore::new();
        let record = history_header_record();
        let id = record.id;
        store.insert(record).await;
        for query in [
            "authorization",
            "EXAMPLECREDENTIAL",
            "requestvalue",
            "server: exampleserver",
            "set-cookie: second=two",
            "/example-target",
        ] {
            let filters = ListFilters {
                query: Some(query.into()),
                search_headers: true,
                ..Default::default()
            };
            let page = store.list_page(&filters).await;
            assert_eq!(
                page.items.iter().map(|row| row.id).collect::<Vec<_>>(),
                vec![id],
                "{query}"
            );
            assert_eq!(page.filtered_total, Some(1));
            let advanced = ListFilters {
                advanced_search: Some(query.into()),
                query: None,
                ..filters.clone()
            };
            assert_eq!(store.list(&advanced).await.len(), 1, "advanced {query}");
        }
        let combined = ListFilters {
            query: Some("ExampleCredential".into()),
            advanced_search: Some("ExampleServer".into()),
            search_headers: true,
            method: Some("GET".into()),
            in_scope_only: true,
            scope_patterns: vec!["example.com".into()],
            ..Default::default()
        };
        assert_eq!(store.list(&combined).await.len(), 1);
        assert!(store
            .list(&ListFilters {
                excluded_scope_patterns: vec!["example.com".into()],
                ..combined.clone()
            })
            .await
            .is_empty());
        assert!(store
            .list(&ListFilters {
                method: Some("POST".into()),
                ..combined
            })
            .await
            .is_empty());
    }

    #[tokio::test]
    async fn history_header_search_preserves_case_regex_and_negative_rules() {
        let store = TransactionStore::new();
        let mut record = history_header_record();
        record.request.headers.push(HeaderRecord {
            name: "X-Unicode".into(),
            value: "ÄBC".into(),
        });
        store.insert(record).await;
        for (query, expected) in [("Äbc", 1), ("äbc", 0)] {
            assert_eq!(
                store
                    .list(&ListFilters {
                        query: Some(query.into()),
                        search_headers: true,
                        ..Default::default()
                    })
                    .await
                    .len(),
                expected
            );
            assert_eq!(
                store
                    .list(&ListFilters {
                        advanced_search: Some(query.into()),
                        search_headers: true,
                        ..Default::default()
                    })
                    .await
                    .len(),
                expected
            );
        }
        let filters = ListFilters {
            search_headers: true,
            advanced_search: Some("ExampleCredential".into()),
            advanced_case_sensitive: true,
            ..Default::default()
        };
        assert_eq!(store.list(&filters).await.len(), 1);
        assert!(store
            .list(&ListFilters {
                advanced_search: Some("examplecredential".into()),
                ..filters.clone()
            })
            .await
            .is_empty());
        let regex = ListFilters {
            advanced_search: Some(r"Server: ExampleServer/[0-9]+\.[0-9]+".into()),
            advanced_regex: true,
            ..filters
        };
        assert_eq!(store.list(&regex).await.len(), 1);
        let negative = ListFilters {
            advanced_negative: true,
            ..regex
        };
        assert!(store.list(&negative).await.is_empty());
        assert!(store
            .list(&ListFilters {
                advanced_search: Some(r"example\.com".into()),
                ..negative.clone()
            })
            .await
            .is_empty());
        assert_eq!(
            store
                .list(&ListFilters {
                    advanced_search: Some("absent-header-value".into()),
                    ..negative.clone()
                })
                .await
                .len(),
            1
        );
        assert!(store
            .list(&ListFilters {
                advanced_search: Some("[".into()),
                ..negative
            })
            .await
            .is_empty());
        let headerless = TransactionStore::new();
        headerless.insert(test_record("example.com")).await;
        assert!(headerless
            .list(&ListFilters {
                advanced_search: Some("^$".into()),
                advanced_regex: true,
                search_headers: true,
                ..Default::default()
            })
            .await
            .is_empty());
        assert_eq!(
            store
                .list(&ListFilters {
                    advanced_search: Some(r"^example\.com GET / $".into()),
                    advanced_regex: true,
                    search_headers: true,
                    ..Default::default()
                })
                .await
                .len(),
            1,
            "adding headers preserves metadata anchors"
        );
    }

    #[tokio::test]
    async fn history_header_search_does_not_cap_large_or_late_headers() {
        let store = TransactionStore::new();
        let mut record = history_header_record();
        record.request.headers.insert(
            0,
            HeaderRecord {
                name: "X-Padding".into(),
                value: "界".repeat(100_000),
            },
        );
        record
            .response
            .as_mut()
            .unwrap()
            .headers
            .push(HeaderRecord {
                name: "Set-Cookie".into(),
                value: "tail=LastHeaderNeedle".into(),
            });
        record.request.body_preview = "body-only-sentinel".into();
        let persisted = serde_json::to_value(&record).unwrap();
        assert!(
            persisted.get("header_search_text").is_none(),
            "derived text must not enter the persisted record"
        );
        strip_transaction_bodies(&mut record);
        store.insert(record).await;
        let page = store
            .list_page(&ListFilters {
                query: Some("lastheaderneedle".into()),
                search_headers: true,
                ..Default::default()
            })
            .await;
        assert_eq!(page.items.len(), 1);
        assert!(page.items[0].header_search_text.len() > 300_000);
        assert!(page.items[0]
            .header_search_text
            .ends_with("Set-Cookie: tail=LastHeaderNeedle"));
        assert!(!page.items[0]
            .header_search_text
            .contains("body-only-sentinel"));
        let mut legacy = serde_json::to_value(&page.items[0]).unwrap();
        legacy.as_object_mut().unwrap().remove("header_search_text");
        let legacy: TransactionSummary = serde_json::from_value(legacy).unwrap();
        assert!(legacy.header_search_text.is_empty());
    }

    #[tokio::test]
    async fn history_header_search_keeps_legacy_query_and_selection_contracts() {
        let store = TransactionStore::new();
        store.insert(history_header_record()).await;
        assert!(store
            .list(&ListFilters {
                query: Some("ExampleCredential".into()),
                ..Default::default()
            })
            .await
            .is_empty());
        let rows = store.list(&ListFilters::default()).await;
        assert!(serde_json::to_value(&rows[0])
            .unwrap()
            .get("header_search_text")
            .is_none());
        let selection: crate::history_selection::HistorySelection = serde_json::from_value(
            serde_json::json!({"session_id": Uuid::new_v4(), "query": "ExampleCredential"}),
        )
        .unwrap();
        assert!(selection.resolve(&store).await.unwrap().is_empty());
        assert!(validate_delete_filters(&ListFilters {
            query: Some("ExampleCredential".into()),
            search_headers: true,
            ..Default::default()
        })
        .is_err());
        let mut explicit = selection;
        explicit.query = None;
        explicit.ids = vec![rows[0].id];
        assert_eq!(explicit.resolve(&store).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn history_header_search_updates_cache_and_live_summaries() {
        let store = TransactionStore::new();
        let mut receiver = store.subscribe();
        let record = history_header_record();
        let id = record.id;
        store.insert(record).await;
        let inserted = receiver.recv().await.unwrap();
        assert!(inserted
            .summary
            .header_search_text
            .contains("ExampleCredential"));
        store
            .update_record(id, |record| {
                record.request.headers.clear();
                record.response = None;
            })
            .await
            .unwrap();
        let updated = receiver.recv().await.unwrap();
        assert!(updated.summary.header_search_text.is_empty());
        assert!(store
            .list(&ListFilters {
                query: Some("ExampleCredential".into()),
                search_headers: true,
                ..Default::default()
            })
            .await
            .is_empty());
        let mut fresh = history_header_record();
        fresh.id = id;
        store.replace_all(vec![fresh]).await;
        let annotated = store
            .update_annotations(id, Some(Some("blue".into())), None)
            .await
            .unwrap();
        assert!(annotated
            .summary
            .header_search_text
            .contains("ExampleCredential"));
        assert_eq!(
            store
                .list(&ListFilters {
                    query: Some("ExampleCredential".into()),
                    search_headers: true,
                    ..Default::default()
                })
                .await
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn history_header_search_preserves_cursor_sort_and_hidden_connect_counts() {
        let store = TransactionStore::new();
        for index in 0..5 {
            let mut record = history_header_record();
            record.path = format!("/{index}");
            if index == 2 {
                record.request.headers.clear();
                record.response = None;
            }
            if index == 4 {
                record.method = "CONNECT".into();
            }
            store.insert(record).await;
        }
        let filters = ListFilters {
            query: Some("ExampleCredential".into()),
            search_headers: true,
            hide_connect: true,
            limit: Some(2),
            ..Default::default()
        };
        let first = store.list_page(&filters).await;
        assert_eq!(
            first
                .items
                .iter()
                .map(|row| row.path.as_str())
                .collect::<Vec<_>>(),
            vec!["/3", "/1"]
        );
        assert!(first.has_more);
        let next = store
            .list_page(&ListFilters {
                before_sequence: first.items.last().map(|row| row.sequence),
                ..filters.clone()
            })
            .await;
        assert_eq!(
            next.items
                .iter()
                .map(|row| row.path.as_str())
                .collect::<Vec<_>>(),
            vec!["/0"]
        );
        assert!(!next.has_more);
        let complete = store
            .list_page(&ListFilters {
                limit: Some(0),
                ..filters.clone()
            })
            .await;
        assert_eq!(complete.total, 5);
        assert_eq!(complete.filtered_total, Some(3));
        assert_eq!(complete.hidden_connect_total, Some(1));
        let sorted = store
            .list_page(&ListFilters {
                sort_key: Some("path".into()),
                sort_direction: Some("asc".into()),
                offset: Some(1),
                ..filters
            })
            .await;
        assert_eq!(
            sorted
                .items
                .iter()
                .map(|row| row.path.as_str())
                .collect::<Vec<_>>(),
            vec!["/1", "/3"]
        );
        assert_eq!(sorted.filtered_total, Some(3));
        assert_eq!(sorted.hidden_connect_total, Some(1));
    }

    #[test]
    fn deletion_filters_require_explicit_supported_nonempty_criteria() {
        assert!(validate_delete_filters(&ListFilters::default()).is_err());
        for filters in [
            ListFilters {
                query: Some(" ".into()),
                ..Default::default()
            },
            ListFilters {
                method: Some("\t".into()),
                ..Default::default()
            },
            ListFilters {
                host: Some("".into()),
                ..Default::default()
            },
            ListFilters {
                mime: Some("\n".into()),
                ..Default::default()
            },
            ListFilters {
                status_range: Some("".into()),
                ..Default::default()
            },
            ListFilters {
                since: Some(" ".into()),
                ..Default::default()
            },
            ListFilters {
                status: Some(200),
                status_range: Some("2xx".into()),
                ..Default::default()
            },
            ListFilters {
                status: Some(0),
                ..Default::default()
            },
            ListFilters {
                status: Some(600),
                ..Default::default()
            },
            ListFilters {
                host: Some("example.com".into()),
                offset: Some(0),
                ..Default::default()
            },
            ListFilters {
                host: Some("example.com".into()),
                limit: Some(10),
                ..Default::default()
            },
            ListFilters {
                host: Some("example.com".into()),
                hide_connect: true,
                ..Default::default()
            },
            ListFilters {
                host: Some("example.com".into()),
                advanced_search: Some("".into()),
                ..Default::default()
            },
        ] {
            assert!(validate_delete_filters(&filters).is_err(), "{filters:?}");
        }
        for filters in [
            ListFilters {
                query: Some("/login".into()),
                ..Default::default()
            },
            ListFilters {
                method: Some("POST".into()),
                ..Default::default()
            },
            ListFilters {
                host: Some("example.com".into()),
                limit: Some(0),
                ..Default::default()
            },
            ListFilters {
                mime: Some("application/json".into()),
                ..Default::default()
            },
            ListFilters {
                status: Some(404),
                ..Default::default()
            },
        ] {
            assert!(validate_delete_filters(&filters).is_ok(), "{filters:?}");
        }
    }

    #[test]
    fn deletion_filters_reject_malformed_ranges_and_overflowing_times() {
        for range in [
            "garbage", "299-200", "99-199", "500-600", "0xx", "6xx", "200-", "200",
        ] {
            let filters = ListFilters {
                status_range: Some(range.into()),
                ..Default::default()
            };
            assert!(validate_delete_filters(&filters).is_err(), "{range}");
        }
        for since in [
            "garbage",
            "2026-02-30",
            "-1h",
            "+1h",
            "1.5h",
            "9223372036854775807d",
            "9223372036854775807s",
            "999999999999999999999h",
            "999999999999m",
        ] {
            let filters = ListFilters {
                since: Some(since.into()),
                ..Default::default()
            };
            assert!(validate_delete_filters(&filters).is_err(), "{since}");
        }
        for range in ["4xx", "200-299", "100-599"] {
            assert!(validate_delete_filters(&ListFilters {
                status_range: Some(range.into()),
                ..Default::default()
            })
            .is_ok());
        }
        for since in [
            "30m",
            "1h",
            "2d",
            "15s",
            "0s",
            "2026-01-01",
            "2026-01-01T12:00:00Z",
        ] {
            assert!(
                validate_delete_filters(&ListFilters {
                    since: Some(since.into()),
                    ..Default::default()
                })
                .is_ok(),
                "{since}"
            );
        }
    }

    #[tokio::test]
    async fn delete_ids_deduplicates_and_preserves_surviving_indexes_and_bodies() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-delete-records-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&data_dir).unwrap();
        let records: Vec<_> = (0..3)
            .map(|index| {
                let mut record = test_record("example.com");
                record.path = format!("/{index}");
                record.sequence = index + 1;
                record.request.body_preview = format!("fixture body {index}");
                record.request.body_size = record.request.body_preview.len();
                record
            })
            .collect();
        let ids: Vec<_> = records.iter().map(|record| record.id).collect();
        let locators = crate::session::write_transactions_file_for_test_returning_locators(
            &data_dir, &records,
        )
        .unwrap();
        let store = TransactionStore::from_records_with_journal(
            records.into_iter().rev().collect(),
            data_dir.join("transactions.journal"),
            None,
        );
        store.adopt_written_locators(locators).await;
        let survivor_locator = store.inner.read().await.locators[&ids[1]];
        let mut reload = store.subscribe_retention();
        let event_sequence = store.latest_event_sequence();

        assert_eq!(
            store.delete_ids(&[ids[0], ids[2], ids[0]]).await.unwrap(),
            2
        );
        assert_eq!(store.latest_event_sequence(), event_sequence + 1);
        assert!(reload.try_recv().is_ok());
        assert!(reload.try_recv().is_err());
        assert!(store.get(ids[0]).await.is_none());
        assert!(store.get(ids[2]).await.is_none());
        let survivor = store.get(ids[1]).await.unwrap();
        assert_eq!(survivor.request.body_preview, "fixture body 1");
        assert_eq!(survivor.path, "/1");
        let inner = store.inner.read().await;
        assert_eq!(inner.entries.len(), 1);
        assert_eq!(inner.summaries.len(), 1);
        assert_eq!(inner.by_id[&ids[1]], 0);
        assert_eq!(inner.locators.len(), 1);
        assert_eq!(inner.locators[&ids[1]].offset, survivor_locator.offset);
        drop(inner);
        let lines = std::fs::read_to_string(data_dir.join("transactions.journal")).unwrap();
        let entry: TransactionJournalEntry = serde_json::from_str(lines.trim()).unwrap();
        let TransactionJournalEntry::Delete { ids: deleted } = entry else {
            panic!("expected deletion tombstone")
        };
        assert_eq!(deleted, vec![ids[0], ids[2]]);
        assert_eq!(store.delete_ids(&[ids[1]]).await.unwrap(), 1);
        assert!(store.is_empty().await);
        drop(store);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn delete_ids_rejects_empty_missing_and_wrong_session_without_appending() {
        let record = test_record("example.com");
        let id = record.id;
        let mut store = TransactionStore::from_records(vec![record]);
        let (tx, rx) = mpsc::channel();
        store.journal_tx = Some(tx);
        for ids in [vec![], vec![Uuid::new_v4()], vec![id, Uuid::new_v4()]] {
            assert_eq!(
                store.delete_ids(&ids).await.unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(store.len().await, 1);
            assert!(rx.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn delete_selection_checks_token_after_concurrent_response_update_finishes() {
        use crate::history_selection::{selection_token, HistorySelection};
        use std::{sync::Arc, time::Duration};
        let record = test_record("example.com");
        let id = record.id;
        let mut store = TransactionStore::from_records(vec![record]);
        let (tx, rx) = mpsc::channel();
        store.journal_tx = Some(tx);
        let store = Arc::new(store);
        let mut selection: HistorySelection = serde_json::from_value(serde_json::json!({
            "session_id": Uuid::new_v4(), "host": "example.com"
        }))
        .unwrap();
        selection.selection_token = Some(selection_token(
            selection.session_id,
            &selection.resolve(&store).await.unwrap(),
        ));
        let update = {
            let store = store.clone();
            tokio::spawn(async move {
                store
                    .update_record_durable(id, |record| record.status = Some(404))
                    .await
            })
        };
        let (rx, command) = tokio::task::spawn_blocking(move || {
            let command = rx.recv_timeout(Duration::from_secs(1)).unwrap();
            (rx, command)
        })
        .await
        .unwrap();
        let TransactionJournalCommand::Append { ack: Some(ack), .. } = command else {
            panic!("expected acknowledged update")
        };
        let deletion = {
            let store = store.clone();
            tokio::spawn(async move { store.delete_selection(&selection).await })
        };
        ack.send(Ok(())).unwrap();
        assert!(update.await.unwrap().unwrap().is_some());
        assert_eq!(
            deletion.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(
            rx.try_recv().is_err(),
            "stale selection must not append a tombstone"
        );
        assert_eq!(store.get(id).await.unwrap().status, Some(404));
    }

    #[tokio::test]
    async fn delete_all_handles_empty_store_without_a_journal() {
        let store = TransactionStore::new();
        assert_eq!(store.delete_all().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn delete_ids_requires_available_journal() {
        let record = test_record("example.com");
        let id = record.id;
        let mut store = TransactionStore::from_records(vec![record]);
        assert_eq!(
            store.delete_ids(&[id]).await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        let (tx, rx) = mpsc::channel();
        drop(rx);
        store.journal_tx = Some(tx);
        let error = store.delete_ids(&[id]).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(
            error
                .get_ref()
                .unwrap()
                .downcast_ref::<io::Error>()
                .unwrap()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        assert!(store.get(id).await.is_some());
    }

    #[tokio::test]
    async fn delete_ids_waits_for_ack_and_keeps_memory_on_append_failure() {
        use std::{sync::Arc, time::Duration};
        let record = test_record("example.com");
        let id = record.id;
        let mut store = TransactionStore::from_records(vec![record]);
        let (tx, rx) = mpsc::channel();
        store.journal_tx = Some(tx);
        let store = Arc::new(store);
        let mut reload = store.subscribe_retention();
        let pending = {
            let store = store.clone();
            tokio::spawn(async move { store.delete_ids(&[id]).await })
        };
        let command = tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(1)))
            .await
            .unwrap()
            .unwrap();
        let TransactionJournalCommand::Append { ack: Some(ack), .. } = command else {
            panic!("expected acknowledged append")
        };
        let count = tokio::time::timeout(Duration::from_millis(200), store.len())
            .await
            .unwrap();
        assert_eq!(
            count, 1,
            "pending persistence must not mutate or block reads"
        );
        assert!(reload.try_recv().is_err());
        ack.send(Err(io::Error::other("injected journal failure")))
            .unwrap();
        assert!(pending.await.unwrap().is_err());
        assert!(store.get(id).await.is_some());
        assert!(reload.try_recv().is_err());
    }

    #[tokio::test]
    async fn delete_ids_lost_ack_is_persistence_failure_without_memory_changes() {
        let record = test_record("example.com");
        let id = record.id;
        let mut store = TransactionStore::from_records(vec![record]);
        let (tx, rx) = mpsc::channel();
        store.journal_tx = Some(tx);
        let writer = std::thread::spawn(move || {
            let command = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
            assert!(matches!(
                command,
                TransactionJournalCommand::Append { ack: Some(_), .. }
            ));
            drop(command);
        });
        let error = store.delete_ids(&[id]).await.unwrap_err();
        writer.join().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(
            error
                .get_ref()
                .unwrap()
                .downcast_ref::<io::Error>()
                .unwrap()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        assert!(store.get(id).await.is_some());
    }

    /// Shared fixture for the store, receipt and HTTP error classifications.
    pub(crate) async fn failed_delete_ack_for_test(
        clear: bool,
        journal_path: Option<&Path>,
    ) -> io::Error {
        use std::{sync::Arc, time::Duration};
        let mut selected = test_record("example.com");
        selected.path = "/selected".into();
        let selected_id = selected.id;
        let mut survivor = test_record("example.com");
        survivor.path = "/survivor".into();
        let mut store = TransactionStore::from_records(vec![selected, survivor]);
        let before = store.snapshot(None).await;
        let before_json = serde_json::to_value(&before).unwrap();
        let (tx, rx) = mpsc::channel();
        store.journal_tx = Some(tx);
        let store = Arc::new(store);
        let event_sequence = store.latest_event_sequence();
        let mut retention = store.subscribe_retention();
        let pending = {
            let store = store.clone();
            tokio::spawn(async move {
                if clear {
                    store.delete_all().await
                } else {
                    let selection = serde_json::from_value(serde_json::json!({
                        "session_id": Uuid::new_v4(), "ids": [selected_id]
                    }))
                    .unwrap();
                    store
                        .delete_selection(&selection)
                        .await
                        .map(|(count, _)| count)
                }
            })
        };
        let command = tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(5)))
            .await
            .unwrap()
            .unwrap();
        let TransactionJournalCommand::Append {
            line,
            ack: Some(ack),
        } = command
        else {
            panic!("expected acknowledged deletion")
        };
        assert_eq!(
            serde_json::to_value(store.snapshot(None).await).unwrap(),
            before_json
        );
        if let Some(path) = journal_path {
            // Model a complete write followed by a failed fsync acknowledgement.
            // These exact bytes may be recovered even though memory stays intact.
            let mut file = fs::File::create(path).unwrap();
            for record in before.iter().rev() {
                file.write_all(&encode_transaction_insert_journal_line(record).unwrap())
                    .unwrap();
            }
            file.write_all(&line).unwrap();
            file.flush().unwrap();
            file.sync_all().unwrap();
        }
        ack.send(Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "injected sync failure",
        )))
        .unwrap();
        let error = pending.await.unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        let source = error
            .get_ref()
            .unwrap()
            .downcast_ref::<io::Error>()
            .unwrap();
        assert_eq!(source.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(source.to_string(), "injected sync failure");
        assert_eq!(
            serde_json::to_value(store.snapshot(None).await).unwrap(),
            before_json
        );
        assert_eq!(store.list(&ListFilters::default()).await.len(), 2);
        assert!(store.get(selected_id).await.is_some());
        assert_eq!(store.latest_event_sequence(), event_sequence);
        assert!(retention.try_recv().is_err());
        error
    }

    #[tokio::test]
    async fn delete_invalid_input_ack_is_uncertain_and_tombstone_can_replay() {
        for clear in [false, true] {
            let data_dir =
                std::env::temp_dir().join(format!("sniper-delete-ack-{}", Uuid::new_v4()));
            let (registry, active) =
                crate::session::SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
            let journal_path = active.storage_dir().join("transactions.journal");
            drop(active);
            drop(registry);
            failed_delete_ack_for_test(clear, Some(&journal_path)).await;
            let (registry, reloaded) =
                crate::session::SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();
            let rows = reloaded.store.list(&ListFilters::default()).await;
            assert_eq!(rows.len(), usize::from(!clear));
            assert!(rows.iter().all(|row| row.path == "/survivor"));
            drop(reloaded);
            drop(registry);
            fs::remove_dir_all(data_dir).unwrap();
        }
    }

    pub(crate) async fn stale_delete_selection_error_for_test() -> io::Error {
        let record = test_record("example.com");
        let id = record.id;
        let mut store = TransactionStore::from_records(vec![record]);
        let (tx, rx) = mpsc::channel();
        store.journal_tx = Some(tx);
        let selection = serde_json::from_value(serde_json::json!({
            "session_id": Uuid::new_v4(), "ids": [id], "selection_token": "0".repeat(64)
        }))
        .unwrap();
        let error = store.delete_selection(&selection).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(
            rx.try_recv().is_err(),
            "stale validation must not append anything"
        );
        assert!(store.get(id).await.is_some());
        error
    }

    #[tokio::test]
    async fn stale_delete_selection_remains_invalid_input_without_appending() {
        stale_delete_selection_error_for_test().await;
    }

    #[tokio::test]
    async fn cancelled_delete_waiting_for_ack_does_not_mutate_memory() {
        use std::{sync::Arc, time::Duration};
        let record = test_record("example.com");
        let id = record.id;
        let mut store = TransactionStore::from_records(vec![record]);
        let (tx, rx) = mpsc::channel();
        store.journal_tx = Some(tx);
        let store = Arc::new(store);
        let pending = {
            let store = store.clone();
            tokio::spawn(async move { store.delete_ids(&[id]).await })
        };
        let command = tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(1)))
            .await
            .unwrap()
            .unwrap();
        let TransactionJournalCommand::Append { ack: Some(ack), .. } = command else {
            panic!("expected acknowledged append")
        };
        pending.abort();
        assert!(pending.await.unwrap_err().is_cancelled());
        assert!(ack
            .send(Err(io::Error::other("injected failed append")))
            .is_err());
        assert!(store.get(id).await.is_some());
    }

    #[test]
    fn transaction_journal_writer_reports_open_failure() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-store-journal-open-failure-{}",
            uuid::Uuid::new_v4()
        ));
        let journal_path = data_dir.join("transactions.journal");
        std::fs::create_dir_all(&journal_path).unwrap();

        let writer = start_transaction_journal_writer(journal_path);

        assert!(writer.is_none());
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[cfg(unix)]
    #[test]
    fn transaction_journal_writer_creates_private_file_and_directory() {
        use std::os::unix::fs::PermissionsExt as _;

        let data_dir = std::env::temp_dir().join(format!(
            "sniper-store-journal-private-{}",
            uuid::Uuid::new_v4()
        ));
        let journal_path = data_dir.join("transactions.journal");

        let writer = start_transaction_journal_writer(journal_path.clone()).unwrap();
        drop(writer);

        let dir_mode = std::fs::metadata(&data_dir).unwrap().permissions().mode() & 0o777;
        let file_mode = std::fs::metadata(&journal_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert_eq!(file_mode, 0o600);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn locators_follow_the_file_after_a_rewrite() {
        // A rewrite moves every offset after the first record whose serialized form
        // changed. A stale offset does not error — it parses whatever line happens
        // to sit there and hands back a different request's traffic.
        let storage_dir =
            std::env::temp_dir().join(format!("sniper-locator-refresh-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&storage_dir).unwrap();
        let make = |path: &str, body: &str, sequence: u64| {
            let mut record = TransactionRecord::http(
                Utc::now(),
                "GET".to_string(),
                "https".to_string(),
                "shift.example:443".to_string(),
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
            );
            record.sequence = sequence;
            record
        };
        let first = make("/first", "short", 1);
        let second = make("/second", "the second body", 2);
        let second_id = second.id;
        crate::session::write_transactions_file_for_test(
            &storage_dir,
            &[first.clone(), second.clone()],
        )
        .unwrap();
        let located = crate::session::read_transactions_file_for_test(&storage_dir).unwrap();

        let mut stripped_second = second.clone();
        super::strip_transaction_bodies(&mut stripped_second);
        let store = TransactionStore::from_records_with_journal_and_event_sequence(
            vec![stripped_second],
            storage_dir.join("transactions.journal"),
            None,
            0,
        );
        store
            .set_body_locator_for_test(second_id, located[1].1)
            .await;

        // Rewrite with a longer first record, which pushes the second one along.
        let grown_first = make("/first", &"x".repeat(4096), 1);
        let fresh = crate::session::write_transactions_file_for_test_returning_locators(
            &storage_dir,
            &[grown_first, second.clone()],
        )
        .unwrap();
        store.adopt_written_locators(fresh).await;

        let fetched = store.get(second_id).await.expect("record should be found");
        assert_eq!(fetched.path, "/second");
        assert_eq!(fetched.request.body_preview, "the second body");

        let _ = std::fs::remove_dir_all(storage_dir);
    }

    #[tokio::test]
    async fn get_reads_bodies_back_for_a_record_kept_on_disk() {
        // Viewing a request is the one place the body text is needed. If get()
        // returned the stripped copy, the detail pane would show an empty body for
        // everything captured before the last restart.
        let storage_dir =
            std::env::temp_dir().join(format!("sniper-get-rehydrate-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&storage_dir).unwrap();
        let mut record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "detail.example:443".to_string(),
            "/view".to_string(),
            Some(200),
            1,
            MessageRecord {
                headers: vec![],
                body_preview: "request text".to_string(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 12,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            },
            Some(MessageRecord {
                headers: vec![],
                body_preview: "response text".to_string(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 13,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            }),
            vec![],
            None,
            None,
        );
        record.sequence = 1;
        let record_id = record.id;
        crate::session::write_transactions_file_for_test(&storage_dir, &[record.clone()]).unwrap();
        let locator = crate::session::read_transactions_file_for_test(&storage_dir).unwrap()[0].1;

        let mut stripped = record.clone();
        super::strip_transaction_bodies(&mut stripped);
        // An annotation applied after loading must win over the copy on disk.
        stripped.color_tag = Some("red".to_string());
        let store = TransactionStore::from_records_with_journal_and_event_sequence(
            vec![stripped],
            storage_dir.join("transactions.journal"),
            None,
            0,
        );
        store.set_body_locator_for_test(record_id, locator).await;

        let fetched = store.get(record_id).await.expect("record should be found");
        assert_eq!(fetched.request.body_preview, "request text");
        assert_eq!(
            fetched.response.as_ref().unwrap().body_preview,
            "response text"
        );
        assert_eq!(fetched.color_tag.as_deref(), Some("red"));

        let _ = std::fs::remove_dir_all(storage_dir);
    }

    #[tokio::test]
    async fn rewriting_copies_bodies_across_for_a_stripped_record() {
        // The gate this whole change rests on: once bodies live on disk, handing a
        // stripped record to a writer would replace the stored bodies with nothing.
        // snapshot_for_persistence must read them back first.
        let storage_dir =
            std::env::temp_dir().join(format!("sniper-rehydrate-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&storage_dir).unwrap();
        let mut record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "rehydrate.example:443".to_string(),
            "/body".to_string(),
            Some(200),
            1,
            MessageRecord {
                headers: vec![],
                body_preview: "the request body".to_string(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 16,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            },
            Some(MessageRecord {
                headers: vec![],
                body_preview: "the response body".to_string(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 17,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            }),
            vec![],
            None,
            None,
        );
        record.sequence = 1;
        let record_id = record.id;
        crate::session::write_transactions_file_for_test(&storage_dir, &[record.clone()]).unwrap();
        let locator = crate::session::read_transactions_file_for_test(&storage_dir).unwrap()[0].1;

        // Build a store holding the stripped record plus its locator, as loading will.
        let mut stripped = record.clone();
        super::strip_transaction_bodies(&mut stripped);
        let store = TransactionStore::from_records_with_journal_and_event_sequence(
            vec![stripped],
            storage_dir.join("transactions.journal"),
            None,
            0,
        );
        store.set_body_locator_for_test(record_id, locator).await;

        // The store hands back the stripped record plus where its bodies sit; the
        // writer is what puts them in the new file. What matters is that the file
        // it writes still has them.
        let persisted = store.snapshot_for_persistence(None).await.unwrap();
        assert_eq!(persisted.len(), 1);
        assert!(persisted[0].0.request.body_preview.is_empty());
        assert!(persisted[0].1.is_some(), "bodies must be locatable on disk");

        crate::session::rewrite_transactions_file_for_test(&storage_dir, &persisted).unwrap();
        let rewritten = crate::session::read_transactions_file_for_test(&storage_dir).unwrap();
        assert_eq!(rewritten.len(), 1);
        assert_eq!(rewritten[0].0.request.body_preview, "the request body");
        assert_eq!(
            rewritten[0].0.response.as_ref().unwrap().body_preview,
            "the response body"
        );

        let _ = std::fs::remove_dir_all(storage_dir);
    }

    // The test above proves the happy path: a stripped record plus its locator
    // persists with its bodies intact, because the writer copies the original
    // line. This one asks what happens when the record is UPDATED after it got
    // that locator. The loader drops locators for records it replayed from the
    // journal (from_located_records_with_journal), on the principle that memory
    // newer than disk must not be served from disk. update_record does not.
    #[tokio::test]
    async fn an_update_after_persist_survives_the_next_persist() {
        let storage_dir =
            std::env::temp_dir().join(format!("sniper-update-locator-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&storage_dir).unwrap();
        let mut record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "update.example:443".to_string(),
            "/body".to_string(),
            Some(200),
            1,
            MessageRecord {
                headers: vec![],
                body_preview: "the request body".to_string(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 16,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            },
            Some(MessageRecord {
                headers: vec![],
                body_preview: "the response body".to_string(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 17,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            }),
            vec![],
            None,
            None,
        );
        record.sequence = 1;
        let record_id = record.id;
        crate::session::write_transactions_file_for_test(&storage_dir, &[record.clone()]).unwrap();
        let locator = crate::session::read_transactions_file_for_test(&storage_dir).unwrap()[0].1;

        // The state a load leaves behind: bodies on disk, stripped in memory.
        let mut stripped = record.clone();
        super::strip_transaction_bodies(&mut stripped);
        let store = TransactionStore::from_records_with_journal_and_event_sequence(
            vec![stripped],
            storage_dir.join("transactions.journal"),
            None,
            0,
        );
        store.set_body_locator_for_test(record_id, locator).await;

        // Something the proxy does routinely: finish a record after it was first
        // written. src/proxy.rs calls update_record/update_record_durable here.
        store
            .update_record(record_id, |record| {
                record.duration_ms = 250;
                record.notes = vec!["SSL passthrough: 10 bytes sent".to_string()];
            })
            .await
            .unwrap();

        let persisted = store.snapshot_for_persistence(None).await.unwrap();
        assert_eq!(persisted.len(), 1);

        crate::session::rewrite_transactions_file_for_test(&storage_dir, &persisted).unwrap();
        let rewritten = crate::session::read_transactions_file_for_test(&storage_dir).unwrap();
        assert_eq!(rewritten.len(), 1);

        // The bodies still have to be there - that is what the locator is for.
        assert_eq!(rewritten[0].0.request.body_preview, "the request body");
        assert_eq!(
            rewritten[0].0.response.as_ref().unwrap().body_preview,
            "the response body"
        );
        // And so does the update.
        assert_eq!(
            rewritten[0].0.notes,
            vec!["SSL passthrough: 10 bytes sent".to_string()],
            "an update made after the record got a locator must reach the new file"
        );
        assert_eq!(rewritten[0].0.duration_ms, 250);

        let _ = std::fs::remove_dir_all(storage_dir);
    }

    // The fix above covers one persist. This asks whether it holds across a
    // restart: the loader keeps the locator for a record it replayed from an
    // Update journal entry (only Insert ids reach replayed_transaction_ids), so
    // the stale line could be copied again on the next persist.
    #[tokio::test]
    async fn an_update_replayed_from_the_journal_still_reaches_the_next_file() {
        let storage_dir =
            std::env::temp_dir().join(format!("sniper-update-reload-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&storage_dir).unwrap();
        let mut record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "reload.example:443".to_string(),
            "/body".to_string(),
            Some(200),
            1,
            MessageRecord {
                headers: vec![],
                body_preview: "the request body".to_string(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 16,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            },
            Some(MessageRecord {
                headers: vec![],
                body_preview: "the response body".to_string(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 17,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            }),
            vec![],
            None,
            None,
        );
        record.sequence = 1;
        let record_id = record.id;
        crate::session::write_transactions_file_for_test(&storage_dir, &[record.clone()]).unwrap();
        let locator = crate::session::read_transactions_file_for_test(&storage_dir).unwrap()[0].1;

        // A second load, through the real loader: the record came back from an
        // Update entry in the journal, so it is whole in memory and carries the
        // note, while the locator still points at the line written before it.
        let mut updated = record.clone();
        updated.notes = vec!["replayed from the journal".to_string()];
        let mut locators = std::collections::HashMap::new();
        locators.insert(record_id, locator);
        let store = TransactionStore::from_located_records_with_journal(
            vec![updated],
            locators,
            // Only Insert ids land here; an Update-replayed record does not.
            &std::collections::HashSet::new(),
            storage_dir.join("transactions.journal"),
            0,
        );

        let persisted = store.snapshot_for_persistence(None).await.unwrap();
        crate::session::rewrite_transactions_file_for_test(&storage_dir, &persisted).unwrap();
        let rewritten = crate::session::read_transactions_file_for_test(&storage_dir).unwrap();

        assert_eq!(rewritten[0].0.request.body_preview, "the request body");
        assert_eq!(
            rewritten[0].0.notes,
            vec!["replayed from the journal".to_string()],
            "an update restored from the journal must reach the new file too"
        );

        let _ = std::fs::remove_dir_all(storage_dir);
    }

    // A BodyLocator is a byte range, not a key. If one goes stale and lands on
    // another record's line, that line parses fine and the caller would be handed
    // a different request's traffic with no error - the exact failure AGENTS.md
    // section 5.1 describes. The read path has to notice.
    #[tokio::test]
    async fn a_locator_pointing_at_another_record_does_not_serve_its_traffic() {
        let storage_dir =
            std::env::temp_dir().join(format!("sniper-crossed-locator-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&storage_dir).unwrap();

        let make = |host: &str, body: &str| {
            let mut record = TransactionRecord::http(
                Utc::now(),
                "GET".to_string(),
                "https".to_string(),
                host.to_string(),
                "/body".to_string(),
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
                Some(MessageRecord {
                    headers: vec![],
                    body_preview: body.to_string(),
                    body_encoding: BodyEncoding::Utf8,
                    body_size: body.len(),
                    decoded_body_size: None,
                    preview_truncated: false,
                    content_type: None,
                    content_decoded: false,
                }),
                vec![],
                None,
                None,
            );
            record.sequence = 1;
            record
        };
        let mine = make("mine.example:443", "my own response");
        let theirs = make("theirs.example:443", "SOMEONE ELSES TRAFFIC");
        let mine_id = mine.id;

        crate::session::write_transactions_file_for_test(&storage_dir, &[mine, theirs.clone()])
            .unwrap();
        let on_disk = crate::session::read_transactions_file_for_test(&storage_dir).unwrap();
        let theirs_locator = on_disk
            .iter()
            .find(|(record, _)| record.id == theirs.id)
            .map(|(_, locator)| *locator)
            .unwrap();

        // My record, stripped as a load leaves it, but pointed at their line.
        let mut stripped = on_disk
            .iter()
            .find(|(record, _)| record.id == mine_id)
            .map(|(record, _)| record.clone())
            .unwrap();
        super::strip_transaction_bodies(&mut stripped);
        let store = TransactionStore::from_records_with_journal_and_event_sequence(
            vec![stripped],
            storage_dir.join("transactions.journal"),
            None,
            0,
        );
        // from_records_with_journal_and_event_sequence takes storage_dir from the
        // journal path's parent, so the read path can already find the file.
        store
            .set_body_locator_for_test(mine_id, theirs_locator)
            .await;

        let fetched = store.get(mine_id).await.expect("record is in the store");
        assert_eq!(fetched.id, mine_id);
        assert_eq!(
            fetched.response.as_ref().unwrap().body_preview,
            "",
            "a crossed locator must yield no body, never another record's traffic"
        );

        let _ = std::fs::remove_dir_all(storage_dir);
    }

    fn search_request(value: &str) -> super::BodySearchRequest {
        super::BodySearchRequest {
            value: value.to_string(),
            sides: super::BodySearchSides::default(),
            case_sensitive: false,
            max_matches: 50,
            byte_budget: 10_000_000,
            context_bytes: 48,
        }
    }

    fn record_with_bodies(
        host: &str,
        request_body: &str,
        response_body: &str,
    ) -> TransactionRecord {
        let mut record = TransactionRecord::http(
            Utc::now(),
            "POST".to_string(),
            "https".to_string(),
            host.to_string(),
            "/api/orders".to_string(),
            Some(200),
            1,
            MessageRecord {
                headers: vec![HeaderRecord {
                    name: "x-trace".to_string(),
                    value: "trace-in-a-header".to_string(),
                }],
                body_preview: request_body.to_string(),
                body_encoding: BodyEncoding::Utf8,
                body_size: request_body.len(),
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            },
            Some(MessageRecord {
                headers: vec![],
                body_preview: response_body.to_string(),
                body_encoding: BodyEncoding::Utf8,
                body_size: response_body.len(),
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            }),
            vec![],
            None,
            None,
        );
        record.sequence = 1;
        record
    }

    // The gap this closes: the metadata haystack has no bodies in it, so a value
    // that only ever appeared in one is invisible to `query` no matter how it is
    // spelled. Both searches run against the same record here.
    #[tokio::test]
    async fn a_body_search_finds_what_the_metadata_query_cannot() {
        let store = TransactionStore::from_records_with_max_entries(Vec::new(), None);
        store
            .insert(record_with_bodies(
                "orders.example",
                "{\"order_id\":\"A-9931\"}",
                "{\"internalNote\":\"staff only\"}",
            ))
            .await;

        let by_metadata = store
            .list(&ListFilters {
                query: Some("internalNote".to_string()),
                ..Default::default()
            })
            .await;
        assert!(
            by_metadata.is_empty(),
            "metadata search cannot see into a body"
        );

        let found = store
            .search_bodies(&ListFilters::default(), &search_request("internalNote"))
            .await;
        assert_eq!(found.match_count, 1);
        let hit = &found.transactions[0].matches[0];
        assert_eq!(hit.side, "response-body");
        assert!(hit.context.contains("staff only"));
        assert!(found.complete);
        assert_eq!(found.unsearchable, 0);
    }

    // An analyst needs to know WHERE a value showed up, not just that it did:
    // a token in a request the client sent means something different from the
    // same token coming back in a response.
    #[tokio::test]
    async fn a_body_search_says_which_side_of_the_exchange_matched() {
        let store = TransactionStore::from_records_with_max_entries(Vec::new(), None);
        store
            .insert(record_with_bodies(
                "orders.example",
                "shared-token-value",
                "shared-token-value",
            ))
            .await;

        let found = store
            .search_bodies(
                &ListFilters::default(),
                &search_request("shared-token-value"),
            )
            .await;
        assert_eq!(found.transactions.len(), 1, "one transaction, two places");
        let sides: Vec<&str> = found.transactions[0]
            .matches
            .iter()
            .map(|m| m.side)
            .collect();
        assert_eq!(sides, vec!["request-body", "response-body"]);

        let in_header = store
            .search_bodies(
                &ListFilters::default(),
                &search_request("trace-in-a-header"),
            )
            .await;
        assert_eq!(in_header.match_count, 1);
        assert_eq!(in_header.transactions[0].matches[0].side, "request-headers");
    }

    // A budget that runs out must not look like an answer. An agent that reads
    // "no matches" as "not present" would clear a finding that was never checked.
    #[tokio::test]
    async fn a_truncated_body_search_says_so_rather_than_reporting_absence() {
        let store = TransactionStore::from_records_with_max_entries(Vec::new(), None);
        for _ in 0..5 {
            store
                .insert(record_with_bodies("orders.example", "", "needle here"))
                .await;
        }

        let mut request = search_request("needle");
        request.byte_budget = 1;
        let found = store.search_bodies(&ListFilters::default(), &request).await;
        assert!(
            !found.complete,
            "a scan cut short by its budget must report complete = false"
        );
        assert!(found.records_scanned < found.records_considered);

        let mut capped = search_request("needle");
        capped.max_matches = 2;
        let limited = store.search_bodies(&ListFilters::default(), &capped).await;
        assert_eq!(limited.match_count, 2);
        assert_eq!(limited.transactions.len(), 2);
        assert!(!limited.complete);
        assert_eq!(limited.stopped_by, Some("max_matches"));
    }

    // After a restart every body lives on disk behind a locator, so this is the
    // path a real search takes. A record whose locator no longer points at its
    // own line is counted, not searched — and it makes the result incomplete,
    // because "not found" says nothing about a record that was never read.
    #[tokio::test]
    async fn a_body_search_reads_bodies_back_from_disk() {
        let storage_dir =
            std::env::temp_dir().join(format!("sniper-body-search-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&storage_dir).unwrap();
        let readable = record_with_bodies("readable.example", "", "disk-only-needle");
        let mut crossed = record_with_bodies("crossed.example", "", "disk-only-needle");
        crossed.sequence = 2;
        crate::session::write_transactions_file_for_test(
            &storage_dir,
            &[readable.clone(), crossed.clone()],
        )
        .unwrap();
        let on_disk = crate::session::read_transactions_file_for_test(&storage_dir).unwrap();
        let readable_locator = on_disk[0].1;

        let stripped: Vec<_> = on_disk
            .iter()
            .map(|(record, _)| {
                let mut record = record.clone();
                super::strip_transaction_bodies(&mut record);
                record
            })
            .collect();
        let store = TransactionStore::from_records_with_journal_and_event_sequence(
            stripped,
            storage_dir.join("transactions.journal"),
            None,
            0,
        );
        store
            .set_body_locator_for_test(readable.id, readable_locator)
            .await;
        store
            .set_body_locator_for_test(crossed.id, readable_locator)
            .await;

        let found = store
            .search_bodies(&ListFilters::default(), &search_request("disk-only-needle"))
            .await;
        assert_eq!(found.transactions.len(), 1);
        assert_eq!(found.transactions[0].id, readable.id);
        assert_eq!(found.transactions[0].host, "readable.example");
        assert_eq!(found.unsearchable, 1);
        assert!(
            !found.complete,
            "an unreadable record makes the answer partial"
        );
        assert_eq!(found.stopped_by, None, "nothing cut the scan short");

        let _ = std::fs::remove_dir_all(storage_dir);
    }

    // Bodies are not ASCII. A window edge that lands inside a multi-byte
    // character must widen to the boundary, not panic the scan.
    #[test]
    fn match_context_never_splits_a_character() {
        let body = "주문번호 A-9931 확인";
        let at = body.find("A-9931").unwrap();
        for width in 0..8 {
            let context = super::match_context(body, at, "A-9931".len(), width);
            assert!(context.contains("A-9931"), "width {width}: {context}");
        }
        assert_eq!(super::match_context(body, at, 6, 1000), body);
    }

    #[tokio::test]
    async fn list_page_can_sort_by_whether_a_record_was_edited() {
        // The Edited column is sortable, so the server has to know the key. An
        // unknown key silently falls back to time order, which looks like the
        // column simply does not sort.
        let store = TransactionStore::new();
        for (path, edited) in [
            ("/plain", false),
            ("/changed", true),
            ("/also-plain", false),
        ] {
            let mut record = TransactionRecord::http(
                Utc::now(),
                "GET".to_string(),
                "https".to_string(),
                "sort.example:443".to_string(),
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
            );
            if edited {
                record.original_request = Some(MessageRecord {
                    headers: vec![],
                    body_preview: "before".to_string(),
                    body_encoding: BodyEncoding::Utf8,
                    body_size: 6,
                    decoded_body_size: None,
                    preview_truncated: false,
                    content_type: None,
                    content_decoded: false,
                });
            }
            store.insert(record).await;
        }

        let page = store
            .list_page(&ListFilters {
                sort_key: Some("edited".to_string()),
                sort_direction: Some("desc".to_string()),
                ..ListFilters::default()
            })
            .await;
        assert_eq!(
            page.items.first().map(|item| item.path.as_str()),
            Some("/changed")
        );
        assert!(page
            .items
            .first()
            .map(|item| item.has_match_replace)
            .unwrap_or(false));
    }

    #[test]
    fn stripping_bodies_keeps_everything_a_summary_needs() {
        // Bodies come off records loaded from disk. Anything the history list or a
        // persist decision reads must survive that, or the list silently changes
        // and a rewrite could shrink a record to nothing.
        let mut record = TransactionRecord::http(
            Utc::now(),
            "POST".to_string(),
            "https".to_string(),
            "strip.example:443".to_string(),
            "/submit".to_string(),
            Some(200),
            7,
            MessageRecord {
                headers: vec![],
                body_preview: "request body".to_string(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 4096,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: Some("application/json".to_string()),
                content_decoded: false,
            },
            Some(MessageRecord {
                headers: vec![],
                body_preview: "response body".to_string(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 8192,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: Some("text/html".to_string()),
                content_decoded: false,
            }),
            vec!["a note".to_string()],
            None,
            None,
        );
        let before = record.summary();

        super::strip_transaction_bodies(&mut record);

        assert!(record.request.body_preview.is_empty());
        assert!(record.response.as_ref().unwrap().body_preview.is_empty());
        // Sizes, content types and note counts are what the list shows.
        let after = record.summary();
        assert_eq!(after.request_bytes, before.request_bytes);
        assert_eq!(after.response_bytes, before.response_bytes);
        assert_eq!(after.content_type, before.content_type);
        assert_eq!(after.has_response, before.has_response);
        assert_eq!(after.note_count, before.note_count);
        assert_eq!(after.status, before.status);
        assert_eq!(after.sequence, before.sequence);
    }

    async fn publish_fixture_snapshot(
        store: Arc<TransactionStore>,
        snapshot: TransactionPersistenceSnapshot,
        storage_dir: &Path,
    ) -> io::Result<()> {
        let staged = storage_dir.join(format!("staged-{}", Uuid::new_v4()));
        fs::create_dir_all(&staged)?;
        let records: Vec<_> = snapshot.iter().map(|(record, _)| record.clone()).collect();
        let locators =
            crate::session::write_transactions_file_for_test_returning_locators(&staged, &records)
                .unwrap();
        let source = staged.join("transactions.ndjson");
        let destination = storage_dir.join("transactions.ndjson");
        let result = tokio::task::spawn_blocking(move || {
            store.publish_persistence_snapshot(&snapshot, locators, || {
                crate::platform::rename(&source, &destination)
            })
        })
        .await
        .unwrap();
        let _ = fs::remove_dir_all(staged);
        result
    }

    #[tokio::test]
    async fn publication_keeps_late_updates_inserts_annotations_and_deletions() {
        let dir = std::env::temp_dir().join(format!("sniper-publication-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let updated = record_with_bodies("example.com", "old update", "saved");
        let annotated = record_with_bodies("example.com", "annotated body", "saved");
        let deleted = record_with_bodies("example.com", "deleted body", "saved");
        let reused = record_with_bodies("example.com", "old reused body", "saved");
        let (updated_id, annotated_id, deleted_id, reused_id) =
            (updated.id, annotated.id, deleted.id, reused.id);
        let store = Arc::new(TransactionStore::from_records_with_journal(
            vec![updated, annotated, deleted, reused],
            dir.join("transactions.journal"),
            None,
        ));
        let snapshot = store.snapshot_for_persistence(None).await.unwrap();
        let captured_event = snapshot.latest_event_sequence;
        assert!(snapshot.journal_rotation_confirmed);
        store
            .update_record(updated_id, |record| {
                record.request.body_preview = "late update".into();
                record.request.body_size = 11;
            })
            .await
            .unwrap();
        store
            .update_annotations(
                annotated_id,
                Some(Some("blue".into())),
                Some(Some("late note".into())),
            )
            .await
            .unwrap();
        store.delete_ids(&[deleted_id]).await.unwrap();
        let inserted = record_with_bodies("example.com", "late insert", "saved");
        let inserted_id = inserted.id;
        store.insert(inserted).await;
        let mut replacement = record_with_bodies("example.com", "late same id", "saved");
        replacement.id = reused_id;
        store.insert(replacement).await;
        assert!(store.latest_event_sequence() > captured_event);

        publish_fixture_snapshot(store.clone(), snapshot, &dir)
            .await
            .unwrap();
        assert_eq!(
            store.get(updated_id).await.unwrap().request.body_preview,
            "late update"
        );
        assert_eq!(
            store.get(inserted_id).await.unwrap().request.body_preview,
            "late insert"
        );
        assert_eq!(
            store.get(reused_id).await.unwrap().request.body_preview,
            "late same id"
        );
        assert!(store.get(deleted_id).await.is_none());
        let annotated = store.get(annotated_id).await.unwrap();
        assert_eq!(annotated.request.body_preview, "annotated body");
        assert_eq!(annotated.color_tag.as_deref(), Some("blue"));
        assert_eq!(annotated.user_note.as_deref(), Some("late note"));
        let inner = store.inner.read().await;
        assert_eq!(inner.locators.len(), 1);
        assert!(inner.locators.contains_key(&annotated_id));
        assert!(inner.entries[inner.by_id[&annotated_id]]
            .request
            .body_preview
            .is_empty());
        drop(inner);
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn duplicate_insert_unreadable_dependency_blocks_capture_and_prepared_publication() {
        let mut failures = Vec::new();
        for mismatched in [false, true] {
            let dir = std::env::temp_dir()
                .join(format!("sniper-duplicate-dependency-{}", Uuid::new_v4()));
            fs::create_dir_all(&dir).unwrap();
            let original = record_with_bodies("example.com", "original saved body", "saved");
            let id = original.id;
            let store = Arc::new(TransactionStore::from_records_with_journal(
                vec![original],
                dir.join("transactions.journal"),
                None,
            ));
            let snapshot = store.snapshot_for_persistence(None).await.unwrap();
            publish_fixture_snapshot(store.clone(), snapshot, &dir)
                .await
                .unwrap();
            let prepared = store.snapshot_for_persistence(None).await.unwrap();
            if mismatched {
                let other = record_with_bodies("example.com", "unrelated saved body", "saved");
                crate::session::write_transactions_file_for_test(&dir, &[other]).unwrap();
            } else {
                fs::remove_file(dir.join("transactions.ndjson")).unwrap();
            }
            let mut replacement = record_with_bodies("example.com", "new supplied body", "saved");
            replacement.id = id;
            store.insert(replacement).await;
            assert_eq!(
                store.len().await,
                2,
                "same-ID ordering rows must remain present"
            );
            assert_eq!(
                store.get(id).await.unwrap().request.body_preview,
                "new supplied body"
            );
            let capture_rejected = store.snapshot_for_persistence(None).await.is_err();
            let attempted = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let attempted_by_publisher = attempted.clone();
            let publisher = store.clone();
            let publication_rejected = tokio::task::spawn_blocking(move || {
                publisher.publish_persistence_snapshot(
                    &prepared,
                    HashMap::from([(id, crate::session::BodyLocator { offset: 0, len: 1 })]),
                    || {
                        attempted_by_publisher.store(true, Ordering::SeqCst);
                        Ok(())
                    },
                )
            })
            .await
            .unwrap()
            .is_err();
            let renamed = attempted.load(Ordering::SeqCst);
            if !capture_rejected || !publication_rejected || renamed {
                failures.push(format!("{} source: capture_rejected={capture_rejected}, publication_rejected={publication_rejected}, rename_attempted={renamed}", if mismatched { "mismatched" } else { "missing" }));
            }
            if mismatched {
                store.replace_all(Vec::new()).await;
            } else {
                store.delete_ids(&[id]).await.unwrap();
            }
            assert!(
                store
                    .snapshot_for_persistence(None)
                    .await
                    .unwrap()
                    .is_empty(),
                "removing all dependent rows must clear the blocker"
            );
            let _ = fs::remove_dir_all(dir);
        }
        assert!(
            failures.is_empty(),
            "unreadable duplicate bodies must fail closed: {}",
            failures.join("; ")
        );
    }

    #[tokio::test]
    async fn duplicate_body_search_keeps_each_ordering_rows_distinct_body() {
        let older = record_with_bodies("example.com", "older-only-needle", "saved");
        let mut newer = record_with_bodies("example.com", "newer-only-needle", "saved");
        newer.id = older.id;
        let store = TransactionStore::from_records(vec![newer, older]);
        let older_outcome = store
            .search_bodies(
                &ListFilters::default(),
                &search_request("older-only-needle"),
            )
            .await;
        let newer_outcome = store
            .search_bodies(
                &ListFilters::default(),
                &search_request("newer-only-needle"),
            )
            .await;
        assert_eq!(
            (older_outcome.match_count, newer_outcome.match_count),
            (1, 1),
            "duplicate ordering rows must search their own bodies exactly once"
        );
        assert!(older_outcome.complete && newer_outcome.complete);
        assert_ne!(
            older_outcome.transactions[0].sequence,
            newer_outcome.transactions[0].sequence
        );
    }

    async fn unreadable_duplicate_fixture(
        max_entries: Option<usize>,
    ) -> (Arc<TransactionStore>, PathBuf, TransactionRecord) {
        let dir = std::env::temp_dir().join(format!("sniper-unresolved-row-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let original = record_with_bodies("example.com", "original saved body", "saved");
        let store = Arc::new(TransactionStore::from_records_with_journal(
            vec![original.clone()],
            dir.join("transactions.journal"),
            max_entries,
        ));
        let snapshot = store.snapshot_for_persistence(None).await.unwrap();
        publish_fixture_snapshot(store.clone(), snapshot, &dir)
            .await
            .unwrap();
        fs::remove_file(dir.join("transactions.ndjson")).unwrap();
        let mut replacement = record_with_bodies("example.com", "new supplied body", "saved");
        replacement.id = original.id;
        store.insert(replacement).await;
        (store, dir, original)
    }

    #[tokio::test]
    async fn unresolved_duplicate_dependency_survives_annotations_noops_and_source_restore() {
        let (store, dir, original) = unreadable_duplicate_fixture(None).await;
        let id = original.id;
        store
            .update_annotations(id, Some(Some("blue".into())), Some(Some("new note".into())))
            .await
            .unwrap();
        store.update_record(id, |_| {}).await.unwrap();
        crate::session::write_transactions_file_for_test(&dir, &[original]).unwrap();
        let journal_before = fs::read(dir.join("transactions.journal")).unwrap();
        let error = store.snapshot_for_persistence(None).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error
            .to_string()
            .contains("preserved transaction body dependency"));
        assert_eq!(
            fs::read(dir.join("transactions.journal")).unwrap(),
            journal_before,
            "a blocked capture must not rotate the journal"
        );
        assert_eq!(store.len().await, 2);
        assert_eq!(
            store.inner.read().await.unresolved_body_generations.len(),
            1
        );
        let outcome = store
            .search_bodies(
                &ListFilters::default(),
                &search_request("new supplied body"),
            )
            .await;
        assert_eq!(outcome.match_count, 1);
        assert_eq!(outcome.unsearchable, 1);
        assert!(!outcome.complete);
        store.delete_all().await.unwrap();
        assert!(store
            .snapshot_for_persistence(None)
            .await
            .unwrap()
            .is_empty());
        assert!(store
            .inner
            .read()
            .await
            .unresolved_body_generations
            .is_empty());
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn late_retention_trim_keeps_survivor_and_new_body_during_publication() {
        let dir = std::env::temp_dir().join(format!("sniper-late-trim-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let oldest = record_with_bodies("example.com", "trimmed body", "saved");
        let oldest_id = oldest.id;
        let survivor = record_with_bodies("example.com", "surviving body", "saved");
        let survivor_id = survivor.id;
        let store = Arc::new(TransactionStore::from_records_with_journal(
            vec![survivor, oldest],
            dir.join("transactions.journal"),
            Some(2),
        ));
        let snapshot = store.snapshot_for_persistence(None).await.unwrap();
        let newest = record_with_bodies("example.com", "new resident body", "saved");
        let newest_id = newest.id;
        store.insert(newest).await;
        publish_fixture_snapshot(store.clone(), snapshot, &dir)
            .await
            .unwrap();
        assert_eq!(store.len().await, 2);
        assert!(store.get(oldest_id).await.is_none());
        assert_eq!(
            store.get(survivor_id).await.unwrap().request.body_preview,
            "surviving body"
        );
        assert_eq!(
            store.get(newest_id).await.unwrap().request.body_preview,
            "new resident body"
        );
        let inner = store.inner.read().await;
        assert!(inner.locators.contains_key(&survivor_id));
        assert!(!inner.locators.contains_key(&oldest_id));
        assert!(!inner.locators.contains_key(&newest_id));
        drop(inner);
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn retention_removes_only_the_discarded_duplicate_dependency() {
        let (store, dir, original) = unreadable_duplicate_fixture(Some(1)).await;
        assert_eq!(store.len().await, 1);
        assert!(store
            .inner
            .read()
            .await
            .unresolved_body_generations
            .is_empty());
        let snapshot = store.snapshot_for_persistence(None).await.unwrap();
        assert_eq!(snapshot[0].0.request.body_preview, "new supplied body");
        publish_fixture_snapshot(store.clone(), snapshot, &dir)
            .await
            .unwrap();
        assert_eq!(
            store.get(original.id).await.unwrap().request.body_preview,
            "new supplied body"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn queued_body_search_never_rebinds_displaced_or_replaced_rows() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            for replace_body in [false, true] {
                let record = record_with_bodies("example.com", "original-only-needle", "saved");
                let id = record.id;
                let store = Arc::new(TransactionStore::from_records(vec![record]));
                let (started_tx, started_rx) = oneshot::channel();
                let (resume_tx, resume_rx) = mpsc::channel();
                let blocker = tokio::task::spawn_blocking(move || {
                    started_tx.send(()).unwrap();
                    resume_rx.recv().unwrap();
                });
                started_rx.await.unwrap();
                let searching = store.clone();
                let (queued_tx, queued_rx) = oneshot::channel();
                let search = tokio::spawn(async move {
                    let filters = ListFilters::default();
                    let request = search_request("original-only-needle");
                    let future = searching.search_bodies(&filters, &request);
                    tokio::pin!(future);
                    let mut queued_tx = Some(queued_tx);
                    std::future::poll_fn(|context| {
                        match std::future::Future::poll(future.as_mut(), context) {
                            std::task::Poll::Pending => {
                                if let Some(tx) = queued_tx.take() {
                                    tx.send(()).unwrap();
                                }
                                std::task::Poll::Pending
                            }
                            ready => ready,
                        }
                    })
                    .await
                });
                queued_rx.await.unwrap();
                if replace_body {
                    store
                        .update_record(id, |record| {
                            record.request.body_preview = "replacement-only-needle".into();
                        })
                        .await
                        .unwrap();
                } else {
                    let mut replacement =
                        record_with_bodies("example.com", "replacement-only-needle", "saved");
                    replacement.id = id;
                    store.insert(replacement).await;
                }
                resume_tx.send(()).unwrap();
                blocker.await.unwrap();
                let outcome = search.await.unwrap();
                if replace_body {
                    assert_eq!(outcome.match_count, 0);
                    assert_eq!(outcome.unsearchable, 1);
                    assert!(!outcome.complete);
                } else {
                    assert_eq!(outcome.match_count, 1);
                    assert_eq!(outcome.unsearchable, 0);
                    assert!(outcome.complete);
                }
                let latest = store
                    .search_bodies(
                        &ListFilters::default(),
                        &search_request("replacement-only-needle"),
                    )
                    .await;
                assert_eq!(latest.match_count, 1);
                assert!(latest.complete);
            }
        });
    }

    #[tokio::test]
    async fn same_id_insert_invalidates_locator_and_preserves_older_ordering_row() {
        let dir = std::env::temp_dir().join(format!("sniper-same-id-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let record = record_with_bodies("example.com", "older body", "saved");
        let id = record.id;
        let store = Arc::new(TransactionStore::from_records_with_journal(
            vec![record],
            dir.join("transactions.journal"),
            None,
        ));
        let snapshot = store.snapshot_for_persistence(None).await.unwrap();
        publish_fixture_snapshot(store.clone(), snapshot, &dir)
            .await
            .unwrap();
        let old_generation = store.inner.read().await.body_generations[0];
        let mut replacement = record_with_bodies("example.com", "replacement body", "saved");
        replacement.id = id;
        store.insert(replacement).await;
        assert_eq!(
            store.get(id).await.unwrap().request.body_preview,
            "replacement body"
        );
        let inner = store.inner.read().await;
        assert_eq!(inner.entries.len(), 2);
        assert_eq!(inner.by_id[&id], 1);
        assert!(!inner.locators.contains_key(&id));
        assert_eq!(inner.entries[0].request.body_preview, "older body");
        assert_eq!(inner.body_generations[0], old_generation);
        assert_ne!(inner.body_generations[1], old_generation);
        drop(inner);
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn publication_generation_survives_replace_all_and_rejects_stale_file() {
        let record = record_with_bodies("example.com", "before", "saved");
        let id = record.id;
        let store = Arc::new(TransactionStore::from_records(vec![record.clone()]));
        let snapshot = store.snapshot_for_persistence(None).await.unwrap();
        let stale_snapshot = store.snapshot_for_persistence(None).await.unwrap();
        let old_token = snapshot.body_generations[&id];
        store
            .update_annotations(id, None, Some(Some("one".into())))
            .await
            .unwrap();
        store
            .update_annotations(id, None, Some(Some("two".into())))
            .await
            .unwrap();
        let event_before_replace = store.latest_event_sequence();
        let mut replacement = record;
        replacement.request.body_preview = "after replacement".into();
        store.replace_all(vec![replacement]).await;
        assert!(store.latest_event_sequence() > event_before_replace);
        assert_ne!(store.inner.read().await.body_generations[0], old_token);
        let publisher = store.clone();
        tokio::task::spawn_blocking(move || {
            publisher.publish_persistence_snapshot(
                &snapshot,
                HashMap::from([(id, crate::session::BodyLocator { offset: 0, len: 1 })]),
                || Ok(()),
            )
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            store.get(id).await.unwrap().request.body_preview,
            "after replacement"
        );
        assert!(store.inner.read().await.locators.is_empty());
        let file_generation = store.inner.read().await.file_generation;
        store.replace_all(Vec::new()).await;
        assert_eq!(store.inner.read().await.file_generation, file_generation);
        let result = tokio::task::spawn_blocking(move || {
            store.publish_persistence_snapshot(&stale_snapshot, HashMap::new(), || {
                panic!("stale snapshot must not attempt rename")
            })
        })
        .await
        .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn partial_snapshot_cannot_publish_or_discard_omitted_rows() {
        let store = Arc::new(TransactionStore::from_records(vec![
            record_with_bodies("example.com", "first", "saved"),
            record_with_bodies("example.com", "second", "saved"),
        ]));
        let snapshot = store.snapshot_for_persistence(Some(1)).await.unwrap();
        assert_eq!(snapshot.len(), 1);
        let generation = snapshot.file_generation;
        let publisher = store.clone();
        let result = tokio::task::spawn_blocking(move || {
            publisher.publish_persistence_snapshot(&snapshot, HashMap::new(), || {
                panic!("partial snapshots must not rename the file")
            })
        })
        .await
        .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        let inner = store.inner.read().await;
        assert_eq!(inner.entries.len(), 2);
        assert_eq!(inner.file_generation, generation);
        assert!(inner.locators.is_empty());
        assert!(inner
            .entries
            .iter()
            .all(|record| !record.request.body_preview.is_empty()));
    }

    #[tokio::test]
    async fn publication_rename_error_leaves_generations_and_bodies_unchanged() {
        let record = record_with_bodies("example.com", "resident body", "saved");
        let id = record.id;
        let store = Arc::new(TransactionStore::from_records(vec![record]));
        let snapshot = store.snapshot_for_persistence(None).await.unwrap();
        let old_generation = snapshot.file_generation;
        let publisher = store.clone();
        let result = tokio::task::spawn_blocking(move || {
            publisher.publish_persistence_snapshot(
                &snapshot,
                HashMap::from([(id, crate::session::BodyLocator { offset: 0, len: 1 })]),
                || {
                    Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "synthetic rename failure",
                    ))
                },
            )
        })
        .await
        .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        let inner = store.inner.read().await;
        assert_eq!(inner.file_generation, old_generation);
        assert!(inner.locators.is_empty());
        assert_eq!(inner.entries[0].request.body_preview, "resident body");
    }

    #[tokio::test]
    async fn missing_or_mismatched_body_aborts_update_before_edit_or_journal() {
        let dir = std::env::temp_dir().join(format!("sniper-missing-body-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let record = record_with_bodies("example.com", "saved body", "saved");
        let id = record.id;
        let other = record_with_bodies("example.com", "other body", "saved");
        let locators = crate::session::write_transactions_file_for_test_returning_locators(
            &dir,
            &[other.clone()],
        )
        .unwrap();
        let mut stripped = record;
        strip_transaction_bodies(&mut stripped);
        let store = TransactionStore::from_records_with_journal(
            vec![stripped],
            dir.join("transactions.journal"),
            None,
        );
        store
            .set_body_locator_for_test(id, locators[&other.id])
            .await;
        for remove_file in [false, true] {
            if remove_file {
                fs::remove_file(dir.join("transactions.ndjson")).unwrap();
            }
            let result = store
                .update_record_durable(id, |_| panic!("edit must not run without its body"))
                .await;
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
            assert!(fs::read(dir.join("transactions.journal"))
                .unwrap()
                .is_empty());
            assert!(store.inner.read().await.locators.contains_key(&id));
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn body_search_resolves_current_locator_after_queued_worker_resumes() {
        // Occupy the sole blocking worker so publication definitely occurs
        // between candidate collection and disk access, with no timing sleeps.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let dir =
                std::env::temp_dir().join(format!("sniper-search-publication-{}", Uuid::new_v4()));
            fs::create_dir_all(&dir).unwrap();
            let mut first = record_with_bodies("example.com", "first-only-needle", "saved");
            first.sequence = 2;
            let mut second = record_with_bodies("example.com", "other body", "saved");
            second.sequence = 1;
            let old_locators = crate::session::write_transactions_file_for_test_returning_locators(
                &dir,
                &[second.clone(), first.clone()],
            )
            .unwrap();
            let store = Arc::new(TransactionStore::from_records_with_journal(
                vec![first.clone(), second.clone()],
                dir.join("transactions.journal"),
                None,
            ));
            store.adopt_written_locators(old_locators).await;
            let snapshot = store.snapshot_for_persistence(None).await.unwrap();
            let staged = dir.join("staged");
            fs::create_dir_all(&staged).unwrap();
            let new_locators = crate::session::write_transactions_file_for_test_returning_locators(
                &staged,
                &[first.clone(), second],
            )
            .unwrap();
            let source = staged.join("transactions.ndjson");
            let destination = dir.join("transactions.ndjson");
            let (started_tx, started_rx) = oneshot::channel();
            let (resume_tx, resume_rx) = mpsc::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                started_tx.send(()).unwrap();
                resume_rx.recv().unwrap();
            });
            started_rx.await.unwrap();
            let searching = store.clone();
            let (queued_tx, queued_rx) = oneshot::channel();
            let search = tokio::spawn(async move {
                let filters = ListFilters::default();
                let request = search_request("first-only-needle");
                let future = searching.search_bodies(&filters, &request);
                tokio::pin!(future);
                // Poll once to enqueue its blocking scan before announcing the barrier.
                let mut queued_tx = Some(queued_tx);
                std::future::poll_fn(|context| {
                    match std::future::Future::poll(future.as_mut(), context) {
                        std::task::Poll::Pending => {
                            if let Some(tx) = queued_tx.take() {
                                tx.send(()).unwrap();
                            }
                            std::task::Poll::Pending
                        }
                        ready => ready,
                    }
                })
                .await
            });
            queued_rx.await.unwrap();
            let publisher = store.clone();
            thread::spawn(move || {
                publisher.publish_persistence_snapshot(&snapshot, new_locators, || {
                    crate::platform::rename(&source, &destination)
                })
            })
            .join()
            .unwrap()
            .unwrap();
            resume_tx.send(()).unwrap();
            blocker.await.unwrap();
            let outcome = search.await.unwrap();
            assert!(outcome.complete);
            assert_eq!(outcome.unsearchable, 0);
            assert_eq!(outcome.match_count, 1);
            assert_eq!(outcome.transactions[0].id, first.id);
            let _ = fs::remove_dir_all(dir);
        });
    }

    #[test]
    fn cancelled_offline_rotation_keeps_mutation_guard_until_worker_finishes() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let dir =
                std::env::temp_dir().join(format!("sniper-cancel-offline-{}", Uuid::new_v4()));
            fs::create_dir_all(&dir).unwrap();
            let record = test_record("example.com");
            let line = encode_transaction_insert_journal_line(&record).unwrap();
            fs::write(dir.join("transactions.journal"), &line).unwrap();
            let mut store = TransactionStore::from_records(vec![record]);
            store.storage_dir = Some(dir.clone());
            let (tx, rx) = mpsc::channel();
            drop(rx);
            store.journal_tx = Some(tx);
            let (started_tx, started_rx) = oneshot::channel();
            let (resume_tx, resume_rx) = mpsc::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                started_tx.send(()).unwrap();
                resume_rx.recv().unwrap();
            });
            started_rx.await.unwrap();
            let mut snapshot = Box::pin(store.snapshot_for_persistence(None));
            std::future::poll_fn(|context| {
                assert!(std::future::Future::poll(snapshot.as_mut(), context).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            drop(snapshot);
            assert!(
                store.insert_lock.try_lock().is_err(),
                "detached worker must own the mutation barrier"
            );
            resume_tx.send(()).unwrap();
            blocker.await.unwrap();
            let _guard =
                tokio::time::timeout(std::time::Duration::from_secs(5), store.insert_lock.lock())
                    .await
                    .unwrap();
            assert!(fs::read(dir.join("transactions.journal"))
                .unwrap()
                .is_empty());
            assert_eq!(
                fs::read(dir.join("transactions.journal.checkpoint")).unwrap(),
                line
            );
            let _ = fs::remove_dir_all(dir);
        });
    }

    #[tokio::test]
    async fn disconnected_writer_rotates_offline_before_confirming_snapshot() {
        let dir = std::env::temp_dir().join(format!("sniper-offline-rotate-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let record = test_record("example.com");
        let line = encode_transaction_insert_journal_line(&record).unwrap();
        fs::write(dir.join("transactions.journal"), &line).unwrap();
        let mut store = TransactionStore::from_records(vec![record]);
        store.storage_dir = Some(dir.clone());
        let (tx, rx) = mpsc::channel();
        drop(rx);
        store.journal_tx = Some(tx);
        let snapshot = store.snapshot_for_persistence(None).await.unwrap();
        assert!(snapshot.journal_rotation_confirmed);
        assert!(fs::read(dir.join("transactions.journal"))
            .unwrap()
            .is_empty());
        assert_eq!(
            fs::read(dir.join("transactions.journal.checkpoint")).unwrap(),
            line
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn lost_rotation_ack_or_writer_error_never_truncates_offline() {
        for explicit_error in [false, true] {
            let dir =
                std::env::temp_dir().join(format!("sniper-uncertain-rotate-{}", Uuid::new_v4()));
            fs::create_dir_all(&dir).unwrap();
            let record = test_record("example.com");
            let line = encode_transaction_insert_journal_line(&record).unwrap();
            fs::write(dir.join("transactions.journal"), &line).unwrap();
            let mut store = TransactionStore::from_records(vec![record]);
            store.storage_dir = Some(dir.clone());
            let (tx, rx) = mpsc::channel();
            store.journal_tx = Some(tx);
            let writer = thread::spawn(move || match rx.recv().unwrap() {
                TransactionJournalCommand::Rotate { ack } => {
                    if explicit_error {
                        ack.send(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "explicit writer error",
                        )))
                        .unwrap();
                    }
                }
                _ => panic!("expected rotation"),
            });
            assert!(store.snapshot_for_persistence(None).await.is_err());
            writer.join().unwrap();
            assert_eq!(fs::read(dir.join("transactions.journal")).unwrap(), line);
            assert!(!dir.join("transactions.journal.checkpoint").exists());
            let _ = fs::remove_dir_all(dir);
        }
    }

    #[tokio::test]
    async fn failed_writer_startup_can_rotate_after_storage_recovers() {
        let dir = std::env::temp_dir().join(format!("sniper-startup-rotate-{}", Uuid::new_v4()));
        let journal = dir.join("transactions.journal");
        fs::create_dir_all(&journal).unwrap();
        let record = test_record("example.com");
        let line = encode_transaction_insert_journal_line(&record).unwrap();
        let store =
            TransactionStore::from_records_with_journal(vec![record], journal.clone(), None);
        assert!(store.journal_tx.is_none());
        assert!(store.journal_start_failed);
        fs::remove_dir(&journal).unwrap();
        fs::write(&journal, &line).unwrap();
        assert!(
            store
                .snapshot_for_persistence(None)
                .await
                .unwrap()
                .journal_rotation_confirmed
        );
        assert!(fs::read(&journal).unwrap().is_empty());
        assert_eq!(
            fs::read(dir.join("transactions.journal.checkpoint")).unwrap(),
            line
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn snapshot_for_persistence_continues_when_journal_writer_stopped() {
        let mut store =
            TransactionStore::from_records_with_max_entries(vec![test_record("example.com")], None);
        let (tx, rx) = mpsc::channel();
        drop(rx);
        store.journal_tx = Some(tx);

        let snapshot = store.snapshot_for_persistence(None).await.unwrap();

        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].0.host, "example.com");
        assert!(!snapshot.journal_rotation_confirmed);
    }

    #[tokio::test]
    async fn insert_keeps_memory_and_snapshot_when_journal_append_fails() {
        let mut store = TransactionStore::from_records_with_max_entries(Vec::new(), None);
        let (tx, rx) = mpsc::channel();
        drop(rx);
        store.journal_tx = Some(tx);

        let record = test_record("lost.example");
        let outcome = store.insert(record).await;
        assert!(outcome.immediate_snapshot_required());

        let listed = store.list(&ListFilters::default()).await;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].host, "lost.example");

        let snapshot = store.snapshot_for_persistence(None).await.unwrap();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].0.host, "lost.example");
    }

    #[tokio::test]
    async fn insert_requests_snapshot_fallback_without_journal_writer() {
        let store = TransactionStore::from_records_with_max_entries(Vec::new(), None);

        let outcome = store.insert(test_record("snapshot.example")).await;

        assert!(outcome.immediate_snapshot_required());
        let listed = store.list(&ListFilters::default()).await;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].host, "snapshot.example");
    }

    #[tokio::test]
    async fn update_record_refreshes_summary_cache_and_notifies_watchers() {
        let store = TransactionStore::new();
        let mut record = test_record("passthrough.example:443");
        record.duration_ms = 0;
        record.notes = vec!["SSL passthrough tunnel established.".to_string()];
        let record_id = record.id;
        let mut receiver = store.subscribe();

        store.insert(record).await;
        let inserted = receiver.recv().await.unwrap();
        assert_eq!(inserted.event_sequence, 1);
        assert_eq!(inserted.summary.id, record_id);
        assert_eq!(inserted.summary.duration_ms, 0);

        let updated = store
            .update_record(record_id, |record| {
                record.duration_ms = 250;
                record.notes = vec!["SSL passthrough: 10 bytes sent, 20 bytes received".into()];
            })
            .await
            .unwrap();

        assert_eq!(updated.duration_ms, 250);
        assert_eq!(updated.note_count, 1);
        let event = receiver.recv().await.unwrap();
        assert_eq!(event.event_sequence, 2);
        assert_eq!(event.summary.id, record_id);
        assert_eq!(event.summary.duration_ms, 250);
        let listed = store.list(&ListFilters::default()).await;
        assert_eq!(listed[0].duration_ms, 250);
        assert_eq!(listed[0].note_count, 1);
    }

    #[tokio::test]
    async fn durable_update_record_appends_update_journal_entry() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-store-record-update-journal-{}",
            uuid::Uuid::new_v4()
        ));
        let journal_path = data_dir.join("transactions.journal");
        let store =
            TransactionStore::from_records_with_journal(Vec::new(), journal_path.clone(), None);
        let record = test_record("streamed.example");
        let record_id = record.id;

        let outcome = store.insert(record).await;
        assert!(!outcome.immediate_snapshot_required());
        let updated = store
            .update_record_durable(record_id, |record| {
                record.status = Some(200);
                record.duration_ms = 125;
                record.notes = vec!["stream complete".to_string()];
            })
            .await
            .unwrap()
            .unwrap();

        assert_eq!(updated.status, Some(200));
        assert_eq!(updated.duration_ms, 125);
        let lines = std::fs::read_to_string(&journal_path).unwrap();
        let entries = lines
            .lines()
            .map(|line| serde_json::from_str::<TransactionJournalEntry>(line).unwrap())
            .collect::<Vec<_>>();
        let Some(TransactionJournalEntry::Update { record }) = entries.last() else {
            panic!("expected durable record update journal entry");
        };
        assert_eq!(record.id, record_id);
        assert_eq!(record.status, Some(200));
        assert_eq!(record.duration_ms, 125);
        assert_eq!(record.notes, vec!["stream complete".to_string()]);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn annotation_update_notifies_transaction_subscribers() {
        let store = TransactionStore::new();
        let record = test_record("annotated.example");
        let record_id = record.id;
        store.insert(record).await;
        let mut receiver = store.subscribe();

        store
            .update_annotations(record_id, Some(Some("yellow".to_string())), None)
            .await
            .expect("annotation should update");

        let event = receiver.recv().await.unwrap();
        assert_eq!(event.event_sequence, 2);
        assert_eq!(event.summary.id, record_id);
        assert_eq!(event.summary.sequence, 1);
        assert_eq!(event.summary.color_tag.as_deref(), Some("yellow"));
        assert_eq!(store.latest_sequence(), 1);
        assert_eq!(store.latest_event_sequence(), 2);
    }

    #[tokio::test]
    async fn insert_notifies_retention_when_overflow_trims_history() {
        let store = TransactionStore::from_records_with_max_entries(
            vec![test_record("old.example")],
            Some(1),
        );
        let mut retention_events = store.subscribe_retention();

        store.insert(test_record("new.example")).await;

        assert!(retention_events.try_recv().is_ok());
        let listed = store.list(&ListFilters::default()).await;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].host, "new.example");
    }

    #[tokio::test]
    async fn insert_waiting_on_journal_does_not_block_history_reads() {
        use std::{sync::Arc, time::Duration};

        let mut store = TransactionStore::from_records_with_max_entries(
            vec![test_record("existing.example")],
            None,
        );
        let (tx, rx) = mpsc::channel();
        store.journal_tx = Some(tx);
        let store = Arc::new(store);

        let insert_task = {
            let store = store.clone();
            tokio::spawn(async move { store.insert(test_record("pending.example")).await })
        };

        let command = tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(1)))
            .await
            .unwrap()
            .unwrap();
        let ack = match command {
            TransactionJournalCommand::Append { ack: Some(ack), .. } => ack,
            _ => panic!("expected journal append command with ack"),
        };

        let listed = tokio::time::timeout(
            Duration::from_millis(200),
            store.list(&ListFilters::default()),
        )
        .await
        .expect("history reads should not wait on pending journal append");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].host, "existing.example");

        let mut snapshot_task = Box::pin({
            let store = store.clone();
            tokio::spawn(async move { store.snapshot_for_persistence(None).await })
        });
        tokio::time::timeout(Duration::from_millis(200), &mut snapshot_task)
            .await
            .expect_err("snapshot compaction should wait for pending journaled insert");

        ack.send(Ok(())).unwrap();
        let insert_outcome = insert_task.await.unwrap();
        assert!(!insert_outcome.immediate_snapshot_required());

        let listed = store.list(&ListFilters::default()).await;
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].host, "pending.example");

        let snapshot = snapshot_task.await.unwrap().unwrap();
        assert_eq!(snapshot.len(), 2);
        assert_eq!(snapshot[0].0.host, "pending.example");
    }

    #[tokio::test]
    async fn annotation_update_waiting_on_journal_does_not_block_history_reads() {
        use std::{sync::Arc, time::Duration};

        let mut store = TransactionStore::from_records_with_max_entries(
            vec![test_record("existing.example")],
            None,
        );
        let id = store.snapshot(None).await[0].id;
        let (tx, rx) = mpsc::channel();
        store.journal_tx = Some(tx);
        let store = Arc::new(store);

        let update_task = {
            let store = store.clone();
            tokio::spawn(async move {
                store
                    .update_annotations(id, Some(Some("yellow".to_string())), None)
                    .await
            })
        };

        let command = tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(1)))
            .await
            .unwrap()
            .unwrap();
        let ack = match command {
            TransactionJournalCommand::Append { ack: Some(ack), .. } => ack,
            _ => panic!("expected journal append command with ack"),
        };

        let listed = tokio::time::timeout(
            Duration::from_millis(200),
            store.list(&ListFilters::default()),
        )
        .await
        .expect("history reads should not wait on pending annotation journal append");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].host, "existing.example");
        assert!(listed[0].color_tag.is_none());

        ack.send(Ok(())).unwrap();
        let update = update_task.await.unwrap().unwrap();
        assert_eq!(update.applied_color_tag.as_deref(), Some("yellow"));

        let listed = store.list(&ListFilters::default()).await;
        assert_eq!(listed[0].color_tag.as_deref(), Some("yellow"));
    }

    #[tokio::test]
    async fn durable_annotation_update_does_not_mutate_when_journal_append_fails() {
        use std::{sync::Arc, time::Duration};

        let mut record = test_record("existing.example");
        record.color_tag = Some("old".to_string());
        let id = record.id;
        let mut store = TransactionStore::from_records_with_max_entries(vec![record], None);
        let (tx, rx) = mpsc::channel();
        store.journal_tx = Some(tx);
        let store = Arc::new(store);

        let update_task = {
            let store = store.clone();
            tokio::spawn(async move {
                store
                    .update_annotations_durable(id, Some(Some("new".to_string())), None)
                    .await
            })
        };

        let command = tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(1)))
            .await
            .unwrap()
            .unwrap();
        let ack = match command {
            TransactionJournalCommand::Append { ack: Some(ack), .. } => ack,
            _ => panic!("expected journal append command with ack"),
        };
        ack.send(Err(io::Error::other("journal failed"))).unwrap();

        let error = update_task.await.unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        let listed = store.list(&ListFilters::default()).await;
        assert_eq!(listed[0].color_tag.as_deref(), Some("old"));
    }

    #[tokio::test]
    async fn stale_annotation_client_version_does_not_overwrite_newer_value() {
        let record = test_record("existing.example");
        let id = record.id;
        let store = TransactionStore::from_records_with_max_entries(vec![record], None);

        let newer = store
            .update_annotations_with_journal_mode(
                id,
                Some(Some("blue".to_string())),
                Some(Some("newer note".to_string())),
                Some("browser-client".to_string()),
                Some(2),
                false,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(newer.applied_color_tag.as_deref(), Some("blue"));
        assert_eq!(newer.summary.annotation_revision, 1);

        let stale = store
            .update_annotations_with_journal_mode(
                id,
                Some(Some("red".to_string())),
                Some(Some("stale note".to_string())),
                Some("browser-client".to_string()),
                Some(1),
                false,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stale.summary.color_tag.as_deref(), Some("blue"));
        assert!(stale.summary.has_user_note);
        assert_eq!(stale.summary.annotation_revision, 1);

        let stored = store.get(id).await.unwrap();
        assert_eq!(stored.color_tag.as_deref(), Some("blue"));
        assert_eq!(stored.user_note.as_deref(), Some("newer note"));
        assert_eq!(stored.annotation_revision, 1);
        assert_eq!(
            stored
                .annotation_client_versions
                .get("browser-client")
                .copied(),
            Some(2)
        );
    }

    #[tokio::test]
    async fn cli_annotation_client_versions_are_compacted_per_record() {
        let record = test_record("existing.example");
        let id = record.id;
        let store = TransactionStore::from_records_with_max_entries(vec![record], None);

        store
            .update_annotations_with_journal_mode(
                id,
                Some(Some("blue".to_string())),
                None,
                Some("browser-client".to_string()),
                Some(7),
                false,
            )
            .await
            .unwrap()
            .unwrap();

        for index in 0..3 {
            store
                .update_annotations_with_journal_mode(
                    id,
                    Some(Some(format!("cli-{index}"))),
                    None,
                    Some(format!("sniper-cli:{index}")),
                    Some(1),
                    false,
                )
                .await
                .unwrap()
                .unwrap();
        }

        let stored = store.get(id).await.unwrap();
        assert_eq!(stored.annotation_client_versions.len(), 2);
        assert_eq!(
            stored
                .annotation_client_versions
                .get("browser-client")
                .copied(),
            Some(7)
        );
        assert_eq!(
            stored
                .annotation_client_versions
                .get("sniper-cli:2")
                .copied(),
            Some(1)
        );
        assert!(!stored
            .annotation_client_versions
            .contains_key("sniper-cli:0"));
        assert!(!stored
            .annotation_client_versions
            .contains_key("sniper-cli:1"));
    }

    #[tokio::test]
    async fn stale_durable_annotation_does_not_append_journal_entry() {
        let mut record = test_record("existing.example");
        record.color_tag = Some("blue".to_string());
        record.annotation_revision = 7;
        record
            .annotation_client_versions
            .insert("browser-client".to_string(), 3);
        let id = record.id;
        let mut store = TransactionStore::from_records_with_max_entries(vec![record], None);
        let (tx, rx) = mpsc::channel();
        store.journal_tx = Some(tx);

        let stale = store
            .update_annotations_durable_with_client(
                id,
                Some(Some("red".to_string())),
                None,
                Some("browser-client".to_string()),
                Some(2),
            )
            .await
            .unwrap()
            .unwrap();

        assert_eq!(stale.summary.color_tag.as_deref(), Some("blue"));
        assert_eq!(stale.summary.annotation_revision, 7);
        assert!(rx.try_recv().is_err());
        let stored = store.get(id).await.unwrap();
        assert_eq!(stored.color_tag.as_deref(), Some("blue"));
        assert_eq!(stored.annotation_revision, 7);
    }

    #[tokio::test]
    async fn annotation_restore_appends_rollback_journal_entry() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-store-annotation-rollback-journal-{}",
            uuid::Uuid::new_v4()
        ));
        let journal_path = data_dir.join("transactions.journal");
        let mut record = test_record("example.com");
        record.color_tag = Some("old".to_string());
        let id = record.id;
        let store =
            TransactionStore::from_records_with_journal(vec![record], journal_path.clone(), None);

        let update = store
            .update_annotations(id, Some(Some("new".to_string())), Some(None))
            .await
            .unwrap();
        let mut receiver = store.subscribe();
        assert!(store
            .restore_annotations_if_current(
                id,
                update.applied_color_tag,
                update.applied_user_note,
                update.previous_color_tag,
                update.previous_user_note,
            )
            .await
            .unwrap());

        let event = receiver.recv().await.unwrap();
        assert_eq!(event.summary.id, id);
        assert_eq!(event.summary.color_tag.as_deref(), Some("old"));
        assert!(!event.summary.has_user_note);
        assert_eq!(
            event.summary.annotation_revision,
            update.summary.annotation_revision.saturating_add(1)
        );
        let stored = store.get(id).await.unwrap();
        assert_eq!(stored.color_tag.as_deref(), Some("old"));
        assert!(stored.user_note.is_none());
        assert_eq!(
            stored.annotation_revision,
            event.summary.annotation_revision
        );

        let lines = std::fs::read_to_string(&journal_path).unwrap();
        let entries = lines
            .lines()
            .map(|line| serde_json::from_str::<TransactionJournalEntry>(line).unwrap())
            .collect::<Vec<_>>();
        let Some(TransactionJournalEntry::Annotation {
            color_tag,
            user_note,
            annotation_revision,
            previous_annotation_revision,
            ..
        }) = entries.last()
        else {
            panic!("expected annotation rollback journal entry");
        };
        assert!(matches!(
            color_tag,
            Some(NullableStringPatch::Set(value)) if value == "old"
        ));
        assert!(matches!(user_note, Some(NullableStringPatch::Clear)));
        assert_eq!(
            *annotation_revision,
            Some(event.summary.annotation_revision)
        );
        assert_eq!(
            *previous_annotation_revision,
            Some(update.summary.annotation_revision)
        );

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn annotation_restore_does_not_mutate_when_rollback_journal_append_fails() {
        let mut record = test_record("example.com");
        record.color_tag = Some("old".to_string());
        let id = record.id;
        let mut store = TransactionStore::from_records_with_max_entries(vec![record], None);
        let (tx, rx) = mpsc::channel();
        drop(rx);
        store.journal_tx = Some(tx);

        let update = store
            .update_annotations(id, Some(Some("new".to_string())), Some(None))
            .await
            .unwrap();
        let error = store
            .restore_annotations_if_current(
                id,
                update.applied_color_tag,
                update.applied_user_note,
                update.previous_color_tag,
                update.previous_user_note,
            )
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        let stored = store.get(id).await.unwrap();
        assert_eq!(stored.color_tag.as_deref(), Some("new"));
        assert_eq!(stored.user_note, None);
    }

    #[tokio::test]
    async fn list_page_reports_hidden_connect_total() {
        let mut connect = test_record("connect.example:443");
        connect.method = "CONNECT".to_string();
        connect.path = "connect.example:443".to_string();
        let http = test_record("http.example:443");
        let store = TransactionStore::from_records(vec![connect, http]);

        let page = store
            .list_page(&ListFilters {
                hide_connect: true,
                limit: Some(10),
                ..Default::default()
            })
            .await;

        assert_eq!(page.total, 2);
        assert_eq!(page.filtered_total, Some(1));
        assert_eq!(page.hidden_connect_total, Some(1));
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].host, "http.example:443");
    }

    #[tokio::test]
    async fn site_map_records_project_only_metadata_without_body_previews() {
        let mut record = test_record("site.example");
        record.request.body_preview = "x".repeat(1024);
        record.response.as_mut().unwrap().body_preview = "y".repeat(1024);
        record.notes.push("scanner note".to_string());
        record.user_note = Some("user note".to_string());
        let store = TransactionStore::from_records(vec![record]);

        let site_map_records = store.site_map_records().await;

        assert_eq!(site_map_records.len(), 1);
        assert_eq!(site_map_records[0].host, "site.example");
        assert_eq!(site_map_records[0].note_count, 2);
    }

    #[tokio::test]
    async fn before_sequence_is_ignored_for_non_index_sorts() {
        let store = TransactionStore::from_records(vec![
            test_record("c.example"),
            test_record("b.example"),
            test_record("a.example"),
        ]);

        let first_page = store
            .list_page(&ListFilters {
                limit: Some(1),
                sort_key: Some("host".into()),
                sort_direction: Some("asc".into()),
                ..Default::default()
            })
            .await;
        assert_eq!(first_page.items[0].host, "a.example");

        let second_page = store
            .list_page(&ListFilters {
                limit: Some(1),
                offset: Some(1),
                before_sequence: Some(first_page.items[0].sequence),
                sort_key: Some("host".into()),
                sort_direction: Some("asc".into()),
                ..Default::default()
            })
            .await;

        assert_eq!(second_page.items.len(), 1);
        assert_eq!(second_page.items[0].host, "b.example");
    }

    #[tokio::test]
    async fn transaction_sort_key_trims_validated_api_whitespace() {
        let store = TransactionStore::from_records(vec![
            test_record("c.example"),
            test_record("b.example"),
            test_record("a.example"),
        ]);

        let page = store
            .list_page(&ListFilters {
                sort_key: Some(" host ".into()),
                sort_direction: Some("asc".into()),
                limit: Some(10),
                ..Default::default()
            })
            .await;

        assert_eq!(
            page.items
                .iter()
                .map(|item| item.host.as_str())
                .collect::<Vec<_>>(),
            vec!["a.example", "b.example", "c.example"]
        );
    }

    #[tokio::test]
    async fn store_respects_capacity_and_filters() {
        let store = TransactionStore::new();
        let empty_message = MessageRecord {
            headers: Vec::new(),
            body_preview: String::new(),
            body_encoding: crate::model::BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };

        store
            .insert(TransactionRecord::http(
                Utc::now(),
                "GET".into(),
                "http".into(),
                "one.local".into(),
                "/".into(),
                Some(200),
                1,
                empty_message.clone(),
                Some(empty_message.clone()),
                Vec::new(),
                None,
                None,
            ))
            .await;

        store
            .insert(TransactionRecord::http(
                Utc::now(),
                "POST".into(),
                "http".into(),
                "two.local".into(),
                "/submit".into(),
                Some(201),
                2,
                empty_message.clone(),
                Some(empty_message.clone()),
                Vec::new(),
                None,
                None,
            ))
            .await;

        store
            .insert(TransactionRecord::http(
                Utc::now(),
                "DELETE".into(),
                "http".into(),
                "three.local".into(),
                "/resource".into(),
                Some(204),
                3,
                empty_message.clone(),
                Some(empty_message),
                Vec::new(),
                None,
                None,
            ))
            .await;

        let all = store.list(&ListFilters::default()).await;
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].method, "DELETE");

        let filtered = store
            .list(&ListFilters {
                query: Some("two.local".into()),
                method: Some("POST".into()),
                limit: Some(10),
                ..Default::default()
            })
            .await;
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].host, "two.local");

        let older_than_second = store
            .list(&ListFilters {
                limit: Some(10),
                before_sequence: Some(all[1].sequence),
                ..Default::default()
            })
            .await;
        assert_eq!(older_than_second.len(), 1);
        assert_eq!(older_than_second[0].host, "one.local");

        let page = store
            .list_page(&ListFilters {
                limit: Some(1),
                offset: Some(1),
                sort_key: Some("index".into()),
                sort_direction: Some("desc".into()),
                ..Default::default()
            })
            .await;
        assert_eq!(page.total, 3);
        assert_eq!(page.filtered_total, None);
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].host, "two.local");
        assert!(page.has_more);

        let searched = store
            .list_page(&ListFilters {
                query: Some("resource".into()),
                limit: Some(10),
                ..Default::default()
            })
            .await;
        assert_eq!(searched.filtered_total, Some(1));
        assert_eq!(searched.items[0].host, "three.local");
    }

    #[tokio::test]
    async fn only_notes_filter_includes_user_notes() {
        let mut user_noted = test_record("user-note.local");
        user_noted.user_note = Some("manual note".to_string());
        let internal_noted = TransactionRecord::http(
            Utc::now(),
            "GET".into(),
            "https".into(),
            "internal-note.local".into(),
            "/".into(),
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
            vec!["scanner note".to_string()],
            None,
            None,
        );
        let unnoted = test_record("plain.local");
        let store = TransactionStore::from_records(vec![unnoted, user_noted, internal_noted]);

        let page = store
            .list_page(&ListFilters {
                only_notes: true,
                limit: Some(10),
                ..Default::default()
            })
            .await;
        let hosts = page
            .items
            .iter()
            .map(|item| item.host.as_str())
            .collect::<Vec<_>>();

        assert!(hosts.contains(&"user-note.local"));
        assert!(hosts.contains(&"internal-note.local"));
        assert!(!hosts.contains(&"plain.local"));
    }

    #[tokio::test]
    async fn notes_sort_counts_user_notes() {
        let mut plain = test_record("plain.local");
        plain.sequence = 1;
        let mut user_noted = test_record("user-note.local");
        user_noted.sequence = 2;
        user_noted.user_note = Some("manual note".to_string());
        let mut internal_noted = test_record("internal-note.local");
        internal_noted.sequence = 3;
        internal_noted.notes = vec!["scanner note".to_string(), "manual marker".to_string()];
        let store = TransactionStore::from_records(vec![plain, user_noted, internal_noted]);

        let page = store
            .list_page(&ListFilters {
                sort_key: Some("notes".to_string()),
                sort_direction: Some("desc".to_string()),
                limit: Some(10),
                ..Default::default()
            })
            .await;

        assert_eq!(
            page.items
                .iter()
                .map(|item| item.host.as_str())
                .collect::<Vec<_>>(),
            vec!["internal-note.local", "user-note.local", "plain.local"]
        );
    }

    #[tokio::test]
    async fn store_applies_live_retention_limit() {
        let store = TransactionStore::from_records_with_max_entries(Vec::new(), Some(2));
        let empty_message = MessageRecord {
            headers: Vec::new(),
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };

        for index in 0..5 {
            store
                .insert(TransactionRecord::http(
                    Utc::now(),
                    "GET".into(),
                    "https".into(),
                    format!("{}.local", index),
                    format!("/{index}"),
                    Some(200),
                    index as u64,
                    empty_message.clone(),
                    None,
                    Vec::new(),
                    None,
                    None,
                ))
                .await;
        }

        let all = store.snapshot(None).await;
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].host, "4.local");
        assert_eq!(all[1].host, "3.local");
        assert!(store.get(all[0].id).await.is_some());
    }

    #[tokio::test]
    async fn store_applies_large_retention_limit_exactly() {
        let max_entries = 5000;
        let store = TransactionStore::from_records_with_max_entries(Vec::new(), Some(max_entries));
        let empty_message = MessageRecord {
            headers: Vec::new(),
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };

        for index in 0..(max_entries + 32) {
            store
                .insert(TransactionRecord::http(
                    Utc::now(),
                    "GET".into(),
                    "https".into(),
                    format!("{index}.local"),
                    format!("/{index}"),
                    Some(200),
                    index as u64,
                    empty_message.clone(),
                    None,
                    Vec::new(),
                    None,
                    None,
                ))
                .await;
        }

        let page = store
            .list_page(&ListFilters {
                limit: Some(max_entries + 100),
                ..Default::default()
            })
            .await;
        assert_eq!(page.total, max_entries);
        assert_eq!(page.items.len(), max_entries);
        assert_eq!(page.items[0].host, "5031.local");
        assert_eq!(
            page.items.last().map(|item| item.host.as_str()),
            Some("32.local")
        );
    }

    #[tokio::test]
    async fn storage_order_paging_uses_sequence_cursor_without_duplicates() {
        let store = TransactionStore::new();
        let empty_message = MessageRecord {
            headers: Vec::new(),
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };

        for index in 0..8 {
            store
                .insert(TransactionRecord::http(
                    Utc::now(),
                    "GET".into(),
                    "https".into(),
                    format!("{index}.local"),
                    format!("/{index}"),
                    Some(200),
                    index,
                    empty_message.clone(),
                    None,
                    Vec::new(),
                    None,
                    None,
                ))
                .await;
        }

        let first_page = store
            .list_page(&ListFilters {
                limit: Some(3),
                sort_key: Some("index".into()),
                sort_direction: Some("desc".into()),
                ..Default::default()
            })
            .await;
        assert_eq!(
            first_page
                .items
                .iter()
                .map(|item| item.host.as_str())
                .collect::<Vec<_>>(),
            vec!["7.local", "6.local", "5.local"]
        );
        assert!(first_page.has_more);

        let second_page = store
            .list_page(&ListFilters {
                limit: Some(3),
                before_sequence: first_page.items.last().map(|item| item.sequence),
                sort_key: Some("index".into()),
                sort_direction: Some("desc".into()),
                ..Default::default()
            })
            .await;
        assert_eq!(
            second_page
                .items
                .iter()
                .map(|item| item.host.as_str())
                .collect::<Vec<_>>(),
            vec!["4.local", "3.local", "2.local"]
        );
        assert!(second_page.has_more);

        let final_page = store
            .list_page(&ListFilters {
                limit: Some(3),
                before_sequence: second_page.items.last().map(|item| item.sequence),
                sort_key: Some("index".into()),
                sort_direction: Some("desc".into()),
                ..Default::default()
            })
            .await;
        assert_eq!(
            final_page
                .items
                .iter()
                .map(|item| item.host.as_str())
                .collect::<Vec<_>>(),
            vec!["1.local", "0.local"]
        );
        assert!(!final_page.has_more);
    }

    #[tokio::test]
    async fn index_ascending_page_starts_from_oldest_sequence() {
        let records = (1..=8)
            .rev()
            .map(|sequence| {
                let mut record = test_record(&format!("{sequence}.local"));
                record.sequence = sequence;
                record
            })
            .collect();
        let store = TransactionStore::from_records(records);

        let page = store
            .list_page(&ListFilters {
                limit: Some(3),
                sort_key: Some("index".into()),
                sort_direction: Some("asc".into()),
                ..Default::default()
            })
            .await;

        assert_eq!(
            page.items
                .iter()
                .map(|item| item.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert!(page.has_more);
    }

    #[tokio::test]
    async fn storage_order_paging_repairs_legacy_zero_sequences() {
        let empty_message = MessageRecord {
            headers: Vec::new(),
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };
        let mut records = Vec::new();
        for index in 0..8 {
            records.push(TransactionRecord::http(
                Utc::now(),
                "GET".into(),
                "https".into(),
                format!("{index}.legacy"),
                format!("/{index}"),
                Some(200),
                index,
                empty_message.clone(),
                None,
                Vec::new(),
                None,
                None,
            ));
        }

        let store = TransactionStore::from_records(records.into_iter().rev().collect());
        let first_page = store
            .list_page(&ListFilters {
                limit: Some(3),
                sort_key: Some("index".into()),
                sort_direction: Some("desc".into()),
                ..Default::default()
            })
            .await;
        let second_page = store
            .list_page(&ListFilters {
                limit: Some(3),
                before_sequence: first_page.items.last().map(|item| item.sequence),
                sort_key: Some("index".into()),
                sort_direction: Some("desc".into()),
                ..Default::default()
            })
            .await;

        assert_eq!(
            first_page
                .items
                .iter()
                .map(|item| item.host.as_str())
                .collect::<Vec<_>>(),
            vec!["7.legacy", "6.legacy", "5.legacy"]
        );
        assert_eq!(
            second_page
                .items
                .iter()
                .map(|item| item.host.as_str())
                .collect::<Vec<_>>(),
            vec!["4.legacy", "3.legacy", "2.legacy"]
        );
        assert!(first_page.items.iter().all(|item| item.sequence > 0));
    }

    #[tokio::test]
    async fn storage_sequence_repair_handles_unadvanceable_max_sequence() {
        let mut max_record = test_record("max-sequence.legacy");
        max_record.sequence = u64::MAX;
        let store = TransactionStore::from_records(vec![max_record]);

        store.insert(test_record("after-max.example")).await;

        let page = store
            .list_page(&ListFilters {
                limit: Some(10),
                sort_key: Some("index".into()),
                sort_direction: Some("desc".into()),
                ..Default::default()
            })
            .await;

        assert_eq!(
            page.items
                .iter()
                .map(|item| (item.host.as_str(), item.sequence))
                .collect::<Vec<_>>(),
            vec![("after-max.example", 2), ("max-sequence.legacy", 1)]
        );
        assert_eq!(store.latest_sequence(), 2);
    }

    #[tokio::test]
    async fn started_at_sort_uses_timestamp_not_insert_sequence() {
        let store = TransactionStore::new();
        let empty_message = MessageRecord {
            headers: Vec::new(),
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };
        let base = Utc::now();

        store
            .insert(TransactionRecord::http(
                base + Duration::seconds(1),
                "GET".into(),
                "https".into(),
                "newer-start.local".into(),
                "/newer".into(),
                Some(200),
                1,
                empty_message.clone(),
                None,
                Vec::new(),
                None,
                None,
            ))
            .await;
        store
            .insert(TransactionRecord::http(
                base,
                "GET".into(),
                "https".into(),
                "older-start.local".into(),
                "/older".into(),
                Some(200),
                1,
                empty_message,
                None,
                Vec::new(),
                None,
                None,
            ))
            .await;

        let page = store
            .list_page(&ListFilters {
                sort_key: Some("started_at".into()),
                sort_direction: Some("desc".into()),
                limit: Some(10),
                ..Default::default()
            })
            .await;

        assert_eq!(page.items[0].host, "newer-start.local");
        assert_eq!(page.items[1].host, "older-start.local");
    }

    #[tokio::test]
    async fn css_mime_filter_matches_text_css_before_generic_text() {
        let store = TransactionStore::new();
        let request = MessageRecord {
            headers: Vec::new(),
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };
        let response = MessageRecord {
            content_type: Some("text/css; charset=utf-8".into()),
            ..request.clone()
        };

        store
            .insert(TransactionRecord::http(
                Utc::now(),
                "GET".into(),
                "https".into(),
                "assets.local:443".into(),
                "/style".into(),
                Some(200),
                1,
                request,
                Some(response),
                Vec::new(),
                None,
                None,
            ))
            .await;

        let css = store
            .list(&ListFilters {
                mime_types: Some(vec!["css".into()]),
                ..Default::default()
            })
            .await;
        let json = store
            .list(&ListFilters {
                mime_types: Some(vec!["json".into()]),
                ..Default::default()
            })
            .await;

        assert_eq!(css.len(), 1);
        assert!(json.is_empty());
    }

    #[tokio::test]
    async fn plain_text_mime_filter_matches_other_not_json() {
        let store = TransactionStore::new();
        let request = MessageRecord {
            headers: Vec::new(),
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };
        let response = MessageRecord {
            content_type: Some("text/plain; charset=utf-8".into()),
            ..request.clone()
        };

        store
            .insert(TransactionRecord::http(
                Utc::now(),
                "GET".into(),
                "https".into(),
                "notes.local:443".into(),
                "/readme".into(),
                Some(200),
                1,
                request,
                Some(response),
                Vec::new(),
                None,
                None,
            ))
            .await;

        let json = store
            .list(&ListFilters {
                mime_types: Some(vec!["json".into()]),
                ..Default::default()
            })
            .await;
        let other = store
            .list(&ListFilters {
                mime_types: Some(vec!["other".into()]),
                ..Default::default()
            })
            .await;

        assert!(json.is_empty());
        assert_eq!(other.len(), 1);
    }

    #[tokio::test]
    async fn websocket_mime_filter_takes_priority_over_path_extension() {
        let store = TransactionStore::new();
        let request = MessageRecord {
            headers: vec![
                HeaderRecord {
                    name: "Upgrade".into(),
                    value: "websocket".into(),
                },
                HeaderRecord {
                    name: "Connection".into(),
                    value: "upgrade".into(),
                },
            ],
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };
        let response = MessageRecord {
            headers: Vec::new(),
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: Some("application/json".into()),
            content_decoded: false,
        };

        store
            .insert(TransactionRecord::http(
                Utc::now(),
                "GET".into(),
                "https".into(),
                "ws.local:443".into(),
                "/socket.json".into(),
                Some(101),
                1,
                request,
                Some(response),
                Vec::new(),
                None,
                None,
            ))
            .await;

        let websocket = store
            .list(&ListFilters {
                mime_types: Some(vec!["websocket".into()]),
                ..Default::default()
            })
            .await;
        let json = store
            .list(&ListFilters {
                mime_types: Some(vec!["json".into()]),
                ..Default::default()
            })
            .await;

        assert_eq!(websocket.len(), 1);
        assert!(json.is_empty());
    }

    #[tokio::test]
    async fn websocket_mime_filter_ignores_hidden_path_extension() {
        let store = TransactionStore::new();
        let request = MessageRecord {
            headers: vec![
                HeaderRecord {
                    name: "Upgrade".into(),
                    value: "websocket".into(),
                },
                HeaderRecord {
                    name: "Connection".into(),
                    value: "upgrade".into(),
                },
            ],
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };

        store
            .insert(TransactionRecord::http(
                Utc::now(),
                "GET".into(),
                "https".into(),
                "ws.local:443".into(),
                "/socket.css".into(),
                Some(101),
                1,
                request,
                None,
                Vec::new(),
                None,
                None,
            ))
            .await;

        let websocket = store
            .list(&ListFilters {
                mime_types: Some(vec!["websocket".into()]),
                hidden_extensions: vec!["css".into()],
                ..Default::default()
            })
            .await;

        assert_eq!(websocket.len(), 1);
    }

    #[tokio::test]
    async fn path_extension_mime_fallback_ignores_query_string() {
        let store = TransactionStore::new();
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

        store
            .insert(TransactionRecord::http(
                Utc::now(),
                "GET".into(),
                "https".into(),
                "assets.local:443".into(),
                "/app.js?v=1".into(),
                Some(200),
                1,
                message,
                None,
                Vec::new(),
                None,
                None,
            ))
            .await;

        let script = store
            .list(&ListFilters {
                mime_types: Some(vec!["script".into()]),
                ..Default::default()
            })
            .await;
        let other = store
            .list(&ListFilters {
                mime_types: Some(vec!["other".into()]),
                ..Default::default()
            })
            .await;

        assert_eq!(script.len(), 1);
        assert!(other.is_empty());
    }

    #[tokio::test]
    async fn ecmascript_mime_filter_matches_script() {
        let store = TransactionStore::new();
        let request = MessageRecord {
            headers: Vec::new(),
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };
        let response = MessageRecord {
            content_type: Some("application/ecmascript".into()),
            ..request.clone()
        };

        store
            .insert(TransactionRecord::http(
                Utc::now(),
                "GET".into(),
                "https".into(),
                "assets.local:443".into(),
                "/module".into(),
                Some(200),
                1,
                request,
                Some(response),
                Vec::new(),
                None,
                None,
            ))
            .await;

        let script = store
            .list(&ListFilters {
                mime_types: Some(vec!["script".into()]),
                ..Default::default()
            })
            .await;
        let other = store
            .list(&ListFilters {
                mime_types: Some(vec!["other".into()]),
                ..Default::default()
            })
            .await;

        assert_eq!(script.len(), 1);
        assert!(other.is_empty());
    }

    #[tokio::test]
    async fn port_and_scope_filters_handle_bracketed_ipv6_hosts() {
        let store = TransactionStore::new();
        let empty_message = MessageRecord {
            headers: Vec::new(),
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };

        store
            .insert(TransactionRecord::http(
                Utc::now(),
                "GET".into(),
                "https".into(),
                "[::1]:9443".into(),
                "/ipv6".into(),
                Some(200),
                1,
                empty_message,
                None,
                Vec::new(),
                None,
                None,
            ))
            .await;

        let filtered = store
            .list(&ListFilters {
                port: Some("9443".into()),
                in_scope_only: true,
                scope_patterns: vec!["::1".into()],
                ..Default::default()
            })
            .await;

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].host, "[::1]:9443");
    }

    #[tokio::test]
    async fn port_filter_matches_default_ports_for_bare_hosts() {
        let store = TransactionStore::new();
        store
            .insert(test_record_with_scheme("plain-http.example", "http"))
            .await;
        store
            .insert(test_record_with_scheme("secure-https.example", "https"))
            .await;

        let http = store
            .list(&ListFilters {
                port: Some("80".into()),
                ..Default::default()
            })
            .await;
        let https = store
            .list(&ListFilters {
                port: Some("443".into()),
                ..Default::default()
            })
            .await;

        assert_eq!(http.len(), 1);
        assert_eq!(http[0].host, "plain-http.example");
        assert_eq!(https.len(), 1);
        assert_eq!(https[0].host, "secure-https.example");
    }

    #[tokio::test]
    async fn scope_filters_match_url_shaped_patterns() {
        let store = TransactionStore::new();
        let empty_message = MessageRecord {
            headers: Vec::new(),
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };

        store
            .insert(TransactionRecord::http(
                Utc::now(),
                "GET".into(),
                "https".into(),
                "api.example.test:9443".into(),
                "/kept".into(),
                Some(200),
                1,
                empty_message,
                None,
                Vec::new(),
                None,
                None,
            ))
            .await;

        let filtered = store
            .list(&ListFilters {
                in_scope_only: true,
                scope_patterns: vec!["https://*.example.test:9443/scope".into()],
                ..Default::default()
            })
            .await;

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].host, "api.example.test:9443");
    }
}

#[cfg(test)]
mod retention_status_tests {
    use super::*;

    fn record() -> TransactionRecord {
        TransactionRecord::http(
            chrono::Utc::now(),
            "GET".into(),
            "https".into(),
            "example.com".into(),
            "/synthetic".into(),
            Some(200),
            1,
            crate::model::MessageRecord::from_headers_and_body(
                &http::HeaderMap::new(),
                b"fixture",
                1024,
            ),
            None,
            vec![],
            None,
            None,
        )
    }

    #[tokio::test]
    async fn history_retention_duplicate_identity_and_protection_status_are_distinct() {
        let record = record();
        let id = record.id;
        let store = TransactionStore::from_records_with_max_entries_and_event_sequence(
            vec![record.clone(), record],
            None,
            0,
        );
        let conflict = store
            .retention_status_details(&HashSet::new(), Some(1))
            .await;
        assert_eq!((conflict.total_count, conflict.protected_count), (2, 0));
        assert!(conflict.identity_conflict);
        assert!(!conflict.all_records_protected);
        let protected = store
            .retention_status_details(&HashSet::from([id]), Some(1))
            .await;
        assert_eq!((protected.total_count, protected.protected_count), (2, 1));
        assert!(protected.all_records_protected);
        assert!(!protected.identity_conflict);
        assert!(
            !store
                .retention_status_details(&HashSet::new(), Some(2))
                .await
                .identity_conflict
        );
        assert!(
            !store
                .retention_status_details(&HashSet::new(), None)
                .await
                .identity_conflict
        );
    }

    #[tokio::test]
    async fn history_retention_duplicate_group_is_eligible_when_within_excess() {
        let duplicate = record();
        let store = TransactionStore::from_records_with_max_entries_and_event_sequence(
            vec![duplicate.clone(), duplicate, record()],
            None,
            0,
        );
        let status = store
            .retention_status_details(&HashSet::new(), Some(1))
            .await;
        assert!(!status.identity_conflict);
    }
}

#[cfg(test)]
#[path = "store_service_map_epoch_tests.rs"]
mod service_map_epoch_tests;
