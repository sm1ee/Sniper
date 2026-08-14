use std::{
    collections::{HashMap, HashSet},
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread,
};

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, oneshot, Mutex as AsyncMutex, RwLock};
use tracing::warn;
use uuid::Uuid;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use regex::{Regex, RegexBuilder};

use crate::model::{
    compact_annotation_client_versions_for_insert, TrafficKind, TransactionRecord,
    TransactionSummary,
};

#[derive(Clone, Debug, Default)]
pub struct ListFilters {
    pub query: Option<String>,
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
    inner: RwLock<StoreInner>,
    insert_lock: AsyncMutex<()>,
    events: broadcast::Sender<TransactionEvent>,
    retention_events: broadcast::Sender<()>,
    journal_tx: Option<mpsc::Sender<TransactionJournalCommand>>,
    /// Session directory, so a record whose bodies were dropped can be read back
    /// out of transactions.ndjson. Derived from the journal path.
    storage_dir: Option<PathBuf>,
    max_entries: Option<usize>,
    next_sequence: AtomicU64,
    next_event_sequence: AtomicU64,
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
}

#[derive(Default)]
struct StoreInner {
    /// Oldest to newest. New captures append, queries iterate in reverse.
    entries: Vec<TransactionRecord>,
    summaries: Vec<CachedSummary>,
    by_id: HashMap<Uuid, usize>,
    /// Where a record's line sits in transactions.ndjson, for records whose bodies
    /// were dropped after loading. Bodies are read back through this rather than
    /// kept resident: they are ~90% of a record and the history list never needs
    /// them (`ListFilters` has no body search and `summary()` reads only sizes).
    locators: HashMap<Uuid, crate::session::BodyLocator>,
}

/// Drops the body text a record carries, leaving sizes, headers and metadata.
/// Only safe for a record that has a locator, so the text can be read back.
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
}

impl CachedSummary {
    fn new(summary: TransactionSummary) -> Self {
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
        }
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
        Self {
            entries,
            summaries,
            by_id,
            locators: HashMap::new(),
        }
    }

    fn push(&mut self, record: TransactionRecord, summary: TransactionSummary) {
        let index = self.entries.len();
        self.by_id.insert(record.id, index);
        self.entries.push(record);
        self.summaries.push(CachedSummary::new(summary));
    }

    fn trim_to_max_entries(&mut self, max_entries: usize) -> bool {
        if max_entries == 0 {
            let trimmed =
                !self.entries.is_empty() || !self.summaries.is_empty() || !self.by_id.is_empty();
            self.entries.clear();
            self.summaries.clear();
            self.by_id.clear();
            return trimmed;
        }

        if self.entries.len() <= max_entries {
            return false;
        }

        let remove_count = self.entries.len().saturating_sub(max_entries);
        for record in self.entries.drain(0..remove_count) {
            self.by_id.remove(&record.id);
        }
        self.summaries.drain(0..remove_count);
        for index in self.by_id.values_mut() {
            *index = index.saturating_sub(remove_count);
        }
        true
    }
}

impl TransactionStore {
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
            inner: RwLock::new(inner),
            insert_lock: AsyncMutex::new(()),
            events,
            retention_events,
            journal_tx: None,
            storage_dir: None,
            max_entries,
            next_sequence: AtomicU64::new(max_seq + 1),
            next_event_sequence: AtomicU64::new(max_seq.max(latest_event_sequence) + 1),
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
        for id in replayed_ids {
            locators.remove(id);
        }
        for record in records.iter_mut() {
            if locators.contains_key(&record.id) {
                strip_transaction_bodies(record);
            }
        }
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
        store
    }

    pub async fn insert(&self, mut record: TransactionRecord) -> TransactionInsertOutcome {
        let _insert_guard = self.insert_lock.lock().await;
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
        inner.push(record, summary.clone());
        let mut retention_trimmed = false;
        if let Some(max_entries) = self.max_entries {
            retention_trimmed = inner.trim_to_max_entries(max_entries);
        }
        drop(inner);
        self.publish_transaction_event(summary);
        if retention_trimmed {
            let _ = self.retention_events.send(());
        }
        TransactionInsertOutcome {
            journal_fallback_required,
        }
    }

    pub async fn len(&self) -> usize {
        self.inner.read().await.entries.len()
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
        let since_dt = filters.since.as_deref().and_then(parse_since);
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
                    items.push(cached.summary.clone());
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
                .map(|cached| cached.summary.clone())
                .collect()
        } else {
            filtered
                .into_iter()
                .skip(offset)
                .take(limit)
                .map(|cached| cached.summary.clone())
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

    pub async fn snapshot(&self, limit: Option<usize>) -> Vec<TransactionRecord> {
        let inner = self.inner.read().await;
        snapshot_entries(&inner, limit)
    }

    /// Puts the body text back on a record whose bodies were dropped after loading.
    /// The in-memory copy carries the current annotations, which may be ahead of
    /// what is on disk, so those are kept and only the bodies come from the file.
    fn rehydrate(&self, record: &TransactionRecord, inner: &StoreInner) -> TransactionRecord {
        let Some(locator) = inner.locators.get(&record.id).copied() else {
            return record.clone();
        };
        let Some(storage_dir) = self.storage_dir.as_deref() else {
            return record.clone();
        };
        let Some(mut full) = crate::session::read_transaction_at(storage_dir, locator) else {
            warn!(record_id = %record.id, "could not read transaction bodies back from disk");
            return record.clone();
        };
        full.notes = record.notes.clone();
        full.color_tag = record.color_tag.clone();
        full.user_note = record.user_note.clone();
        full.annotation_revision = record.annotation_revision;
        full.annotation_client_versions = record.annotation_client_versions.clone();
        full
    }

    /// Records to write, each with where its bodies already sit on disk. The
    /// writer copies those lines across rather than loading them, so compaction
    /// never has to hold the whole history in memory.
    pub async fn snapshot_for_persistence(
        &self,
        limit: Option<usize>,
    ) -> io::Result<Vec<(TransactionRecord, Option<crate::session::BodyLocator>)>> {
        let _insert_guard = self.insert_lock.lock().await;
        let inner = self.inner.read().await;
        if let Some(tx) = &self.journal_tx {
            if let Err(error) = rotate_transaction_journal(tx) {
                if error.kind() == io::ErrorKind::BrokenPipe {
                    warn!(
                        ?error,
                        "transaction journal writer stopped; continuing with full snapshot"
                    );
                } else {
                    return Err(error);
                }
            }
        }
        Ok(snapshot_entries(&inner, limit)
            .into_iter()
            .map(|record| {
                let locator = inner.locators.get(&record.id).copied();
                (record, locator)
            })
            .collect())
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
            record.clone()
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
        inner.summaries[index] = CachedSummary::new(summary.clone());
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
        drop(inner);
        self.publish_transaction_event(summary);
        Ok(true)
    }

    pub async fn replace_all(&self, records: Vec<TransactionRecord>) {
        let mut inner = StoreInner::from_newest_first(records);
        if let Some(max_entries) = self.max_entries {
            inner.trim_to_max_entries(max_entries);
        }
        let max_seq = inner.entries.iter().map(|r| r.sequence).max().unwrap_or(0);
        *self.inner.write().await = inner;
        self.next_sequence.store(max_seq + 1, Ordering::Relaxed);
        self.next_event_sequence
            .store(max_seq + 1, Ordering::Relaxed);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<TransactionEvent> {
        self.events.subscribe()
    }

    pub fn subscribe_retention(&self) -> broadcast::Receiver<()> {
        self.retention_events.subscribe()
    }

    /// Points the store at where a compaction just put each record, and drops the
    /// bodies it no longer has to hold. Must be called after every rewrite of
    /// transactions.ndjson: the offsets from before it are stale, and a stale
    /// offset silently returns a different request's traffic.
    pub async fn adopt_written_locators(
        &self,
        locators: HashMap<Uuid, crate::session::BodyLocator>,
    ) {
        let mut inner = self.inner.write().await;
        for record in inner.entries.iter_mut() {
            if locators.contains_key(&record.id) {
                strip_transaction_bodies(record);
            }
        }
        inner.locators = locators;
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

            let mut file = match open_private_append_file(&journal_path) {
                Ok(file) => file,
                Err(error) => {
                    warn!(?error, path = %journal_path.display(), "failed to open transaction journal");
                    let _ = ready_tx.send(Err(error));
                    return;
                }
            };
            let _ = ready_tx.send(Ok(()));

            while let Ok(command) = rx.recv() {
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
                        if let Some(ack) = ack {
                            let _ = ack.send(result);
                        }
                        if failed {
                            return;
                        }
                    }
                    TransactionJournalCommand::Rotate { ack } => {
                        let result = rotate_transaction_journal_file(&mut file, &journal_path);
                        if let Err(error) = &result {
                            warn!(?error, path = %journal_path.display(), "failed to rotate transaction journal");
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

fn rotate_transaction_journal(tx: &mpsc::Sender<TransactionJournalCommand>) -> io::Result<()> {
    let (ack, rx) = mpsc::channel();
    tx.send(TransactionJournalCommand::Rotate { ack })
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "transaction journal writer stopped",
            )
        })?;
    rx.recv().map_err(|_| {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            "transaction journal writer stopped",
        )
    })?
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

    file.set_len(0)?;
    file.sync_all()
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
        fs::rename(&tmp_path, checkpoint_path)?;
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
    fs::File::open(path).and_then(|directory| directory.sync_all())
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

fn parse_since(input: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let trimmed = input.trim();
    // Relative: "1h", "30m", "2d", "7d"
    if let Some(rest) = trimmed.strip_suffix('h') {
        let hours: i64 = rest.parse().ok()?;
        return Some(chrono::Utc::now() - chrono::Duration::hours(hours));
    }
    if let Some(rest) = trimmed.strip_suffix('m') {
        let minutes: i64 = rest.parse().ok()?;
        return Some(chrono::Utc::now() - chrono::Duration::minutes(minutes));
    }
    if let Some(rest) = trimmed.strip_suffix('d') {
        let days: i64 = rest.parse().ok()?;
        return Some(chrono::Utc::now() - chrono::Duration::days(days));
    }
    if let Some(rest) = trimmed.strip_suffix('s') {
        let secs: i64 = rest.parse().ok()?;
        return Some(chrono::Utc::now() - chrono::Duration::seconds(secs));
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
        if !matcher.matches(cached) {
            return false;
        }
    }

    let Some(value) = query else { return true };
    cached.quick_haystack.contains(value)
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

fn normalize_host_for_matching(host: &str) -> String {
    let mut value = host.trim().to_ascii_lowercase();
    if let Some((_, rest)) = value.split_once("://") {
        value = rest.to_string();
    } else if let Some(rest) = value.strip_prefix("//") {
        value = rest.to_string();
    }
    let host = value.split(['/', '?', '#']).next().unwrap_or("").trim();
    host_without_port(host).to_string()
}

fn host_without_port(host: &str) -> &str {
    let trimmed = host.trim();
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return &rest[..end];
        }
    }
    if trimmed.matches(':').count() == 1 {
        return trimmed
            .split_once(':')
            .map(|(value, _)| value)
            .unwrap_or(trimmed);
    }
    trimmed
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

    fn matches(&self, cached: &CachedSummary) -> bool {
        match self {
            Self::Plain {
                needle,
                case_sensitive,
                negative,
            } => {
                let matched = if *case_sensitive {
                    cached.advanced_haystack.contains(needle)
                } else {
                    cached.advanced_haystack_lower.contains(needle)
                };
                if *negative {
                    !matched
                } else {
                    matched
                }
            }
            Self::Regex { regex, negative } => {
                let matched = regex.is_match(&cached.advanced_haystack);
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
mod tests {
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
        let storage_dir = std::env::temp_dir()
            .join(format!("sniper-locator-refresh-{}", uuid::Uuid::new_v4()));
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
        store.set_body_locator_for_test(second_id, located[1].1).await;

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
        let storage_dir = std::env::temp_dir()
            .join(format!("sniper-get-rehydrate-{}", uuid::Uuid::new_v4()));
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
        let storage_dir = std::env::temp_dir()
            .join(format!("sniper-rehydrate-{}", uuid::Uuid::new_v4()));
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

    #[tokio::test]
    async fn list_page_can_sort_by_whether_a_record_was_edited() {
        // The Edited column is sortable, so the server has to know the key. An
        // unknown key silently falls back to time order, which looks like the
        // column simply does not sort.
        let store = TransactionStore::new();
        for (path, edited) in [("/plain", false), ("/changed", true), ("/also-plain", false)] {
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
        assert_eq!(page.items.first().map(|item| item.path.as_str()), Some("/changed"));
        assert!(page.items.first().map(|item| item.has_match_replace).unwrap_or(false));
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
