use std::{
    cmp::Ordering,
    collections::{HashMap, VecDeque},
    sync::atomic::{AtomicU64, Ordering as AtomicOrdering},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

use crate::model::{
    websocket_total_frame_count, MessageRecord, WebSocketFrameRecord, WebSocketSessionRecord,
    WebSocketSessionSummary,
};

const MAX_WEBSOCKET_BROADCAST_CAPACITY: usize = 4096;
const DEFAULT_WEBSOCKET_LIST_LIMIT: usize = 5_000;
const WEBSOCKET_CAPTURE_PREVIEW_BYTES: usize = 64 * 1024;

pub struct WebSocketStore {
    max_entries: usize,
    max_frames_per_session: usize,
    inner: RwLock<WebSocketStoreInner>,
    events: broadcast::Sender<WebSocketSessionSummary>,
    retention_events: broadcast::Sender<()>,
    next_sequence: AtomicU64,
}

struct WebSocketStoreInner {
    order: VecDeque<Uuid>,
    sessions: HashMap<Uuid, WebSocketSessionEntry>,
    started_at_desc_ordered: bool,
}

impl WebSocketStoreInner {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            order: VecDeque::with_capacity(capacity),
            sessions: HashMap::with_capacity(capacity),
            started_at_desc_ordered: true,
        }
    }
}

#[derive(Clone)]
struct WebSocketSessionEntry {
    id: Uuid,
    sequence: u64,
    started_at: DateTime<Utc>,
    closed_at: Option<DateTime<Utc>>,
    duration_ms: Option<u64>,
    scheme: String,
    host: String,
    path: String,
    status: Option<u16>,
    request: MessageRecord,
    response: Option<MessageRecord>,
    frames: VecDeque<WebSocketFrameRecord>,
    frame_count: usize,
    notes: Vec<String>,
}

impl From<WebSocketSessionRecord> for WebSocketSessionEntry {
    fn from(record: WebSocketSessionRecord) -> Self {
        let frame_count = websocket_total_frame_count(&record.frames);
        Self {
            id: record.id,
            sequence: record.sequence,
            started_at: record.started_at,
            closed_at: record.closed_at,
            duration_ms: record.duration_ms,
            scheme: record.scheme,
            host: record.host,
            path: record.path,
            status: record.status,
            request: record.request,
            response: record.response,
            frames: VecDeque::from(record.frames),
            frame_count,
            notes: record.notes,
        }
    }
}

impl WebSocketSessionEntry {
    fn summary(&self) -> WebSocketSessionSummary {
        WebSocketSessionSummary {
            id: self.id,
            sequence: self.sequence,
            started_at: self.started_at,
            closed_at: self.closed_at,
            duration_ms: self.duration_ms,
            scheme: self.scheme.clone(),
            host: self.host.clone(),
            path: self.path.clone(),
            status: self.status,
            frame_count: self.frame_count,
            retained_frame_count: self.frames.len(),
            last_frame_index: self.frames.back().map(|frame| frame.index),
            note_count: self.notes.len(),
        }
    }

    fn to_record(&self) -> WebSocketSessionRecord {
        self.to_record_with_frame_window(None, None)
    }

    fn to_record_with_frame_window(
        &self,
        frame_limit: Option<usize>,
        before_index: Option<usize>,
    ) -> WebSocketSessionRecord {
        let frames = frame_window(&self.frames, frame_limit, before_index);

        WebSocketSessionRecord {
            id: self.id,
            sequence: self.sequence,
            started_at: self.started_at,
            closed_at: self.closed_at,
            duration_ms: self.duration_ms,
            scheme: self.scheme.clone(),
            host: self.host.clone(),
            path: self.path.clone(),
            status: self.status,
            request: self.request.clone(),
            response: self.response.clone(),
            frames,
            notes: self.notes.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct WebSocketListPage {
    pub items: Vec<WebSocketSessionSummary>,
    pub total: usize,
    pub filtered_total: Option<usize>,
    pub offset: usize,
    pub limit: usize,
    pub has_more: bool,
}

#[derive(Clone, Debug, Default)]
pub struct WebSocketListFilters {
    pub query: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub after_id: Option<Uuid>,
    pub sort_key: Option<String>,
    pub sort_direction: Option<String>,
    pub scope_patterns: Vec<String>,
    pub excluded_scope_patterns: Vec<String>,
    pub in_scope_only: bool,
    pub live_only: bool,
}

impl WebSocketStore {
    pub fn new(max_entries: usize, max_frames_per_session: usize) -> Self {
        Self::from_sessions(max_entries, max_frames_per_session, Vec::new())
    }

    pub fn from_sessions(
        max_entries: usize,
        max_frames_per_session: usize,
        records: Vec<WebSocketSessionRecord>,
    ) -> Self {
        let (events, _) =
            broadcast::channel(max_entries.clamp(32, MAX_WEBSOCKET_BROADCAST_CAPACITY));
        let (retention_events, _) =
            broadcast::channel(max_entries.clamp(32, MAX_WEBSOCKET_BROADCAST_CAPACITY));
        let mut records =
            sessions_with_live_preserved(records, max_entries, max_frames_per_session);
        normalize_websocket_sequences(&mut records);
        let max_sequence = records
            .iter()
            .map(|record| record.sequence)
            .max()
            .unwrap_or(0);
        let inner = inner_from_records(records, max_entries);
        Self {
            max_entries,
            max_frames_per_session,
            inner: RwLock::new(inner),
            events,
            retention_events,
            next_sequence: AtomicU64::new(max_sequence.saturating_add(1)),
        }
    }

    pub async fn open(&self, mut session: WebSocketSessionRecord) {
        if session.sequence == 0 {
            session.sequence = self.next_sequence.fetch_add(1, AtomicOrdering::Relaxed);
        } else {
            advance_next_websocket_sequence(
                &self.next_sequence,
                session.sequence.saturating_add(1),
            );
        }
        trim_frame_overflow(&mut session.frames, self.max_frames_per_session);
        let started_at = session.started_at;
        let id = session.id;
        let entry = WebSocketSessionEntry::from(session);
        let mut inner = self.inner.write().await;
        remove_ordered_session(&mut inner, id);
        if inner.started_at_desc_ordered {
            inner.started_at_desc_ordered = inner
                .order
                .front()
                .and_then(|id| inner.sessions.get(id))
                .is_none_or(|current_newest| started_at >= current_newest.started_at);
        }
        inner.order.push_front(id);
        inner.sessions.insert(id, entry);
        let removed_any = trim_overflow(&mut inner, self.max_entries);
        if removed_any && !inner.started_at_desc_ordered {
            inner.started_at_desc_ordered = compute_storage_order_matches_started_at_desc(&inner);
        }
        if let Some(summary) = inner.sessions.get(&id).map(WebSocketSessionEntry::summary) {
            let _ = self.events.send(summary);
        }
        if removed_any {
            let _ = self.retention_events.send(());
        }
    }

    pub async fn append_frame(&self, id: Uuid, frame: WebSocketFrameRecord) -> bool {
        let mut inner = self.inner.write().await;
        if let Some(session) = inner.sessions.get_mut(&id) {
            let next_frame_count = frame.index.saturating_add(1);
            session.frames.push_back(frame);
            session.frame_count = session
                .frame_count
                .max(next_frame_count)
                .max(session.frames.len());
            trim_frame_deque_overflow(&mut session.frames, self.max_frames_per_session);
            let _ = self.events.send(session.summary());
            true
        } else {
            false
        }
    }

    pub async fn contains(&self, id: Uuid) -> bool {
        self.inner.read().await.sessions.contains_key(&id)
    }

    pub async fn close(
        &self,
        id: Uuid,
        closed_at: DateTime<Utc>,
        duration_ms: u64,
        note: Option<String>,
    ) -> bool {
        let mut inner = self.inner.write().await;
        if let Some(session) = inner.sessions.get_mut(&id) {
            session.closed_at = Some(closed_at);
            session.duration_ms = Some(duration_ms);
            if let Some(note) = note {
                session.notes.push(note);
            }
            let summary = session.summary();
            let removed_any = trim_overflow(&mut inner, self.max_entries);
            if inner.sessions.contains_key(&id) {
                let _ = self.events.send(summary);
            }
            if removed_any && !inner.started_at_desc_ordered {
                inner.started_at_desc_ordered =
                    compute_storage_order_matches_started_at_desc(&inner);
            }
            if removed_any {
                let _ = self.retention_events.send(());
            }
            true
        } else {
            false
        }
    }

    pub async fn list(&self, limit: Option<usize>) -> Vec<WebSocketSessionSummary> {
        self.list_page(limit, None).await.items
    }

    pub async fn list_page(
        &self,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> WebSocketListPage {
        self.list_page_filtered(&WebSocketListFilters {
            limit,
            offset,
            ..WebSocketListFilters::default()
        })
        .await
    }

    pub async fn list_page_filtered(&self, filters: &WebSocketListFilters) -> WebSocketListPage {
        let inner = self.inner.read().await;
        let total = inner.order.len();
        let limit = filters
            .limit
            .unwrap_or(DEFAULT_WEBSOCKET_LIST_LIMIT)
            .min(self.max_entries);
        let normalized_query = filters
            .query
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_ascii_lowercase);
        if let Some(page) = list_unfiltered_storage_order_page(
            &inner,
            total,
            limit,
            filters.offset.unwrap_or(0),
            filters,
            normalized_query.as_deref(),
        ) {
            return page;
        }
        if let Some(page) = list_filtered_storage_order_page(
            &inner,
            total,
            limit,
            filters,
            normalized_query.as_deref(),
        ) {
            return page;
        }
        let mut matched: Vec<(usize, WebSocketSessionSummary)> = inner
            .order
            .iter()
            .enumerate()
            .filter_map(|(index, id)| {
                inner
                    .sessions
                    .get(id)
                    .map(WebSocketSessionEntry::summary)
                    .map(|summary| (index, summary))
            })
            .filter(|(_, summary)| {
                websocket_summary_matches_filters(summary, filters, normalized_query.as_deref())
            })
            .collect();
        sort_websocket_summaries(
            &mut matched,
            filters.sort_key.as_deref(),
            filters.sort_direction.as_deref(),
        );
        let filtered_total = matched.len();
        let offset = sorted_summary_offset_after_id(&matched, filters.after_id)
            .unwrap_or_else(|| filters.offset.unwrap_or(0))
            .min(filtered_total);
        let summaries = matched.into_iter().skip(offset).map(|(_, summary)| summary);
        let items = if limit == 0 {
            summaries.collect::<Vec<_>>()
        } else {
            summaries.take(limit).collect::<Vec<_>>()
        };
        WebSocketListPage {
            items,
            total,
            filtered_total: Some(filtered_total),
            offset,
            limit,
            has_more: limit != 0 && offset.saturating_add(limit) < filtered_total,
        }
    }

    pub async fn get(&self, id: Uuid) -> Option<WebSocketSessionRecord> {
        self.inner
            .read()
            .await
            .sessions
            .get(&id)
            .map(WebSocketSessionEntry::to_record)
    }

    pub async fn get_windowed(
        &self,
        id: Uuid,
        frame_limit: Option<usize>,
        before_index: Option<usize>,
    ) -> Option<WebSocketSessionRecord> {
        self.inner
            .read()
            .await
            .sessions
            .get(&id)
            .map(|session| session.to_record_with_frame_window(frame_limit, before_index))
    }

    pub async fn len(&self) -> usize {
        self.inner.read().await.order.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.inner.read().await.order.is_empty()
    }

    pub async fn snapshot(&self, limit: Option<usize>) -> Vec<WebSocketSessionRecord> {
        self.snapshot_with_frame_limit(limit, None).await
    }

    pub async fn snapshot_with_frame_limit(
        &self,
        limit: Option<usize>,
        frame_limit: Option<usize>,
    ) -> Vec<WebSocketSessionRecord> {
        let inner = self.inner.read().await;
        let limit = limit.unwrap_or(self.max_entries).min(self.max_entries);
        let mut closed_remaining = limit.saturating_sub(
            inner
                .order
                .iter()
                .filter_map(|id| inner.sessions.get(id))
                .filter(|session| session.closed_at.is_none())
                .count(),
        );
        inner
            .order
            .iter()
            .filter_map(|id| inner.sessions.get(id))
            .filter(|session| {
                if session.closed_at.is_none() {
                    return true;
                }
                if closed_remaining == 0 {
                    return false;
                }
                closed_remaining -= 1;
                true
            })
            .map(|session| session.to_record_with_frame_window(frame_limit, None))
            .collect()
    }

    pub async fn replace_all(&self, records: Vec<WebSocketSessionRecord>) {
        let mut inner = self.inner.write().await;
        *inner = inner_from_records(
            sessions_with_live_preserved(records, self.max_entries, self.max_frames_per_session),
            self.max_entries,
        );
    }

    pub fn subscribe(&self) -> broadcast::Receiver<WebSocketSessionSummary> {
        self.events.subscribe()
    }

    pub fn subscribe_retention(&self) -> broadcast::Receiver<()> {
        self.retention_events.subscribe()
    }
}

pub(crate) fn sessions_with_live_preserved(
    records: Vec<WebSocketSessionRecord>,
    max_entries: usize,
    max_frames_per_session: usize,
) -> Vec<WebSocketSessionRecord> {
    let live_count = records
        .iter()
        .filter(|session| session.closed_at.is_none())
        .count();
    let mut closed_remaining = max_entries.saturating_sub(live_count);
    records
        .into_iter()
        .filter_map(|mut session| {
            trim_frame_overflow(&mut session.frames, max_frames_per_session);
            normalize_restored_frame_previews(&mut session.frames);
            if session.closed_at.is_none() {
                return Some(session);
            }
            if closed_remaining == 0 {
                return None;
            }
            closed_remaining -= 1;
            Some(session)
        })
        .collect()
}

fn normalize_restored_frame_previews(frames: &mut [WebSocketFrameRecord]) {
    for frame in frames {
        match frame.body_encoding {
            crate::model::BodyEncoding::Utf8 => normalize_restored_utf8_frame(frame),
            crate::model::BodyEncoding::Base64 => normalize_restored_base64_frame(frame),
        }
    }
}

fn normalize_restored_utf8_frame(frame: &mut WebSocketFrameRecord) {
    let preview_len = frame.body_preview.len();
    if frame.body_size < preview_len {
        frame.body_size = preview_len;
    }
    if preview_len <= WEBSOCKET_CAPTURE_PREVIEW_BYTES {
        return;
    }

    let mut truncate_at = WEBSOCKET_CAPTURE_PREVIEW_BYTES;
    while !frame.body_preview.is_char_boundary(truncate_at) {
        truncate_at -= 1;
    }
    frame.body_preview.truncate(truncate_at);
    frame.preview_truncated = true;
}

fn normalize_restored_base64_frame(frame: &mut WebSocketFrameRecord) {
    let Ok(mut decoded) = STANDARD.decode(frame.body_preview.as_bytes()) else {
        frame.body_preview.clear();
        frame.body_size = 0;
        frame.preview_truncated = false;
        return;
    };
    if frame.body_size < decoded.len() {
        frame.body_size = decoded.len();
    }
    if decoded.len() <= WEBSOCKET_CAPTURE_PREVIEW_BYTES {
        return;
    }

    decoded.truncate(WEBSOCKET_CAPTURE_PREVIEW_BYTES);
    frame.body_preview = STANDARD.encode(decoded);
    frame.preview_truncated = true;
}

fn inner_from_records(
    records: Vec<WebSocketSessionRecord>,
    max_entries: usize,
) -> WebSocketStoreInner {
    let mut inner = WebSocketStoreInner::with_capacity(records.len().min(max_entries));
    for record in records {
        remove_ordered_session(&mut inner, record.id);
        let id = record.id;
        inner.order.push_back(id);
        inner
            .sessions
            .insert(id, WebSocketSessionEntry::from(record));
    }
    inner.started_at_desc_ordered = compute_storage_order_matches_started_at_desc(&inner);
    inner
}

fn normalize_websocket_sequences(records: &mut [WebSocketSessionRecord]) {
    if !records.iter().any(|record| record.sequence == 0) {
        return;
    }
    let total = records.len() as u64;
    for (index, record) in records.iter_mut().enumerate() {
        if record.sequence == 0 {
            record.sequence = total.saturating_sub(index as u64);
        }
    }
}

fn advance_next_websocket_sequence(next_sequence: &AtomicU64, target: u64) {
    let mut current = next_sequence.load(AtomicOrdering::Relaxed);
    while current < target {
        match next_sequence.compare_exchange_weak(
            current,
            target,
            AtomicOrdering::Relaxed,
            AtomicOrdering::Relaxed,
        ) {
            Ok(_) => break,
            Err(actual) => current = actual,
        }
    }
}

fn frame_window(
    frames: &VecDeque<WebSocketFrameRecord>,
    frame_limit: Option<usize>,
    before_index: Option<usize>,
) -> Vec<WebSocketFrameRecord> {
    let end = before_index
        .and_then(|before| {
            frames
                .iter()
                .position(|frame| frame.index >= before)
                .or(Some(frames.len()))
        })
        .unwrap_or(frames.len());
    match frame_limit {
        Some(0) => Vec::new(),
        Some(limit) if end > limit => frames.iter().take(end).skip(end - limit).cloned().collect(),
        _ => frames.iter().take(end).cloned().collect(),
    }
}

pub(crate) fn trim_frame_overflow(
    frames: &mut Vec<WebSocketFrameRecord>,
    max_frames_per_session: usize,
) {
    if frames.len() > max_frames_per_session {
        let overflow = frames.len() - max_frames_per_session;
        frames.drain(..overflow);
    }
}

fn trim_frame_deque_overflow(
    frames: &mut VecDeque<WebSocketFrameRecord>,
    max_frames_per_session: usize,
) {
    while frames.len() > max_frames_per_session {
        frames.pop_front();
    }
}

fn remove_ordered_session(inner: &mut WebSocketStoreInner, id: Uuid) {
    inner.sessions.remove(&id);
    if let Some(index) = inner.order.iter().position(|candidate| *candidate == id) {
        inner.order.remove(index);
    }
}

fn websocket_summary_matches_filters(
    summary: &WebSocketSessionSummary,
    filters: &WebSocketListFilters,
    normalized_query: Option<&str>,
) -> bool {
    if filters.in_scope_only
        && !crate::scope::is_host_in_scope(
            &summary.host,
            &filters.scope_patterns,
            &filters.excluded_scope_patterns,
        )
    {
        return false;
    }
    if filters.live_only && summary.closed_at.is_some() {
        return false;
    }
    if let Some(query) = normalized_query {
        if !websocket_summary_search_haystack(summary).contains(query) {
            return false;
        }
    }
    true
}

fn list_filtered_storage_order_page(
    inner: &WebSocketStoreInner,
    total: usize,
    limit: usize,
    filters: &WebSocketListFilters,
    normalized_query: Option<&str>,
) -> Option<WebSocketListPage> {
    if !storage_order_satisfies_websocket_sort(inner, filters) {
        return None;
    }

    if let Some(start_index) = storage_order_offset_after_id(inner, filters.after_id) {
        let mut matched_count = 0usize;
        let mut items = if limit == 0 {
            Vec::with_capacity(total.saturating_sub(start_index))
        } else {
            Vec::with_capacity(limit.min(total.saturating_sub(start_index)))
        };

        for id in inner.order.iter().skip(start_index) {
            let Some(summary) = inner.sessions.get(id).map(WebSocketSessionEntry::summary) else {
                continue;
            };
            if !websocket_summary_matches_filters(&summary, filters, normalized_query) {
                continue;
            }
            matched_count += 1;
            if limit == 0 || items.len() < limit {
                items.push(summary);
            }
            if limit != 0 && matched_count > limit {
                break;
            }
        }

        return Some(WebSocketListPage {
            items,
            total,
            filtered_total: None,
            offset: start_index,
            limit,
            has_more: limit != 0 && matched_count > limit,
        });
    }

    let offset = filters.offset.unwrap_or(0);
    let mut matched_count = 0usize;
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

    for id in inner.order.iter() {
        let Some(summary) = inner.sessions.get(id).map(WebSocketSessionEntry::summary) else {
            continue;
        };
        if !websocket_summary_matches_filters(&summary, filters, normalized_query) {
            continue;
        }

        let matched_index = matched_count;
        matched_count += 1;
        if matched_index >= offset && (limit == 0 || items.len() < limit) {
            items.push(summary);
        }
        if stop_after.is_some_and(|threshold| matched_count >= threshold) {
            exhausted = false;
            break;
        }
    }

    let has_more = limit != 0 && matched_count > offset.saturating_add(items.len());
    Some(WebSocketListPage {
        items,
        total,
        filtered_total: exhausted.then_some(matched_count),
        offset,
        limit,
        has_more,
    })
}

fn list_unfiltered_storage_order_page(
    inner: &WebSocketStoreInner,
    total: usize,
    limit: usize,
    offset: usize,
    filters: &WebSocketListFilters,
    normalized_query: Option<&str>,
) -> Option<WebSocketListPage> {
    if normalized_query.is_some() || filters.in_scope_only || filters.live_only {
        return None;
    }
    if !storage_order_satisfies_websocket_sort(inner, filters) {
        return None;
    }

    let offset = storage_order_offset_after_id(inner, filters.after_id)
        .unwrap_or(offset)
        .min(total);
    let summaries = inner
        .order
        .iter()
        .skip(offset)
        .filter_map(|id| inner.sessions.get(id).map(WebSocketSessionEntry::summary));
    let items = if limit == 0 {
        summaries.collect::<Vec<_>>()
    } else {
        summaries.take(limit).collect::<Vec<_>>()
    };
    Some(WebSocketListPage {
        items,
        total,
        filtered_total: Some(total),
        offset,
        limit,
        has_more: limit != 0 && offset.saturating_add(limit) < total,
    })
}

fn storage_order_offset_after_id(
    inner: &WebSocketStoreInner,
    after_id: Option<Uuid>,
) -> Option<usize> {
    let after_id = after_id?;
    inner
        .order
        .iter()
        .position(|id| *id == after_id)
        .map(|index| index.saturating_add(1))
}

fn sorted_summary_offset_after_id(
    entries: &[(usize, WebSocketSessionSummary)],
    after_id: Option<Uuid>,
) -> Option<usize> {
    let after_id = after_id?;
    entries
        .iter()
        .position(|(_, summary)| summary.id == after_id)
        .map(|index| index.saturating_add(1))
}

fn storage_order_satisfies_websocket_sort(
    inner: &WebSocketStoreInner,
    filters: &WebSocketListFilters,
) -> bool {
    let sort_key = filters
        .sort_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("index");
    if matches!(filters.sort_direction.as_deref(), Some("asc")) {
        return false;
    }
    match sort_key {
        "index" => true,
        "started_at" => inner.started_at_desc_ordered,
        _ => false,
    }
}

fn compute_storage_order_matches_started_at_desc(inner: &WebSocketStoreInner) -> bool {
    let mut previous_started_at: Option<DateTime<Utc>> = None;
    for session in inner.order.iter().filter_map(|id| inner.sessions.get(id)) {
        if previous_started_at
            .as_ref()
            .is_some_and(|previous| session.started_at > *previous)
        {
            return false;
        }
        previous_started_at = Some(session.started_at);
    }
    true
}

fn websocket_summary_search_haystack(summary: &WebSocketSessionSummary) -> String {
    [
        summary.scheme.clone(),
        summary.host.clone(),
        summary.path.clone(),
        summary
            .status
            .map(|value| value.to_string())
            .unwrap_or_default(),
        summary.frame_count.to_string(),
        summary
            .duration_ms
            .map(|value| format!("{value} ms"))
            .unwrap_or_else(|| {
                if summary.closed_at.is_none() {
                    "live".to_string()
                } else {
                    "closed".to_string()
                }
            }),
        summary.started_at.to_rfc3339(),
    ]
    .join("\n")
    .to_ascii_lowercase()
}

fn sort_websocket_summaries(
    entries: &mut [(usize, WebSocketSessionSummary)],
    sort_key: Option<&str>,
    sort_direction: Option<&str>,
) {
    let sort_key = sort_key
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .unwrap_or("index");
    if sort_key == "index" {
        let descending = !matches!(sort_direction, Some("asc"));
        entries.sort_by(|left, right| {
            if descending {
                left.0.cmp(&right.0)
            } else {
                right.0.cmp(&left.0)
            }
        });
        return;
    }
    let descending = !matches!(sort_direction, Some("asc"));
    entries.sort_by(|left, right| {
        let ordering = compare_websocket_summary(sort_key, left, right);
        let ordering = if descending {
            ordering.reverse()
        } else {
            ordering
        };
        ordering.then_with(|| left.0.cmp(&right.0))
    });
}

fn compare_websocket_summary(
    sort_key: &str,
    left: &(usize, WebSocketSessionSummary),
    right: &(usize, WebSocketSessionSummary),
) -> Ordering {
    match sort_key {
        "index" => left.0.cmp(&right.0),
        "host" => left
            .1
            .host
            .to_ascii_lowercase()
            .cmp(&right.1.host.to_ascii_lowercase()),
        "path" => left
            .1
            .path
            .to_ascii_lowercase()
            .cmp(&right.1.path.to_ascii_lowercase()),
        "status" => left.1.status.cmp(&right.1.status),
        "frame_count" => left.1.frame_count.cmp(&right.1.frame_count),
        "duration_ms" => left
            .1
            .duration_ms
            .unwrap_or(u64::MAX)
            .cmp(&right.1.duration_ms.unwrap_or(u64::MAX)),
        "started_at" => left.1.started_at.cmp(&right.1.started_at),
        _ => left.0.cmp(&right.0),
    }
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

fn trim_closed_overflow(inner: &mut WebSocketStoreInner, max_entries: usize) -> bool {
    let mut removed_any = false;
    while inner.order.len() > max_entries {
        let Some(index) = inner.order.iter().rposition(|id| {
            inner
                .sessions
                .get(id)
                .is_some_and(|session| session.closed_at.is_some())
        }) else {
            break;
        };
        if let Some(id) = inner.order.remove(index) {
            inner.sessions.remove(&id);
            removed_any = true;
        }
    }
    removed_any
}

fn trim_overflow(inner: &mut WebSocketStoreInner, max_entries: usize) -> bool {
    trim_closed_overflow(inner, max_entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{BodyEncoding, MessageRecord, WebSocketFrameDirection, WebSocketFrameKind};
    use http::HeaderMap;

    fn frame(index: usize) -> WebSocketFrameRecord {
        WebSocketFrameRecord {
            index,
            captured_at: Utc::now(),
            direction: WebSocketFrameDirection::ClientToServer,
            kind: WebSocketFrameKind::Text,
            body_preview: format!("frame-{index}"),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            preview_truncated: false,
        }
    }

    fn session(frames: Vec<WebSocketFrameRecord>) -> WebSocketSessionRecord {
        WebSocketSessionRecord {
            id: Uuid::new_v4(),
            sequence: 0,
            started_at: Utc::now(),
            closed_at: None,
            duration_ms: None,
            scheme: "wss".to_string(),
            host: "example.com".to_string(),
            path: "/ws".to_string(),
            status: Some(101),
            request: MessageRecord::from_headers_and_body(&HeaderMap::new(), &[], 1024),
            response: None,
            frames,
            notes: Vec::new(),
        }
    }

    fn closed_session(frames: Vec<WebSocketFrameRecord>) -> WebSocketSessionRecord {
        let mut record = session(frames);
        record.closed_at = Some(Utc::now());
        record.duration_ms = Some(25);
        record
    }

    #[tokio::test]
    async fn list_page_filtered_without_limit_uses_default_cap() {
        let now = Utc::now();
        let records = (0..(DEFAULT_WEBSOCKET_LIST_LIMIT + 5))
            .map(|idx| {
                let mut record = session(vec![frame(1)]);
                record.host = format!("host-{idx}.example.test");
                record.started_at = now - chrono::Duration::milliseconds(idx as i64);
                record
            })
            .collect::<Vec<_>>();
        let store = WebSocketStore::from_sessions(10_000, 10, records);

        let page = store
            .list_page_filtered(&WebSocketListFilters::default())
            .await;

        assert_eq!(page.items.len(), DEFAULT_WEBSOCKET_LIST_LIMIT);
        assert_eq!(page.limit, DEFAULT_WEBSOCKET_LIST_LIMIT);
        assert!(page.has_more);
    }

    #[tokio::test]
    async fn list_page_filtered_streams_storage_order_without_full_count() {
        let now = Utc::now();
        let records = (0..25)
            .map(|idx| {
                let mut record = session(vec![frame(1)]);
                record.host = format!("chat-{idx}.example.test");
                record.started_at = now - chrono::Duration::milliseconds(idx as i64);
                record
            })
            .collect::<Vec<_>>();
        let store = WebSocketStore::from_sessions(100, 10, records);

        let page = store
            .list_page_filtered(&WebSocketListFilters {
                query: Some("example.test".to_string()),
                limit: Some(2),
                sort_key: Some("started_at".to_string()),
                sort_direction: Some("desc".to_string()),
                ..WebSocketListFilters::default()
            })
            .await;

        assert_eq!(page.items.len(), 2);
        assert_eq!(page.items[0].host, "chat-0.example.test");
        assert_eq!(page.items[1].host, "chat-1.example.test");
        assert_eq!(page.filtered_total, None);
        assert!(page.has_more);
    }

    #[tokio::test]
    async fn list_page_filtered_honors_sort_direction_without_sort_key() {
        let mut newest = session(vec![frame(1)]);
        newest.host = "newest.example.test".to_string();
        let newest_id = newest.id;
        let mut older = session(vec![frame(1)]);
        older.host = "older.example.test".to_string();
        let older_id = older.id;
        let store = WebSocketStore::from_sessions(10, 10, vec![newest, older]);

        let page = store
            .list_page_filtered(&WebSocketListFilters {
                sort_direction: Some("asc".to_string()),
                ..WebSocketListFilters::default()
            })
            .await;

        assert_eq!(page.items.len(), 2);
        assert_eq!(page.items[0].id, older_id);
        assert_eq!(page.items[1].id, newest_id);
    }

    #[tokio::test]
    async fn list_page_filtered_searches_sorts_and_offsets_after_filtering() {
        let mut live = session(vec![frame(1)]);
        live.host = "zeta.example.test".to_string();
        live.path = "/chat".to_string();
        live.started_at = Utc::now();

        let mut closed = closed_session(vec![frame(1), frame(2)]);
        closed.host = "api.example.test".to_string();
        closed.path = "/socket".to_string();
        closed.status = Some(500);
        closed.duration_ms = Some(12);
        closed.started_at = Utc::now();

        let store = WebSocketStore::from_sessions(10, 10, vec![live, closed]);

        let page = store
            .list_page_filtered(&WebSocketListFilters {
                query: Some("500".to_string()),
                limit: Some(10),
                sort_key: Some("host".to_string()),
                sort_direction: Some("asc".to_string()),
                ..WebSocketListFilters::default()
            })
            .await;

        assert_eq!(page.total, 2);
        assert_eq!(page.filtered_total, Some(1));
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].host, "api.example.test");

        let sorted_page = store
            .list_page_filtered(&WebSocketListFilters {
                limit: Some(1),
                offset: Some(1),
                sort_key: Some("host".to_string()),
                sort_direction: Some("asc".to_string()),
                ..WebSocketListFilters::default()
            })
            .await;

        assert_eq!(sorted_page.filtered_total, Some(2));
        assert_eq!(sorted_page.items.len(), 1);
        assert_eq!(sorted_page.items[0].host, "zeta.example.test");
        assert!(!sorted_page.has_more);

        let unlimited_sorted_page = store
            .list_page_filtered(&WebSocketListFilters {
                limit: Some(0),
                offset: Some(1),
                sort_key: Some("host".to_string()),
                sort_direction: Some("asc".to_string()),
                ..WebSocketListFilters::default()
            })
            .await;

        assert_eq!(unlimited_sorted_page.filtered_total, Some(2));
        assert_eq!(unlimited_sorted_page.limit, 0);
        assert_eq!(unlimited_sorted_page.items.len(), 1);
        assert_eq!(unlimited_sorted_page.items[0].host, "zeta.example.test");
        assert!(!unlimited_sorted_page.has_more);
    }

    #[tokio::test]
    async fn list_page_filtered_supports_live_only_and_scope_filters() {
        let mut live = session(vec![frame(1)]);
        live.host = "chat.example.test".to_string();

        let mut closed = closed_session(vec![frame(1)]);
        closed.host = "out.example.test".to_string();
        closed.duration_ms = None;

        let store = WebSocketStore::from_sessions(10, 10, vec![live, closed]);

        let live_page = store
            .list_page_filtered(&WebSocketListFilters {
                live_only: true,
                ..WebSocketListFilters::default()
            })
            .await;

        assert_eq!(live_page.filtered_total, Some(1));
        assert_eq!(live_page.items[0].host, "chat.example.test");

        let scope_page = store
            .list_page_filtered(&WebSocketListFilters {
                in_scope_only: true,
                scope_patterns: vec!["chat.example.test".to_string()],
                ..WebSocketListFilters::default()
            })
            .await;

        assert_eq!(scope_page.filtered_total, Some(1));
        assert_eq!(scope_page.items[0].host, "chat.example.test");
    }

    #[tokio::test]
    async fn list_page_filtered_started_at_desc_returns_storage_window_when_monotonic() {
        let base = Utc::now();
        let mut newest = session(vec![frame(1)]);
        newest.host = "newest.example.test".to_string();
        newest.started_at = base;
        let mut middle = session(vec![frame(1)]);
        middle.host = "middle.example.test".to_string();
        middle.started_at = base - chrono::Duration::seconds(10);
        let mut oldest = session(vec![frame(1)]);
        oldest.host = "oldest.example.test".to_string();
        oldest.started_at = base - chrono::Duration::seconds(20);
        let store = WebSocketStore::from_sessions(10, 10, vec![newest, middle, oldest]);

        assert!(store.inner.read().await.started_at_desc_ordered);
        let page = store
            .list_page_filtered(&WebSocketListFilters {
                limit: Some(1),
                offset: Some(1),
                sort_key: Some("started_at".to_string()),
                sort_direction: Some("desc".to_string()),
                ..WebSocketListFilters::default()
            })
            .await;

        assert_eq!(page.total, 3);
        assert_eq!(page.filtered_total, Some(3));
        assert_eq!(page.offset, 1);
        assert_eq!(page.limit, 1);
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].host, "middle.example.test");
        assert!(page.has_more);
    }

    #[tokio::test]
    async fn list_page_filtered_after_id_survives_newer_live_insert_without_duplicate() {
        let base = Utc::now();
        let mut newest = session(vec![frame(1)]);
        newest.host = "newest.example.test".to_string();
        newest.started_at = base;
        let mut middle = session(vec![frame(1)]);
        middle.host = "middle.example.test".to_string();
        middle.started_at = base - chrono::Duration::seconds(10);
        let mut oldest = session(vec![frame(1)]);
        oldest.host = "oldest.example.test".to_string();
        oldest.started_at = base - chrono::Duration::seconds(20);
        let oldest_id = oldest.id;
        let store = WebSocketStore::from_sessions(10, 10, vec![newest, middle, oldest]);

        let first_page = store
            .list_page_filtered(&WebSocketListFilters {
                limit: Some(2),
                sort_key: Some("started_at".to_string()),
                sort_direction: Some("desc".to_string()),
                ..WebSocketListFilters::default()
            })
            .await;
        let after_id = first_page.items.last().expect("cursor row").id;
        let first_page_ids = first_page
            .items
            .iter()
            .map(|summary| summary.id)
            .collect::<Vec<_>>();

        let mut newer = session(vec![frame(1)]);
        newer.host = "newer.example.test".to_string();
        newer.started_at = base + chrono::Duration::seconds(10);
        store.open(newer).await;

        let second_page = store
            .list_page_filtered(&WebSocketListFilters {
                limit: Some(2),
                offset: Some(first_page.items.len()),
                after_id: Some(after_id),
                sort_key: Some("started_at".to_string()),
                sort_direction: Some("desc".to_string()),
                ..WebSocketListFilters::default()
            })
            .await;

        assert_eq!(second_page.items.len(), 1);
        assert_eq!(second_page.items[0].id, oldest_id);
        assert!(second_page
            .items
            .iter()
            .all(|summary| !first_page_ids.contains(&summary.id)));
        assert!(!second_page.has_more);
    }

    #[tokio::test]
    async fn list_page_filtered_after_id_survives_cursor_row_leaving_live_filter() {
        let base = Utc::now();
        let mut newest = session(vec![frame(1)]);
        newest.host = "newest.example.test".to_string();
        newest.started_at = base;
        let mut middle = session(vec![frame(1)]);
        middle.host = "middle.example.test".to_string();
        middle.started_at = base - chrono::Duration::seconds(10);
        let middle_id = middle.id;
        let mut oldest = session(vec![frame(1)]);
        oldest.host = "oldest.example.test".to_string();
        oldest.started_at = base - chrono::Duration::seconds(20);
        let oldest_id = oldest.id;
        let store = WebSocketStore::from_sessions(10, 10, vec![newest, middle, oldest]);

        let first_page = store
            .list_page_filtered(&WebSocketListFilters {
                limit: Some(2),
                live_only: true,
                sort_key: Some("started_at".to_string()),
                sort_direction: Some("desc".to_string()),
                ..WebSocketListFilters::default()
            })
            .await;
        let after_id = first_page.items.last().expect("cursor row").id;
        assert_eq!(after_id, middle_id);

        assert!(store.close(middle_id, Utc::now(), 123, None).await);

        let second_page = store
            .list_page_filtered(&WebSocketListFilters {
                limit: Some(2),
                offset: Some(first_page.items.len()),
                after_id: Some(after_id),
                live_only: true,
                sort_key: Some("started_at".to_string()),
                sort_direction: Some("desc".to_string()),
                ..WebSocketListFilters::default()
            })
            .await;

        assert_eq!(second_page.items.len(), 1);
        assert_eq!(second_page.items[0].id, oldest_id);
        assert!(!second_page.has_more);
    }

    #[tokio::test]
    async fn list_page_filtered_after_id_reports_cursor_offset_without_explicit_offset() {
        let base = Utc::now();
        let mut newest = session(vec![frame(1)]);
        newest.host = "newest.example.test".to_string();
        newest.started_at = base;
        let mut middle = session(vec![frame(1)]);
        middle.host = "middle.example.test".to_string();
        middle.started_at = base - chrono::Duration::seconds(10);
        let mut oldest = session(vec![frame(1)]);
        oldest.host = "oldest.example.test".to_string();
        oldest.started_at = base - chrono::Duration::seconds(20);
        let oldest_id = oldest.id;
        let store = WebSocketStore::from_sessions(10, 10, vec![newest, middle, oldest]);

        let first_page = store
            .list_page_filtered(&WebSocketListFilters {
                limit: Some(2),
                live_only: true,
                sort_key: Some("started_at".to_string()),
                sort_direction: Some("desc".to_string()),
                ..WebSocketListFilters::default()
            })
            .await;
        let after_id = first_page.items.last().expect("cursor row").id;

        let second_page = store
            .list_page_filtered(&WebSocketListFilters {
                limit: Some(2),
                after_id: Some(after_id),
                live_only: true,
                sort_key: Some("started_at".to_string()),
                sort_direction: Some("desc".to_string()),
                ..WebSocketListFilters::default()
            })
            .await;

        assert_eq!(second_page.offset, 2);
        assert_eq!(second_page.items.len(), 1);
        assert_eq!(second_page.items[0].id, oldest_id);
        assert!(!second_page.has_more);
    }

    #[tokio::test]
    async fn list_page_filtered_started_at_desc_falls_back_when_storage_order_is_not_monotonic() {
        let base = Utc::now();
        let mut newest = session(vec![frame(1)]);
        newest.host = "newest.example.test".to_string();
        newest.started_at = base;
        let mut middle = session(vec![frame(1)]);
        middle.host = "middle.example.test".to_string();
        middle.started_at = base - chrono::Duration::seconds(10);
        let mut oldest = session(vec![frame(1)]);
        oldest.host = "oldest.example.test".to_string();
        oldest.started_at = base - chrono::Duration::seconds(20);
        let store = WebSocketStore::from_sessions(10, 10, vec![newest, oldest, middle]);

        assert!(!store.inner.read().await.started_at_desc_ordered);
        let page = store
            .list_page_filtered(&WebSocketListFilters {
                limit: Some(3),
                sort_key: Some("started_at".to_string()),
                sort_direction: Some("desc".to_string()),
                ..WebSocketListFilters::default()
            })
            .await;

        assert_eq!(
            page.items
                .iter()
                .map(|summary| summary.host.as_str())
                .collect::<Vec<_>>(),
            vec![
                "newest.example.test",
                "middle.example.test",
                "oldest.example.test"
            ]
        );
    }

    #[tokio::test]
    async fn list_page_filtered_after_id_applies_after_fallback_sort() {
        let base = Utc::now();
        let mut newest = session(vec![frame(1)]);
        newest.host = "newest.example.test".to_string();
        newest.started_at = base;
        let mut middle = session(vec![frame(1)]);
        middle.host = "middle.example.test".to_string();
        middle.started_at = base - chrono::Duration::seconds(10);
        let mut oldest = session(vec![frame(1)]);
        oldest.host = "oldest.example.test".to_string();
        oldest.started_at = base - chrono::Duration::seconds(20);
        let oldest_id = oldest.id;
        let store = WebSocketStore::from_sessions(10, 10, vec![newest, oldest, middle]);

        let first_page = store
            .list_page_filtered(&WebSocketListFilters {
                limit: Some(2),
                sort_key: Some("started_at".to_string()),
                sort_direction: Some("desc".to_string()),
                ..WebSocketListFilters::default()
            })
            .await;
        let after_id = first_page.items.last().expect("cursor row").id;
        let first_page_ids = first_page
            .items
            .iter()
            .map(|summary| summary.id)
            .collect::<Vec<_>>();

        let mut newer = session(vec![frame(1)]);
        newer.host = "newer.example.test".to_string();
        newer.started_at = base + chrono::Duration::seconds(10);
        store.open(newer).await;

        let second_page = store
            .list_page_filtered(&WebSocketListFilters {
                limit: Some(2),
                offset: Some(first_page.items.len()),
                after_id: Some(after_id),
                sort_key: Some("started_at".to_string()),
                sort_direction: Some("desc".to_string()),
                ..WebSocketListFilters::default()
            })
            .await;

        assert_eq!(second_page.items.len(), 1);
        assert_eq!(second_page.items[0].id, oldest_id);
        assert!(second_page
            .items
            .iter()
            .all(|summary| !first_page_ids.contains(&summary.id)));
        assert!(!second_page.has_more);
    }

    #[tokio::test]
    async fn open_marks_started_at_desc_order_dirty_for_out_of_order_session() {
        let base = Utc::now();
        let mut newest = session(vec![frame(1)]);
        newest.started_at = base;
        let mut older = session(vec![frame(1)]);
        older.started_at = base - chrono::Duration::seconds(10);
        let store = WebSocketStore::from_sessions(10, 10, vec![newest]);

        store.open(older).await;

        assert!(!store.inner.read().await.started_at_desc_ordered);
    }

    #[tokio::test]
    async fn open_recomputes_started_at_desc_order_after_retention_removes_dirty_record() {
        let base = Utc::now();
        let mut newest = session(vec![frame(1)]);
        newest.started_at = base;
        let mut older = closed_session(vec![frame(1)]);
        older.started_at = base - chrono::Duration::seconds(10);
        let mut future = session(vec![frame(1)]);
        future.started_at = base + chrono::Duration::seconds(10);
        let store = WebSocketStore::from_sessions(2, 10, vec![newest]);

        store.open(older).await;
        assert!(!store.inner.read().await.started_at_desc_ordered);
        store.open(future).await;

        assert!(store.inner.read().await.started_at_desc_ordered);
    }

    #[tokio::test]
    async fn list_page_filtered_index_sort_keeps_desc_newest_first() {
        let mut newest = session(vec![frame(1)]);
        newest.host = "newest.example.test".to_string();
        let mut middle = session(vec![frame(1)]);
        middle.host = "middle.example.test".to_string();
        let mut oldest = session(vec![frame(1)]);
        oldest.host = "oldest.example.test".to_string();
        let store = WebSocketStore::from_sessions(10, 10, vec![newest, middle, oldest]);

        let desc = store
            .list_page_filtered(&WebSocketListFilters {
                sort_key: Some("index".to_string()),
                sort_direction: Some("desc".to_string()),
                ..WebSocketListFilters::default()
            })
            .await;
        let asc = store
            .list_page_filtered(&WebSocketListFilters {
                sort_key: Some("index".to_string()),
                sort_direction: Some("asc".to_string()),
                ..WebSocketListFilters::default()
            })
            .await;

        assert_eq!(desc.items[0].host, "newest.example.test");
        assert_eq!(desc.items[2].host, "oldest.example.test");
        assert_eq!(
            desc.items
                .iter()
                .map(|item| item.sequence)
                .collect::<Vec<_>>(),
            vec![3, 2, 1]
        );
        assert_eq!(asc.items[0].host, "oldest.example.test");
        assert_eq!(asc.items[2].host, "newest.example.test");
        assert_eq!(
            asc.items
                .iter()
                .map(|item| item.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[tokio::test]
    async fn index_sort_preserves_capture_sequence_after_retention_trim() {
        let mut first = closed_session(vec![frame(1)]);
        first.host = "first.example.test".to_string();
        let mut second = closed_session(vec![frame(1)]);
        second.host = "second.example.test".to_string();
        let mut third = closed_session(vec![frame(1)]);
        third.host = "third.example.test".to_string();
        let store = WebSocketStore::new(2, 10);

        store.open(first).await;
        store.open(second).await;
        store.open(third).await;

        let desc = store
            .list_page_filtered(&WebSocketListFilters {
                sort_key: Some("index".to_string()),
                sort_direction: Some("desc".to_string()),
                ..WebSocketListFilters::default()
            })
            .await;
        let asc = store
            .list_page_filtered(&WebSocketListFilters {
                sort_key: Some("index".to_string()),
                sort_direction: Some("asc".to_string()),
                ..WebSocketListFilters::default()
            })
            .await;

        assert_eq!(
            desc.items
                .iter()
                .map(|item| (item.host.as_str(), item.sequence))
                .collect::<Vec<_>>(),
            vec![("third.example.test", 3), ("second.example.test", 2)]
        );
        assert_eq!(
            asc.items
                .iter()
                .map(|item| (item.host.as_str(), item.sequence))
                .collect::<Vec<_>>(),
            vec![("second.example.test", 2), ("third.example.test", 3)]
        );
    }

    #[tokio::test]
    async fn from_sessions_trims_restored_frames_to_cap() {
        let store =
            WebSocketStore::from_sessions(10, 2, vec![session(vec![frame(1), frame(2), frame(3)])]);

        let restored = store.snapshot(None).await;

        assert_eq!(restored[0].frames.len(), 2);
        assert_eq!(restored[0].frames[0].index, 2);
        assert_eq!(restored[0].frames[1].index, 3);
    }

    #[tokio::test]
    async fn from_sessions_normalizes_oversized_restored_frame_previews() {
        let mut restored_frame = frame(1);
        restored_frame.body_preview = "x".repeat(WEBSOCKET_CAPTURE_PREVIEW_BYTES + 1);
        restored_frame.body_size = restored_frame.body_preview.len();
        restored_frame.preview_truncated = false;
        let store = WebSocketStore::from_sessions(10, 10, vec![session(vec![restored_frame])]);

        let restored = store.snapshot(None).await;
        let frame = &restored[0].frames[0];

        assert_eq!(frame.body_preview.len(), WEBSOCKET_CAPTURE_PREVIEW_BYTES);
        assert!(frame.preview_truncated);
    }

    #[tokio::test]
    async fn open_trims_initial_frames_to_cap() {
        let store = WebSocketStore::new(10, 2);

        store
            .open(session(vec![frame(0), frame(1), frame(2)]))
            .await;

        let restored = store.snapshot(None).await;
        assert_eq!(
            restored[0]
                .frames
                .iter()
                .map(|frame| frame.index)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        let page = store.list_page(Some(10), None).await;
        assert_eq!(page.items[0].frame_count, 3);
        assert_eq!(page.items[0].retained_frame_count, 2);
        assert_eq!(page.items[0].last_frame_index, Some(2));
    }

    #[tokio::test]
    async fn get_windowed_returns_only_requested_tail_frames() {
        let record = session(vec![frame(0), frame(1), frame(2), frame(3)]);
        let record_id = record.id;
        let store = WebSocketStore::from_sessions(10, 10, vec![record]);

        let detail = store.get_windowed(record_id, Some(2), None).await.unwrap();

        assert_eq!(
            detail
                .frames
                .iter()
                .map(|frame| frame.index)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );

        let older_detail = store
            .get_windowed(record_id, Some(2), Some(2))
            .await
            .unwrap();
        assert_eq!(
            older_detail
                .frames
                .iter()
                .map(|frame| frame.index)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );

        let exhausted_detail = store
            .get_windowed(record_id, Some(2), Some(0))
            .await
            .unwrap();
        assert!(exhausted_detail.frames.is_empty());
    }

    #[tokio::test]
    async fn summary_tracks_last_retained_frame_index_after_frame_cap() {
        let record = session(vec![frame(0), frame(1)]);
        let record_id = record.id;
        let store = WebSocketStore::from_sessions(10, 2, vec![record]);

        assert!(store.append_frame(record_id, frame(2)).await);

        let page = store.list_page(Some(10), None).await;
        let summary = &page.items[0];
        assert_eq!(summary.frame_count, 3);
        assert_eq!(summary.retained_frame_count, 2);
        assert_eq!(summary.last_frame_index, Some(2));
    }

    #[tokio::test]
    async fn append_frame_tracks_total_count_when_retention_cap_is_zero() {
        let record = session(Vec::new());
        let record_id = record.id;
        let store = WebSocketStore::from_sessions(10, 0, vec![record]);

        assert!(store.append_frame(record_id, frame(0)).await);

        let summary = &store.list_page(Some(10), None).await.items[0];
        assert_eq!(summary.frame_count, 1);
        assert_eq!(summary.retained_frame_count, 0);
        assert_eq!(summary.last_frame_index, None);
    }

    #[tokio::test]
    async fn append_frame_caps_with_tail_order_after_many_overflow_frames() {
        let record = session(Vec::new());
        let record_id = record.id;
        let store = WebSocketStore::from_sessions(10, 3, vec![record]);

        for index in 0..10 {
            assert!(store.append_frame(record_id, frame(index)).await);
        }

        let stored = store.get(record_id).await.unwrap();
        assert_eq!(
            stored
                .frames
                .iter()
                .map(|frame| frame.index)
                .collect::<Vec<_>>(),
            vec![7, 8, 9]
        );
        let summary = &store.list_page(Some(10), None).await.items[0];
        assert_eq!(summary.frame_count, 10);
        assert_eq!(summary.retained_frame_count, 3);
        assert_eq!(summary.last_frame_index, Some(9));
    }

    #[tokio::test]
    async fn snapshot_materializes_vec_frames_in_wire_order() {
        let store = WebSocketStore::new(10, 3);
        store
            .open(session(vec![frame(1), frame(2), frame(3)]))
            .await;

        let snapshot = store.snapshot(None).await;
        let raw = serde_json::to_string(&snapshot).unwrap();
        assert!(raw.contains("\"frames\""));
        assert!(!raw.contains("\"order\""));
        assert!(!raw.contains("\"sessions\""));

        let value = serde_json::to_value(&snapshot[0]).unwrap();
        assert!(value["frames"].is_array());

        let round_trip: WebSocketSessionRecord = serde_json::from_value(value).unwrap();
        assert_eq!(
            round_trip
                .frames
                .iter()
                .map(|frame| frame.index)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[tokio::test]
    async fn snapshot_with_frame_limit_persists_only_tail_frames() {
        let store = WebSocketStore::new(10, 10);
        store
            .open(session(vec![
                frame(1),
                frame(2),
                frame(3),
                frame(4),
                frame(5),
            ]))
            .await;

        let snapshot = store.snapshot_with_frame_limit(None, Some(2)).await;

        assert_eq!(
            snapshot[0]
                .frames
                .iter()
                .map(|frame| frame.index)
                .collect::<Vec<_>>(),
            vec![4, 5]
        );
        assert_eq!(store.get(snapshot[0].id).await.unwrap().frames.len(), 5);
    }

    #[tokio::test]
    async fn reopening_same_session_id_replaces_ordered_entry() {
        let first = session(vec![frame(1)]);
        let first_id = first.id;
        let mut replacement = session(vec![frame(2)]);
        replacement.id = first_id;
        replacement.host = "replacement.example".to_string();
        let store = WebSocketStore::new(10, 10);

        store.open(first).await;
        store.open(replacement).await;

        let page = store.list_page(Some(10), None).await;
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].host, "replacement.example");
        let stored = store.get(first_id).await.unwrap();
        assert_eq!(stored.frames[0].index, 2);
    }

    #[tokio::test]
    async fn list_page_returns_offset_window_without_resending_prefix() {
        let store = WebSocketStore::new(10, 10);
        let first = session(Vec::new());
        let second = session(Vec::new());
        let second_id = second.id;
        let third = session(Vec::new());

        store.open(first).await;
        store.open(second).await;
        store.open(third).await;

        let page = store.list_page(Some(1), Some(1)).await;

        assert_eq!(page.total, 3);
        assert_eq!(page.offset, 1);
        assert_eq!(page.limit, 1);
        assert!(page.has_more);
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].id, second_id);
    }

    #[tokio::test]
    async fn list_page_limit_zero_returns_all_unfiltered_items_after_offset() {
        let store = WebSocketStore::new(10, 10);
        let first = session(Vec::new());
        let first_id = first.id;
        let second = session(Vec::new());
        let second_id = second.id;
        let third = session(Vec::new());

        store.open(first).await;
        store.open(second).await;
        store.open(third).await;

        let page = store.list_page(Some(0), Some(1)).await;

        assert_eq!(page.total, 3);
        assert_eq!(page.offset, 1);
        assert_eq!(page.limit, 0);
        assert!(!page.has_more);
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.items[0].id, second_id);
        assert_eq!(page.items[1].id, first_id);
    }

    #[tokio::test]
    async fn list_page_limit_zero_returns_all_filtered_items_after_offset() {
        let store = WebSocketStore::new(10, 10);
        let mut first = session(Vec::new());
        first.host = "first.example.test".to_string();
        let first_id = first.id;
        let mut second = session(Vec::new());
        second.host = "second.example.test".to_string();
        let second_id = second.id;
        let mut third = session(Vec::new());
        third.host = "third.example.test".to_string();

        store.open(first).await;
        store.open(second).await;
        store.open(third).await;

        let page = store
            .list_page_filtered(&WebSocketListFilters {
                query: Some("example.test".to_string()),
                limit: Some(0),
                offset: Some(1),
                ..WebSocketListFilters::default()
            })
            .await;

        assert_eq!(page.total, 3);
        assert_eq!(page.offset, 1);
        assert_eq!(page.limit, 0);
        assert_eq!(page.filtered_total, Some(3));
        assert!(!page.has_more);
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.items[0].id, second_id);
        assert_eq!(page.items[1].id, first_id);
    }

    #[tokio::test]
    async fn open_preserves_live_sessions_when_all_entries_are_live() {
        let store = WebSocketStore::new(1, 10);
        let first = session(Vec::new());
        let first_id = first.id;
        store.open(first).await;

        let second = session(Vec::new());
        let second_id = second.id;
        store.open(second).await;

        assert!(store.get(first_id).await.is_some());
        assert!(store.get(second_id).await.is_some());
        assert!(store.append_frame(first_id, frame(1)).await);
        assert!(
            store
                .close(first_id, Utc::now(), 10, Some("closed".to_string()))
                .await
        );

        let snapshot = store.snapshot(Some(10)).await;
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].id, second_id);
        assert_eq!(store.list_page(Some(10), None).await.total, 1);
    }

    #[tokio::test]
    async fn from_sessions_does_not_preallocate_full_retention_for_empty_restore() {
        let store = WebSocketStore::from_sessions(500_000, 10, Vec::new());

        assert_eq!(store.inner.read().await.order.capacity(), 0);
    }

    #[tokio::test]
    async fn snapshot_preserves_live_sessions_past_limit() {
        let store = WebSocketStore::new(1, 10);
        let first = session(vec![frame(1)]);
        let first_id = first.id;
        let second = session(Vec::new());
        let second_id = second.id;
        store.open(first).await;
        store.open(second).await;

        let snapshot = store.snapshot(Some(1)).await;

        assert_eq!(snapshot.len(), 2);
        assert!(snapshot.iter().any(|session| session.id == first_id));
        assert!(snapshot.iter().any(|session| session.id == second_id));
    }

    #[tokio::test]
    async fn replace_all_preserves_live_sessions_past_limit() {
        let first = session(vec![frame(1)]);
        let first_id = first.id;
        let second = session(Vec::new());
        let second_id = second.id;
        let store = WebSocketStore::from_sessions(1, 10, vec![second, first]);

        let snapshot = store.snapshot(Some(1)).await;

        assert_eq!(snapshot.len(), 2);
        assert!(snapshot.iter().any(|session| session.id == first_id));
        assert!(snapshot.iter().any(|session| session.id == second_id));
    }

    #[tokio::test]
    async fn open_evicts_oldest_closed_session_first() {
        let store = WebSocketStore::new(2, 10);
        let closed = closed_session(Vec::new());
        let closed_id = closed.id;
        store.open(closed).await;

        let live = session(Vec::new());
        let live_id = live.id;
        store.open(live).await;
        store.open(session(Vec::new())).await;

        let snapshot = store.snapshot(None).await;
        assert_eq!(snapshot.len(), 2);
        assert!(!snapshot.iter().any(|session| session.id == closed_id));
        assert!(snapshot.iter().any(|session| session.id == live_id));
    }

    #[tokio::test]
    async fn open_notifies_retention_when_overflow_removes_session() {
        let store = WebSocketStore::new(1, 10);
        let closed = closed_session(Vec::new());
        let closed_id = closed.id;
        store.open(closed).await;
        let mut retention_events = store.subscribe_retention();

        let live = session(Vec::new());
        let live_id = live.id;
        store.open(live).await;

        assert!(retention_events.try_recv().is_ok());
        assert!(store.get(closed_id).await.is_none());
        assert!(store.get(live_id).await.is_some());
    }
}
