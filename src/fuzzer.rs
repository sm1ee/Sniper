use std::{collections::VecDeque, error::Error as StdError, fmt, sync::LazyLock};

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use regex::{NoExpand, Regex};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

const FUZZER_PAYLOAD_MARKER: &str = "$payload$";
const MAX_FUZZER_PAYLOADS: usize = 5_000;
const MAX_FUZZER_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_FUZZER_TOTAL_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
const MAX_FUZZER_MARKERS_PER_REQUEST: usize = 128;
const MAX_FUZZER_EXPANDED_REQUEST_BYTES: usize = 4 * 1024 * 1024;

static MARKER_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(regex::escape(FUZZER_PAYLOAD_MARKER).as_str()).expect("valid marker regex")
});

use crate::{
    event_log::{EventLevel, EventLogEntry},
    model::{EditableRequest, RequestTargetOverride},
    proxy,
    state::AppState,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzerAttackStatus {
    Completed,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FuzzerAttackResult {
    #[serde(default)]
    pub index: usize,
    #[serde(default)]
    pub payload: String,
    pub transaction_id: Option<Uuid>,
    pub status: Option<u16>,
    pub duration_ms: Option<u64>,
    #[serde(default)]
    pub response_bytes: usize,
    pub note: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FuzzerAttackRecord {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub status: FuzzerAttackStatus,
    pub template: EditableRequest,
    #[serde(default)]
    pub payload_count: usize,
    #[serde(default)]
    pub marker_count: usize,
    #[serde(default)]
    pub results: Vec<FuzzerAttackResult>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FuzzerAttackSummary {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub status: FuzzerAttackStatus,
    pub host: String,
    pub path: String,
    pub payload_count: usize,
    pub result_count: usize,
}

#[derive(Clone, Debug, Deserialize)]
pub struct FuzzerAttackPayload {
    pub session_id: Option<Uuid>,
    #[serde(default)]
    pub expected_active_session_id: Option<Uuid>,
    #[serde(default)]
    pub expected_workspace_revision: Option<u64>,
    pub template: EditableRequest,
    pub payloads: Vec<String>,
    pub source_transaction_id: Option<Uuid>,
    pub http_version: Option<String>,
    pub target: Option<RequestTargetOverride>,
}

#[derive(Debug)]
pub struct FuzzerPersistenceError {
    source: anyhow::Error,
}

impl FuzzerPersistenceError {
    pub(crate) fn new(source: anyhow::Error) -> Self {
        Self { source }
    }
}

impl fmt::Display for FuzzerPersistenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "fuzzer attack completed but failed to persist session: {}",
            self.source
        )
    }
}

impl StdError for FuzzerPersistenceError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source.source()
    }
}

pub struct FuzzerStore {
    max_entries: usize,
    attacks: RwLock<VecDeque<FuzzerAttackRecord>>,
}

impl FuzzerStore {
    pub fn new(max_entries: usize) -> Self {
        Self::from_attacks(max_entries, Vec::new())
    }

    pub fn from_attacks(max_entries: usize, records: Vec<FuzzerAttackRecord>) -> Self {
        let mut attacks = VecDeque::with_capacity(records.len().min(max_entries));
        attacks.extend(records.into_iter().take(max_entries));
        Self {
            max_entries,
            attacks: RwLock::new(attacks),
        }
    }

    pub async fn insert(&self, record: FuzzerAttackRecord) -> Vec<FuzzerAttackRecord> {
        let mut attacks = self.attacks.write().await;
        attacks.push_front(record);
        let mut evicted = Vec::new();
        while attacks.len() > self.max_entries {
            if let Some(record) = attacks.pop_back() {
                evicted.push(record);
            }
        }
        evicted
    }

    pub async fn list(&self, limit: Option<usize>) -> Vec<FuzzerAttackSummary> {
        self.attacks
            .read()
            .await
            .iter()
            .take(limit.unwrap_or(self.max_entries).min(self.max_entries))
            .map(FuzzerAttackRecord::summary)
            .collect()
    }

    pub async fn get(&self, id: Uuid) -> Option<FuzzerAttackRecord> {
        self.attacks
            .read()
            .await
            .iter()
            .find(|attack| attack.id == id)
            .cloned()
    }

    pub async fn snapshot(&self, limit: Option<usize>) -> Vec<FuzzerAttackRecord> {
        self.attacks
            .read()
            .await
            .iter()
            .take(limit.unwrap_or(self.max_entries).min(self.max_entries))
            .cloned()
            .collect()
    }

    pub async fn len(&self) -> usize {
        self.attacks.read().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.attacks.read().await.is_empty()
    }

    pub async fn replace_all(&self, records: Vec<FuzzerAttackRecord>) {
        let mut attacks = self.attacks.write().await;
        attacks.clear();
        attacks.extend(records.into_iter().take(self.max_entries));
    }

    pub async fn remove_and_restore(&self, id: Uuid, restore: Vec<FuzzerAttackRecord>) -> bool {
        let mut attacks = self.attacks.write().await;
        let before = attacks.len();
        attacks.retain(|attack| attack.id != id);
        let removed = attacks.len() < before;
        if removed {
            for record in restore {
                if attacks.len() >= self.max_entries {
                    break;
                }
                attacks.push_back(record);
            }
        }
        removed
    }
}

impl FuzzerAttackRecord {
    pub fn summary(&self) -> FuzzerAttackSummary {
        FuzzerAttackSummary {
            id: self.id,
            started_at: self.started_at,
            completed_at: self.completed_at,
            status: self.status.clone(),
            host: self.template.host.clone(),
            path: self.template.path.clone(),
            payload_count: self.payload_count,
            result_count: self.results.len(),
        }
    }
}

pub async fn run_attack(
    state: std::sync::Arc<AppState>,
    template: EditableRequest,
    payloads: Vec<String>,
    source_transaction_id: Option<Uuid>,
    http_version: Option<String>,
    target: Option<RequestTargetOverride>,
) -> Result<FuzzerAttackRecord> {
    let session = state.session().await;
    run_attack_for_session(
        state,
        session,
        template,
        payloads,
        source_transaction_id,
        http_version,
        target,
    )
    .await
}

pub async fn run_attack_for_session(
    state: std::sync::Arc<AppState>,
    session: std::sync::Arc<crate::session::SessionContext>,
    template: EditableRequest,
    payloads: Vec<String>,
    source_transaction_id: Option<Uuid>,
    http_version: Option<String>,
    target: Option<RequestTargetOverride>,
) -> Result<FuzzerAttackRecord> {
    let started_at = Utc::now();
    let marker_count = count_request_markers(&template);
    if marker_count == 0 {
        return Err(anyhow!("Request template is missing $payload$ markers."));
    }
    validate_marker_count(marker_count)?;

    let normalized_payloads = normalize_payloads(payloads);
    if normalized_payloads.is_empty() {
        return Err(anyhow!("Fuzzer needs at least one payload"));
    }
    validate_fuzzer_payloads(&normalized_payloads)?;
    validate_fuzzer_expanded_request_budget(&template, &normalized_payloads)?;

    let (started_event, started_evicted_events) = session
        .event_log
        .push_with_evicted(
            EventLevel::Info,
            "fuzzer",
            "Attack started",
            format!(
                "Running {} payload(s) against {}{}",
                normalized_payloads.len(),
                template.host,
                template.path
            ),
        )
        .await;

    let mut results = Vec::with_capacity(normalized_payloads.len());
    let mut notes = Vec::new();
    let mut failed = false;

    for (index, payload) in normalized_payloads.iter().enumerate() {
        let request = apply_payload_to_request(&template, payload)?;
        match proxy::try_send_replay_request_for_session(
            state.clone(),
            session.clone(),
            request,
            target.clone(),
            source_transaction_id,
            http_version.clone(),
        )
        .await
        {
            Ok(record) => {
                results.push(FuzzerAttackResult {
                    index,
                    payload: payload.clone(),
                    transaction_id: Some(record.id),
                    status: record.status,
                    duration_ms: Some(record.duration_ms),
                    response_bytes: record
                        .response
                        .as_ref()
                        .map_or(0, |response| response.body_size),
                    note: None,
                });
            }
            Err(error) => {
                failed = true;
                let message = error.to_string();
                let record = error.record();
                notes.push(message.clone());
                results.push(FuzzerAttackResult {
                    index,
                    payload: payload.clone(),
                    transaction_id: record.map(|record| record.id),
                    status: record.and_then(|record| record.status),
                    duration_ms: record.map(|record| record.duration_ms),
                    response_bytes: record
                        .and_then(|record| record.response.as_ref())
                        .map_or(0, |response| response.body_size),
                    note: Some(message),
                });
            }
        }
    }

    let completed_at = Utc::now();
    let record = FuzzerAttackRecord {
        id: Uuid::new_v4(),
        started_at,
        completed_at,
        status: if failed {
            FuzzerAttackStatus::Failed
        } else {
            FuzzerAttackStatus::Completed
        },
        template: template.clone(),
        payload_count: normalized_payloads.len(),
        marker_count,
        results,
        notes,
    };

    let _mutation_guard = session.mutation_guard().await;
    let evicted_attacks = session.fuzzer.insert(record.clone()).await;
    let (completed_event, evicted_events) = session
        .event_log
        .push_with_evicted(
            EventLevel::Info,
            "fuzzer",
            "Attack completed",
            format!(
                "Completed {} payload(s) against {}{}",
                record.payload_count, template.host, template.path
            ),
        )
        .await;
    if let Err(error) = state
        .persist_session_context_mutation_locked(&session)
        .await
    {
        rollback_failed_fuzzer_persist(
            &session,
            record.id,
            evicted_attacks,
            completed_event.id,
            evicted_events,
            started_event.id,
            started_evicted_events,
        )
        .await;
        if let Err(rollback_error) = state
            .persist_session_context_mutation_locked(&session)
            .await
        {
            tracing::warn!(
                ?rollback_error,
                session_id = %session.id(),
                "failed to persist rolled back fuzzer state after attack persist failure"
            );
        }
        return Err(FuzzerPersistenceError::new(error).into());
    }

    Ok(record)
}

async fn rollback_failed_fuzzer_persist(
    session: &std::sync::Arc<crate::session::SessionContext>,
    attack_id: Uuid,
    evicted_attacks: Vec<FuzzerAttackRecord>,
    completed_event_id: Uuid,
    evicted_events: Vec<EventLogEntry>,
    started_event_id: Uuid,
    started_evicted_events: Vec<EventLogEntry>,
) {
    session
        .fuzzer
        .remove_and_restore(attack_id, evicted_attacks)
        .await;
    session
        .event_log
        .remove_and_restore(completed_event_id, evicted_events)
        .await;
    session
        .event_log
        .remove_and_restore(started_event_id, started_evicted_events)
        .await;
}

fn count_request_markers(request: &EditableRequest) -> usize {
    let mut count = count_markers(&request.method)
        + count_markers(&request.path)
        + count_markers(&request.body);
    if !has_literal_host_header(request) {
        count += count_markers(&request.host);
    }
    for header in &request.headers {
        count += count_markers(&header.name);
        count += count_markers(&header.value);
    }
    count
}

fn has_literal_host_header(request: &EditableRequest) -> bool {
    request
        .headers
        .iter()
        .any(|header| header.name.eq_ignore_ascii_case("host"))
}

fn validate_marker_count(marker_count: usize) -> Result<()> {
    if marker_count > MAX_FUZZER_MARKERS_PER_REQUEST {
        return Err(anyhow!(
            "Fuzzer request templates cannot contain more than {MAX_FUZZER_MARKERS_PER_REQUEST} $payload$ markers"
        ));
    }
    Ok(())
}

fn validate_fuzzer_payloads(payloads: &[String]) -> Result<()> {
    if payloads.len() > MAX_FUZZER_PAYLOADS {
        return Err(anyhow!(
            "Fuzzer payload count cannot exceed {MAX_FUZZER_PAYLOADS}"
        ));
    }

    let mut total_bytes = 0usize;
    for (index, payload) in payloads.iter().enumerate() {
        let payload_bytes = payload.len();
        if payload_bytes > MAX_FUZZER_PAYLOAD_BYTES {
            return Err(anyhow!(
                "Fuzzer payload {index} cannot exceed {MAX_FUZZER_PAYLOAD_BYTES} bytes"
            ));
        }
        total_bytes = total_bytes.saturating_add(payload_bytes);
        if total_bytes > MAX_FUZZER_TOTAL_PAYLOAD_BYTES {
            return Err(anyhow!(
                "Fuzzer payloads cannot exceed {MAX_FUZZER_TOTAL_PAYLOAD_BYTES} total bytes"
            ));
        }
    }
    Ok(())
}

fn validate_fuzzer_expanded_request_budget(
    template: &EditableRequest,
    payloads: &[String],
) -> Result<()> {
    for (index, payload) in payloads.iter().enumerate() {
        let request_bytes = expanded_request_size(template, payload.len());
        if request_bytes > MAX_FUZZER_EXPANDED_REQUEST_BYTES {
            return Err(anyhow!(
                "Fuzzer payload {index} expands the request to {request_bytes} bytes, above the {MAX_FUZZER_EXPANDED_REQUEST_BYTES} byte limit"
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_expanded_requests<F>(
    template: &EditableRequest,
    payloads: &[String],
    mut validate_request: F,
) -> Result<()>
where
    F: FnMut(&EditableRequest) -> std::result::Result<(), String>,
{
    let marker_count = count_request_markers(template);
    if marker_count == 0 {
        return Err(anyhow!("Request template is missing $payload$ markers."));
    }
    validate_marker_count(marker_count)?;

    let normalized_payloads = normalize_payloads(payloads.to_vec());
    if normalized_payloads.is_empty() {
        return Err(anyhow!("Fuzzer needs at least one payload"));
    }
    validate_fuzzer_payloads(&normalized_payloads)?;
    validate_fuzzer_expanded_request_budget(template, &normalized_payloads)?;

    for (index, payload) in normalized_payloads.iter().enumerate() {
        let request = apply_payload_to_request(template, payload)?;
        if let Err(error) = validate_request(&request) {
            return Err(anyhow!(
                "Fuzzer payload {index} expands to an invalid request: {error}"
            ));
        }
    }

    Ok(())
}

fn expanded_request_size(template: &EditableRequest, payload_len: usize) -> usize {
    let host_bytes = if has_literal_host_header(template) {
        template.host.len()
    } else {
        expanded_value_len(&template.host, payload_len)
    };
    let mut bytes = expanded_value_len(&template.scheme, payload_len)
        .saturating_add(host_bytes)
        .saturating_add(expanded_value_len(&template.method, payload_len))
        .saturating_add(expanded_value_len(&template.path, payload_len))
        .saturating_add(expanded_value_len(&template.body, payload_len));

    for header in &template.headers {
        bytes = bytes
            .saturating_add(expanded_value_len(&header.name, payload_len))
            .saturating_add(expanded_value_len(&header.value, payload_len));
    }
    bytes
}

fn expanded_value_len(value: &str, payload_len: usize) -> usize {
    let marker_count = count_markers(value);
    value
        .len()
        .saturating_sub(marker_count.saturating_mul(FUZZER_PAYLOAD_MARKER.len()))
        .saturating_add(marker_count.saturating_mul(payload_len))
}

fn apply_payload_to_request(template: &EditableRequest, payload: &str) -> Result<EditableRequest> {
    let mut request = template.clone();
    if !has_literal_host_header(&request) {
        request.host = replace_markers(&request.host, payload)?;
    }
    request.method = replace_markers(&request.method, payload)?;
    request.path = replace_markers(&request.path, payload)?;
    request.body = replace_markers(&request.body, payload)?;
    for header in &mut request.headers {
        header.name = replace_markers(&header.name, payload)?;
        header.value = replace_markers(&header.value, payload)?;
    }
    if let Some(host) = request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("host"))
        .map(|header| header.value.clone())
    {
        request.host = host;
    }
    request.normalize_content_length();
    Ok(request)
}

fn normalize_payloads(payloads: Vec<String>) -> Vec<String> {
    payloads
        .into_iter()
        .map(|payload| payload.strip_suffix('\r').unwrap_or(&payload).to_string())
        .collect()
}

fn count_markers(value: &str) -> usize {
    MARKER_REGEX.find_iter(value).count()
}

fn replace_markers(value: &str, payload: &str) -> Result<String> {
    if MARKER_REGEX.is_match(value) {
        return Ok(MARKER_REGEX
            .replace_all(value, NoExpand(payload))
            .into_owned());
    }
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::AppConfig,
        model::{BodyEncoding, HeaderRecord},
        state::AppState,
    };
    use std::sync::Arc;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[test]
    fn counts_and_replaces_payload_markers() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            method: "$payload$".to_string(),
            path: "/items/$payload$".to_string(),
            headers: vec![HeaderRecord {
                name: "x-test".to_string(),
                value: "$payload$".to_string(),
            }],
            body: "{\"id\":\"$payload$\"}".to_string(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };

        assert_eq!(count_request_markers(&request), 4);
        let applied = apply_payload_to_request(&request, "abc").unwrap();
        assert_eq!(applied.method, "abc");
        assert_eq!(applied.path, "/items/abc");
        assert_eq!(applied.headers[0].value, "abc");
        assert_eq!(applied.body, "{\"id\":\"abc\"}");

        let applied = apply_payload_to_request(&request, " admin ").unwrap();
        assert_eq!(applied.path, "/items/ admin ");
        assert_eq!(applied.headers[0].value, " admin ");
    }

    #[test]
    fn fuzzer_normalizes_content_length_after_body_payload_expansion() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            method: "POST".to_string(),
            path: "/search".to_string(),
            headers: vec![HeaderRecord {
                name: "Content-Length".to_string(),
                value: "11".to_string(),
            }],
            body: "q=$payload$".to_string(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };

        let applied = apply_payload_to_request(&request, "abcd").unwrap();

        assert_eq!(applied.body, "q=abcd");
        assert_eq!(
            applied
                .headers
                .iter()
                .find(|header| header.name.eq_ignore_ascii_case("content-length"))
                .map(|header| header.value.as_str()),
            Some("6")
        );
        validate_expanded_requests(
            &request,
            &["abcd".to_string()],
            crate::api::validate_editable_request,
        )
        .unwrap();
    }

    #[test]
    fn replaces_payload_markers_without_expanding_dollar_syntax() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "$payload$.example.com".to_string(),
            method: "POST".to_string(),
            path: "/search/$payload$".to_string(),
            headers: vec![HeaderRecord {
                name: "x-payload".to_string(),
                value: "$payload$".to_string(),
            }],
            body: "{\"q\":\"$payload$\"}".to_string(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let payload = "$1-${jndi:ldap://x}-$ne";

        assert_eq!(count_request_markers(&request), 4);
        let applied = apply_payload_to_request(&request, payload).unwrap();

        assert_eq!(applied.host, format!("{payload}.example.com"));
        assert_eq!(applied.path, format!("/search/{payload}"));
        assert_eq!(applied.headers[0].value, payload);
        assert_eq!(applied.body, format!("{{\"q\":\"{payload}\"}}"));
    }

    #[test]
    fn normalize_payloads_preserves_empty_string_payloads() {
        let payloads = normalize_payloads(vec!["".to_string(), "admin\r".to_string()]);

        assert_eq!(payloads, vec!["".to_string(), "admin".to_string()]);
    }

    #[test]
    fn fuzzer_rejects_oversized_payload_sets() {
        let too_many = vec!["x".to_string(); MAX_FUZZER_PAYLOADS + 1];
        assert!(validate_fuzzer_payloads(&too_many)
            .unwrap_err()
            .to_string()
            .contains("payload count"));

        let too_large = vec!["x".repeat(MAX_FUZZER_PAYLOAD_BYTES + 1)];
        assert!(validate_fuzzer_payloads(&too_large)
            .unwrap_err()
            .to_string()
            .contains("cannot exceed"));

        let too_many_bytes = vec!["x".repeat(MAX_FUZZER_PAYLOAD_BYTES); 65];
        assert!(validate_fuzzer_payloads(&too_many_bytes)
            .unwrap_err()
            .to_string()
            .contains("total bytes"));
    }

    #[test]
    fn fuzzer_rejects_marker_and_expansion_amplification() {
        let mut request = EditableRequest {
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: FUZZER_PAYLOAD_MARKER.repeat(MAX_FUZZER_MARKERS_PER_REQUEST + 1),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        assert!(validate_marker_count(count_request_markers(&request))
            .unwrap_err()
            .to_string()
            .contains("markers"));

        let marker_count = (MAX_FUZZER_EXPANDED_REQUEST_BYTES / MAX_FUZZER_PAYLOAD_BYTES) + 1;
        assert!(marker_count <= MAX_FUZZER_MARKERS_PER_REQUEST);
        request.body = FUZZER_PAYLOAD_MARKER.repeat(marker_count);
        let payloads = vec!["x".repeat(MAX_FUZZER_PAYLOAD_BYTES)];
        assert!(validate_fuzzer_expanded_request_budget(&request, &payloads)
            .unwrap_err()
            .to_string()
            .contains("expands the request"));
    }

    #[tokio::test]
    async fn from_attacks_does_not_preallocate_full_retention_for_empty_restore() {
        let store = FuzzerStore::from_attacks(500_000, Vec::new());

        assert_eq!(store.attacks.read().await.capacity(), 0);
    }

    #[test]
    fn host_header_marker_takes_precedence_over_authority_marker() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "authority-$payload$.example.com".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: vec![HeaderRecord {
                name: "Host".to_string(),
                value: "header-$payload$.example.com".to_string(),
            }],
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };

        assert_eq!(count_request_markers(&request), 1);
        let applied = apply_payload_to_request(&request, "demo").unwrap();

        assert_eq!(applied.headers[0].value, "header-demo.example.com");
        assert_eq!(applied.host, "header-demo.example.com");
    }

    #[test]
    fn fixed_host_header_rejects_authority_only_payload_marker() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "authority-$payload$.example.com".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: vec![HeaderRecord {
                name: "Host".to_string(),
                value: "fixed.example.com".to_string(),
            }],
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };

        assert_eq!(count_request_markers(&request), 0);
        let error = validate_expanded_requests(&request, &["demo".to_string()], |_| Ok(()))
            .expect_err("authority-only marker should be ignored by the fixed Host header");

        assert!(error.to_string().contains("missing $payload$ markers"));
    }

    #[test]
    fn host_header_override_excludes_authority_markers_from_expansion_budget() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: FUZZER_PAYLOAD_MARKER.repeat(MAX_FUZZER_MARKERS_PER_REQUEST),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: vec![HeaderRecord {
                name: "Host".to_string(),
                value: "header-$payload$.example.com".to_string(),
            }],
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };

        let payload = "d".repeat(MAX_FUZZER_PAYLOAD_BYTES);
        validate_expanded_requests(&request, std::slice::from_ref(&payload), |_| Ok(())).unwrap();
        let applied = apply_payload_to_request(&request, &payload).unwrap();

        assert!(applied.host.starts_with("header-dddd"));
        assert!(applied.host.ends_with(".example.com"));
    }

    #[tokio::test]
    async fn forced_http2_failure_result_keeps_history_transaction_id() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_handle = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .await
                .unwrap();
        });

        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 32,
            max_transaction_entries: 32,
            body_preview_bytes: 4096,
            data_dir: std::env::temp_dir()
                .join(format!("sniper-fuzzer-http2-failure-{}", Uuid::new_v4())),
        };
        let data_dir = config.data_dir.clone();
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let request = EditableRequest {
            scheme: "http".to_string(),
            host: upstream_addr.to_string(),
            method: "GET".to_string(),
            path: "/$payload$".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };

        let attack = run_attack(
            state,
            request,
            vec!["forced".to_string()],
            None,
            Some("HTTP/2".to_string()),
            None,
        )
        .await
        .unwrap();
        assert!(matches!(attack.status, FuzzerAttackStatus::Failed));
        let result = attack.results.first().unwrap();
        let transaction_id = result
            .transaction_id
            .expect("failed replay result should keep transaction id");
        assert_eq!(result.status, Some(502));
        assert!(result
            .note
            .as_deref()
            .unwrap_or_default()
            .contains("HTTP/2"));

        let records = session.store.snapshot(Some(10)).await;
        assert!(records.iter().any(|record| record.id == transaction_id));

        upstream_handle.abort();
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn upstream_connection_failure_marks_fuzzer_result_failed_with_transaction_record() {
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 32,
            max_transaction_entries: 32,
            body_preview_bytes: 4096,
            data_dir: std::env::temp_dir()
                .join(format!("sniper-fuzzer-upstream-failure-{}", Uuid::new_v4())),
        };
        let data_dir = config.data_dir.clone();
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let request = EditableRequest {
            scheme: "http".to_string(),
            host: "127.0.0.1:1".to_string(),
            method: "GET".to_string(),
            path: "/$payload$".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };

        let attack = run_attack_for_session(
            state,
            session.clone(),
            request,
            vec!["payload".to_string()],
            None,
            None,
            None,
        )
        .await
        .unwrap();

        assert!(matches!(attack.status, FuzzerAttackStatus::Failed));
        let result = attack.results.first().unwrap();
        let transaction_id = result
            .transaction_id
            .expect("failed replay result should keep transaction id");
        assert_eq!(result.status, Some(502));
        assert!(result
            .note
            .as_deref()
            .unwrap_or_default()
            .contains("Upstream request failed"));

        let records = session.store.snapshot(Some(10)).await;
        assert!(records.iter().any(|record| record.id == transaction_id));

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn registry_metadata_failure_persists_rolled_back_fuzzer_snapshot() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-fuzzer-registry-rollback-{}",
            Uuid::new_v4()
        ));
        let state = Arc::new(
            AppState::new(AppConfig {
                proxy_addr: "127.0.0.1:0".parse().unwrap(),
                ui_addr: "127.0.0.1:0".parse().unwrap(),
                max_entries: 32,
                max_transaction_entries: 32,
                body_preview_bytes: 4096,
                data_dir: data_dir.clone(),
            })
            .unwrap(),
        );
        let session = state.session().await;
        let request = EditableRequest {
            scheme: "http".to_string(),
            host: "127.0.0.1:1".to_string(),
            method: "GET".to_string(),
            path: "/$payload$".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let registry_path = session
            .storage_dir()
            .parent()
            .expect("session dir should have registry parent")
            .join("registry.json");
        std::fs::remove_file(&registry_path).unwrap();
        std::fs::create_dir(&registry_path).unwrap();

        let error = run_attack_for_session(
            state.clone(),
            session.clone(),
            request,
            vec!["payload".to_string()],
            None,
            None,
            None,
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("failed to persist session"));
        assert!(session.fuzzer.snapshot(None).await.is_empty());
        assert!(session
            .event_log
            .snapshot(None)
            .await
            .iter()
            .all(|entry| entry.source != "fuzzer"));

        let reloaded = state.sessions.load_context(session.id()).unwrap();
        assert!(reloaded.fuzzer.snapshot(None).await.is_empty());
        assert!(reloaded
            .event_log
            .snapshot(None)
            .await
            .iter()
            .all(|entry| entry.source != "fuzzer"));

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn fuzzer_attack_record_accepts_legacy_missing_collections() {
        let record: FuzzerAttackRecord = serde_json::from_value(serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "started_at": "2026-01-01T00:00:00Z",
            "completed_at": "2026-01-01T00:00:01Z",
            "status": "completed",
            "template": {
                "scheme": "https",
                "host": "example.com",
                "method": "GET",
                "path": "/",
                "headers": [],
                "body": "",
                "body_encoding": "utf8",
                "preview_truncated": false
            }
        }))
        .expect("legacy fuzzer attack record should deserialize");

        assert_eq!(record.payload_count, 0);
        assert_eq!(record.marker_count, 0);
        assert!(record.results.is_empty());
        assert!(record.notes.is_empty());
    }

    #[test]
    fn fuzzer_attack_result_accepts_legacy_missing_counts() {
        let result: FuzzerAttackResult = serde_json::from_value(serde_json::json!({
            "payload": "admin",
            "status": 200
        }))
        .expect("legacy fuzzer attack result should deserialize");

        assert_eq!(result.index, 0);
        assert_eq!(result.payload, "admin");
        assert_eq!(result.response_bytes, 0);
        assert_eq!(result.status, Some(200));
    }

    #[tokio::test]
    async fn fuzzer_store_remove_and_restore_recovers_evicted_attack() {
        fn attack(id: &str) -> FuzzerAttackRecord {
            FuzzerAttackRecord {
                id: Uuid::parse_str(id).unwrap(),
                started_at: Utc::now(),
                completed_at: Utc::now(),
                status: FuzzerAttackStatus::Completed,
                template: EditableRequest {
                    scheme: "https".to_string(),
                    host: "example.test".to_string(),
                    method: "GET".to_string(),
                    path: "/".to_string(),
                    headers: Vec::new(),
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                payload_count: 1,
                marker_count: 1,
                results: Vec::new(),
                notes: Vec::new(),
            }
        }

        let store = FuzzerStore::new(1);
        let old = attack("00000000-0000-0000-0000-000000000011");
        let new = attack("00000000-0000-0000-0000-000000000012");

        assert!(store.insert(old.clone()).await.is_empty());
        let evicted = store.insert(new.clone()).await;
        assert_eq!(
            evicted.iter().map(|attack| attack.id).collect::<Vec<_>>(),
            vec![old.id]
        );

        assert!(store.remove_and_restore(new.id, evicted).await);
        assert_eq!(
            store.get(old.id).await.map(|attack| attack.id),
            Some(old.id)
        );
        assert!(store.get(new.id).await.is_none());
    }
}
