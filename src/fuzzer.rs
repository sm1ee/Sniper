use std::{collections::VecDeque, sync::LazyLock};

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

static MARKER_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("§[^§]*§").expect("valid marker regex"));

use crate::{model::EditableRequest, proxy, state::AppState};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzerAttackStatus {
    Completed,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FuzzerAttackResult {
    pub index: usize,
    pub payload: String,
    pub transaction_id: Option<Uuid>,
    pub status: Option<u16>,
    pub duration_ms: Option<u64>,
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
    pub payload_count: usize,
    pub marker_count: usize,
    pub results: Vec<FuzzerAttackResult>,
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
    pub template: EditableRequest,
    pub payloads: Vec<String>,
    pub source_transaction_id: Option<Uuid>,
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
        let mut attacks = VecDeque::with_capacity(max_entries);
        attacks.extend(records.into_iter().take(max_entries));
        Self {
            max_entries,
            attacks: RwLock::new(attacks),
        }
    }

    pub async fn insert(&self, record: FuzzerAttackRecord) {
        let mut attacks = self.attacks.write().await;
        attacks.push_front(record);
        while attacks.len() > self.max_entries {
            attacks.pop_back();
        }
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

    pub async fn replace_all(&self, records: Vec<FuzzerAttackRecord>) {
        let mut attacks = self.attacks.write().await;
        attacks.clear();
        attacks.extend(records.into_iter().take(self.max_entries));
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
) -> Result<FuzzerAttackRecord> {
    let session = state.session().await;
    let started_at = Utc::now();
    let marker_count = count_request_markers(&template);
    if marker_count == 0 {
        return Err(anyhow!(
            "Request template is missing markers. Use §value§ markers or {{PAYLOAD}}."
        ));
    }

    let normalized_payloads = payloads
        .into_iter()
        .map(|payload| payload.trim().to_string())
        .filter(|payload| !payload.is_empty())
        .collect::<Vec<_>>();
    if normalized_payloads.is_empty() {
        return Err(anyhow!("Fuzzer needs at least one payload"));
    }

    state
        .log_info(
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
        match proxy::send_replay_request(state.clone(), request, None, source_transaction_id, None)
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
                notes.push(message.clone());
                results.push(FuzzerAttackResult {
                    index,
                    payload: payload.clone(),
                    transaction_id: None,
                    status: None,
                    duration_ms: None,
                    response_bytes: 0,
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

    session.fuzzer.insert(record.clone()).await;
    state
        .log_info(
            "fuzzer",
            "Attack completed",
            format!(
                "Completed {} payload(s) against {}{}",
                record.payload_count, template.host, template.path
            ),
        )
        .await;
    if let Err(error) = state.persist_session_context(&session).await {
        tracing::warn!(
            ?error,
            "failed to persist active session after fuzzer attack"
        );
    }

    Ok(record)
}

fn count_request_markers(request: &EditableRequest) -> usize {
    let mut count = count_markers(&request.path) + count_markers(&request.body);
    for header in &request.headers {
        count += count_markers(&header.name);
        count += count_markers(&header.value);
    }
    count
}

fn apply_payload_to_request(template: &EditableRequest, payload: &str) -> Result<EditableRequest> {
    let mut request = template.clone();
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
    Ok(request)
}

fn count_markers(value: &str) -> usize {
    let count = MARKER_REGEX.find_iter(value).count();
    if count > 0 {
        count
    } else {
        value.matches("{{PAYLOAD}}").count() + value.matches("{{INTRUDER}}").count()
    }
}

fn replace_markers(value: &str, payload: &str) -> Result<String> {
    if MARKER_REGEX.is_match(value) {
        return Ok(MARKER_REGEX.replace_all(value, payload).into_owned());
    }

    if value.contains("{{PAYLOAD}}") || value.contains("{{INTRUDER}}") {
        return Ok(value
            .replace("{{PAYLOAD}}", payload)
            .replace("{{INTRUDER}}", payload));
    }

    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{BodyEncoding, HeaderRecord};

    #[test]
    fn counts_and_replaces_burp_markers() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            method: "GET".to_string(),
            path: "/items/§1§".to_string(),
            headers: vec![HeaderRecord {
                name: "x-test".to_string(),
                value: "§header§".to_string(),
            }],
            body: "{\"id\":\"§body§\"}".to_string(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };

        assert_eq!(count_request_markers(&request), 3);
        let applied = apply_payload_to_request(&request, "abc").unwrap();
        assert_eq!(applied.path, "/items/abc");
        assert_eq!(applied.headers[0].value, "abc");
        assert_eq!(applied.body, "{\"id\":\"abc\"}");
    }
}
