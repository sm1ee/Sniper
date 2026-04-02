use std::collections::{HashMap, VecDeque};

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    model::{EditableRequest, RequestTargetOverride},
    proxy,
    state::AppState,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractionSource {
    ResponseBody,
    ResponseHeader,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtractionRule {
    pub variable_name: String,
    pub source: ExtractionSource,
    pub pattern: String,
    #[serde(default = "default_group")]
    pub group: usize,
}

fn default_group() -> usize {
    1
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SequenceStep {
    pub id: Uuid,
    pub label: String,
    pub request: EditableRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<RequestTargetOverride>,
    #[serde(default)]
    pub extractions: Vec<ExtractionRule>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SequenceDefinition {
    pub id: Uuid,
    pub name: String,
    pub steps: Vec<SequenceStep>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SequenceRunStatus {
    Completed,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StepResult {
    pub step_id: Uuid,
    pub label: String,
    pub transaction_id: Option<Uuid>,
    pub status: Option<u16>,
    pub duration_ms: Option<u64>,
    pub extracted: HashMap<String, String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SequenceRunRecord {
    pub id: Uuid,
    pub sequence_id: Uuid,
    pub sequence_name: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub status: SequenceRunStatus,
    pub step_results: Vec<StepResult>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SequenceRunSummary {
    pub id: Uuid,
    pub sequence_id: Uuid,
    pub sequence_name: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub status: SequenceRunStatus,
    pub step_count: usize,
}

impl SequenceRunRecord {
    pub fn summary(&self) -> SequenceRunSummary {
        SequenceRunSummary {
            id: self.id,
            sequence_id: self.sequence_id,
            sequence_name: self.sequence_name.clone(),
            started_at: self.started_at,
            completed_at: self.completed_at,
            status: self.status.clone(),
            step_count: self.step_results.len(),
        }
    }
}

pub struct SequenceStore {
    max_entries: usize,
    definitions: RwLock<Vec<SequenceDefinition>>,
    runs: RwLock<VecDeque<SequenceRunRecord>>,
}

impl SequenceStore {
    pub fn new(max_entries: usize) -> Self {
        Self {
            max_entries,
            definitions: RwLock::new(Vec::new()),
            runs: RwLock::new(VecDeque::new()),
        }
    }

    pub fn from_data(
        max_entries: usize,
        definitions: Vec<SequenceDefinition>,
        runs: Vec<SequenceRunRecord>,
    ) -> Self {
        let mut run_deque = VecDeque::with_capacity(max_entries);
        run_deque.extend(runs.into_iter().take(max_entries));
        Self {
            max_entries,
            definitions: RwLock::new(definitions),
            runs: RwLock::new(run_deque),
        }
    }

    pub async fn list_definitions(&self) -> Vec<SequenceDefinition> {
        self.definitions.read().await.clone()
    }

    pub async fn get_definition(&self, id: Uuid) -> Option<SequenceDefinition> {
        self.definitions
            .read()
            .await
            .iter()
            .find(|d| d.id == id)
            .cloned()
    }

    pub async fn upsert_definition(&self, def: SequenceDefinition) {
        let mut defs = self.definitions.write().await;
        if let Some(existing) = defs.iter_mut().find(|d| d.id == def.id) {
            *existing = def;
        } else {
            defs.push(def);
        }
    }

    pub async fn delete_definition(&self, id: Uuid) -> bool {
        let mut defs = self.definitions.write().await;
        let before = defs.len();
        defs.retain(|d| d.id != id);
        defs.len() < before
    }

    pub async fn insert_run(&self, record: SequenceRunRecord) {
        let mut runs = self.runs.write().await;
        runs.push_front(record);
        while runs.len() > self.max_entries {
            runs.pop_back();
        }
    }

    pub async fn list_runs(&self, limit: Option<usize>) -> Vec<SequenceRunSummary> {
        self.runs
            .read()
            .await
            .iter()
            .take(limit.unwrap_or(self.max_entries).min(self.max_entries))
            .map(SequenceRunRecord::summary)
            .collect()
    }

    pub async fn get_run(&self, id: Uuid) -> Option<SequenceRunRecord> {
        self.runs
            .read()
            .await
            .iter()
            .find(|r| r.id == id)
            .cloned()
    }

    pub async fn snapshot_definitions(&self) -> Vec<SequenceDefinition> {
        self.definitions.read().await.clone()
    }

    pub async fn snapshot_runs(&self, limit: Option<usize>) -> Vec<SequenceRunRecord> {
        self.runs
            .read()
            .await
            .iter()
            .take(limit.unwrap_or(self.max_entries).min(self.max_entries))
            .cloned()
            .collect()
    }
}

fn substitute_variables(text: &str, variables: &HashMap<String, String>) -> String {
    let mut result = text.to_string();
    for (name, value) in variables {
        result = result.replace(&format!("{{{{{name}}}}}"), value);
    }
    result
}

fn apply_variables_to_request(
    request: &EditableRequest,
    variables: &HashMap<String, String>,
) -> EditableRequest {
    EditableRequest {
        scheme: request.scheme.clone(),
        host: substitute_variables(&request.host, variables),
        method: request.method.clone(),
        path: substitute_variables(&request.path, variables),
        headers: request
            .headers
            .iter()
            .map(|h| crate::model::HeaderRecord {
                name: h.name.clone(),
                value: substitute_variables(&h.value, variables),
            })
            .collect(),
        body: substitute_variables(&request.body, variables),
        body_encoding: request.body_encoding.clone(),
        preview_truncated: request.preview_truncated,
    }
}

fn extract_from_response(
    rules: &[ExtractionRule],
    response_body: &str,
    response_headers: &[crate::model::HeaderRecord],
) -> HashMap<String, String> {
    let mut extracted = HashMap::new();
    for rule in rules {
        let source_text = match rule.source {
            ExtractionSource::ResponseBody => response_body.to_string(),
            ExtractionSource::ResponseHeader => response_headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case(&rule.pattern))
                .map(|h| h.value.clone())
                .unwrap_or_default(),
        };

        let value = match rule.source {
            ExtractionSource::ResponseHeader => source_text,
            ExtractionSource::ResponseBody => {
                match Regex::new(&rule.pattern) {
                    Ok(regex) => regex
                        .captures(&source_text)
                        .and_then(|caps| caps.get(rule.group).map(|m| m.as_str().to_string()))
                        .unwrap_or_default(),
                    Err(e) => {
                        tracing::warn!(
                            variable = %rule.variable_name,
                            pattern = %rule.pattern,
                            error = %e,
                            "Invalid regex pattern in extraction rule"
                        );
                        String::new()
                    }
                }
            }
        };

        if !value.is_empty() {
            extracted.insert(rule.variable_name.clone(), value);
        }
    }
    extracted
}

pub async fn run_sequence(
    state: std::sync::Arc<AppState>,
    definition: SequenceDefinition,
) -> Result<SequenceRunRecord> {
    if definition.steps.is_empty() {
        return Err(anyhow!("Sequence has no steps"));
    }

    let started_at = Utc::now();
    let mut variables: HashMap<String, String> = HashMap::new();
    let mut step_results = Vec::with_capacity(definition.steps.len());
    let mut failed = false;

    state
        .log_info(
            "sequence",
            "Sequence started",
            format!(
                "Running \"{}\" with {} step(s)",
                definition.name,
                definition.steps.len()
            ),
        )
        .await;

    for step in &definition.steps {
        let request = apply_variables_to_request(&step.request, &variables);

        match proxy::send_replay_request(
            state.clone(),
            request,
            step.target.clone(),
            None,
            None,
        )
        .await
        {
            Ok(record) => {
                let response_body = record
                    .response
                    .as_ref()
                    .map(|r| {
                        if r.body_encoding == crate::model::BodyEncoding::Utf8 {
                            r.body_preview.clone()
                        } else {
                            String::new()
                        }
                    })
                    .unwrap_or_default();
                let response_headers = record
                    .response
                    .as_ref()
                    .map(|r| r.headers.clone())
                    .unwrap_or_default();
                let extracted =
                    extract_from_response(&step.extractions, &response_body, &response_headers);
                variables.extend(extracted.clone());

                step_results.push(StepResult {
                    step_id: step.id,
                    label: step.label.clone(),
                    transaction_id: Some(record.id),
                    status: record.status,
                    duration_ms: Some(record.duration_ms),
                    extracted,
                    error: None,
                });
            }
            Err(error) => {
                step_results.push(StepResult {
                    step_id: step.id,
                    label: step.label.clone(),
                    transaction_id: None,
                    status: None,
                    duration_ms: None,
                    extracted: HashMap::new(),
                    error: Some(error.to_string()),
                });
                failed = true;
                break;
            }
        }
    }

    let completed_at = Utc::now();
    let status = if failed {
        SequenceRunStatus::Failed
    } else {
        SequenceRunStatus::Completed
    };

    state
        .log_info(
            "sequence",
            "Sequence completed",
            format!(
                "\"{}\" finished with status {:?} ({}/{} steps)",
                definition.name,
                status,
                step_results.len(),
                definition.steps.len()
            ),
        )
        .await;

    let record = SequenceRunRecord {
        id: Uuid::new_v4(),
        sequence_id: definition.id,
        sequence_name: definition.name.clone(),
        started_at,
        completed_at,
        status,
        step_results,
    };

    let session = state.session().await;
    session.sequence.insert_run(record.clone()).await;
    if let Err(error) = state.persist_active_session().await {
        tracing::warn!(?error, "failed to persist session after sequence run");
    }

    Ok(record)
}
