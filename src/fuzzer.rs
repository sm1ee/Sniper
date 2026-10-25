use std::{
    collections::VecDeque,
    sync::{Arc, LazyLock, Mutex as StdMutex},
    time::Duration,
};

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{watch, RwLock},
    task::JoinHandle,
};
use uuid::Uuid;

const MAX_FUZZER_PAYLOADS: usize = 5_000;
const MAX_FUZZER_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_FUZZER_TOTAL_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
const MAX_FUZZER_MARKERS_PER_REQUEST: usize = 128;
const MAX_FUZZER_EXPANDED_REQUEST_BYTES: usize = 4 * 1024 * 1024;
/// Sniper multiplies payloads by positions; one attack sends no more than this.
const MAX_FUZZER_REQUESTS: usize = 50_000;
const MAX_FUZZER_CONCURRENCY: usize = 16;
/// Distinct errors an ended attack keeps as notes; each result keeps its own.
const MAX_FUZZER_NOTES: usize = 20;
/// How long a stop waits for requests in flight before abandoning them.
const STOP_GRACE: Duration = Duration::from_secs(5);

/// A position is `§original§`, as Burp marks one, or `$payload$`, whose
/// original is empty. Sniper leaves every other position at its original.
static MARKER_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$payload\$|§([^§]*)§").expect("valid marker regex"));

use crate::{
    event_log::EventLevel,
    model::{EditableRequest, RequestTargetOverride},
    proxy,
    state::AppState,
};

/// How payloads fill the positions, as Burp Intruder and Caido Automate name it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzerAttackType {
    /// Each position in turn takes every payload; the others keep their original.
    Sniper,
    /// Every position takes the same payload at once.
    #[default]
    BatteringRam,
}

/// The requests of an attack in sending order: for Sniper the position and
/// the payload index, for Battering ram the payload index alone.
pub(crate) fn plan_requests(
    attack_type: FuzzerAttackType,
    positions: usize,
    payloads: usize,
) -> Vec<(Option<usize>, usize)> {
    match attack_type {
        FuzzerAttackType::BatteringRam => (0..payloads).map(|payload| (None, payload)).collect(),
        FuzzerAttackType::Sniper => (0..positions)
            .flat_map(|position| (0..payloads).map(move |payload| (Some(position), payload)))
            .collect(),
    }
}

/// `Completed` and `Failed` only: a build that predates running and stopped
/// attacks reads session state written by this one, and an unknown status
/// would make it set the whole file aside. `running` and `stopped` say the rest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzerAttackStatus {
    Completed,
    /// At least one request was not sent or got no answer.
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
    /// The position Sniper put the payload in; none for Battering ram.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position: Option<usize>,
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
    #[serde(default)]
    pub attack_type: FuzzerAttackType,
    #[serde(default)]
    pub url_encode: bool,
    /// Requests the attack sends; records from before it was kept say 0.
    #[serde(default)]
    pub planned: usize,
    #[serde(default = "one")]
    pub concurrency: usize,
    /// Still sending. Checkpoints keep its results as a stopped attack: a
    /// restart must neither discard completed work nor resume network traffic.
    #[serde(default, skip_serializing_if = "is_false")]
    pub running: bool,
    /// Stopped before every request was sent.
    #[serde(default, skip_serializing_if = "is_false")]
    pub stopped: bool,
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
    #[serde(default)]
    pub planned: usize,
    #[serde(default, skip_serializing_if = "is_false")]
    pub running: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub stopped: bool,
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
    /// Battering ram when left out, which is what this API did before Sniper.
    #[serde(default)]
    pub attack_type: FuzzerAttackType,
    #[serde(default = "yes")]
    pub url_encode: bool,
    #[serde(default = "one")]
    pub concurrency: usize,
}

fn one() -> usize {
    1
}

fn yes() -> bool {
    true
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// How an attack sends, besides its request and payloads.
#[derive(Clone, Copy, Debug)]
pub struct FuzzerAttackOptions {
    pub attack_type: FuzzerAttackType,
    pub url_encode: bool,
    pub concurrency: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FuzzerStartError {
    /// No attack could run as asked; the text says why.
    Invalid(String),
    /// The session already runs one; it has to finish or be stopped first.
    Busy,
}

struct RunningAttack {
    id: Uuid,
    cancel: watch::Sender<bool>,
    task: JoinHandle<()>,
}

pub struct FuzzerStore {
    max_entries: usize,
    attacks: RwLock<VecDeque<FuzzerAttackRecord>>,
    running: StdMutex<Option<RunningAttack>>,
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
            running: StdMutex::new(None),
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

    /// Checkpoint running attacks without changing the live worker. Restoring
    /// this snapshot keeps completed results but never resumes the requests.
    pub async fn snapshot(&self, limit: Option<usize>) -> Vec<FuzzerAttackRecord> {
        let records: Vec<_> = self
            .attacks
            .read()
            .await
            .iter()
            .take(limit.unwrap_or(self.max_entries).min(self.max_entries))
            .cloned()
            .collect();
        records
            .into_iter()
            .map(|mut attack| {
                if attack.running {
                    end_record(&mut attack, true);
                }
                attack
            })
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

    async fn update(&self, id: Uuid, change: impl FnOnce(&mut FuzzerAttackRecord)) {
        if let Some(record) = self
            .attacks
            .write()
            .await
            .iter_mut()
            .find(|attack| attack.id == id)
        {
            change(record);
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.lock().unwrap().is_some()
    }

    fn clear_running(&self, id: Uuid) {
        let mut running = self.running.lock().unwrap();
        if running.as_ref().is_some_and(|attack| attack.id == id) {
            *running = None;
        }
    }

    /// Stops the running attack (that one only, when `id` is given): requests
    /// in flight are dropped, and one being stored is finished unless that
    /// takes longer than the grace period. True when an attack was running.
    /// Not under the session's mutation guard: storing an exchange persists
    /// the session, which takes it.
    pub async fn stop(&self, id: Option<Uuid>) -> bool {
        let running = {
            let mut guard = self.running.lock().unwrap();
            if id.is_some_and(|id| guard.as_ref().is_none_or(|attack| attack.id != id)) {
                return false;
            }
            guard.take()
        };
        let Some(mut running) = running else {
            return false;
        };
        let _ = running.cancel.send(true);
        if tokio::time::timeout(STOP_GRACE, &mut running.task)
            .await
            .is_err()
        {
            running.task.abort();
            let _ = (&mut running.task).await;
        }
        // An aborted worker could not end its record.
        self.update(running.id, |record| {
            if record.running {
                end_record(record, true);
            }
        })
        .await;
        true
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
            planned: self.planned,
            running: self.running,
            stopped: self.stopped,
        }
    }
}

/// What an attack sends, checked before anything goes out: at least one
/// position, the payload limits, and at most `MAX_FUZZER_REQUESTS` requests.
pub(crate) struct AttackPlan {
    pub positions: usize,
    pub payloads: Vec<String>,
    pub requests: Vec<(Option<usize>, usize)>,
}

pub(crate) fn plan_attack(
    template: &EditableRequest,
    payloads: Vec<String>,
    options: FuzzerAttackOptions,
) -> Result<AttackPlan> {
    let positions = count_request_markers(template);
    if positions == 0 {
        return Err(anyhow!(
            "Mark at least one position: choose a value and mark it, or write §value§ or $payload$ in the request."
        ));
    }
    validate_marker_count(positions)?;
    let payloads = normalize_payloads(payloads);
    if payloads.is_empty() {
        return Err(anyhow!("Fuzzer needs at least one payload"));
    }
    validate_fuzzer_payloads(&payloads)?;
    validate_fuzzer_expanded_request_budget(template, &payloads, options.url_encode)?;
    let requests = plan_requests(options.attack_type, positions, payloads.len());
    if requests.len() > MAX_FUZZER_REQUESTS {
        return Err(anyhow!(
            "This attack would send {} requests; an attack sends at most {MAX_FUZZER_REQUESTS}. Use fewer payloads or positions.",
            requests.len()
        ));
    }
    Ok(AttackPlan {
        positions,
        payloads,
        requests,
    })
}

/// Whether a built request can be sent, by the checks Replay applies.
fn sendable(
    request: &EditableRequest,
    target: Option<&RequestTargetOverride>,
) -> std::result::Result<(), String> {
    crate::api::validate_runnable_editable_request(request)?;
    if let Some(target) = target {
        crate::api::validate_request_target_override_for_request(request, target)?;
    }
    Ok(())
}

/// Starts an attack in the background and returns its running record. A
/// request that cannot be sent becomes a result that says why; whether a
/// request is valid can depend on its payload (a base64 body, a host), so the
/// only request check up front is one no payload changes: a truncated body.
#[allow(clippy::too_many_arguments)]
pub async fn start_attack(
    state: Arc<AppState>,
    session: Arc<crate::session::SessionContext>,
    template: EditableRequest,
    payloads: Vec<String>,
    source_transaction_id: Option<Uuid>,
    http_version: Option<String>,
    target: Option<RequestTargetOverride>,
    options: FuzzerAttackOptions,
) -> std::result::Result<FuzzerAttackRecord, FuzzerStartError> {
    if !(1..=MAX_FUZZER_CONCURRENCY).contains(&options.concurrency) {
        return Err(FuzzerStartError::Invalid(format!(
            "Concurrency is 1–{MAX_FUZZER_CONCURRENCY} requests at once."
        )));
    }
    if template.preview_truncated {
        return Err(FuzzerStartError::Invalid(
            "request body preview is truncated and cannot be replayed safely".to_string(),
        ));
    }
    let plan = plan_attack(&template, payloads, options)
        .map_err(|error| FuzzerStartError::Invalid(error.to_string()))?;
    if session.fuzzer.is_running() {
        return Err(FuzzerStartError::Busy);
    }

    let started_at = Utc::now();
    let record = FuzzerAttackRecord {
        id: Uuid::new_v4(),
        started_at,
        completed_at: started_at,
        status: FuzzerAttackStatus::Completed,
        template: template.clone(),
        payload_count: plan.payloads.len(),
        marker_count: plan.positions,
        results: Vec::new(),
        notes: Vec::new(),
        attack_type: options.attack_type,
        url_encode: options.url_encode,
        planned: plan.requests.len(),
        concurrency: options.concurrency,
        running: true,
        stopped: false,
    };
    session.fuzzer.insert(record.clone()).await;
    session
        .event_log
        .push(
            EventLevel::Info,
            "fuzzer",
            "Attack started",
            format!(
                "Sending {} request(s) against {}{}",
                record.planned, template.host, template.path
            ),
        )
        .await;
    let (cancel, cancelled) = watch::channel(false);
    let run = Arc::new(AttackRun {
        state,
        session: Arc::clone(&session),
        id: record.id,
        template,
        payloads: plan.payloads,
        source_transaction_id,
        http_version,
        target,
        url_encode: options.url_encode,
    });
    let task = tokio::spawn(run.execute(plan.requests, options.concurrency, cancelled));
    *session.fuzzer.running.lock().unwrap() = Some(RunningAttack {
        id: record.id,
        cancel,
        task,
    });
    session.schedule_state_persist();
    Ok(record)
}

struct AttackRun {
    state: Arc<AppState>,
    session: Arc<crate::session::SessionContext>,
    id: Uuid,
    template: EditableRequest,
    payloads: Vec<String>,
    source_transaction_id: Option<Uuid>,
    http_version: Option<String>,
    target: Option<RequestTargetOverride>,
    url_encode: bool,
}

impl AttackRun {
    async fn execute(
        self: Arc<Self>,
        requests: Vec<(Option<usize>, usize)>,
        concurrency: usize,
        cancel: watch::Receiver<bool>,
    ) {
        futures_util::stream::iter(requests.into_iter().enumerate())
            .for_each_concurrent(concurrency, |(index, (position, payload))| {
                let run = Arc::clone(&self);
                let mut cancel = cancel.clone();
                async move {
                    if *cancel.borrow() {
                        return;
                    }
                    if let Some(result) = run.send(index, position, payload, &mut cancel).await {
                        run.session
                            .fuzzer
                            .update(run.id, |record| record.results.push(result))
                            .await;
                        run.session.schedule_state_persist();
                    }
                }
            })
            .await;
        let stopped = *cancel.borrow();
        let mut ended = None;
        self.session
            .fuzzer
            .update(self.id, |record| {
                if record.running {
                    end_record(record, stopped);
                }
                ended = Some((record.results.len(), record.planned));
            })
            .await;
        self.session.fuzzer.clear_running(self.id);
        if let Some((sent, planned)) = ended {
            self.session
                .event_log
                .push(
                    EventLevel::Info,
                    "fuzzer",
                    if stopped {
                        "Attack stopped"
                    } else {
                        "Attack completed"
                    },
                    format!(
                        "{sent} of {planned} request(s) against {}{}",
                        self.template.host, self.template.path
                    ),
                )
                .await;
        }
        self.session.schedule_state_persist();
    }

    /// One request: its result, or none when the attack stopped first.
    async fn send(
        &self,
        index: usize,
        position: Option<usize>,
        payload: usize,
        cancel: &mut watch::Receiver<bool>,
    ) -> Option<FuzzerAttackResult> {
        let payload_text = &self.payloads[payload];
        let mut result = FuzzerAttackResult {
            index,
            payload: payload_text.clone(),
            transaction_id: None,
            status: None,
            duration_ms: None,
            response_bytes: 0,
            note: None,
            position,
        };
        let request = match build_request(&self.template, payload_text, position, self.url_encode)
            .map_err(|error| error.to_string())
            .and_then(|request| sendable(&request, self.target.as_ref()).map(|()| request))
        {
            Ok(request) => request,
            Err(error) => {
                result.note = Some(format!("Not sent: {error}"));
                return Some(result);
            }
        };
        let sent = tokio::select! {
            sent = proxy::try_send_replay_request_for_session(
                Arc::clone(&self.state),
                Arc::clone(&self.session),
                request,
                self.target.clone(),
                self.source_transaction_id,
                self.http_version.clone(),
                proxy::SentFrom::Fuzzer,
            ) => sent,
            _ = cancel.wait_for(|stop| *stop) => return None,
        };
        match sent {
            Ok(record) => {
                result.transaction_id = Some(record.id);
                result.status = record.status;
                result.duration_ms = Some(record.duration_ms);
                result.response_bytes = record
                    .response
                    .as_ref()
                    .map_or(0, |response| response.body_size);
            }
            Err(error) => {
                result.note = Some(error.to_string());
                if let Some(record) = error.record() {
                    result.transaction_id = Some(record.id);
                    result.status = record.status;
                    result.duration_ms = Some(record.duration_ms);
                    result.response_bytes = record
                        .response
                        .as_ref()
                        .map_or(0, |response| response.body_size);
                }
            }
        }
        Some(result)
    }
}

/// Ends a running record: results in sending order, the first few distinct
/// errors as its notes, and Failed if any request was not sent or failed.
fn end_record(record: &mut FuzzerAttackRecord, stopped: bool) {
    record.results.sort_by_key(|result| result.index);
    record.running = false;
    record.stopped = stopped;
    record.completed_at = Utc::now();
    record.notes.clear();
    for note in record
        .results
        .iter()
        .filter_map(|result| result.note.as_ref())
    {
        if record.notes.len() >= MAX_FUZZER_NOTES {
            break;
        }
        if !record.notes.contains(note) {
            record.notes.push(note.clone());
        }
    }
    record.status = if record.results.iter().any(|result| result.note.is_some()) {
        FuzzerAttackStatus::Failed
    } else {
        FuzzerAttackStatus::Completed
    };
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
            "Fuzzer request templates cannot contain more than {MAX_FUZZER_MARKERS_PER_REQUEST} positions"
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
    url_encode: bool,
) -> Result<()> {
    for (index, payload) in payloads.iter().enumerate() {
        let request_bytes = expanded_request_size(template, payload.len(), url_encode);
        if request_bytes > MAX_FUZZER_EXPANDED_REQUEST_BYTES {
            return Err(anyhow!(
                "Fuzzer payload {index} expands the request to {request_bytes} bytes, above the {MAX_FUZZER_EXPANDED_REQUEST_BYTES} byte limit"
            ));
        }
    }
    Ok(())
}

fn expanded_request_size(
    template: &EditableRequest,
    payload_len: usize,
    url_encode: bool,
) -> usize {
    let path_payload_len = if url_encode {
        payload_len.saturating_mul(3)
    } else {
        payload_len
    };
    let host_bytes = if has_literal_host_header(template) {
        template.host.len()
    } else {
        expanded_value_len(&template.host, payload_len)
    };
    let mut bytes = expanded_value_len(&template.scheme, payload_len)
        .saturating_add(host_bytes)
        .saturating_add(expanded_value_len(&template.method, payload_len))
        .saturating_add(expanded_value_len(&template.path, path_payload_len))
        .saturating_add(expanded_value_len(&template.body, payload_len));

    for header in &template.headers {
        bytes = bytes
            .saturating_add(expanded_value_len(&header.name, payload_len))
            .saturating_add(expanded_value_len(&header.value, payload_len));
    }
    bytes
}

fn expanded_value_len(value: &str, payload_len: usize) -> usize {
    let (count, marked) = MARKER_REGEX
        .find_iter(value)
        .fold((0usize, 0usize), |(count, marked), found| {
            (count + 1, marked + found.len())
        });
    value
        .len()
        .saturating_sub(marked)
        .saturating_add(count.saturating_mul(payload_len))
}

#[cfg(test)]
fn apply_payload_to_request(template: &EditableRequest, payload: &str) -> Result<EditableRequest> {
    build_request(template, payload, None, false)
}

/// One request of an attack: the payload goes into `position`, or into every
/// position for Battering ram (`None`), and the other positions keep their
/// originals. Positions count in request order: method, path, the authority
/// when no Host header names it, headers, body.
pub(crate) fn build_request(
    template: &EditableRequest,
    payload: &str,
    position: Option<usize>,
    url_encode: bool,
) -> Result<EditableRequest> {
    let mut next = 0usize;
    let mut fill = |value: &str, in_url: bool| -> String {
        MARKER_REGEX
            .replace_all(value, |captures: &regex::Captures<'_>| {
                let here = next;
                next += 1;
                if position.is_none_or(|position| position == here) {
                    if in_url && url_encode {
                        encode_url_payload(payload)
                    } else {
                        payload.to_string()
                    }
                } else {
                    captures
                        .get(1)
                        .map_or_else(String::new, |original| original.as_str().to_string())
                }
            })
            .into_owned()
    };
    let mut request = template.clone();
    request.method = fill(&request.method, false);
    request.path = fill(&request.path, true);
    if !has_literal_host_header(&request) {
        request.host = fill(&request.host, false);
    }
    for header in &mut request.headers {
        header.name = fill(&header.name, false);
        header.value = fill(&header.value, false);
    }
    request.body = fill(&request.body, false);
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

/// What a payload cannot carry raw in a request target, or what would end its
/// value early, is percent-encoded, as Burp does by default. `%` stays, so a
/// list of payloads encoded already still works, and so do `/` and `.`.
fn encode_url_payload(payload: &str) -> String {
    let mut encoded = String::with_capacity(payload.len());
    for byte in payload.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~!$'()*,/:@%".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
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
        crate::api::validate_editable_request(&applied).unwrap();
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

    fn query_template(path: &str) -> EditableRequest {
        EditableRequest {
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            method: "GET".to_string(),
            path: path.to_string(),
            headers: vec![HeaderRecord {
                name: "Host".to_string(),
                value: "example.com".to_string(),
            }],
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        }
    }

    #[test]
    fn sniper_fills_one_position_and_keeps_every_other_original() {
        let template = query_template("/search?q=§test§&page=§1§");
        assert_eq!(count_request_markers(&template), 2);
        let first = build_request(&template, "x", Some(0), false).unwrap();
        assert_eq!(first.path, "/search?q=x&page=1");
        let second = build_request(&template, "x", Some(1), false).unwrap();
        assert_eq!(second.path, "/search?q=test&page=x");
        let every = build_request(&template, "x", None, false).unwrap();
        assert_eq!(every.path, "/search?q=x&page=x", "Battering ram");
    }

    #[test]
    fn a_payload_marker_is_a_position_with_no_original() {
        let template = query_template("/a/$payload$?q=§test§");
        assert_eq!(
            build_request(&template, "x", Some(1), false).unwrap().path,
            "/a/?q=x"
        );
        assert_eq!(
            build_request(&template, "x", None, false).unwrap().path,
            "/a/x?q=x"
        );
    }

    #[test]
    fn url_encoding_keeps_a_payload_one_value_and_only_in_the_url() {
        let mut template = query_template("/p?q=§§&n=1");
        template.method = "POST".to_string();
        template.body = "{\"v\":\"§§\"}".to_string();
        let payload = "../a b&c=d%27\"<x>#";
        let built = build_request(&template, payload, None, true).unwrap();
        assert_eq!(built.path, "/p?q=../a%20b%26c%3Dd%27%22%3Cx%3E%23&n=1");
        assert_eq!(built.body, format!("{{\"v\":\"{payload}\"}}"));
        assert_eq!(
            build_request(&template, "a b", None, false).unwrap().path,
            "/p?q=a b&n=1"
        );
        assert_eq!(
            build_request(&template, "é", None, true).unwrap().path,
            "/p?q=%C3%A9&n=1"
        );
    }

    #[test]
    fn sniper_plans_each_position_in_turn_with_every_payload() {
        assert_eq!(
            plan_requests(FuzzerAttackType::Sniper, 2, 3),
            vec![
                (Some(0), 0),
                (Some(0), 1),
                (Some(0), 2),
                (Some(1), 0),
                (Some(1), 1),
                (Some(1), 2)
            ]
        );
        assert_eq!(
            plan_requests(FuzzerAttackType::BatteringRam, 2, 3),
            vec![(None, 0), (None, 1), (None, 2)]
        );
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
            body: "$payload$".repeat(MAX_FUZZER_MARKERS_PER_REQUEST + 1),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        assert!(validate_marker_count(count_request_markers(&request))
            .unwrap_err()
            .to_string()
            .contains("positions"));

        let marker_count = (MAX_FUZZER_EXPANDED_REQUEST_BYTES / MAX_FUZZER_PAYLOAD_BYTES) + 1;
        assert!(marker_count <= MAX_FUZZER_MARKERS_PER_REQUEST);
        request.body = "$payload$".repeat(marker_count);
        let payloads = vec!["x".repeat(MAX_FUZZER_PAYLOAD_BYTES)];
        assert!(
            validate_fuzzer_expanded_request_budget(&request, &payloads, false)
                .unwrap_err()
                .to_string()
                .contains("expands the request")
        );
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
        let options = FuzzerAttackOptions {
            attack_type: FuzzerAttackType::BatteringRam,
            url_encode: true,
            concurrency: 1,
        };
        let error = plan_attack(&request, vec!["demo".to_string()], options)
            .err()
            .expect("authority-only marker should be ignored by the fixed Host header");

        assert!(error.to_string().contains("Mark at least one position"));
    }

    #[test]
    fn host_header_override_excludes_authority_markers_from_expansion_budget() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "$payload$".repeat(MAX_FUZZER_MARKERS_PER_REQUEST),
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
        validate_fuzzer_expanded_request_budget(&request, std::slice::from_ref(&payload), false)
            .unwrap();
        let applied = apply_payload_to_request(&request, &payload).unwrap();

        assert!(applied.host.starts_with("header-dddd"));
        assert!(applied.host.ends_with(".example.com"));
    }

    /// Starts an attack as the Fuzzer used to send one (every position at
    /// once, payloads as they are, one request at a time) and waits for it.
    async fn run_to_end(
        state: Arc<AppState>,
        session: Arc<crate::session::SessionContext>,
        template: EditableRequest,
        payloads: Vec<String>,
        http_version: Option<String>,
    ) -> FuzzerAttackRecord {
        let options = FuzzerAttackOptions {
            attack_type: FuzzerAttackType::BatteringRam,
            url_encode: false,
            concurrency: 1,
        };
        let started = start_attack(
            state,
            Arc::clone(&session),
            template,
            payloads,
            None,
            http_version,
            None,
            options,
        )
        .await
        .unwrap();
        wait_for_end(&session, started.id).await
    }

    async fn wait_for_end(
        session: &crate::session::SessionContext,
        id: Uuid,
    ) -> FuzzerAttackRecord {
        for _ in 0..1000 {
            let record = session.fuzzer.get(id).await.unwrap();
            if !record.running {
                return record;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the attack did not end");
    }

    /// A loopback upstream that answers every request with 200 after `delay`.
    async fn upstream(delay: Duration) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buffer = [0u8; 4096];
                    let _ = stream.read(&mut buffer).await;
                    tokio::time::sleep(delay).await;
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                        )
                        .await;
                });
            }
        });
        addr
    }

    async fn scratch_state(
        name: &str,
    ) -> (
        Arc<AppState>,
        Arc<crate::session::SessionContext>,
        std::path::PathBuf,
    ) {
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 32,
            max_transaction_entries: 32,
            body_preview_bytes: 4096,
            data_dir: std::env::temp_dir().join(format!("sniper-fuzzer-{name}-{}", Uuid::new_v4())),
        };
        let data_dir = config.data_dir.clone();
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        (state, session, data_dir)
    }

    fn local_template(addr: std::net::SocketAddr, path: &str) -> EditableRequest {
        EditableRequest {
            scheme: "http".to_string(),
            host: addr.to_string(),
            method: "GET".to_string(),
            path: path.to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        }
    }

    #[tokio::test]
    async fn running_attack_checkpoint_keeps_partial_results_without_stopping_the_worker() {
        let store = FuzzerStore::new(4);
        let started_at = Utc::now();
        let id = Uuid::new_v4();
        let transaction_id = Uuid::new_v4();
        let record = FuzzerAttackRecord {
            id,
            started_at,
            completed_at: started_at,
            status: FuzzerAttackStatus::Completed,
            template: local_template("127.0.0.1:1".parse().unwrap(), "/$payload$"),
            payload_count: 3,
            marker_count: 1,
            results: vec![
                FuzzerAttackResult {
                    index: 1,
                    payload: "invalid".to_string(),
                    transaction_id: None,
                    status: None,
                    duration_ms: None,
                    response_bytes: 0,
                    note: Some("Not sent: synthetic invalid request".to_string()),
                    position: None,
                },
                FuzzerAttackResult {
                    index: 0,
                    payload: "ok".to_string(),
                    transaction_id: Some(transaction_id),
                    status: Some(200),
                    duration_ms: Some(1),
                    response_bytes: 2,
                    note: None,
                    position: None,
                },
            ],
            notes: Vec::new(),
            attack_type: FuzzerAttackType::BatteringRam,
            url_encode: true,
            planned: 3,
            concurrency: 2,
            running: true,
            stopped: false,
        };
        store.insert(record).await;
        assert!(store.snapshot(Some(0)).await.is_empty());
        let checkpoint = store.snapshot(None).await;
        assert_eq!(
            checkpoint.len(),
            1,
            "completed partial work must not be omitted"
        );
        let saved = &checkpoint[0];
        assert_eq!(saved.id, id);
        assert!(!saved.running);
        assert!(saved.stopped);
        assert_eq!(saved.planned, 3);
        assert_eq!(saved.results.len(), 2);
        assert_eq!(saved.results[0].transaction_id, Some(transaction_id));
        assert_eq!(saved.results[1].index, 1);
        assert_eq!(saved.status, FuzzerAttackStatus::Failed);
        assert_eq!(saved.notes, ["Not sent: synthetic invalid request"]);

        let live = store.get(id).await.unwrap();
        assert!(live.running, "checkpointing must not cancel a live attack");
        assert!(!live.stopped);
        assert_eq!(live.results[0].index, 1, "only the checkpoint is sorted");
        assert!(live.notes.is_empty());

        let bytes = serde_json::to_vec(&checkpoint).unwrap();
        let restored = FuzzerStore::from_attacks(4, serde_json::from_slice(&bytes).unwrap());
        assert!(!restored.is_running());
        let restored = restored.get(id).await.unwrap();
        assert!(!restored.running);
        assert!(restored.stopped);
        assert_eq!(restored.results[0].transaction_id, Some(transaction_id));
    }

    #[tokio::test]
    #[ignore = "synthetic checkpoint allocation and timing qualification"]
    async fn large_running_attack_checkpoint_qualification() {
        let count = 16_384;
        let mut record: FuzzerAttackRecord = serde_json::from_value(serde_json::json!({
            "id": Uuid::new_v4(),
            "started_at": Utc::now(),
            "completed_at": Utc::now(),
            "status": "completed",
            "template": local_template("127.0.0.1:1".parse().unwrap(), "/$payload$"),
            "running": true,
            "planned": count + 1
        }))
        .unwrap();
        record.results = (0..count)
            .rev()
            .map(|index| FuzzerAttackResult {
                index,
                payload: "x".repeat(1024),
                transaction_id: None,
                status: Some(200),
                duration_ms: Some(1),
                response_bytes: 2,
                note: None,
                position: None,
            })
            .collect();
        let store = FuzzerStore::new(1);
        store.insert(record).await;
        let start = std::time::Instant::now();
        let checkpoint = store.snapshot(None).await;
        let snapshot_ms = start.elapsed().as_millis();
        let start = std::time::Instant::now();
        let bytes = serde_json::to_vec(&checkpoint).unwrap();
        println!(
            "checkpoint results={count} payload_bytes={} serialized_bytes={} snapshot_ms={snapshot_ms} serialize_ms={}",
            count * 1024,
            bytes.len(),
            start.elapsed().as_millis()
        );
        assert_eq!(checkpoint[0].results.len(), count);
        assert_eq!(checkpoint[0].results[0].index, 0);
        assert!(checkpoint[0].stopped);
        assert!(store.get(checkpoint[0].id).await.unwrap().running);
    }

    #[tokio::test]
    async fn completed_fuzzer_results_are_checkpointed_before_the_next_request_finishes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (second_started, second_waiting) = tokio::sync::oneshot::channel();
        let upstream = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            let mut buffer = [0; 1024];
            first.read(&mut buffer).await.unwrap();
            first
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .await
                .unwrap();
            drop(first);
            let (mut second, _) = listener.accept().await.unwrap();
            second.read(&mut buffer).await.unwrap();
            second_started.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        let (state, session, data_dir) = scratch_state("checkpoint-restart").await;
        let config = state.config.clone();
        let started = start_attack(
            Arc::clone(&state),
            Arc::clone(&session),
            local_template(addr, "/$payload$"),
            vec!["completed".to_string(), "waiting".to_string()],
            None,
            None,
            None,
            FuzzerAttackOptions {
                attack_type: FuzzerAttackType::BatteringRam,
                url_encode: true,
                concurrency: 1,
            },
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(5), second_waiting)
            .await
            .unwrap()
            .unwrap();
        let state_path = session.storage_dir().join("state.json");
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(bytes) = std::fs::read(&state_path) {
                    let saved: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                    if saved["fuzzer_attacks"][0]["results"]
                        .as_array()
                        .is_some_and(|results| results.len() == 1)
                    {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the completed result should be saved while the next request is waiting");
        assert!(session.fuzzer.get(started.id).await.unwrap().running);

        // No graceful stop/final save: model a worker lost after its checkpoint.
        let running = session.fuzzer.running.lock().unwrap().take().unwrap();
        running.task.abort();
        let _ = running.task.await;
        upstream.abort();
        let _ = upstream.await;
        drop(session);
        drop(state);
        let reopened = AppState::new(config).unwrap();
        let restored_session = reopened.session().await;
        let restored = restored_session.fuzzer.get(started.id).await.unwrap();
        assert!(!restored.running);
        assert!(restored.stopped);
        assert_eq!(restored.planned, 2);
        assert_eq!(restored.results.len(), 1);
        assert_eq!(restored.results[0].payload, "completed");
        let transaction_id = restored.results[0].transaction_id.unwrap();
        assert!(restored_session.store.get(transaction_id).await.is_some());
        assert!(!restored_session.fuzzer.is_running());
        drop(restored_session);
        drop(reopened);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn sniper_runs_in_the_background_and_ends_with_each_position_in_order() {
        let addr = upstream(Duration::ZERO).await;
        let (state, session, data_dir) = scratch_state("sniper").await;
        let options = FuzzerAttackOptions {
            attack_type: FuzzerAttackType::Sniper,
            url_encode: true,
            concurrency: 2,
        };
        let started = start_attack(
            state,
            Arc::clone(&session),
            local_template(addr, "/search?q=§test§&page=§1§"),
            vec!["a b".to_string(), "x".to_string()],
            None,
            None,
            None,
            options,
        )
        .await
        .unwrap();
        assert!(started.running);
        assert_eq!(started.planned, 4);
        let checkpoint = session.fuzzer.snapshot(None).await;
        assert_eq!(checkpoint.len(), 1);
        assert!(!checkpoint[0].running);
        assert!(checkpoint[0].stopped);

        let attack = wait_for_end(&session, started.id).await;
        assert_eq!(attack.status, FuzzerAttackStatus::Completed);
        let order: Vec<_> = attack
            .results
            .iter()
            .map(|result| (result.index, result.position))
            .collect();
        assert_eq!(
            order,
            [(0, Some(0)), (1, Some(0)), (2, Some(1)), (3, Some(1))]
        );
        let records = session.store.snapshot(Some(10)).await;
        let paths: std::collections::BTreeSet<_> =
            records.iter().map(|record| record.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "/search?q=a%20b&page=1",
                "/search?q=test&page=a%20b",
                "/search?q=test&page=x",
                "/search?q=x&page=1",
            ]
            .into_iter()
            .collect()
        );
        assert!(records.iter().all(|record| record
            .notes
            .iter()
            .any(|note| note == crate::model::FUZZER_NOTE)));
        assert!(
            session
                .event_log
                .snapshot(None)
                .await
                .iter()
                .all(|entry| entry.source != "replay"),
            "the attack logs itself, not each of its requests"
        );
        assert_eq!(session.fuzzer.snapshot(None).await.len(), 1);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn a_payload_that_breaks_the_request_is_a_result_and_the_rest_are_sent() {
        let addr = upstream(Duration::ZERO).await;
        let (state, session, data_dir) = scratch_state("unsendable").await;
        let options = FuzzerAttackOptions {
            attack_type: FuzzerAttackType::BatteringRam,
            url_encode: false,
            concurrency: 1,
        };
        let started = start_attack(
            state,
            Arc::clone(&session),
            local_template(addr, "/$payload$"),
            vec!["ok".to_string(), "bad path".to_string(), "fine".to_string()],
            None,
            None,
            None,
            options,
        )
        .await
        .unwrap();

        let attack = wait_for_end(&session, started.id).await;
        assert_eq!(attack.status, FuzzerAttackStatus::Failed);
        let broken = &attack.results[1];
        assert_eq!(broken.transaction_id, None);
        assert!(broken.note.as_deref().unwrap().starts_with("Not sent:"));
        assert_eq!(
            [attack.results[0].status, attack.results[2].status],
            [Some(200), Some(200)]
        );
        assert_eq!(attack.notes.len(), 1);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn a_stopped_attack_ends_at_once_and_a_session_runs_one_at_a_time() {
        let addr = upstream(Duration::from_millis(200)).await;
        let (state, session, data_dir) = scratch_state("stop").await;
        let options = FuzzerAttackOptions {
            attack_type: FuzzerAttackType::BatteringRam,
            url_encode: true,
            concurrency: 1,
        };
        let payloads: Vec<String> = (0..20).map(|index| format!("p{index}")).collect();
        let template = local_template(addr, "/$payload$");
        let started = start_attack(
            Arc::clone(&state),
            Arc::clone(&session),
            template.clone(),
            payloads.clone(),
            None,
            None,
            None,
            options,
        )
        .await
        .unwrap();
        let second = start_attack(
            state,
            Arc::clone(&session),
            template,
            payloads,
            None,
            None,
            None,
            options,
        )
        .await;
        assert_eq!(second.unwrap_err(), FuzzerStartError::Busy);

        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(session.fuzzer.stop(Some(started.id)).await);
        let attack = session.fuzzer.get(started.id).await.unwrap();
        assert!(!attack.running);
        assert!(attack.stopped);
        assert!(attack.results.len() < 20);
        assert!(!session.fuzzer.is_running());
        assert!(
            !session.fuzzer.stop(Some(started.id)).await,
            "nothing left to stop"
        );
        let _ = std::fs::remove_dir_all(data_dir);
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

        let attack = run_to_end(
            state,
            session.clone(),
            request,
            vec!["forced".to_string()],
            Some("HTTP/2".to_string()),
        )
        .await;
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

        let attack = run_to_end(
            state,
            session.clone(),
            request,
            vec!["payload".to_string()],
            None,
        )
        .await;

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
                attack_type: Default::default(),
                url_encode: false,
                planned: 0,
                concurrency: 1,
                running: false,
                stopped: false,
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
