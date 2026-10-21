//! Template Scan: templates the operator picks, sent to targets they name,
//! when they ask. Every target and every redirect hop must be in a Scope the
//! operator set, nothing goes to Sniper's own listeners, a job paces itself
//! and stops when asked, and the history keeps only the exchanges a template
//! matched. The job log keeps one line for each of the rest.

use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{broadcast, watch},
    task::JoinHandle,
    time::Instant,
};
use url::Url;
use uuid::Uuid;

use super::{
    active::{self, ActiveTemplate, Follow},
    engine::{Interaction, ResponseView, TemplateMatch, UrlVars, MAX_ACTIVE_BODY_BYTES},
    library::{ListQuery, TemplateMeta},
    model::RISK_TAGS,
};
use crate::{
    event_log::EventLevel,
    model::{BodyEncoding, EditableRequest, HeaderRecord, TransactionRecord},
    oast::OastCallback,
    proxy::TemplateScanSendError,
    session::SessionContext,
    state::AppState,
};

const MAX_TARGETS: usize = 20;
const MAX_TARGET_BYTES: usize = 2_048;
const MAX_JOBS: usize = 10;
const MAX_RESULTS: usize = 1_000;
const MAX_RECENT: usize = 200;
const MAX_WARNINGS: usize = 20;
/// A target that fails this many requests in a row is down or refusing the
/// scan; the rest of its requests are not sent.
const MAX_CONSECUTIVE_FAILURES: usize = 20;
/// How long a stop waits for requests in flight before cutting them off.
const STOP_GRACE: Duration = Duration::from_secs(5);
const MAX_MAX_REQUESTS: usize = 50_000;
const OAST_UNAVAILABLE: &str =
    "they need an Interactsh server to hear their callbacks; set one up in Capture ▸ OAST.";
/// How long an answer waits for its request's callback, as Nuclei's
/// eviction; and how many wait at once, the oldest giving way.
const OAST_WAIT: Duration = Duration::from_secs(60);
// ponytail: a count cap like Nuclei's 5,000-entry cache, so held answers can
// add up to that many bodies; bound bytes instead if large pages make it hurt.
const MAX_OAST_WAITING: usize = 5_000;
/// Callbacks kept for a request whose answer has not come back yet.
const MAX_EARLY_CALLBACKS: usize = 8;
/// Risks an operator may allow one by one. `dos` is never sent.
const METHOD_RISKS: &[&str] = &["method:put", "method:delete", "method:patch"];
/// Sent unless a template names its own: a browser-like agent that still
/// says what is asking.
const USER_AGENT: &str = concat!(
    "Mozilla/5.0 (compatible; Sniper/",
    env!("CARGO_PKG_VERSION"),
    ")"
);

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TemplateScanSnapshot {
    pub jobs: Vec<ScanJob>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanJob {
    pub id: Uuid,
    /// `running`, `completed`, `cancelled` or `interrupted`.
    pub status: String,
    pub started_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<DateTime<Utc>>,
    pub targets: Vec<String>,
    /// The release the templates came from: tag and archive hash.
    pub library: String,
    pub templates: usize,
    /// Requests the templates send before any redirect.
    pub planned: usize,
    pub sent: usize,
    /// Requests that got no response.
    pub failed: usize,
    /// Requests not sent: a Match & Replace rule would have changed where
    /// they went, or their host left Scope.
    pub blocked: usize,
    /// Redirects not followed because they led out of Scope or to Sniper.
    pub redirects_not_followed: usize,
    pub matched: usize,
    pub rate: u32,
    pub concurrency: usize,
    pub max_requests: usize,
    pub allow_risks: Vec<String>,
    pub apply_match_replace: bool,
    pub skipped_targets: Vec<String>,
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub results: Vec<ScanResult>,
    /// The latest requests, newest last: what was asked and what came back.
    #[serde(skip_serializing_if = "VecDeque::is_empty")]
    pub recent: VecDeque<ScanLogEntry>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanResult {
    pub at: DateTime<Utc>,
    pub template_id: String,
    pub name: String,
    pub severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matcher: Option<String>,
    pub method: String,
    pub url: String,
    /// The matched exchange in HTTP history.
    pub record_id: Uuid,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub evidence: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanLogEntry {
    pub at: DateTime<Utc>,
    pub template_id: String,
    pub method: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    pub ms: u64,
    pub matched: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ScanJob {
    /// The job without its result and request lists, for listing.
    fn summary(mut self) -> Self {
        self.results = Vec::new();
        self.recent = VecDeque::new();
        self
    }

    fn warn(&mut self, warning: String) {
        if self.warnings.len() < MAX_WARNINGS && !self.warnings.contains(&warning) {
            self.warnings.push(warning);
        }
    }

    fn log(&mut self, entry: ScanLogEntry) {
        if self.recent.len() >= MAX_RECENT {
            self.recent.pop_front();
        }
        self.recent.push_back(entry);
    }
}

struct RunningScan {
    id: Uuid,
    cancel: watch::Sender<bool>,
    task: JoinHandle<()>,
}

pub struct TemplateScanStore {
    snapshot: Mutex<TemplateScanSnapshot>,
    running: Mutex<Option<RunningScan>>,
}

impl TemplateScanStore {
    pub fn from_snapshot(mut snapshot: TemplateScanSnapshot) -> Self {
        // A restart does not resume sending; it says the job did not finish.
        for job in &mut snapshot.jobs {
            if job.status == "running" {
                job.status = "interrupted".into();
                job.finished_at = Some(Utc::now());
            }
        }
        Self {
            snapshot: Mutex::new(snapshot),
            running: Mutex::new(None),
        }
    }

    pub fn snapshot(&self) -> TemplateScanSnapshot {
        self.snapshot.lock().unwrap().clone()
    }

    pub fn is_running(&self) -> bool {
        self.snapshot
            .lock()
            .unwrap()
            .jobs
            .iter()
            .any(|job| job.status == "running")
    }

    fn update(&self, id: Uuid, change: impl FnOnce(&mut ScanJob)) {
        if let Some(job) = self
            .snapshot
            .lock()
            .unwrap()
            .jobs
            .iter_mut()
            .find(|job| job.id == id)
        {
            change(job);
        }
    }

    /// Stops the running job (that one only, when `id` is given). Requests in
    /// flight are dropped at once; a match being stored is finished, unless
    /// it takes longer than the grace period. True when a job was running.
    pub async fn stop(&self, id: Option<Uuid>) -> bool {
        let running = {
            let mut guard = self.running.lock().unwrap();
            if id.is_some_and(|id| guard.as_ref().is_none_or(|job| job.id != id)) {
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
        // No worker writes after this returns; one that was aborted could not
        // mark its job.
        self.update(running.id, |job| {
            if job.status == "running" {
                job.status = "cancelled".into();
                job.finished_at = Some(Utc::now());
            }
        });
        true
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartScan {
    pub session_id: Uuid,
    pub targets: Vec<String>,
    /// Templates by id; or `filter`, as the template list takes it.
    #[serde(default)]
    pub ids: Vec<String>,
    #[serde(default)]
    pub filter: Option<ListQuery>,
    #[serde(default)]
    pub allow_risks: Vec<String>,
    #[serde(default = "default_rate")]
    pub rate: u32,
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    #[serde(default = "default_max_requests")]
    pub max_requests: usize,
    #[serde(default)]
    pub apply_match_replace: bool,
    #[serde(default)]
    pub acknowledged: bool,
    /// Count what would be sent, and send nothing.
    #[serde(default)]
    pub preview: bool,
}

fn default_rate() -> u32 {
    10
}
fn default_concurrency() -> usize {
    4
}
fn default_max_requests() -> usize {
    active::MAX_TEMPLATE_REQUESTS
}

/// A target as the operator named it: an origin, and optionally a path the
/// application lives under.
#[derive(Clone, Debug)]
struct ScanTarget {
    label: String,
    scheme: String,
    /// The request line's authority: the port only when not the default.
    authority: String,
    /// The host name alone, lowercase, without brackets.
    host: String,
    base_path: String,
    vars: UrlVars,
}

fn parse_target(text: &str) -> Result<ScanTarget, String> {
    let text = text.trim();
    let shape = || {
        format!("{text}: a target is an http:// or https:// origin, optionally with a path, without credentials, query or fragment.")
    };
    let url = Url::parse(text).map_err(|_| shape())?;
    if text.len() > MAX_TARGET_BYTES
        || !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || text.chars().any(char::is_control)
        || url.port_or_known_default() == Some(0)
    {
        return Err(shape());
    }
    let name = url.host_str().ok_or_else(shape)?;
    if name.contains('*') {
        return Err(format!("{text}: a target names one host, not a pattern."));
    }
    let authority = match url.port() {
        Some(port) => format!("{name}:{port}"),
        None => name.to_string(),
    };
    if crate::special_host::is_special_host(&authority) {
        return Err(format!("{text} is Sniper's own page, not a target."));
    }
    let base_path = url.path().trim_end_matches('/').to_string();
    let vars = UrlVars::of_url(&url, &base_path).ok_or_else(shape)?;
    Ok(ScanTarget {
        label: format!("{}://{authority}{base_path}", url.scheme()),
        scheme: url.scheme().to_string(),
        host: name
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase(),
        authority,
        base_path,
        vars,
    })
}

fn parse_targets(texts: &[String]) -> Result<Vec<ScanTarget>, String> {
    if texts.is_empty() || texts.len() > MAX_TARGETS {
        return Err(format!("Name between 1 and {MAX_TARGETS} targets."));
    }
    let mut seen = HashSet::new();
    let mut targets = Vec::new();
    for text in texts {
        let target = parse_target(text)?;
        if seen.insert(target.label.clone()) {
            targets.push(target);
        }
    }
    Ok(targets)
}

fn parse_risks(names: &[String]) -> Result<HashSet<String>, String> {
    let mut allowed = HashSet::new();
    for name in names {
        let name = name.trim().to_ascii_lowercase();
        if name == "dos" {
            return Err("Templates tagged dos are never sent.".into());
        }
        if !(RISK_TAGS.contains(&name.as_str()) || METHOD_RISKS.contains(&name.as_str())) {
            return Err(format!(
                "Unknown risk {name}. Allowable: {}, {}.",
                RISK_TAGS
                    .iter()
                    .filter(|tag| **tag != "dos")
                    .copied()
                    .collect::<Vec<_>>()
                    .join(", "),
                METHOD_RISKS.join(", ")
            ));
        }
        allowed.insert(name);
    }
    Ok(allowed)
}

/// Leaves out templates with a risk the operator did not allow, counting
/// them by the first such risk.
fn apply_risks(
    metas: Vec<TemplateMeta>,
    allowed: &HashSet<String>,
) -> (Vec<TemplateMeta>, BTreeMap<String, usize>) {
    let mut excluded: BTreeMap<String, usize> = BTreeMap::new();
    let kept = metas
        .into_iter()
        .filter(|meta| {
            match meta
                .risks
                .iter()
                .find(|risk| *risk == "dos" || !allowed.contains(risk.as_str()))
            {
                Some(risk) => {
                    *excluded.entry(risk.clone()).or_default() += 1;
                    false
                }
                None => true,
            }
        })
        .collect();
    (kept, excluded)
}

type ApiError = (StatusCode, Json<serde_json::Value>);

fn api_error(status: StatusCode, message: &str) -> ApiError {
    (status, Json(serde_json::json!({"error": message})))
}

fn bad_request(message: impl AsRef<str>) -> ApiError {
    api_error(StatusCode::BAD_REQUEST, message.as_ref())
}

/// Only a missing session is "not found"; one that failed to load is not a
/// wrong id.
fn session_load_error(error: anyhow::Error) -> ApiError {
    if error.to_string().contains("was not found") {
        return api_error(StatusCode::NOT_FOUND, "Session not found.");
    }
    tracing::warn!(%error, "failed to load session for Template Scan");
    api_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Session could not be loaded.",
    )
}

#[derive(Deserialize)]
pub struct SessionQuery {
    pub session_id: Uuid,
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let session = state
        .read_session_context_for_id(query.session_id)
        .await
        .map_err(session_load_error)?;
    let jobs: Vec<ScanJob> = session
        .template_scans
        .snapshot()
        .jobs
        .into_iter()
        .rev()
        .map(ScanJob::summary)
        .collect();
    Ok(Json(
        serde_json::json!({"session_id": session.id(), "jobs": jobs}),
    ))
}

pub async fn get(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Query(query): Query<SessionQuery>,
) -> Result<Json<ScanJob>, ApiError> {
    let session = state
        .read_session_context_for_id(query.session_id)
        .await
        .map_err(session_load_error)?;
    session
        .template_scans
        .snapshot()
        .jobs
        .into_iter()
        .find(|job| job.id == id)
        .map(Json)
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "Template Scan job not found."))
}

pub async fn start(
    State(state): State<Arc<AppState>>,
    Json(request): Json<StartScan>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let targets = parse_targets(&request.targets).map_err(bad_request)?;
    if !(1..=50).contains(&request.rate)
        || !(1..=8).contains(&request.concurrency)
        || !(1..=MAX_MAX_REQUESTS).contains(&request.max_requests)
    {
        return Err(bad_request(format!(
            "Limits: rate 1–50 requests a second, concurrency 1–8, max_requests 1–{MAX_MAX_REQUESTS}."
        )));
    }
    let allowed = parse_risks(&request.allow_risks).map_err(bad_request)?;
    let (metas, ignored) = match (request.ids.is_empty(), &request.filter) {
        (false, None) => state.templates.active_selection(&request.ids, None),
        (true, Some(filter)) => state.templates.active_selection(&[], Some(filter)),
        _ => {
            return Err(bad_request(
                "Choose templates either by ids or by a filter.",
            ))
        }
    };
    let (mut metas, excluded_by_risk) = apply_risks(metas, &allowed);

    let session = state
        .session_context_for_id(request.session_id)
        .await
        .map_err(session_load_error)?;
    // An OAST template's callback goes to the session's Interactsh server;
    // with none registered nothing would hear it, so it is not sent.
    let oast = session
        .oast
        .get_registration_info()
        .await
        .map(|(correlation_id, domain)| active::OastUrls {
            correlation_id,
            domain,
        });
    let oast_unavailable = if oast.is_none() {
        let before = metas.len();
        metas.retain(|meta| !meta.oast);
        before - metas.len()
    } else {
        0
    };
    let planned = metas.iter().map(|meta| meta.requests).sum::<usize>() * targets.len();
    let (include, exclude) = session.runtime.scope_lists().await;
    if include.is_empty() {
        return Err(bad_request(
            "Scope has no include patterns. Template Scan sends only to hosts in Scope; add the hosts you test there.",
        ));
    }
    for target in &targets {
        if !crate::scope::is_host_in_scope(&target.authority, &include, &exclude) {
            return Err(bad_request(format!("{} is not in Scope.", target.label)));
        }
        if crate::proxy::targets_own_listener(&state, &session, &target.scheme, &target.authority)
            .await
        {
            return Err(bad_request(format!(
                "{} is one of Sniper's own listeners.",
                target.label
            )));
        }
    }
    let labels: Vec<String> = targets.iter().map(|target| target.label.clone()).collect();
    if request.preview {
        return Ok(Json(serde_json::json!({
            "preview": true,
            "session_id": session.id(),
            "targets": labels,
            "templates": metas.len(),
            "requests": planned,
            "max_requests": request.max_requests,
            "ignored_ids": ignored,
            "excluded_by_risk": excluded_by_risk,
            "oast_unavailable": oast_unavailable,
        })));
    }
    if !request.acknowledged {
        return Err(bad_request(
            "Confirm the scan: it sends the templates' requests to the targets.",
        ));
    }
    if metas.is_empty() && oast_unavailable > 0 {
        return Err(bad_request(format!(
            "The selected templates cannot be sent: {OAST_UNAVAILABLE}"
        )));
    }
    if metas.is_empty() {
        return Err(bad_request(
            "No template that can be sent matches the selection.",
        ));
    }
    if planned > request.max_requests {
        return Err(bad_request(format!(
            "This scan plans {planned} requests, more than its limit of {}. Choose fewer templates or targets, or raise the limit.",
            request.max_requests
        )));
    }

    // Compiled before the job exists, from the release the list came from.
    let library = Arc::clone(&state.templates);
    let (templates, unreadable) = tokio::task::spawn_blocking(move || {
        let mut templates = Vec::new();
        let mut unreadable = 0;
        for meta in &metas {
            match library.compile_active(meta) {
                Ok(template) => templates.push(Arc::new(template)),
                Err(_) => unreadable += 1,
            }
        }
        (templates, unreadable)
    })
    .await
    .map_err(|_| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The templates could not be read.",
        )
    })?;
    if templates.is_empty() {
        return Err(api_error(
            StatusCode::CONFLICT,
            "The template library changed; list the templates again.",
        ));
    }
    let release = state.templates.release_label().unwrap_or_default();
    let client = crate::proxy::build_template_scan_client(
        session.runtime.upstream_insecure().await,
        &session.runtime.upstream_proxy().await,
    )
    .map_err(|_| bad_request("The upstream proxy settings could not be used."))?;

    let operation_lock = state.session_operation_lock(session.id()).await;
    let _operation_guard = operation_lock.lock_owned().await;
    if !state.sessions.contains_session(session.id())
        || !state.is_current_session_context(&session).await
    {
        return Err(api_error(
            StatusCode::CONFLICT,
            "Session changed or was deleted; reload Templates.",
        ));
    }
    let _guard = session.owned_mutation_guard().await;
    if session.template_scans.is_running() {
        return Err(api_error(
            StatusCode::CONFLICT,
            "A Template Scan is already running in this session.",
        ));
    }
    let mut allow_risks: Vec<String> = allowed.into_iter().collect();
    allow_risks.sort();
    let planned = templates
        .iter()
        .map(|template| template.request_count())
        .sum::<usize>()
        * targets.len();
    let mut job = ScanJob {
        id: Uuid::new_v4(),
        status: "running".into(),
        started_at: Utc::now(),
        targets: labels,
        library: release.clone(),
        templates: templates.len(),
        planned,
        rate: request.rate,
        concurrency: request.concurrency,
        max_requests: request.max_requests,
        allow_risks,
        apply_match_replace: request.apply_match_replace,
        ..ScanJob::default()
    };
    if unreadable > 0 {
        job.warn(format!(
            "{unreadable} templates could not be read from the library and were not sent."
        ));
    }
    if oast_unavailable > 0 {
        job.warn(format!(
            "{oast_unavailable} templates were not sent: {OAST_UNAVAILABLE}"
        ));
    }
    {
        let mut snapshot = session.template_scans.snapshot.lock().unwrap();
        if snapshot.jobs.len() >= MAX_JOBS {
            snapshot.jobs.remove(0);
        }
        snapshot.jobs.push(job.clone());
    }
    session.schedule_state_persist();
    session
        .event_log
        .push(
            EventLevel::Info,
            "templates",
            "Template Scan started",
            format!(
                "{} templates, {} targets, {} requests planned",
                job.templates,
                job.targets.len(),
                job.planned
            ),
        )
        .await;
    let (cancel, cancelled) = watch::channel(false);
    let oast = oast
        .filter(|_| templates.iter().any(|template| template.oast))
        .map(|urls| OastWatch {
            urls,
            pending: Mutex::default(),
        });
    let run = Arc::new(Run {
        state: Arc::clone(&state),
        session: Arc::clone(&session),
        job: job.id,
        library: release,
        oast,
        failures: targets.iter().map(|_| AtomicUsize::new(0)).collect(),
        skipped: targets.iter().map(|_| AtomicBool::new(false)).collect(),
        templates,
        targets,
        client,
        apply_match_replace: request.apply_match_replace,
        max_requests: request.max_requests,
        concurrency: request.concurrency,
        gap: Duration::from_secs(1) / request.rate,
        next_slot: tokio::sync::Mutex::new(Instant::now()),
        sent: AtomicUsize::new(0),
        limit_reached: AtomicBool::new(false),
    });
    let task = tokio::spawn(run.execute(cancelled));
    *session.template_scans.running.lock().unwrap() = Some(RunningScan {
        id: job.id,
        cancel,
        task,
    });
    Ok(Json(
        serde_json::to_value(job.summary()).unwrap_or_default(),
    ))
}

pub async fn stop(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(query): Json<SessionQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let session = state
        .session_context_for_id(query.session_id)
        .await
        .map_err(session_load_error)?;
    let operation_lock = state.session_operation_lock(session.id()).await;
    let _operation_guard = operation_lock.lock_owned().await;
    if !state.sessions.contains_session(session.id())
        || !state.is_current_session_context(&session).await
    {
        return Err(api_error(
            StatusCode::CONFLICT,
            "Session changed or was deleted.",
        ));
    }
    // Not under the mutation guard: a worker storing a match persists the
    // session, which takes it.
    if !session.template_scans.stop(Some(id)).await {
        return Err(api_error(
            StatusCode::NOT_FOUND,
            "No running Template Scan job has this id.",
        ));
    }
    session.schedule_state_persist();
    Ok(Json(
        serde_json::json!({"stopped": true, "session_id": session.id()}),
    ))
}

/// One running job: what it sends, where, and how fast.
struct Run {
    state: Arc<AppState>,
    session: Arc<SessionContext>,
    job: Uuid,
    library: String,
    /// Set when the scan sends OAST templates.
    oast: Option<OastWatch>,
    templates: Vec<Arc<ActiveTemplate>>,
    targets: Vec<ScanTarget>,
    client: reqwest::Client,
    apply_match_replace: bool,
    max_requests: usize,
    concurrency: usize,
    /// Time between two requests, across all workers.
    gap: Duration,
    next_slot: tokio::sync::Mutex<Instant>,
    sent: AtomicUsize,
    limit_reached: AtomicBool,
    /// Consecutive failures, and whether the target is given up, by target.
    failures: Vec<AtomicUsize>,
    skipped: Vec<AtomicBool>,
}

/// The session's Interactsh server a scan's OAST markers point at, and the
/// answers waiting to hear a callback, by the id of the URL they sent.
struct OastWatch {
    urls: active::OastUrls,
    pending: Mutex<HashMap<String, Pending>>,
}

enum Pending {
    /// Callbacks that came before the answer to their request did.
    Early(Instant, Vec<OastCallback>),
    Answered(Instant, Arc<Waiting>),
}

impl Pending {
    fn since(&self) -> Instant {
        match self {
            Pending::Early(since, _) | Pending::Answered(since, _) => *since,
        }
    }
}

/// An answer judged again when its request's callback comes.
struct Waiting {
    template: Arc<ActiveTemplate>,
    target: usize,
    hop: Hop,
    values: HashMap<String, String>,
    number: usize,
    history: Vec<Option<Arc<ResponseView>>>,
    reported: AtomicBool,
}

impl OastWatch {
    /// Notes the ids a request is about to send, so a callback that beats
    /// its answer is kept for it.
    fn expect(&self, ids: &[String]) {
        let mut pending = self.pending.lock().unwrap();
        pending.retain(|_, entry| entry.since().elapsed() < OAST_WAIT);
        for id in ids {
            while pending.len() >= MAX_OAST_WAITING {
                let Some(oldest) = pending
                    .iter()
                    .min_by_key(|(_, entry)| entry.since())
                    .map(|(id, _)| id.clone())
                else {
                    break;
                };
                pending.remove(&oldest);
            }
            pending
                .entry(id.clone())
                .or_insert_with(|| Pending::Early(Instant::now(), Vec::new()));
        }
    }

    /// Stops waiting for ids whose request got no answer, or matched
    /// without a callback.
    fn forget(&self, ids: &[String]) {
        let mut pending = self.pending.lock().unwrap();
        for id in ids {
            pending.remove(id);
        }
    }

    /// The answer is in: later callbacks are judged with it. Returns the
    /// ones that came first.
    fn answered(&self, ids: &[String], waiting: &Arc<Waiting>) -> Vec<OastCallback> {
        let mut pending = self.pending.lock().unwrap();
        let mut early = Vec::new();
        for id in ids {
            let answered = Pending::Answered(Instant::now(), Arc::clone(waiting));
            if let Some(Pending::Early(_, callbacks)) = pending.insert(id.clone(), answered) {
                early.extend(callbacks);
            }
        }
        early
    }

    /// The answer a callback is for, once it is in; a callback that beats
    /// its answer is kept until then.
    fn heard(&self, callback: OastCallback) -> Option<(Arc<Waiting>, OastCallback)> {
        let id = callback.correlation_id.trim().to_ascii_lowercase();
        let mut pending = self.pending.lock().unwrap();
        match pending.get_mut(&id)? {
            Pending::Early(_, callbacks) => {
                if callbacks.len() < MAX_EARLY_CALLBACKS {
                    callbacks.push(callback);
                }
                None
            }
            Pending::Answered(_, waiting) => Some((Arc::clone(waiting), callback)),
        }
    }

    fn waiting(&self) -> bool {
        !self.pending.lock().unwrap().is_empty()
    }
}

/// One request of a chain and its answer.
#[derive(Clone)]
struct Hop {
    request: EditableRequest,
    record: TransactionRecord,
}

impl Hop {
    fn url(&self) -> String {
        format!(
            "{}://{}{}",
            self.request.scheme, self.request.host, self.request.path
        )
    }
}

/// Where a redirect sends the next request.
struct NextHop {
    scheme: String,
    authority: String,
    path: String,
    method: String,
    keep_body: bool,
}

/// What Go's client does with a redirect, as Nuclei sends through it: 301,
/// 302 and 303 turn into a GET without the body (a HEAD stays one), 307 and
/// 308 repeat the request.
fn redirect_step(status: u16, method: &str) -> Option<(String, bool)> {
    match status {
        301..=303 => Some((
            if matches!(method, "GET" | "HEAD") {
                method
            } else {
                "GET"
            }
            .to_string(),
            false,
        )),
        307 | 308 => Some((method.to_string(), true)),
        _ => None,
    }
}

fn host_of(authority: &str) -> String {
    crate::scope::host_without_port(authority)
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase()
}

/// The request as text, for matchers that read `request`.
fn request_text(request: &EditableRequest) -> String {
    let mut text = format!("{} {} HTTP/1.1\r\n", request.method, request.path);
    for header in &request.headers {
        text.push_str(&format!("{}: {}\r\n", header.name, header.value));
    }
    text.push_str("\r\n");
    text.push_str(&request.body);
    text
}

/// Keeps a request's answer for the run's later matchers. Like Nuclei, a
/// request number keeps the last answer it got, across payload passes.
fn remember(
    history: &mut Vec<Option<Arc<ResponseView>>>,
    index: usize,
    answer: Option<Arc<ResponseView>>,
) {
    if history.len() <= index {
        history.resize(index + 1, None);
    }
    if answer.is_some() {
        history[index] = answer;
    }
}

/// What one request's answers came to.
#[derive(Default)]
struct Judged {
    matched: bool,
    /// Values its internal extractors hand to the run's later requests.
    carried: Vec<(String, String)>,
    /// The answer later matchers read as this request's (`body_1`), kept
    /// only when they do.
    answer: Option<Arc<ResponseView>>,
}

/// The cookies a response set, by name, for the run's later requests to the
/// same host.
fn remember_cookies(
    jar: &mut Vec<(String, String, String)>,
    host: &str,
    record: &TransactionRecord,
) {
    let Some(response) = record
        .original_response
        .as_ref()
        .or(record.response.as_ref())
    else {
        return;
    };
    for header in &response.headers {
        if !header.name.eq_ignore_ascii_case("set-cookie") {
            continue;
        }
        let Some((name, value)) = header
            .value
            .split(';')
            .next()
            .and_then(|pair| pair.split_once('='))
        else {
            continue;
        };
        let (name, value) = (name.trim().to_string(), value.trim().to_string());
        jar.retain(|(h, n, _)| !(h == host && *n == name));
        jar.push((host.to_string(), name, value));
    }
}

impl Run {
    fn update(&self, change: impl FnOnce(&mut ScanJob)) {
        self.session.template_scans.update(self.job, change);
    }

    fn warn(&self, warning: String) {
        self.update(|job| job.warn(warning));
    }

    fn stopping(&self, cancel: &watch::Receiver<bool>, target: usize) -> bool {
        *cancel.borrow()
            || self.limit_reached.load(Ordering::Relaxed)
            || self.skipped[target].load(Ordering::Relaxed)
    }

    /// One more request within the job's limit, or none.
    fn take_budget(&self) -> bool {
        let taken = self
            .sent
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |sent| {
                (sent < self.max_requests).then_some(sent + 1)
            })
            .is_ok();
        if !taken && !self.limit_reached.swap(true, Ordering::SeqCst) {
            self.warn(format!(
                "Stopped at the limit of {} requests; redirects count towards it.",
                self.max_requests
            ));
        }
        taken
    }

    /// Waits for this request's turn: one every `gap`, across all workers.
    async fn pace(&self) {
        let at = {
            let mut next = self.next_slot.lock().await;
            let at = (*next).max(Instant::now());
            *next = at + self.gap;
            at
        };
        tokio::time::sleep_until(at).await;
    }

    async fn execute(self: Arc<Self>, cancel: watch::Receiver<bool>) {
        // Callbacks are heard from before the first request goes out.
        let (enough, listening) = watch::channel(false);
        let listener = self.oast.is_some().then(|| {
            let heard = self.session.oast.subscribe();
            tokio::spawn(Arc::clone(&self).listen(heard, listening))
        });
        let pairs: Vec<(usize, usize)> = (0..self.templates.len())
            .flat_map(|template| (0..self.targets.len()).map(move |target| (template, target)))
            .collect();
        futures_util::stream::iter(pairs)
            .for_each_concurrent(self.concurrency, |(template, target)| {
                self.template_on_target(template, target, cancel.clone())
            })
            .await;
        if let Some(listener) = listener {
            // As Nuclei does, the last requests' callbacks get time to come:
            // two polls of the session's server.
            if self.oast.as_ref().is_some_and(OastWatch::waiting) && !*cancel.borrow() {
                let interval = self.session.oast.get_config().await.polling_interval_secs;
                let mut cancel = cancel.clone();
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(interval.max(1) * 2)) => {}
                    _ = cancel.wait_for(|stop| *stop) => {}
                }
            }
            let _ = enough.send(true);
            let _ = listener.await;
        }
        let cancelled = *cancel.borrow();
        let mut counts = (0, 0, 0);
        self.update(|job| {
            counts = (job.sent, job.matched, job.failed);
            if job.status == "running" {
                job.status = if cancelled { "cancelled" } else { "completed" }.into();
                job.finished_at = Some(Utc::now());
            }
        });
        self.session.schedule_state_persist();
        self.session
            .event_log
            .push(
                EventLevel::Info,
                "templates",
                if cancelled {
                    "Template Scan stopped"
                } else {
                    "Template Scan finished"
                },
                format!(
                    "{} requests sent, {} matched, {} failed",
                    counts.0, counts.1, counts.2
                ),
            )
            .await;
    }

    async fn template_on_target(
        &self,
        template_index: usize,
        target_index: usize,
        mut cancel: watch::Receiver<bool>,
    ) {
        let template = &self.templates[template_index];
        let target = &self.targets[target_index];
        let id = &template.template.info.id;
        let oast = self.oast.as_ref().map(|watch| &watch.urls);
        let Ok(run) = template.start_run(&target.vars, oast) else {
            self.warn(format!(
                "{id} could not work out its variables and was not sent."
            ));
            return;
        };
        // Nuclei keeps one cookie jar for a template's run on a target.
        let mut jar = Vec::new();
        // The run's answers so far, by request, for matchers that read them.
        let mut history: Vec<Option<Arc<ResponseView>>> = Vec::new();
        for pass in 0..template.passes() {
            if template.load_pass(&run, pass).is_err() {
                self.warn(format!(
                    "{id} could not fill payload {} and did not send it.",
                    pass + 1
                ));
                continue;
            }
            for index in 0..template.sequence_len() {
                if self.stopping(&cancel, target_index) {
                    return;
                }
                let built = match template.build(index, &target.base_path, &run) {
                    Ok(built) => built,
                    Err(_) => {
                        self.warn(format!(
                            "{id} could not build its request {} and did not send it.",
                            index + 1
                        ));
                        remember(&mut history, index, None);
                        continue;
                    }
                };
                // The OAST URLs this request carries, when its matchers wait
                // to hear them called.
                let oast_ids = match &self.oast {
                    Some(watch) if template.reads_interaction => {
                        let ids = run.oast_ids_in(&built);
                        watch.expect(&ids);
                        ids
                    }
                    _ => Vec::new(),
                };
                let hops = self
                    .send_chain(template, target_index, built, &mut jar, &mut cancel)
                    .await;
                if hops.is_empty() {
                    if let Some(watch) = &self.oast {
                        watch.forget(&oast_ids);
                    }
                    remember(&mut history, index, None);
                    continue;
                }
                let values = run.values();
                let waiting = (!oast_ids.is_empty()).then(|| (hops[0].clone(), values.clone()));
                let judged = self
                    .judge(template, target, hops, values, index + 1, history.clone())
                    .await;
                if let (Some(watch), Some((hop, values))) = (&self.oast, waiting) {
                    if judged.matched {
                        watch.forget(&oast_ids);
                    } else {
                        let waiting = Arc::new(Waiting {
                            template: Arc::clone(template),
                            target: target_index,
                            hop,
                            values,
                            number: index + 1,
                            history: history.clone(),
                            reported: AtomicBool::new(false),
                        });
                        for callback in watch.answered(&oast_ids, &waiting) {
                            self.judge_callback(&waiting, callback).await;
                        }
                    }
                }
                template.carry(&run, judged.carried);
                remember(&mut history, index, judged.answer);
                if judged.matched && template.stop_at_first_match {
                    return;
                }
            }
        }
    }

    /// Sends a request and the redirects it may follow. Returns each answer
    /// received, in order; an empty list when none came.
    async fn send_chain(
        &self,
        template: &ActiveTemplate,
        target_index: usize,
        built: active::BuiltRequest,
        jar: &mut Vec<(String, String, String)>,
        cancel: &mut watch::Receiver<bool>,
    ) -> Vec<Hop> {
        let target = &self.targets[target_index];
        let id = &template.template.info.id;
        let mut hops: Vec<Hop> = Vec::new();
        let mut scheme = target.scheme.clone();
        let mut authority = target.authority.clone();
        let mut method = built.method.clone();
        let mut path = built.target.clone();
        let mut body = built.body.clone();
        let mut body_dropped = false;
        let timeout = built
            .timeout
            .unwrap_or(crate::proxy::TEMPLATE_SCAN_REQUEST_TIMEOUT);
        loop {
            if hops.is_empty() {
                // Scope may have narrowed since the scan started.
                let (include, exclude) = self.session.runtime.scope_lists().await;
                if include.is_empty()
                    || !crate::scope::is_host_in_scope(&authority, &include, &exclude)
                {
                    if !self.skipped[target_index].swap(true, Ordering::Relaxed) {
                        self.update(|job| {
                            job.blocked += 1;
                            job.skipped_targets.push(target.label.clone());
                            job.warn(format!(
                                "{} left Scope; its remaining requests were not sent.",
                                target.label
                            ));
                        });
                    }
                    break;
                }
            }
            let request = self.request(
                target,
                &scheme,
                &authority,
                &method,
                &path,
                &body,
                body_dropped,
                &built.headers,
                jar,
            );
            if *cancel.borrow() || !self.take_budget() {
                break;
            }
            tokio::select! {
                _ = self.pace() => {}
                _ = cancel.wait_for(|stop| *stop) => break,
            }
            let started = std::time::Instant::now();
            let send = tokio::time::timeout(
                timeout,
                crate::proxy::send_template_scan_request(
                    &self.state,
                    &self.session,
                    &self.client,
                    request.clone(),
                    self.apply_match_replace,
                ),
            );
            let outcome = tokio::select! {
                outcome = send => outcome.unwrap_or_else(|_| {
                    Err(TemplateScanSendError::Failed(format!("timed out after {timeout:?}")))
                }),
                _ = cancel.wait_for(|stop| *stop) => break,
            };
            let entry = ScanLogEntry {
                at: Utc::now(),
                template_id: id.clone(),
                method: method.clone(),
                url: format!("{scheme}://{authority}{path}"),
                ms: started.elapsed().as_millis() as u64,
                ..ScanLogEntry::default()
            };
            let record = match outcome {
                Err(TemplateScanSendError::Blocked) => {
                    self.update(|job| {
                        job.blocked += 1;
                        job.log(ScanLogEntry {
                            error: Some(
                                "not sent: a Match & Replace rule changed its destination".into(),
                            ),
                            ..entry
                        });
                    });
                    break;
                }
                Err(TemplateScanSendError::Failed(message)) => {
                    let failures = self.failures[target_index].fetch_add(1, Ordering::Relaxed) + 1;
                    let give_up = failures >= MAX_CONSECUTIVE_FAILURES
                        && !self.skipped[target_index].swap(true, Ordering::Relaxed);
                    self.update(|job| {
                        job.sent += 1;
                        job.failed += 1;
                        job.log(ScanLogEntry {
                            error: Some(message.chars().take(200).collect()),
                            ..entry
                        });
                        if give_up {
                            job.skipped_targets.push(target.label.clone());
                            job.warn(format!(
                                "{} failed {MAX_CONSECUTIVE_FAILURES} requests in a row; its remaining requests were not sent.",
                                target.label
                            ));
                        }
                    });
                    break;
                }
                Ok(record) => record,
            };
            self.failures[target_index].store(0, Ordering::Relaxed);
            self.update(|job| job.sent += 1);
            let next = if template.follow != Follow::None && hops.len() < template.max_redirects {
                self.next_hop(
                    template.follow,
                    target,
                    &scheme,
                    &authority,
                    &path,
                    &method,
                    &record,
                )
                .await
            } else {
                None
            };
            if template.cookies {
                remember_cookies(jar, &host_of(&authority), &record);
            }
            hops.push(Hop { request, record });
            let Some(next) = next else { break };
            scheme = next.scheme;
            authority = next.authority;
            path = next.path;
            method = next.method;
            if !next.keep_body {
                body_dropped |= !body.is_empty();
                body.clear();
            }
        }
        hops
    }

    #[allow(clippy::too_many_arguments)]
    fn request(
        &self,
        target: &ScanTarget,
        scheme: &str,
        authority: &str,
        method: &str,
        path: &str,
        body: &str,
        body_dropped: bool,
        template_headers: &[(String, String)],
        jar: &[(String, String, String)],
    ) -> EditableRequest {
        let host = host_of(authority);
        let mut headers = vec![HeaderRecord {
            name: "Host".into(),
            value: authority.to_string(),
        }];
        for (name, value) in template_headers {
            // Go keeps credentials to the host they were meant for, and a body
            // a redirect dropped takes its description along.
            let credential =
                name.eq_ignore_ascii_case("authorization") || name.eq_ignore_ascii_case("cookie");
            let describes_body = name.eq_ignore_ascii_case("content-type")
                || name.eq_ignore_ascii_case("content-length");
            if (credential && host != target.host) || (describes_body && body_dropped) {
                continue;
            }
            headers.push(HeaderRecord {
                name: name.clone(),
                value: value.clone(),
            });
        }
        for (name, value) in [
            ("User-Agent", USER_AGENT),
            ("Accept", "*/*"),
            ("Accept-Language", "en"),
        ] {
            if !headers
                .iter()
                .any(|header| header.name.eq_ignore_ascii_case(name))
            {
                headers.push(HeaderRecord {
                    name: name.into(),
                    value: value.into(),
                });
            }
        }
        let cookies: Vec<String> = jar
            .iter()
            .filter(|(owner, _, _)| *owner == host)
            .map(|(_, name, value)| format!("{name}={value}"))
            .collect();
        if !cookies.is_empty() {
            headers.push(HeaderRecord {
                name: "Cookie".into(),
                value: cookies.join("; "),
            });
        }
        EditableRequest {
            scheme: scheme.to_string(),
            host: authority.to_string(),
            method: method.to_string(),
            path: path.to_string(),
            headers,
            body: body.to_string(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        }
    }

    /// The next request of a redirect chain, when the template follows
    /// redirects and this one stays in Scope and away from Sniper.
    #[allow(clippy::too_many_arguments)]
    async fn next_hop(
        &self,
        follow: Follow,
        target: &ScanTarget,
        scheme: &str,
        authority: &str,
        path: &str,
        method: &str,
        record: &TransactionRecord,
    ) -> Option<NextHop> {
        let (next_method, keep_body) = redirect_step(record.status?, method)?;
        let response = record
            .original_response
            .as_ref()
            .or(record.response.as_ref())?;
        let mut locations = response
            .headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case("location"));
        let location = locations.next()?.value.trim().to_string();
        if location.is_empty() || locations.next().is_some() {
            return None;
        }
        let next = Url::parse(&format!("{scheme}://{authority}{path}"))
            .ok()?
            .join(&location)
            .ok()?;
        let not_followed = || self.update(|job| job.redirects_not_followed += 1);
        let Some(name) = next.host_str().filter(|_| {
            matches!(next.scheme(), "http" | "https")
                && next.username().is_empty()
                && next.password().is_none()
        }) else {
            not_followed();
            return None;
        };
        let next_authority = match next.port() {
            Some(port) => format!("{name}:{port}"),
            None => name.to_string(),
        };
        // `host-redirects` stays on the host the chain started on, as Nuclei's
        // does; that is the template's choice, not a Scope stop.
        if follow == Follow::SameHost && !next_authority.eq_ignore_ascii_case(&target.authority) {
            return None;
        }
        let (include, exclude) = self.session.runtime.scope_lists().await;
        if include.is_empty()
            || !crate::scope::is_host_in_scope(&next_authority, &include, &exclude)
            || crate::special_host::is_special_host(&next_authority)
            || crate::proxy::targets_own_listener(
                &self.state,
                &self.session,
                next.scheme(),
                &next_authority,
            )
            .await
        {
            not_followed();
            return None;
        }
        let mut raw = next.path().to_string();
        if let Some(query) = next.query() {
            raw.push('?');
            raw.push_str(query);
        }
        Some(NextHop {
            scheme: next.scheme().to_string(),
            authority: next_authority,
            path: active::request_target(&raw)?,
            method: next_method,
            keep_body,
        })
    }

    /// Judges a chain's answers, the last first as Nuclei walks a redirect
    /// chain, and keeps what matched. True when anything did.
    async fn judge(
        &self,
        template: &Arc<ActiveTemplate>,
        target: &ScanTarget,
        hops: Vec<Hop>,
        values: HashMap<String, String>,
        number: usize,
        history: Vec<Option<Arc<ResponseView>>>,
    ) -> Judged {
        let evaluating = Arc::clone(template);
        let vars = target.vars.clone();
        // A matcher may read up to 10 MiB of body; keep that off the async
        // workers.
        let judged = tokio::task::spawn_blocking(move || {
            let mut verdicts: Vec<Vec<TemplateMatch>> = vec![Vec::new(); hops.len()];
            let mut carried: Vec<Vec<(String, String)>> = vec![Vec::new(); hops.len()];
            let mut answer = None;
            for (index, hop) in hops.iter().enumerate().rev() {
                let Some(view) =
                    ResponseView::from_record(&hop.record, vars.clone(), MAX_ACTIVE_BODY_BYTES)
                else {
                    continue;
                };
                let view = view
                    .with_request(request_text(&hop.request), values.clone())
                    .with_history(number, history.clone());
                (verdicts[index], carried[index]) = evaluating.template.evaluate_carrying(&view);
                // Nuclei remembers the last answer of the chain it read, the
                // first one unless a match stopped it sooner.
                if evaluating.history {
                    answer = Some(Arc::new(view));
                }
                if !verdicts[index].is_empty() && evaluating.stop_at_first_match {
                    break;
                }
            }
            // The earliest answer's value comes first, as Nuclei merges a
            // chain's.
            let mut handed: Vec<(String, String)> = Vec::new();
            for (name, value) in carried.into_iter().flatten() {
                if !handed.iter().any(|(seen, _)| *seen == name) {
                    handed.push((name, value));
                }
            }
            (hops, verdicts, handed, answer)
        })
        .await;
        let Ok((hops, verdicts, carried, answer)) = judged else {
            return Judged::default();
        };
        let mut matched = false;
        for (hop, results) in hops.into_iter().zip(verdicts) {
            let found = !results.is_empty();
            self.update(|job| {
                job.log(ScanLogEntry {
                    at: Utc::now(),
                    template_id: template.template.info.id.clone(),
                    method: hop.request.method.clone(),
                    url: hop.url(),
                    status: hop.record.status,
                    ms: hop.record.duration_ms,
                    matched: found,
                    error: None,
                })
            });
            if found {
                matched = true;
                self.keep(template, hop, results, None).await;
            }
        }
        Judged {
            matched,
            carried,
            answer,
        }
    }

    /// Hears the session's callbacks until the scan has waited long enough.
    /// The shared poller polls only the active session, so while another
    /// one is active this polls the scan's own server.
    async fn listen(
        self: Arc<Self>,
        mut heard: broadcast::Receiver<crate::oast::OastCallbackSummary>,
        mut enough: watch::Receiver<bool>,
    ) {
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_default();
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let mut next_poll = Instant::now();
        loop {
            tokio::select! {
                received = heard.recv() => match received {
                    Ok(summary) => {
                        let Some(callback) = self.session.oast.get(summary.id).await else {
                            continue;
                        };
                        let Some((waiting, callback)) =
                            self.oast.as_ref().and_then(|watch| watch.heard(callback))
                        else {
                            continue;
                        };
                        self.judge_callback(&waiting, callback).await;
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return,
                },
                _ = tick.tick() => {
                    if Instant::now() >= next_poll
                        && self.state.session().await.id() != self.session.id()
                    {
                        crate::oast::poll_session_interactsh(&self.session, &client).await;
                        let interval = self.session.oast.get_config().await.polling_interval_secs;
                        next_poll = Instant::now() + Duration::from_secs(interval.max(1));
                    }
                }
                _ = enough.changed() => return,
            }
        }
    }

    /// Judges a waiting answer again with the callback its request caused,
    /// and keeps it the first time that matches.
    async fn judge_callback(&self, waiting: &Arc<Waiting>, callback: OastCallback) {
        if waiting.reported.load(Ordering::Relaxed) {
            return;
        }
        let judging = Arc::clone(waiting);
        let vars = self.targets[waiting.target].vars.clone();
        let interaction = Interaction::new(
            &callback.protocol,
            &callback.raw_data,
            &callback.remote_addr,
        );
        let results = tokio::task::spawn_blocking(move || {
            let view = ResponseView::from_record(&judging.hop.record, vars, MAX_ACTIVE_BODY_BYTES)?
                .with_request(request_text(&judging.hop.request), judging.values.clone())
                .with_history(judging.number, judging.history.clone())
                .with_interaction(interaction);
            Some(judging.template.template.evaluate(&view))
        })
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
        if results.is_empty() || waiting.reported.swap(true, Ordering::Relaxed) {
            return;
        }
        let hop = waiting.hop.clone();
        self.update(|job| {
            job.log(ScanLogEntry {
                at: Utc::now(),
                template_id: waiting.template.template.info.id.clone(),
                method: hop.request.method.clone(),
                url: hop.url(),
                status: hop.record.status,
                ms: hop.record.duration_ms,
                matched: true,
                error: None,
            })
        });
        self.keep(&waiting.template, hop, results, Some(&callback))
            .await;
    }

    /// Stores a matched exchange in the history and files its findings,
    /// with the callback that made it match, if one did.
    async fn keep(
        &self,
        template: &ActiveTemplate,
        hop: Hop,
        results: Vec<TemplateMatch>,
        callback: Option<&OastCallback>,
    ) {
        let url = hop.url();
        let mut record = hop.record;
        record.notes.push(format!(
            "Template {}, job {}.",
            template.template.info.id, self.job
        ));
        let heard = callback.map(|callback| {
            format!(
                "OAST: {} callback from {}.",
                callback.protocol, callback.remote_addr
            )
        });
        record.notes.extend(heard.clone());
        crate::proxy::store_record_and_scan_unconditionally(
            &self.state,
            &self.session,
            record.clone(),
        )
        .await;
        let info = &template.template.info;
        for result in &results {
            let mut finding =
                super::active_finding(&template.template, result, &record, self.job, &self.library);
            if let Some(heard) = &heard {
                finding.detail.push('\n');
                finding.detail.push_str(heard);
            }
            let evidence = finding.evidence.clone();
            self.session.scanner.push(finding).await;
            self.update(|job| {
                job.matched += 1;
                if job.results.len() < MAX_RESULTS {
                    job.results.push(ScanResult {
                        at: Utc::now(),
                        template_id: info.id.clone(),
                        name: info.name.clone(),
                        severity: info.severity.clone(),
                        matcher: result.matcher.clone(),
                        method: record.method.clone(),
                        url: url.clone(),
                        record_id: record.id,
                        evidence,
                    });
                }
            });
        }
        self.session.schedule_state_persist();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        http::{HeaderMap, Method, Uri},
        response::IntoResponse,
        routing::any,
        Router,
    };
    use std::io::Write as _;

    #[derive(Clone, Debug)]
    struct Seen {
        method: String,
        path: String,
        host: String,
        body: String,
        header: String,
    }

    type Log = Arc<Mutex<Vec<Seen>>>;

    /// A loopback site: what each path answers, and what it was asked.
    async fn site(other_port: u16, slow: bool) -> (std::net::SocketAddr, Log, JoinHandle<()>) {
        let log: Log = Arc::default();
        let seen = Arc::clone(&log);
        let router = Router::new().fallback(any(
            move |method: Method, uri: Uri, headers: HeaderMap, body: String| {
                let seen = Arc::clone(&seen);
                async move {
                    let header = |name: &str| {
                        headers
                            .get(name)
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or("")
                            .to_string()
                    };
                    seen.lock().unwrap().push(Seen {
                        method: method.to_string(),
                        path: uri.path().to_string(),
                        host: header("host"),
                        body: body.clone(),
                        header: header("x-test"),
                    });
                    if slow {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                    }
                    let cookie = header("cookie");
                    match uri.path() {
                        "/.git/config" => "[core]\n\trepositoryformatversion = 0\n".into_response(),
                        "/login" => (
                            StatusCode::FOUND,
                            [("location", "/home"), ("set-cookie", "sid=abc; Path=/")],
                            "moved",
                        )
                            .into_response(),
                        "/home" if cookie.contains("sid=abc") => "Welcome back".into_response(),
                        "/home" => "Who are you".into_response(),
                        "/out" => (
                            StatusCode::FOUND,
                            [("location", format!("http://localhost:{other_port}/landing"))],
                            "away",
                        )
                            .into_response(),
                        "/echo" => uri.query().unwrap_or("").to_string().into_response(),
                        "/sleep" => {
                            tokio::time::sleep(Duration::from_secs(2)).await;
                            "slept".into_response()
                        }
                        "/submit" => body.into_response(),
                        "/token" => "token=abc123".into_response(),
                        "/check" if body == "t=abc123" => "valid".into_response(),
                        "/check" => "invalid".into_response(),
                        _ => (StatusCode::NOT_FOUND, "nothing").into_response(),
                    }
                }
            },
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        (address, log, server)
    }

    fn archive(files: &[(&str, &str)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, text) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(text.len() as u64);
            header.set_mode(0o644);
            builder
                .append_data(
                    &mut header,
                    format!("release/http/{name}.yaml"),
                    text.as_bytes(),
                )
                .unwrap();
        }
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gzip.write_all(&builder.into_inner().unwrap()).unwrap();
        gzip.finish().unwrap()
    }

    const TEMPLATES: &[(&str, &str)] = &[
        ("config", "id: example-config\ninfo:\n  name: Example Config\n  severity: medium\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/.git/config']\n    matchers-condition: and\n    matchers:\n      - type: word\n        words: ['[core]']\n      - type: status\n        status: [200]\n"),
        ("login", "id: example-login\ninfo:\n  severity: info\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/login']\n    redirects: true\n    matchers:\n      - type: word\n        words: ['Welcome']\n"),
        ("out", "id: example-out\ninfo:\n  severity: low\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/out']\n    redirects: true\n    max-redirects: 2\n    matchers:\n      - type: status\n        status: [302]\n"),
        ("echo", "id: example-echo\ninfo:\n  severity: high\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/echo?q={{randstr}}']\n    matchers:\n      - type: word\n        words: ['{{randstr}}']\n"),
        ("post", "id: example-post\ninfo:\n  severity: high\nhttp:\n  - method: POST\n    path: ['{{BaseURL}}/submit']\n    headers:\n      Host: '{{Hostname}}'\n      Content-Type: application/x-www-form-urlencoded\n      X-Test: '{{Host}}'\n    body: 'a={{randstr}}'\n    matchers:\n      - type: word\n        words: ['a={{randstr}}']\n"),
        ("miss", "id: example-miss\ninfo: {}\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/nothing-here']\n    matchers:\n      - type: word\n        words: ['never there']\n"),
        ("risky", "id: example-risky\ninfo:\n  tags: intrusive\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/risky']\n    matchers:\n      - type: status\n        status: [200]\n"),
        ("slow", "id: example-slow\ninfo:\n  tags: slow\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/slow-1', '{{BaseURL}}/slow-2', '{{BaseURL}}/slow-3']\n    matchers:\n      - type: status\n        status: [200]\n"),
    ];

    async fn scan_state(name: &str, scope: &[&str]) -> Arc<AppState> {
        scan_state_with(name, scope, TEMPLATES).await
    }

    async fn scan_state_with(
        name: &str,
        scope: &[&str],
        templates: &[(&str, &str)],
    ) -> Arc<AppState> {
        let dir = std::env::temp_dir().join(format!("sniper-scan-{name}-{}", Uuid::new_v4()));
        let state = Arc::new(
            AppState::new(crate::config::AppConfig {
                proxy_addr: "127.0.0.1:0".parse().unwrap(),
                ui_addr: "127.0.0.1:0".parse().unwrap(),
                max_entries: 64,
                max_transaction_entries: 64,
                body_preview_bytes: 64 * 1024,
                data_dir: dir,
            })
            .unwrap(),
        );
        for _ in 0..200 {
            if state.templates.status().state != super::super::library::TaskState::Loading {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        state
            .templates
            .import_blocking(&archive(templates), super::super::library::Source::Import)
            .unwrap();
        state
            .session()
            .await
            .runtime
            .update(crate::runtime::RuntimeSettingsUpdate {
                scope_patterns: Some(scope.iter().map(|s| s.to_string()).collect()),
                ..Default::default()
            })
            .await
            .unwrap();
        state
    }

    fn request(session: Uuid, value: serde_json::Value) -> StartScan {
        let mut body = serde_json::json!({"session_id": session});
        body.as_object_mut()
            .unwrap()
            .extend(value.as_object().unwrap().clone());
        serde_json::from_value(body).unwrap()
    }

    async fn finished(state: &Arc<AppState>, id: Uuid) -> ScanJob {
        for _ in 0..500 {
            let job = state
                .session()
                .await
                .template_scans
                .snapshot()
                .jobs
                .into_iter()
                .find(|job| job.id == id)
                .unwrap();
            if job.status != "running" {
                return job;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the scan did not finish");
    }

    #[tokio::test]
    async fn a_scan_sends_only_to_its_target_and_keeps_only_matches() {
        let (other, other_log, other_server) = site(1, false).await;
        let (address, log, server) = site(other.port(), false).await;
        let state = scan_state("run", &["127.0.0.1"]).await;
        let session = state.session().await;
        let target = format!("http://{address}");
        let selection = serde_json::json!({
            "targets": [target, format!("{target}/")],
            "filter": {"search": "example-"},
            "rate": 50,
        });
        // A preview counts and sends nothing.
        let preview = start(
            State(state.clone()),
            Json(request(session.id(), {
                let mut preview = selection.clone();
                preview["preview"] = true.into();
                preview
            })),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(preview["templates"], 7);
        assert_eq!(preview["requests"], 9);
        assert_eq!(preview["targets"], serde_json::json!([target]));
        assert_eq!(preview["excluded_by_risk"]["intrusive"], 1);
        assert!(log.lock().unwrap().is_empty());
        // Without the acknowledgment nothing starts.
        assert_eq!(
            start(
                State(state.clone()),
                Json(request(session.id(), selection.clone()))
            )
            .await
            .unwrap_err()
            .0,
            StatusCode::BAD_REQUEST
        );

        let mut acknowledged = selection.clone();
        acknowledged["acknowledged"] = true.into();
        acknowledged["filter"] = serde_json::json!({"search": "example-", "tag": ""});
        acknowledged["ids"] = serde_json::json!([]);
        let started = start(
            State(state.clone()),
            Json(request(session.id(), acknowledged)),
        )
        .await
        .unwrap()
        .0;
        let id: Uuid = serde_json::from_value(started["id"].clone()).unwrap();
        let job = finished(&state, id).await;
        server.abort();
        other_server.abort();

        assert_eq!(job.status, "completed", "{job:?}");
        // The slow template's three paths answer at once here; the login
        // redirect adds one.
        assert_eq!(job.sent, 10, "{job:?}");
        assert_eq!(job.redirects_not_followed, 1);
        let mut matched: Vec<&str> = job
            .results
            .iter()
            .map(|result| result.template_id.as_str())
            .collect();
        matched.sort_unstable();
        assert_eq!(
            matched,
            [
                "example-config",
                "example-echo",
                "example-login",
                "example-out",
                "example-post"
            ]
        );
        let seen = log.lock().unwrap().clone();
        let mut paths: Vec<&str> = seen.iter().map(|seen| seen.path.as_str()).collect();
        paths.sort_unstable();
        assert_eq!(
            paths,
            [
                "/.git/config",
                "/echo",
                "/home",
                "/login",
                "/nothing-here",
                "/out",
                "/slow-1",
                "/slow-2",
                "/slow-3",
                "/submit"
            ]
        );
        assert!(seen.iter().all(|seen| seen.host == address.to_string()));
        // The redirect led to a host outside Scope and was not followed.
        assert!(other_log.lock().unwrap().is_empty());
        let post = seen.iter().find(|seen| seen.path == "/submit").unwrap();
        assert_eq!(
            (post.method.as_str(), post.header.as_str()),
            ("POST", "127.0.0.1")
        );
        assert_eq!(post.body.len(), "a=".len() + 27);

        // Only matched exchanges are history, each saying where it came from.
        assert_eq!(session.store.len().await, 5);
        for result in &job.results {
            let record = session.store.get(result.record_id).await.unwrap();
            assert!(record
                .notes
                .iter()
                .any(|note| note == crate::model::TEMPLATE_SCAN_NOTE));
        }
        let login = job
            .results
            .iter()
            .find(|result| result.template_id == "example-login")
            .unwrap();
        assert!(login.url.ends_with("/home"), "{}", login.url);
        let findings = session.scanner.snapshot(None).await;
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding
                    .rule_id
                    .starts_with(crate::templates::ACTIVE_RULE_PREFIX))
                .count(),
            5
        );
    }

    const RAW_TEMPLATES: &[(&str, &str)] = &[
        ("raw-post", "id: example-raw-post\ninfo:\n  severity: high\nhttp:\n  - raw:\n      - |\n        POST /submit?x=1 HTTP/1.1\n        Host: {{Hostname}}\n        Content-Type: application/x-www-form-urlencoded\n        Content-Length: 1\n\n        a={{randstr}}\n    matchers:\n      - type: word\n        words: ['a={{randstr}}']\n"),
        ("raw-session", "id: example-raw-session\ninfo: {}\nhttp:\n  - raw:\n      - |\n        GET /login HTTP/1.1\n        Host: {{Hostname}}\n      - |\n        GET /home HTTP/1.1\n        Host: {{Hostname}}\n    matchers:\n      - type: word\n        words: ['Welcome back']\n"),
        ("raw-own-cookie", "id: example-raw-own-cookie\ninfo: {}\nhttp:\n  - raw:\n      - |\n        GET /login HTTP/1.1\n        Host: {{Hostname}}\n      - |\n        GET /home HTTP/1.1\n        Host: {{Hostname}}\n        Cookie: theme=dark\n    matchers:\n      - type: word\n        words: ['Welcome back']\n"),
        ("steps", "id: example-steps\ninfo: {}\nhttp:\n  - raw:\n      - |\n        GET /token HTTP/1.1\n        Host: {{Hostname}}\n      - |\n        POST /check HTTP/1.1\n        Host: {{Hostname}}\n\n        t={{tok}}\n    extractors:\n      - type: regex\n        name: tok\n        internal: true\n        group: 1\n        regex: ['token=([a-z0-9]+)']\n    matchers:\n      - type: dsl\n        dsl: ['status_code_1 == 200 && body_2 == \"valid\"']\n"),
        ("words", "id: example-words\ninfo: {}\nhttp:\n  - path: ['{{BaseURL}}/echo?q={{word}}']\n    payloads:\n      word: [alpha, beta, gamma]\n    stop-at-first-match: true\n    matchers:\n      - type: word\n        words: ['q=beta']\n"),
        ("no-cookie", "id: example-no-cookie\ninfo: {}\nhttp:\n  - path: ['{{BaseURL}}/login', '{{BaseURL}}/home']\n    disable-cookie: true\n    matchers:\n      - type: word\n        words: ['Welcome back']\n"),
        ("raw-timeout", "id: example-raw-timeout\ninfo: {}\nhttp:\n  - raw:\n      - |\n        @timeout: 300ms\n        GET /sleep HTTP/1.1\n        Host: {{Hostname}}\n    matchers:\n      - type: status\n        status: [200]\n"),
    ];

    #[tokio::test]
    async fn raw_requests_share_cookies_and_keep_their_timeouts() {
        let (address, log, server) = site(1, false).await;
        let state = scan_state_with("raw", &["127.0.0.1"], RAW_TEMPLATES).await;
        let session = state.session().await;
        let started = start(
            State(state.clone()),
            Json(request(
                session.id(),
                serde_json::json!({
                    "targets": [format!("http://{address}")],
                    "filter": {"search": "example-"},
                    "acknowledged": true,
                    "rate": 50,
                }),
            )),
        )
        .await
        .unwrap()
        .0;
        let id: Uuid = serde_json::from_value(started["id"].clone()).unwrap();
        let job = finished(&state, id).await;
        server.abort();

        assert_eq!(job.status, "completed", "{job:?}");
        let mut matched: Vec<&str> = job
            .results
            .iter()
            .map(|result| result.template_id.as_str())
            .collect();
        matched.sort_unstable();
        // The second request of a run carries the cookie the first one was
        // given, beside any cookie the template sets itself, unless the
        // template turns that off.
        // A value extracted from one answer fills a later request, and the
        // matchers read every answer of the run.
        assert_eq!(
            matched,
            [
                "example-raw-own-cookie",
                "example-raw-post",
                "example-raw-session",
                "example-steps",
                "example-words"
            ]
        );
        // Each payload is its own pass, and the first match ends the run.
        let echoes = log
            .lock()
            .unwrap()
            .iter()
            .filter(|seen| seen.path == "/echo")
            .count();
        assert_eq!(echoes, 2);
        // A request that outlives its @timeout fails rather than waiting out
        // the default.
        assert_eq!(job.failed, 1, "{job:?}");
        let seen = log.lock().unwrap().clone();
        let post = seen.iter().find(|seen| seen.path == "/submit").unwrap();
        assert_eq!(post.method, "POST");
        assert_eq!(post.body.len(), "a=".len() + 27);
        assert!(seen.iter().all(|seen| seen.host == address.to_string()));
    }

    const OAST_TEMPLATES: &[(&str, &str)] = &[
        ("oast-hit", "id: example-oast-hit\ninfo:\n  severity: critical\nhttp:\n  - path: ['{{BaseURL}}/.git/config']\n    headers:\n      X-Test: 'http://{{interactsh-url}}/x'\n    matchers-condition: and\n    matchers:\n      - type: word\n        part: interactsh_protocol\n        words: [http]\n      - type: word\n        words: ['[core]']\n"),
        ("oast-quiet", "id: example-oast-quiet\ninfo: {}\nhttp:\n  - path: ['{{BaseURL}}/.git/config']\n    headers:\n      X-Test: 'quiet-{{interactsh-url}}'\n    matchers:\n      - type: word\n        part: interactsh_protocol\n        words: [http]\n"),
        ("plain", "id: example-plain\ninfo: {}\nhttp:\n  - path: ['{{BaseURL}}/.git/config']\n    matchers:\n      - type: word\n        words: ['[core]']\n"),
    ];

    #[tokio::test]
    async fn oast_templates_match_when_their_request_calls_back() {
        let (address, log, server) = site(1, false).await;
        let state = scan_state_with("oast", &["127.0.0.1"], OAST_TEMPLATES).await;
        let session = state.session().await;
        let body = |extra: serde_json::Value| {
            let mut body = serde_json::json!({
                "targets": [format!("http://{address}")],
                "filter": {"search": "example-"},
                "acknowledged": true,
                "rate": 50,
            });
            body.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            request(session.id(), body)
        };

        // With no Interactsh server to hear them, OAST templates are left
        // out, and the preview says so.
        let preview = start(
            State(state.clone()),
            Json(body(serde_json::json!({"preview": true}))),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(preview["templates"], 1);
        assert_eq!(preview["oast_unavailable"], 2);

        session
            .oast
            .pretend_interactsh("https://oast.example.com", &"c".repeat(20))
            .await;
        // The OAST server hears what the target fetches: only the URL sent
        // as `http://…`.
        let heard = Arc::clone(&session.oast);
        let seen = Arc::clone(&log);
        let callbacks = tokio::spawn(async move {
            let mut answered = HashSet::new();
            loop {
                let headers: Vec<String> = seen
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|seen| seen.header.clone())
                    .collect();
                for header in headers {
                    let Some(id) = header
                        .strip_prefix("http://")
                        .and_then(|rest| rest.split('.').next())
                    else {
                        continue;
                    };
                    if answered.insert(id.to_string()) {
                        heard
                            .push(crate::oast::OastCallback {
                                id: Uuid::new_v4(),
                                received_at: Utc::now(),
                                protocol: "http".into(),
                                remote_addr: "192.0.2.10".into(),
                                raw_data: format!(
                                    "GET /x HTTP/1.1\r\nHost: {id}.oast.example.com\r\n\r\n"
                                ),
                                correlation_id: id.to_string(),
                            })
                            .await;
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });
        let started = start(State(state.clone()), Json(body(serde_json::json!({}))))
            .await
            .unwrap()
            .0;
        let id: Uuid = serde_json::from_value(started["id"].clone()).unwrap();
        let job = finished(&state, id).await;
        callbacks.abort();
        server.abort();

        assert_eq!(job.status, "completed", "{job:?}");
        let mut matched: Vec<&str> = job
            .results
            .iter()
            .map(|result| result.template_id.as_str())
            .collect();
        matched.sort_unstable();
        assert_eq!(matched, ["example-oast-hit", "example-plain"]);
        let finding = session
            .scanner
            .snapshot(None)
            .await
            .into_iter()
            .find(|finding| finding.rule_id.contains("example-oast-hit"))
            .unwrap();
        assert!(
            finding
                .detail
                .contains("OAST: http callback from 192.0.2.10"),
            "{}",
            finding.detail
        );
    }

    #[tokio::test]
    async fn a_scan_refuses_targets_outside_scope_and_sniper_itself() {
        let (address, log, server) = site(1, false).await;
        let target = format!("http://{address}");
        let state = scan_state("refuse", &[]).await;
        let session = state.session().await;
        let session_id = session.id();
        let body = serde_json::json!({
            "targets": [target], "ids": ["example-config"], "acknowledged": true,
        });
        let refused = |state: Arc<AppState>, body: serde_json::Value| async move {
            let (_, Json(error)) = start(State(state), Json(request(session_id, body)))
                .await
                .unwrap_err();
            error["error"].as_str().unwrap().to_string()
        };
        assert!(refused(state.clone(), body.clone())
            .await
            .contains("no include patterns"));
        session
            .runtime
            .update(crate::runtime::RuntimeSettingsUpdate {
                scope_patterns: Some(vec!["*.example.com".into()]),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(refused(state.clone(), body.clone())
            .await
            .contains("not in Scope"));
        session
            .runtime
            .update(crate::runtime::RuntimeSettingsUpdate {
                scope_patterns: Some(vec!["127.0.0.1".into()]),
                ..Default::default()
            })
            .await
            .unwrap();
        state.set_active_proxy_addr(address).await;
        assert!(refused(state.clone(), body.clone())
            .await
            .contains("Sniper's own listeners"));
        let mut dos = body.clone();
        dos["allow_risks"] = serde_json::json!(["dos"]);
        assert!(refused(state.clone(), dos).await.contains("never sent"));
        for wrong in [
            "ftp://127.0.0.1/",
            "http://user:pass@127.0.0.1/",
            "http://127.0.0.1/?q=1",
            "http://*.example.com/",
            "http://sniper/",
        ] {
            let mut bad = body.clone();
            bad["targets"] = serde_json::json!([wrong]);
            assert_eq!(
                start(State(state.clone()), Json(request(session.id(), bad)))
                    .await
                    .unwrap_err()
                    .0,
                StatusCode::BAD_REQUEST,
                "{wrong}"
            );
        }
        server.abort();
        assert!(log.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn stop_ends_a_scan_without_waiting_for_its_requests() {
        let (address, log, server) = site(1, true).await;
        let state = scan_state("stop", &["127.0.0.1"]).await;
        let session = state.session().await;
        let started = start(
            State(state.clone()),
            Json(request(
                session.id(),
                serde_json::json!({
                    "targets": [format!("http://{address}")],
                    "ids": ["example-slow"],
                    "concurrency": 1,
                    "acknowledged": true,
                }),
            )),
        )
        .await
        .unwrap()
        .0;
        let id: Uuid = serde_json::from_value(started["id"].clone()).unwrap();
        for _ in 0..250 {
            if !log.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let asked = std::time::Instant::now();
        let _stopped = stop(
            State(state.clone()),
            Path(id),
            Json(SessionQuery {
                session_id: session.id(),
            }),
        )
        .await
        .unwrap();
        assert!(asked.elapsed() < Duration::from_secs(3));
        let job = finished(&state, id).await;
        assert_eq!(job.status, "cancelled");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(log.lock().unwrap().len(), 1);
        assert_eq!(session.store.len().await, 0);
        server.abort();
    }

    #[test]
    fn a_restart_marks_running_jobs_interrupted() {
        let store = TemplateScanStore::from_snapshot(TemplateScanSnapshot {
            jobs: vec![
                ScanJob {
                    status: "running".into(),
                    ..ScanJob::default()
                },
                ScanJob {
                    status: "completed".into(),
                    ..ScanJob::default()
                },
            ],
        });
        let statuses: Vec<String> = store
            .snapshot()
            .jobs
            .into_iter()
            .map(|job| job.status)
            .collect();
        assert_eq!(statuses, ["interrupted", "completed"]);
        assert!(!store.is_running());
    }

    #[test]
    fn redirects_follow_go_and_targets_are_origins() {
        assert_eq!(redirect_step(302, "POST"), Some(("GET".into(), false)));
        assert_eq!(redirect_step(303, "HEAD"), Some(("HEAD".into(), false)));
        assert_eq!(redirect_step(307, "PUT"), Some(("PUT".into(), true)));
        assert_eq!(redirect_step(304, "GET"), None);
        let target = parse_target(" https://Example.com:443/app/ ").unwrap();
        assert_eq!(target.label, "https://example.com/app");
        assert_eq!(
            (target.authority.as_str(), target.base_path.as_str()),
            ("example.com", "/app")
        );
        let ipv6 = parse_target("http://[::1]:8080").unwrap();
        assert_eq!(
            (ipv6.authority.as_str(), ipv6.host.as_str()),
            ("[::1]:8080", "::1")
        );
        assert!(parse_risks(&["Intrusive".into(), "method:put".into()]).is_ok());
        assert!(parse_risks(&["anything".into()]).is_err());
    }
}
