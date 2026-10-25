//! Active Scan: templates sent to targets. A manual scan sends the templates
//! the operator picks to the targets they name, when they ask, and follows a
//! redirect only to one of those targets; the auto scan sends to each new host
//! captured in Scope or on its own list. Nothing goes to Sniper's own
//! listeners, a job paces itself and stops when asked, and the history keeps
//! only the exchanges a template matched. The job log keeps one line for each
//! of the rest.

use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    future::Future,
    pin::Pin,
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
    engine::{Interaction, ResponseView, TemplateMatch, UrlVars, Verdict, MAX_ACTIVE_BODY_BYTES},
    flow::Step,
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
/// Origins the auto scan remembers sending to; the oldest is forgotten first
/// and sent to again if seen again.
const MAX_AUTO_SCANNED: usize = 2_000;
/// Origins waiting at once; one seen beyond that waits for its next sighting.
const MAX_AUTO_QUEUED: usize = 200;
const MAX_AUTO_HOSTS: usize = 50;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TemplateScanSnapshot {
    pub jobs: Vec<ScanJob>,
    pub auto: AutoScan,
}

/// The session's auto scan: the templates turned on for it go once to each
/// new origin captured in Scope or on its own host list.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct AutoScan {
    pub enabled: bool,
    /// Host patterns, as Scope takes them, sent to besides Scope's.
    pub hosts: Vec<String>,
    pub rate: u32,
    pub concurrency: usize,
    /// Origins sent to, oldest first.
    pub scanned: VecDeque<String>,
    /// Origins waiting their turn, oldest first.
    pub queued: VecDeque<String>,
}

impl Default for AutoScan {
    fn default() -> Self {
        Self {
            enabled: false,
            hosts: Vec::new(),
            rate: default_rate(),
            concurrency: default_concurrency(),
            scanned: VecDeque::new(),
            queued: VecDeque::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanJob {
    pub id: Uuid,
    /// `running`, `completed`, `cancelled` or `interrupted`.
    pub status: String,
    /// Started by the auto scan rather than the operator.
    pub auto: bool,
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
    /// they went, or an auto scan's host left Scope.
    pub blocked: usize,
    /// Redirects not followed because they led to a host the scan may not
    /// send to, or to Sniper.
    pub redirects_not_followed: usize,
    pub matched: usize,
    pub rate: u32,
    pub concurrency: usize,
    pub max_requests: usize,
    pub allow_risks: Vec<String>,
    pub apply_match_replace: bool,
    /// What HTTP history keeps of it: `all` its exchanges, or `matched` ones.
    #[serde(default = "matched_history")]
    pub history: String,
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
    /// The exchange in HTTP history, when the scan kept it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_id: Option<Uuid>,
}

/// Jobs recorded before a scan could keep every exchange kept only matches.
fn matched_history() -> String {
    "matched".into()
}

/// Which of a manual scan's exchanges HTTP history keeps.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryMode {
    /// Every one, as Fuzzer keeps its own.
    #[default]
    All,
    /// Only those a template matched, as the auto scan keeps.
    Matched,
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
    /// Held while the auto scan starts its next origin, so two starts do not
    /// race for the one slot.
    pump: tokio::sync::Mutex<()>,
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
            pump: tokio::sync::Mutex::new(()),
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

    /// The running auto scan job and the origin it sends to, if one runs.
    fn running_auto(&self) -> Option<(Uuid, String)> {
        let snapshot = self.snapshot.lock().unwrap();
        let job = snapshot
            .jobs
            .iter()
            .find(|job| job.auto && job.status == "running")?;
        Some((job.id, job.targets.first()?.clone()))
    }

    /// Puts an origin back at the head of the auto scan's queue.
    fn requeue(&self, origin: String) {
        let mut snapshot = self.snapshot.lock().unwrap();
        if !snapshot.auto.queued.contains(&origin) {
            snapshot.auto.queued.push_front(origin);
        }
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
    #[serde(default)]
    pub history: HistoryMode,
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
    tracing::warn!(%error, "failed to load session for Active Scan");
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
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "Scan job not found."))
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
    let (metas, excluded_by_risk) = apply_risks(metas, &allowed);

    let session = state
        .session_context_for_id(request.session_id)
        .await
        .map_err(session_load_error)?;
    let (oast, metas, oast_unavailable) = with_oast(&session, metas).await;
    let planned = metas.iter().map(|meta| meta.requests).sum::<usize>() * targets.len();
    // The operator named these targets, as they do in Replay and Recon; Scope
    // bounds only what Sniper sends on its own, the auto scan.
    for target in &targets {
        if crate::proxy::targets_own_listener(&state, &session, &target.scheme, &target.authority)
            .await
        {
            return Err(bad_request(format!(
                "{} is one of Sniper's own listeners.",
                target.label
            )));
        }
    }
    if request.preview {
        let labels: Vec<String> = targets.iter().map(|target| target.label.clone()).collect();
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
    // A scan the operator starts comes first; the auto scan's host waits its
    // turn again.
    if let Some((id, origin)) = session.template_scans.running_auto() {
        session.template_scans.stop(Some(id)).await;
        session.template_scans.requeue(origin);
    }
    let mut allow_risks: Vec<String> = allowed.into_iter().collect();
    allow_risks.sort();
    let job = launch(
        &state,
        &session,
        Plan {
            targets,
            metas,
            oast,
            oast_unavailable,
            allow_risks,
            rate: request.rate,
            concurrency: request.concurrency,
            max_requests: request.max_requests,
            apply_match_replace: request.apply_match_replace,
            auto_hosts: None,
            keep_all: request.history == HistoryMode::All,
            warnings: Vec::new(),
        },
    )
    .await?;
    Ok(Json(
        serde_json::to_value(job.summary()).unwrap_or_default(),
    ))
}

/// The session's Interactsh server, and the templates left once those that
/// need one are dropped when it has none: nothing would hear their callbacks.
async fn with_oast(
    session: &SessionContext,
    mut metas: Vec<TemplateMeta>,
) -> (Option<active::OastUrls>, Vec<TemplateMeta>, usize) {
    let oast = session
        .oast
        .get_registration_info()
        .await
        .map(|(correlation_id, domain)| active::OastUrls {
            correlation_id,
            domain,
        });
    let unavailable = if oast.is_none() {
        let before = metas.len();
        metas.retain(|meta| !meta.oast);
        before - metas.len()
    } else {
        0
    };
    (oast, metas, unavailable)
}

/// What a scan sends, settled before it starts.
struct Plan {
    targets: Vec<ScanTarget>,
    metas: Vec<TemplateMeta>,
    oast: Option<active::OastUrls>,
    oast_unavailable: usize,
    allow_risks: Vec<String>,
    rate: u32,
    concurrency: usize,
    max_requests: usize,
    apply_match_replace: bool,
    /// For a job the auto scan starts, its own host list, which its requests
    /// may also go to; None for one the operator started.
    auto_hosts: Option<Vec<String>>,
    /// Keep every exchange in history, not only the matched ones.
    keep_all: bool,
    warnings: Vec<String>,
}

/// Compiles a plan's templates, records its job and starts sending.
async fn launch(
    state: &Arc<AppState>,
    session: &Arc<SessionContext>,
    plan: Plan,
) -> Result<ScanJob, ApiError> {
    let Plan {
        targets,
        metas,
        oast,
        oast_unavailable,
        allow_risks,
        rate,
        concurrency,
        max_requests,
        apply_match_replace,
        auto_hosts,
        keep_all,
        warnings,
    } = plan;
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
        || !state.is_current_session_context(session).await
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
            "A scan is already running in this session.",
        ));
    }
    let planned = templates
        .iter()
        .map(|template| template.request_count())
        .sum::<usize>()
        * targets.len();
    let mut job = ScanJob {
        id: Uuid::new_v4(),
        status: "running".into(),
        auto: auto_hosts.is_some(),
        started_at: Utc::now(),
        targets: targets.iter().map(|target| target.label.clone()).collect(),
        library: release.clone(),
        templates: templates.len(),
        planned,
        rate,
        concurrency,
        max_requests,
        allow_risks,
        apply_match_replace,
        history: if keep_all { "all" } else { "matched" }.into(),
        ..ScanJob::default()
    };
    for warning in warnings {
        job.warn(warning);
    }
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
            // Auto jobs give way first, so the scans the operator ran stay
            // listed.
            let oldest = snapshot.jobs.iter().position(|job| job.auto).unwrap_or(0);
            snapshot.jobs.remove(oldest);
        }
        snapshot.jobs.push(job.clone());
    }
    session.schedule_state_persist();
    session
        .event_log
        .push(
            EventLevel::Info,
            "templates",
            if job.auto {
                "Auto scan started on a host"
            } else {
                "Manual scan started"
            },
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
        state: Arc::clone(state),
        session: Arc::clone(session),
        job: job.id,
        library: release,
        oast,
        failures: targets.iter().map(|_| AtomicUsize::new(0)).collect(),
        skipped: targets.iter().map(|_| AtomicBool::new(false)).collect(),
        templates,
        targets,
        extra_hosts: auto_hosts,
        keep_all,
        client,
        apply_match_replace,
        max_requests,
        concurrency,
        gap: Duration::from_secs(1) / rate,
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
    Ok(job)
}

/// Whether the auto scan may send to a host: one in a non-empty Scope or on
/// its own host list; never one Scope excludes.
async fn reaches(session: &SessionContext, authority: &str, hosts: &[String]) -> bool {
    let (include, exclude) = session.runtime.scope_lists().await;
    let within = |patterns: &[String]| {
        !patterns.is_empty() && crate::scope::is_host_in_scope(authority, patterns, &exclude)
    };
    within(&include) || within(hosts)
}

/// Queues a captured request's origin for the auto scan the first time the
/// session sees it, when the auto scan is on and may send there, and starts
/// sending if no scan runs.
pub async fn observe(
    state: &Arc<AppState>,
    session: &Arc<SessionContext>,
    scheme: &str,
    host: &str,
) {
    let Some(hosts) = ({
        let snapshot = session.template_scans.snapshot.lock().unwrap();
        snapshot.auto.enabled.then(|| snapshot.auto.hosts.clone())
    }) else {
        return;
    };
    let Ok(target) = parse_target(&format!("{scheme}://{host}")) else {
        return;
    };
    let fresh = |auto: &AutoScan| {
        auto.enabled
            && auto.queued.len() < MAX_AUTO_QUEUED
            && !auto.scanned.contains(&target.label)
            && !auto.queued.contains(&target.label)
    };
    if !fresh(&session.template_scans.snapshot.lock().unwrap().auto)
        || !reaches(session, &target.authority, &hosts).await
        || crate::proxy::targets_own_listener(state, session, &target.scheme, &target.authority)
            .await
    {
        return;
    }
    {
        let mut snapshot = session.template_scans.snapshot.lock().unwrap();
        if !fresh(&snapshot.auto) {
            return;
        }
        snapshot.auto.queued.push_back(target.label.clone());
    }
    session.schedule_state_persist();
    tokio::spawn(pump(Arc::clone(state), Arc::clone(session)));
}

/// Starts the auto scan on the next waiting origin, when it is on, templates
/// are on for it and no scan runs in the session.
pub fn pump(
    state: Arc<AppState>,
    session: Arc<SessionContext>,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    // Boxed: a scan's end starts the next scan, so an unboxed future's type
    // would contain itself.
    Box::pin(async move {
        // Waits rather than gives up: a pump about to return may already
        // have looked at the queue this host just joined.
        let _pumping = session.template_scans.pump.lock().await;
        loop {
            let metas = state.templates.auto_selection();
            let (origin, hosts, rate, concurrency) = {
                let mut snapshot = session.template_scans.snapshot.lock().unwrap();
                if metas.is_empty()
                    || !snapshot.auto.enabled
                    || snapshot.jobs.iter().any(|job| job.status == "running")
                {
                    return;
                }
                let Some(origin) = snapshot.auto.queued.pop_front() else {
                    return;
                };
                let auto = &mut snapshot.auto;
                if !auto.scanned.contains(&origin) {
                    auto.scanned.push_back(origin.clone());
                    if auto.scanned.len() > MAX_AUTO_SCANNED {
                        auto.scanned.pop_front();
                    }
                }
                (origin, auto.hosts.clone(), auto.rate, auto.concurrency)
            };
            session.schedule_state_persist();
            let Ok(target) = parse_target(&origin) else {
                continue;
            };
            // It sends what a scan sends by default: a risky template stays out.
            let (metas, excluded) = apply_risks(metas, &HashSet::new());
            let (oast, metas, oast_unavailable) = with_oast(&session, metas).await;
            if metas.is_empty() {
                continue;
            }
            let mut warnings = Vec::new();
            if !excluded.is_empty() {
                let risks: Vec<String> = excluded
                    .iter()
                    .map(|(risk, count)| format!("{risk} {count}"))
                    .collect();
                warnings.push(format!(
                    "Templates turned on but tagged risky were not sent: {}.",
                    risks.join(", ")
                ));
            }
            let planned = metas.iter().map(|meta| meta.requests).sum::<usize>();
            let plan = Plan {
                targets: vec![target],
                metas,
                oast,
                oast_unavailable,
                allow_risks: Vec::new(),
                rate,
                concurrency,
                max_requests: planned.clamp(1, MAX_MAX_REQUESTS),
                apply_match_replace: false,
                auto_hosts: Some(hosts),
                // Unattended, it would fill history with every host it met.
                keep_all: false,
                warnings,
            };
            match launch(&state, &session, plan).await {
                Ok(_) => return,
                // A scan the operator started got in first; the host waits
                // for it to end, as one it takes over from does.
                Err(_) if session.template_scans.is_running() => {
                    session.template_scans.requeue(origin);
                    return;
                }
                Err((_, Json(error))) => {
                    session
                        .event_log
                        .push(
                            EventLevel::Warn,
                            "templates",
                            "Auto scan skipped a host",
                            error["error"].as_str().unwrap_or_default().to_string(),
                        )
                        .await;
                }
            }
        }
    })
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetAutoScan {
    pub session_id: Uuid,
    pub enabled: bool,
    /// Host patterns, as Scope takes them, sent to besides Scope's; omitted
    /// keeps the list.
    #[serde(default)]
    pub hosts: Option<Vec<String>>,
    #[serde(default)]
    pub rate: Option<u32>,
    #[serde(default)]
    pub concurrency: Option<usize>,
    #[serde(default)]
    pub acknowledged: bool,
}

fn auto_view(state: &AppState, session: &SessionContext) -> serde_json::Value {
    let auto = session.template_scans.snapshot().auto;
    serde_json::json!({
        "session_id": session.id(),
        "enabled": auto.enabled,
        "hosts": auto.hosts,
        "rate": auto.rate,
        "concurrency": auto.concurrency,
        "scanned": auto.scanned.len(),
        "queued": auto.queued.len(),
        "templates": state.templates.auto_selection().len(),
    })
}

pub async fn auto_status(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let session = state
        .read_session_context_for_id(query.session_id)
        .await
        .map_err(session_load_error)?;
    Ok(Json(auto_view(&state, &session)))
}

pub async fn set_auto_scan(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SetAutoScan>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if request.rate.is_some_and(|rate| !(1..=50).contains(&rate))
        || request
            .concurrency
            .is_some_and(|concurrency| !(1..=8).contains(&concurrency))
    {
        return Err(bad_request(
            "Limits: rate 1–50 requests a second, concurrency 1–8.",
        ));
    }
    let hosts = request.hosts.map(|hosts| {
        hosts
            .into_iter()
            .map(|host| host.trim().to_ascii_lowercase())
            .filter(|host| !host.is_empty())
            .collect::<Vec<_>>()
    });
    if hosts.as_ref().is_some_and(|hosts| {
        hosts.len() > MAX_AUTO_HOSTS
            || hosts.iter().any(|host| {
                host.len() > 253 || host.contains('/') || host.chars().any(char::is_whitespace)
            })
    }) {
        return Err(bad_request(format!(
            "Name at most {MAX_AUTO_HOSTS} hosts as Scope takes them: example.com, *.example.com, example.com:8443."
        )));
    }
    if request.enabled && !request.acknowledged {
        return Err(bad_request(
            "Confirm the auto scan: it sends the templates turned on for it to each new host captured in Scope or on its list.",
        ));
    }
    let session = state
        .session_context_for_id(request.session_id)
        .await
        .map_err(session_load_error)?;
    let running = {
        let mut snapshot = session.template_scans.snapshot.lock().unwrap();
        let auto = &mut snapshot.auto;
        auto.enabled = request.enabled;
        if let Some(hosts) = hosts {
            auto.hosts = hosts;
        }
        if let Some(rate) = request.rate {
            auto.rate = rate;
        }
        if let Some(concurrency) = request.concurrency {
            auto.concurrency = concurrency;
        }
        if !request.enabled {
            auto.queued.clear();
        }
        snapshot
            .jobs
            .iter()
            .find(|job| job.auto && job.status == "running")
            .map(|job| job.id)
    };
    if let Some(id) = running.filter(|_| !request.enabled) {
        session.template_scans.stop(Some(id)).await;
    }
    session.schedule_state_persist();
    session
        .event_log
        .push(
            EventLevel::Info,
            "templates",
            if request.enabled {
                "Auto scan turned on"
            } else {
                "Auto scan turned off"
            },
            String::new(),
        )
        .await;
    if request.enabled {
        tokio::spawn(pump(Arc::clone(&state), Arc::clone(&session)));
    }
    Ok(Json(auto_view(&state, &session)))
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
            "No running scan has this id.",
        ));
    }
    session.schedule_state_persist();
    // A stopped auto job skips its host; the auto scan goes on with the next.
    tokio::spawn(pump(Arc::clone(&state), Arc::clone(&session)));
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
    /// For the auto scan, the hosts its requests may go to besides Scope's.
    /// None for a scan the operator started, which goes only to the targets
    /// they named.
    extra_hosts: Option<Vec<String>>,
    /// Keep every exchange in history, not only the matched ones.
    keep_all: bool,
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
    block: usize,
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
    /// The answers make a flow's call of the block true.
    answered: bool,
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

    /// Whether a request may go to a host: for the auto scan, one in Scope or
    /// on its list; for a scan the operator started, one of the targets they
    /// named, so a redirect cannot carry it to a host they did not.
    async fn may_send(&self, authority: &str) -> bool {
        match &self.extra_hosts {
            Some(hosts) => reaches(&self.session, authority, hosts).await,
            None => self
                .targets
                .iter()
                .any(|target| target.authority.eq_ignore_ascii_case(authority)),
        }
    }

    async fn may_send_hop(&self, authority: &str, target_index: usize, redirect: bool) -> bool {
        if self.may_send(authority).await {
            return true;
        }
        if redirect {
            self.update(|job| job.redirects_not_followed += 1);
        } else if !self.skipped[target_index].swap(true, Ordering::Relaxed) {
            self.update(|job| {
                job.blocked += 1;
                job.skipped_targets
                    .push(self.targets[target_index].label.clone());
                job.warn(format!(
                    "{} left Scope; its remaining requests were not sent.",
                    self.targets[target_index].label
                ));
            });
        }
        false
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
        // Keep the listener in this future: aborting a scan after its stop
        // grace period must drop a callback blocked in storage as well.
        let (enough, listening) = watch::channel(false);
        let heard = self.oast.as_ref().map(|_| self.session.oast.subscribe());
        let listener = async {
            if let Some(heard) = heard {
                Arc::clone(&self).listen(heard, listening).await;
            }
        };
        let requests = async {
            let pairs: Vec<(usize, usize)> = (0..self.templates.len())
                .flat_map(|template| (0..self.targets.len()).map(move |target| (template, target)))
                .collect();
            futures_util::stream::iter(pairs)
                .for_each_concurrent(self.concurrency, |(template, target)| {
                    self.template_on_target(template, target, cancel.clone())
                })
                .await;
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
        };
        tokio::join!(requests, listener);
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
                match (self.extra_hosts.is_some(), cancelled) {
                    (true, true) => "Auto scan stopped",
                    (true, false) => "Auto scan finished",
                    (false, true) => "Manual scan stopped",
                    (false, false) => "Manual scan finished",
                },
                format!(
                    "{} requests sent, {} matched, {} failed",
                    counts.0, counts.1, counts.2
                ),
            )
            .await;
        // The auto scan goes on with its next host once a scan finishes.
        if !cancelled {
            tokio::spawn(pump(Arc::clone(&self.state), Arc::clone(&self.session)));
        }
    }

    async fn template_on_target(
        &self,
        template_index: usize,
        target_index: usize,
        mut cancel: watch::Receiver<bool>,
    ) {
        let template = &self.templates[template_index];
        let target = &self.targets[target_index];
        let id = &template.blocks[0].template.info.id;
        let oast = self.oast.as_ref().map(|watch| &watch.urls);
        let Ok(run) = template.start_run(&target.vars, oast) else {
            self.warn(format!(
                "{id} could not work out its variables and was not sent."
            ));
            return;
        };
        // Nuclei keeps one cookie jar for a template's run on a target.
        let mut jar = Vec::new();
        // Whether the blocks the flow last called matched, which decides its
        // `&&` and `||`.
        let mut status = false;
        let mut step = 0;
        while let Some(current) = template.steps.get(step) {
            step += 1;
            let called = match current {
                Step::SkipIf(when, to) => {
                    if status == *when {
                        step = *to;
                    }
                    continue;
                }
                Step::Run(blocks) => blocks,
            };
            status = false;
            for &block_index in called {
                let block = &template.blocks[block_index];
                // The block's answers so far, by request, for matchers that
                // read them.
                let mut history: Vec<Option<Arc<ResponseView>>> = Vec::new();
                'block: for pass in 0..block.passes() {
                    if block.load_pass(&run, pass).is_err() {
                        self.warn(format!(
                            "{id} could not fill payload {} and did not send it.",
                            pass + 1
                        ));
                        continue;
                    }
                    for index in 0..block.sequence_len() {
                        if self.stopping(&cancel, target_index) {
                            return;
                        }
                        let built = match block.build(index, &target.base_path, &run) {
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
                        // The OAST URLs this request carries, when its matchers
                        // wait to hear them called.
                        let oast_ids = match &self.oast {
                            Some(watch) if block.reads_interaction => {
                                let ids = run.oast_ids_in(&built);
                                watch.expect(&ids);
                                ids
                            }
                            _ => Vec::new(),
                        };
                        let hops = self
                            .send_chain(block, target_index, built, &mut jar, &mut cancel)
                            .await;
                        if hops.is_empty() {
                            if let Some(watch) = &self.oast {
                                watch.forget(&oast_ids);
                            }
                            remember(&mut history, index, None);
                            continue;
                        }
                        let values = run.values();
                        let waiting =
                            (!oast_ids.is_empty()).then(|| (hops[0].clone(), values.clone()));
                        let judged = self
                            .judge(
                                template,
                                block_index,
                                target,
                                hops,
                                values,
                                index + 1,
                                history.clone(),
                            )
                            .await;
                        status |= judged.answered;
                        if let (Some(watch), Some((hop, values))) = (&self.oast, waiting) {
                            if judged.matched {
                                watch.forget(&oast_ids);
                            } else {
                                let waiting = Arc::new(Waiting {
                                    template: Arc::clone(template),
                                    block: block_index,
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
                        // What it extracts is there for the rest of the run, the
                        // later blocks included.
                        template.carry(&run, judged.carried);
                        remember(&mut history, index, judged.answer);
                        if judged.matched && block.stop_at_first_match {
                            break 'block;
                        }
                    }
                }
            }
        }
    }

    /// Sends a request and the redirects it may follow. Returns each answer
    /// received, in order; an empty list when none came.
    async fn send_chain(
        &self,
        block: &active::Block,
        target_index: usize,
        built: active::BuiltRequest,
        jar: &mut Vec<(String, String, String)>,
        cancel: &mut watch::Receiver<bool>,
    ) -> Vec<Hop> {
        let target = &self.targets[target_index];
        let id = &block.template.info.id;
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
            if !self
                .may_send_hop(&authority, target_index, !hops.is_empty())
                .await
            {
                break;
            }
            // A block that turns cookies off neither sends nor keeps them,
            // though earlier blocks filled the run's jar.
            let request = self.request(
                target,
                &scheme,
                &authority,
                &method,
                &path,
                &body,
                body_dropped,
                &built.headers,
                if block.cookies { jar } else { &[] },
            );
            if *cancel.borrow() || !self.take_budget() {
                break;
            }
            tokio::select! {
                _ = self.pace() => {}
                _ = cancel.wait_for(|stop| *stop) => break,
            }
            // Scope can narrow while this request waits for its rate slot,
            // including a redirect whose destination was allowed earlier.
            if !self
                .may_send_hop(&authority, target_index, !hops.is_empty())
                .await
            {
                break;
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
            let next = if block.follow != Follow::None && hops.len() < block.max_redirects {
                self.next_hop(
                    block.follow,
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
            if block.cookies {
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
        if !self.may_send(&next_authority).await
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
        block: usize,
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
            let mut verdicts = vec![Verdict::default(); hops.len()];
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
                let judging = &evaluating.blocks[block];
                verdicts[index] = judging.template.verdict(&view);
                // Nuclei remembers the last answer of the chain it read, the
                // first one unless a match stopped it sooner.
                if judging.history {
                    answer = Some(Arc::new(view));
                }
                let verdict = &verdicts[index];
                if (verdict.matched || !verdict.results.is_empty()) && judging.stop_at_first_match {
                    break;
                }
            }
            (hops, verdicts, answer)
        })
        .await;
        let Ok((hops, verdicts, answer)) = judged else {
            return Judged::default();
        };
        let mut matched = false;
        let mut answered = false;
        // The earliest answer's value comes first, as Nuclei merges a chain's.
        let mut carried: Vec<(String, String)> = Vec::new();
        for (hop, verdict) in hops.into_iter().zip(verdicts) {
            answered |= template.blocks[block].template.answers_call(&verdict);
            for (name, value) in verdict.carried {
                if !carried.iter().any(|(seen, _)| *seen == name) {
                    carried.push((name, value));
                }
            }
            // A match only internal matchers made is not reported, yet it
            // stops the block as any other does.
            matched |= verdict.matched;
            let results = verdict.results;
            let found = !results.is_empty();
            let template_id = template.blocks[block].template.info.id.clone();
            if self.keep_all {
                self.store(&template_id, hop.record.clone(), None).await;
            }
            self.update(|job| {
                job.log(ScanLogEntry {
                    at: Utc::now(),
                    template_id,
                    method: hop.request.method.clone(),
                    url: hop.url(),
                    status: hop.record.status,
                    ms: hop.record.duration_ms,
                    matched: found,
                    error: None,
                    record_id: (self.keep_all || found).then_some(hop.record.id),
                })
            });
            if found {
                matched = true;
                self.keep(&template.blocks[block], hop, results, None).await;
            }
        }
        Judged {
            matched,
            answered,
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
            Some(
                judging.template.blocks[judging.block]
                    .template
                    .evaluate(&view),
            )
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
                template_id: waiting.template.blocks[waiting.block]
                    .template
                    .info
                    .id
                    .clone(),
                method: hop.request.method.clone(),
                url: hop.url(),
                status: hop.record.status,
                ms: hop.record.duration_ms,
                matched: true,
                error: None,
                record_id: Some(hop.record.id),
            })
        });
        self.keep(
            &waiting.template.blocks[waiting.block],
            hop,
            results,
            Some(&callback),
        )
        .await;
    }

    /// Puts an exchange in history, noted with its template and job and with
    /// what else is said of it.
    async fn store(&self, template_id: &str, mut record: TransactionRecord, also: Option<String>) {
        record
            .notes
            .push(format!("Template {template_id}, job {}.", self.job));
        record.notes.extend(also);
        crate::proxy::store_record_and_scan_unconditionally(&self.state, &self.session, record)
            .await;
    }

    /// Files a matched exchange's findings, with the callback that made it
    /// match, if one did. A scan that keeps every exchange stored it when it
    /// was judged; one that keeps only matches stores it now.
    async fn keep(
        &self,
        block: &active::Block,
        hop: Hop,
        results: Vec<TemplateMatch>,
        callback: Option<&OastCallback>,
    ) {
        let url = hop.url();
        let record = hop.record;
        let heard = callback.map(|callback| {
            format!(
                "OAST: {} callback from {}.",
                callback.protocol, callback.remote_addr
            )
        });
        if !self.keep_all {
            self.store(&block.template.info.id, record.clone(), heard.clone())
                .await;
        } else if let Some(heard) = &heard {
            // It is in history already, from before the callback came.
            self.session
                .store
                .update_record(record.id, |stored| stored.notes.push(heard.clone()))
                .await;
        }
        let info = &block.template.info;
        for result in &results {
            let mut finding =
                super::active_finding(&block.template, result, &record, self.job, &self.library);
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
        // Scope is empty: the operator named the target, and that is enough.
        let state = scan_state("run", &[]).await;
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
        acknowledged["history"] = "matched".into();
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
        // The redirect led to a host the scan was not given and was not followed.
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

    const BLOCK_TEMPLATES: &[(&str, &str)] = &[
        // The second block sends what the first one extracted, as Nuclei's
        // template context hands it on.
        ("blocks-token", "id: example-blocks-token\ninfo: {}\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/token']\n    extractors:\n      - type: regex\n        name: tok\n        internal: true\n        group: 1\n        regex: ['token=([a-z0-9]+)']\n  - raw:\n      - |\n        POST /check HTTP/1.1\n        Host: {{Hostname}}\n\n        t={{tok}}\n    matchers:\n      - type: word\n        words: ['valid']\n        condition: and\n      - type: word\n        negative: true\n        words: ['invalid']\n    matchers-condition: and\n"),
        // Cookies carry from one block to the next, but not into a block
        // that turns them off.
        ("blocks-cookie", "id: example-blocks-cookie\ninfo: {}\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/login']\n  - method: GET\n    path: ['{{BaseURL}}/home']\n    matchers:\n      - type: word\n        words: ['Welcome back']\n"),
        ("blocks-no-cookie", "id: example-blocks-no-cookie\ninfo: {}\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/login']\n  - method: GET\n    path: ['{{BaseURL}}/home']\n    disable-cookie: true\n    matchers:\n      - type: word\n        words: ['Welcome back']\n"),
        // A block whose matchers are all internal reports nothing, as in
        // Nuclei, yet its match still stops it.
        ("blocks-quiet", "id: example-blocks-quiet\ninfo: {}\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/.git/config', '{{BaseURL}}/never']\n    stop-at-first-match: true\n    matchers:\n      - type: word\n        internal: true\n        words: ['[core]']\n  - method: GET\n    path: ['{{BaseURL}}/home']\n    matchers:\n      - type: word\n        name: second\n        words: ['Who are you']\n"),
        // Each block judges its own answers.
        ("blocks-own", "id: example-blocks-own\ninfo: {}\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/.git/config']\n    matchers:\n      - type: word\n        name: config\n        words: ['[core]']\n  - method: GET\n    path: ['{{BaseURL}}/nothing']\n    matchers:\n      - type: word\n        name: nothing\n        words: ['[core]']\n"),
    ];

    #[tokio::test]
    async fn request_blocks_run_in_order_and_share_what_they_learn() {
        let (address, log, server) = site(1, false).await;
        let state = scan_state_with("blocks", &["127.0.0.1"], BLOCK_TEMPLATES).await;
        let session = state.session().await;
        let started = start(
            State(state.clone()),
            Json(request(
                session.id(),
                serde_json::json!({
                    "targets": [format!("http://{address}")],
                    "filter": {"search": "example-blocks"},
                    "acknowledged": true,
                    "rate": 50,
                }),
            )),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(started["templates"], 5, "{started}");
        let id: Uuid = serde_json::from_value(started["id"].clone()).unwrap();
        let job = finished(&state, id).await;
        server.abort();

        assert_eq!(job.status, "completed", "{job:?}");
        assert_eq!(
            matched_names(&job),
            [
                "example-blocks-cookie",
                "example-blocks-own:config",
                "example-blocks-quiet:second",
                "example-blocks-token"
            ]
        );
        let seen = log.lock().unwrap().clone();
        let check = seen.iter().find(|seen| seen.path == "/check").unwrap();
        assert_eq!(check.body, "t=abc123");
        assert!(!seen.iter().any(|seen| seen.path == "/never"));
    }

    /// `template[:matcher]` of each result, sorted.
    fn matched_names(job: &ScanJob) -> Vec<String> {
        let mut names: Vec<String> = job
            .results
            .iter()
            .map(|result| match &result.matcher {
                Some(matcher) => format!("{}:{matcher}", result.template_id),
                None => result.template_id.clone(),
            })
            .collect();
        names.sort_unstable();
        names
    }

    const FLOW_TEMPLATES: &[(&str, &str)] = &[
        // The second block runs when the first matched, quietly or not...
        ("flow-and", "id: example-flow-and\ninfo: {}\nflow: http(1) && http(2)\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/.git/config']\n    matchers:\n      - type: word\n        internal: true\n        words: ['[core]']\n  - method: GET\n    path: ['{{BaseURL}}/home']\n    matchers:\n      - type: word\n        words: ['Who are you']\n"),
        // ...and is not sent when it did not.
        ("flow-skip", "id: example-flow-skip\ninfo: {}\nflow: http(1) && http(2)\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/flow-first']\n    matchers:\n      - type: word\n        words: ['[core]']\n  - method: GET\n    path: ['{{BaseURL}}/flow-skipped']\n    matchers:\n      - type: status\n        status: [404]\n"),
        // `||` stops at the first block that matched, and blocks run in the
        // flow's order, named by id or position.
        ("flow-or", "id: example-flow-or\ninfo: {}\nflow: (http(\"config\") || http(1)) && http(3)\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/flow-unasked']\n    matchers:\n      - type: status\n        status: [404]\n  - id: config\n    method: GET\n    path: ['{{BaseURL}}/.git/config']\n    matchers:\n      - type: word\n        name: config\n        words: ['[core]']\n  - method: GET\n    path: ['{{BaseURL}}/token']\n    matchers:\n      - type: word\n        name: token\n        words: ['token=']\n"),
        // A block with only an internal extractor is true once it found
        // something, which the next block sends.
        ("flow-extract", "id: example-flow-extract\ninfo: {}\nflow: http(1) && http(2)\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/token']\n    extractors:\n      - type: regex\n        name: tok\n        internal: true\n        group: 1\n        regex: ['token=([a-z0-9]+)']\n  - raw:\n      - |\n        POST /check HTTP/1.1\n        Host: {{Hostname}}\n\n        t={{tok}}\n    matchers-condition: and\n    matchers:\n      - type: word\n        name: checked\n        words: ['valid']\n      - type: word\n        negative: true\n        words: ['invalid']\n"),
        // Any other flow is a script, which never runs.
        ("flow-script", "id: example-flow-script\ninfo: {}\nflow: |\n  http(1)\n  set('a', 1)\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/flow-script']\n    matchers:\n      - type: status\n        status: [200]\n"),
    ];

    #[tokio::test]
    async fn flows_run_the_blocks_their_calls_reach() {
        let (address, log, server) = site(1, false).await;
        let state = scan_state_with("flows", &["127.0.0.1"], FLOW_TEMPLATES).await;
        let session = state.session().await;
        let started = start(
            State(state.clone()),
            Json(request(
                session.id(),
                serde_json::json!({
                    "targets": [format!("http://{address}")],
                    "filter": {"search": "example-flow"},
                    "acknowledged": true,
                    "rate": 50,
                }),
            )),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(started["templates"], 4, "{started}");
        let id: Uuid = serde_json::from_value(started["id"].clone()).unwrap();
        let job = finished(&state, id).await;
        server.abort();

        assert_eq!(job.status, "completed", "{job:?}");
        assert_eq!(
            matched_names(&job),
            [
                "example-flow-and",
                "example-flow-extract",
                "example-flow-or:config",
                "example-flow-or:token"
            ]
        );
        let seen = log.lock().unwrap().clone();
        let sent = |path: &str| seen.iter().any(|seen| seen.path == path);
        assert!(sent("/flow-first"));
        for path in ["/flow-skipped", "/flow-unasked", "/flow-script"] {
            assert!(!sent(path), "{path} was sent");
        }
    }

    const AUTO_TEMPLATES: &[(&str, &str)] = &[
        ("auto-config", "id: example-auto-config\ninfo:\n  severity: high\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/.git/config']\n    matchers:\n      - type: word\n        words: ['[core]']\n"),
        // One that can judge captured traffic is never sent by the auto scan.
        ("auto-passive", "id: example-auto-passive\ninfo: {}\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}']\n    matchers:\n      - type: word\n        words: ['Who are you']\n"),
        ("auto-off", "id: example-auto-off\ninfo: {}\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/off']\n    matchers:\n      - type: status\n        status: [404]\n"),
    ];

    fn auto_request(session: Uuid, value: serde_json::Value) -> SetAutoScan {
        let mut body = serde_json::json!({"session_id": session});
        body.as_object_mut()
            .unwrap()
            .extend(value.as_object().unwrap().clone());
        serde_json::from_value(body).unwrap()
    }

    async fn turn_auto(state: &Arc<AppState>, value: serde_json::Value) -> serde_json::Value {
        let session = state.session().await.id();
        set_auto_scan(State(state.clone()), Json(auto_request(session, value)))
            .await
            .unwrap()
            .0
    }

    fn auto_jobs(session: &SessionContext) -> Vec<ScanJob> {
        let mut jobs = session.template_scans.snapshot().jobs;
        jobs.retain(|job| job.auto);
        jobs
    }

    /// The auto jobs once nothing waits or runs.
    async fn auto_settled(session: &SessionContext) -> Vec<ScanJob> {
        for _ in 0..1_000 {
            let snapshot = session.template_scans.snapshot();
            if snapshot.auto.queued.is_empty()
                && snapshot.jobs.iter().all(|job| job.status != "running")
            {
                return auto_jobs(session);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the auto scan did not settle");
    }

    async fn wait_for(what: &str, check: impl Fn() -> bool) {
        for _ in 0..1_000 {
            if check() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for {what}");
    }

    #[tokio::test]
    async fn the_auto_scan_sends_what_is_on_to_each_new_host_in_scope_once() {
        let (address, log, server) = site(1, false).await;
        let state = scan_state_with("auto", &["127.0.0.1"], AUTO_TEMPLATES).await;
        state
            .templates
            .set_auto(&["example-auto-config".into()], true)
            .unwrap();
        let session = state.session().await;
        // Turning it on is consent to send.
        let refused = set_auto_scan(
            State(state.clone()),
            Json(auto_request(
                session.id(),
                serde_json::json!({"enabled": true}),
            )),
        )
        .await;
        assert_eq!(refused.unwrap_err().0, StatusCode::BAD_REQUEST);
        turn_auto(
            &state,
            serde_json::json!({"enabled": true, "acknowledged": true, "rate": 50}),
        )
        .await;
        let host = address.to_string();
        observe(&state, &session, "http", &host).await;
        observe(&state, &session, "http", &host).await;
        observe(&state, &session, "https", "outside.example.com").await;
        let jobs = auto_settled(&session).await;
        assert_eq!(jobs.len(), 1, "{jobs:?}");
        assert_eq!(jobs[0].targets, [format!("http://{address}")]);
        assert_eq!(jobs[0].templates, 1);
        assert_eq!(jobs[0].matched, 1, "{jobs:?}");
        // A host is sent to once.
        observe(&state, &session, "http", &host).await;
        assert_eq!(auto_settled(&session).await.len(), 1);
        server.abort();
        let seen = log.lock().unwrap().clone();
        assert_eq!(
            seen.iter()
                .filter(|seen| seen.path == "/.git/config")
                .count(),
            1
        );
        assert!(seen.iter().all(|seen| seen.path != "/off"));
        let status = auto_status(
            State(state.clone()),
            Query(SessionQuery {
                session_id: session.id(),
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(status["scanned"], 1, "{status}");
        assert_eq!(status["templates"], 1);
    }

    #[tokio::test]
    async fn a_host_that_arrives_while_the_pump_finishes_is_still_sent_to() {
        let (address, _log, server) = site(1, false).await;
        let state = scan_state_with("auto-busy", &["127.0.0.1"], AUTO_TEMPLATES).await;
        state
            .templates
            .set_auto(&["example-auto-config".into()], true)
            .unwrap();
        let session = state.session().await;
        turn_auto(
            &state,
            serde_json::json!({"enabled": true, "acknowledged": true, "rate": 50}),
        )
        .await;
        // A pump that found nothing to do still holds its lock for a moment.
        let finishing = session.template_scans.pump.lock().await;
        observe(&state, &session, "http", &address.to_string()).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(finishing);
        assert_eq!(auto_settled(&session).await.len(), 1);
        server.abort();
    }

    #[tokio::test]
    async fn a_host_the_proxy_captures_goes_to_the_auto_scan() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (address, _, server) = site(1, false).await;
        let state = scan_state_with("auto-proxy", &["127.0.0.1"], AUTO_TEMPLATES).await;
        state
            .templates
            .set_auto(&["example-auto-config".into()], true)
            .unwrap();
        turn_auto(
            &state,
            serde_json::json!({"enabled": true, "acknowledged": true, "rate": 50}),
        )
        .await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = listener.local_addr().unwrap();
        let proxy = tokio::spawn(crate::proxy::serve_proxy(listener, Arc::clone(&state)));
        let mut stream = tokio::net::TcpStream::connect(proxy_address).await.unwrap();
        stream
            .write_all(
                format!("GET http://{address}/home HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let session = state.session().await;
        wait_for("an auto job", || !auto_jobs(&session).is_empty()).await;
        let jobs = auto_settled(&session).await;
        assert_eq!(jobs[0].targets, [format!("http://{address}")]);
        assert_eq!(jobs[0].matched, 1, "{jobs:?}");
        proxy.abort();
        server.abort();
    }

    #[tokio::test]
    async fn the_auto_scan_reaches_its_own_hosts_but_never_excluded_ones() {
        let (address, _, server) = site(1, false).await;
        let state = scan_state_with("auto-hosts", &["scope.example.com"], AUTO_TEMPLATES).await;
        state
            .templates
            .set_auto(&["example-auto-config".into()], true)
            .unwrap();
        let session = state.session().await;
        turn_auto(
            &state,
            serde_json::json!({"enabled": true, "acknowledged": true, "rate": 50, "hosts": ["127.0.0.1"]}),
        )
        .await;
        observe(&state, &session, "http", &address.to_string()).await;
        let jobs = auto_settled(&session).await;
        assert_eq!(jobs.len(), 1);
        // Its requests went out although the host is not in Scope.
        assert_eq!(jobs[0].matched, 1, "{jobs:?}");
        session
            .runtime
            .update(crate::runtime::RuntimeSettingsUpdate {
                excluded_scope_patterns: Some(vec!["127.0.0.1".into()]),
                ..Default::default()
            })
            .await
            .unwrap();
        let (other, _, other_server) = site(1, false).await;
        observe(&state, &session, "http", &other.to_string()).await;
        assert_eq!(auto_settled(&session).await.len(), 1);
        server.abort();
        other_server.abort();
    }

    #[tokio::test]
    async fn a_scan_the_operator_starts_takes_over_from_the_auto_scan() {
        let (slow, _, slow_server) = site(1, true).await;
        let (address, _, server) = site(1, false).await;
        let state = scan_state_with("auto-manual", &["127.0.0.1"], AUTO_TEMPLATES).await;
        state
            .templates
            .set_auto(&["example-auto-config".into()], true)
            .unwrap();
        let session = state.session().await;
        turn_auto(
            &state,
            serde_json::json!({"enabled": true, "acknowledged": true}),
        )
        .await;
        observe(&state, &session, "http", &slow.to_string()).await;
        wait_for("the auto job", || {
            auto_jobs(&session)
                .iter()
                .any(|job| job.status == "running")
        })
        .await;
        let started = start(
            State(state.clone()),
            Json(request(
                session.id(),
                serde_json::json!({
                    "targets": [format!("http://{address}")],
                    "ids": ["example-auto-off"],
                    "acknowledged": true,
                    "rate": 50,
                }),
            )),
        )
        .await
        .unwrap()
        .0;
        let id: Uuid = serde_json::from_value(started["id"].clone()).unwrap();
        assert_eq!(finished(&state, id).await.status, "completed");
        // The host the auto scan was on waited its turn and is sent to again.
        wait_for("the auto scan to resume", || {
            let jobs = auto_jobs(&session);
            jobs.len() == 2 && jobs[0].status == "cancelled" && jobs[1].targets == jobs[0].targets
        })
        .await;
        turn_auto(&state, serde_json::json!({"enabled": false})).await;
        slow_server.abort();
        server.abort();
    }

    #[tokio::test]
    async fn a_host_the_operator_beats_to_a_start_waits_its_turn() {
        let (address, _, server) = site(1, false).await;
        let state = scan_state_with("auto-race", &["127.0.0.1"], AUTO_TEMPLATES).await;
        state
            .templates
            .set_auto(&["example-auto-config".into()], true)
            .unwrap();
        let session = state.session().await;
        turn_auto(
            &state,
            serde_json::json!({"enabled": true, "acknowledged": true, "rate": 50}),
        )
        .await;
        // Both wait for the session; the operator's scan asked first, after
        // the auto scan had seen nothing running.
        let held = state
            .session_operation_lock(session.id())
            .await
            .lock_owned()
            .await;
        let manual = tokio::spawn(start(
            State(state.clone()),
            Json(request(
                session.id(),
                serde_json::json!({
                    "targets": [format!("http://{address}")],
                    "ids": ["example-auto-off"],
                    "acknowledged": true,
                    "rate": 50,
                }),
            )),
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;
        observe(&state, &session, "http", &address.to_string()).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(held);
        let started = manual.await.unwrap().unwrap().0;
        let id: Uuid = serde_json::from_value(started["id"].clone()).unwrap();
        assert_eq!(finished(&state, id).await.status, "completed");
        wait_for("the host to be sent to", || auto_jobs(&session).len() == 1).await;
        server.abort();
    }

    #[tokio::test]
    async fn turning_the_auto_scan_off_stops_it_and_forgets_what_waits() {
        let (slow, _, slow_server) = site(1, true).await;
        let state = scan_state_with("auto-off", &["127.0.0.1", "localhost"], AUTO_TEMPLATES).await;
        state
            .templates
            .set_auto(&["example-auto-config".into()], true)
            .unwrap();
        let session = state.session().await;
        turn_auto(
            &state,
            serde_json::json!({"enabled": true, "acknowledged": true}),
        )
        .await;
        observe(&state, &session, "http", &slow.to_string()).await;
        observe(&state, &session, "http", "localhost:9").await;
        wait_for("the auto job", || {
            auto_jobs(&session)
                .iter()
                .any(|job| job.status == "running")
        })
        .await;
        let status = turn_auto(&state, serde_json::json!({"enabled": false})).await;
        assert_eq!(status["enabled"], false);
        assert_eq!(status["queued"], 0, "{status}");
        assert_eq!(auto_jobs(&session)[0].status, "cancelled");
        observe(&state, &session, "http", "localhost:10").await;
        assert_eq!(session.template_scans.snapshot().auto.queued.len(), 0);
        slow_server.abort();
    }

    #[test]
    fn the_auto_scan_survives_a_restart_and_its_job_reads_as_interrupted() {
        let mut snapshot = TemplateScanSnapshot::default();
        snapshot.auto.enabled = true;
        snapshot
            .auto
            .queued
            .push_back("https://app.example.com".into());
        snapshot.jobs.push(ScanJob {
            status: "running".into(),
            auto: true,
            ..ScanJob::default()
        });
        let text = serde_json::to_string(&snapshot).unwrap();
        let store = TemplateScanStore::from_snapshot(serde_json::from_str(&text).unwrap());
        let restored = store.snapshot();
        assert!(restored.auto.enabled);
        assert_eq!(restored.auto.queued, ["https://app.example.com"]);
        assert_eq!(restored.jobs[0].status, "interrupted");
        // An older state without it reads as off.
        let old: TemplateScanSnapshot = serde_json::from_str(r#"{"jobs":[]}"#).unwrap();
        assert!(!old.auto.enabled);
        assert_eq!(old.auto.rate, 10);
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
        // Every answer is in history once, the callback's noted on the one it
        // matched, though the answer was stored before the callback came.
        assert_eq!(session.store.len().await, job.sent - job.failed);
        let hit = job
            .results
            .iter()
            .find(|result| result.template_id == "example-oast-hit")
            .unwrap();
        let record = session.store.get(hit.record_id).await.unwrap();
        assert!(
            record
                .notes
                .iter()
                .any(|note| note == "OAST: http callback from 192.0.2.10."),
            "{:?}",
            record.notes
        );
    }

    // A manual scan keeps every exchange in history, as Fuzzer does, so each
    // line of its log opens what was sent and what came back. Told to, it keeps
    // only the matched ones, as the auto scan always does.
    #[tokio::test]
    async fn stopping_an_oast_scan_owns_its_callback_worker_until_it_exits() {
        let (address, log, server) = site(1, false).await;
        let state = scan_state_with("oast-stop", &["127.0.0.1"], OAST_TEMPLATES).await;
        let session = state.session().await;
        session
            .oast
            .pretend_interactsh("https://oast.example.com", &"c".repeat(20))
            .await;
        let started = start(
            State(Arc::clone(&state)),
            Json(request(
                session.id(),
                serde_json::json!({
                    "targets": [format!("http://{address}")],
                    "ids": ["example-oast-hit"],
                    "acknowledged": true,
                    "history": "matched",
                }),
            )),
        )
        .await
        .unwrap()
        .0;
        let id: Uuid = serde_json::from_value(started["id"].clone()).unwrap();
        let correlation = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let answered = session
                    .template_scans
                    .snapshot()
                    .jobs
                    .iter()
                    .find(|job| job.id == id)
                    .is_some_and(|job| !job.recent.is_empty());
                if answered {
                    if let Some(value) = log.lock().unwrap().iter().find_map(|seen| {
                        seen.header
                            .strip_prefix("http://")
                            .and_then(|rest| rest.split('.').next())
                            .map(str::to_string)
                    }) {
                        break value;
                    }
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the local request did not finish");
        // Stall a matched callback's storage, not its HTTP request. Stop's
        // grace period must not leave this worker detached behind the lock.
        let store = session.store.owned_persistence_mutation_guard().await;
        session
            .oast
            .push(OastCallback {
                id: Uuid::new_v4(),
                received_at: Utc::now(),
                protocol: "http".into(),
                remote_addr: "192.0.2.10".into(),
                raw_data: "GET /x HTTP/1.1\r\n\r\n".into(),
                correlation_id: correlation,
            })
            .await;
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if session
                    .template_scans
                    .snapshot()
                    .jobs
                    .iter()
                    .find(|job| job.id == id)
                    .unwrap()
                    .recent
                    .iter()
                    .any(|entry| entry.matched)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the callback did not reach storage");
        assert!(session.template_scans.stop(Some(id)).await);
        drop(store);
        // The mutex is FIFO: any detached insertion already waiting would
        // finish before this guard can be acquired.
        drop(session.store.owned_persistence_mutation_guard().await);
        server.abort();
        assert_eq!(
            session.store.len().await,
            0,
            "a stopped callback wrote after Stop returned"
        );
        assert_eq!(
            session.template_scans.snapshot().jobs[0].status,
            "cancelled"
        );
    }

    #[tokio::test]
    async fn a_manual_scan_keeps_every_exchange_unless_told_to_keep_only_matches() {
        let (address, _log, server) = site(1, false).await;
        let target = format!("http://{address}");
        for (name, history) in [
            ("history-default", None),
            ("history-all", Some("all")),
            ("history-matched", Some("matched")),
        ] {
            let state = scan_state(name, &[]).await;
            let session = state.session().await;
            let mut body = serde_json::json!({
                "targets": [target], "ids": ["example-config", "example-miss"],
                "acknowledged": true, "rate": 50,
            });
            if let Some(history) = history {
                body["history"] = history.into();
            }
            let started = start(State(state.clone()), Json(request(session.id(), body)))
                .await
                .unwrap()
                .0;
            let id: Uuid = serde_json::from_value(started["id"].clone()).unwrap();
            let job = finished(&state, id).await;
            assert_eq!((job.sent, job.matched), (2, 1), "{name}: {job:?}");
            let keeps_all = history != Some("matched");
            assert_eq!(
                job.history,
                if keeps_all { "all" } else { "matched" },
                "{name}"
            );
            assert_eq!(
                session.store.len().await,
                if keeps_all { 2 } else { 1 },
                "{name}"
            );
            for entry in &job.recent {
                assert_eq!(
                    entry.record_id.is_some(),
                    keeps_all || entry.matched,
                    "{name}: {entry:?}"
                );
                if let Some(record_id) = entry.record_id {
                    let record = session.store.get(record_id).await.unwrap();
                    assert!(entry.url.ends_with(&record.path), "{name}");
                    assert!(record
                        .notes
                        .iter()
                        .any(|note| note == crate::model::TEMPLATE_SCAN_NOTE));
                    assert_eq!(
                        record
                            .notes
                            .iter()
                            .filter(|note| note.starts_with("Template "))
                            .count(),
                        1,
                        "{name}: one record, noted once"
                    );
                }
            }
        }
        server.abort();
    }

    // "Turned on": the templates whose On box is ticked, whatever the search.
    #[tokio::test]
    async fn a_scan_can_take_the_templates_turned_on() {
        let (address, _log, server) = site(1, false).await;
        let state = scan_state("turned-on", &[]).await;
        let session = state.session().await;
        state
            .templates
            .set_auto(&["example-config".into()], true)
            .unwrap();
        let preview = start(
            State(state.clone()),
            Json(request(
                session.id(),
                serde_json::json!({
                    "targets": [format!("http://{address}")],
                    "filter": {"enabled": true}, "preview": true,
                }),
            )),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(preview["templates"], 1);
        assert_eq!(preview["requests"], 1);
        server.abort();
    }

    // The operator names a scan's targets. Scope bounds what Sniper sends on its
    // own, the auto scan, not this; Sniper itself is never a target.
    #[tokio::test]
    async fn a_scan_takes_the_targets_it_is_given_whatever_scope_says_but_never_sniper() {
        let (address, log, server) = site(1, false).await;
        let target = format!("http://{address}");
        let state = scan_state("refuse", &[]).await;
        let session = state.session().await;
        let session_id = session.id();
        let body = serde_json::json!({
            "targets": [target], "ids": ["example-config"], "acknowledged": true,
        });
        let counted = |state: Arc<AppState>, body: serde_json::Value| async move {
            let mut preview = body;
            preview["preview"] = true.into();
            start(State(state), Json(request(session_id, preview)))
                .await
                .unwrap()
                .0["templates"]
                .clone()
        };
        let refused = |state: Arc<AppState>, body: serde_json::Value| async move {
            let (_, Json(error)) = start(State(state), Json(request(session_id, body)))
                .await
                .unwrap_err();
            error["error"].as_str().unwrap().to_string()
        };
        // An empty Scope, one naming other hosts, one excluding this host.
        assert_eq!(counted(state.clone(), body.clone()).await, 1);
        let scopes: [(&[&str], &[&str]); 2] =
            [(&["*.example.com"], &[]), (&["127.0.0.1"], &["127.0.0.1"])];
        for (include, exclude) in scopes {
            session
                .runtime
                .update(crate::runtime::RuntimeSettingsUpdate {
                    scope_patterns: Some(include.iter().map(|s| s.to_string()).collect()),
                    excluded_scope_patterns: Some(exclude.iter().map(|s| s.to_string()).collect()),
                    ..Default::default()
                })
                .await
                .unwrap();
            assert_eq!(
                counted(state.clone(), body.clone()).await,
                1,
                "{include:?} {exclude:?}"
            );
        }
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
    async fn an_auto_scan_rechecks_scope_after_waiting_for_its_rate_slot() {
        let (address, log, server) = site(1, false).await;
        let state = scan_state("paced-scope", &["127.0.0.1"]).await;
        let session = state.session().await;
        let (metas, _) = state
            .templates
            .active_selection(&["example-config".into()], None);
        let template = Arc::new(state.templates.compile_active(&metas[0]).unwrap());
        let target = parse_target(&format!("http://{address}")).unwrap();
        let job = Uuid::new_v4();
        session
            .template_scans
            .snapshot
            .lock()
            .unwrap()
            .jobs
            .push(ScanJob {
                id: job,
                status: "running".into(),
                ..ScanJob::default()
            });
        let run = Arc::new(Run {
            state: Arc::clone(&state),
            session: Arc::clone(&session),
            job,
            library: String::new(),
            oast: None,
            templates: vec![template],
            targets: vec![target],
            extra_hosts: Some(Vec::new()),
            keep_all: true,
            client: crate::proxy::build_template_scan_client(false, &Default::default()).unwrap(),
            apply_match_replace: false,
            max_requests: 10,
            concurrency: 1,
            gap: Duration::from_millis(1),
            next_slot: tokio::sync::Mutex::new(Instant::now()),
            sent: AtomicUsize::new(0),
            limit_reached: AtomicBool::new(false),
            failures: vec![AtomicUsize::new(0)],
            skipped: vec![AtomicBool::new(false)],
        });
        // Hold the rate limiter until the request has passed its first
        // scope check and reserved a budget slot. No wall-clock race.
        let slot = run.next_slot.lock().await;
        let (_cancel, cancelled) = watch::channel(false);
        let worker = Arc::clone(&run);
        let task = tokio::spawn(async move { worker.template_on_target(0, 0, cancelled).await });
        tokio::time::timeout(Duration::from_secs(2), async {
            while run.sent.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the request did not reach its rate slot");
        session
            .runtime
            .update(crate::runtime::RuntimeSettingsUpdate {
                excluded_scope_patterns: Some(vec!["127.0.0.1".into()]),
                ..Default::default()
            })
            .await
            .unwrap();
        drop(slot);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("the scoped-out request did not finish")
            .unwrap();
        server.abort();
        assert!(
            log.lock().unwrap().is_empty(),
            "a host excluded while pacing must receive no request"
        );
        assert_eq!(session.store.len().await, 0);
        let saved = session.template_scans.snapshot();
        assert_eq!(saved.jobs[0].sent, 0);
        assert_eq!(saved.jobs[0].blocked, 1);
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
            ..TemplateScanSnapshot::default()
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
