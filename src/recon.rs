//! Explicitly scoped, session-owned endpoint discovery. Findings are evidence,
//! not proxy transactions: archived and static candidates never imply liveness.
use std::{
    collections::{HashMap, HashSet, VecDeque},
    io::{self, BufRead, Read},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::{Duration, Instant},
};

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;
use url::Url;
use uuid::Uuid;

use crate::{
    recon_sources::{self, Discovery, SourceReport},
    session::SessionContext,
    state::AppState,
};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ReconSnapshot {
    pub jobs: Vec<ReconJob>,
    pub endpoints: Vec<ReconEndpoint>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReconJob {
    pub id: Uuid,
    pub target_url: String,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub sources: Vec<ReconSource>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReconSource {
    pub source: String,
    pub status: String,
    pub requests: usize,
    pub discovered: usize,
    pub truncated: bool,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReconEndpoint {
    pub url: String,
    pub method: String,
    pub raw_urls: Vec<String>,
    pub evidence: Vec<ReconEvidence>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconEvidence {
    pub source: String,
    pub kind: String,
    pub location: String,
    pub timestamp: Option<String>,
    pub status: Option<u16>,
}

struct RunningJob {
    id: Uuid,
    cancel: Arc<AtomicBool>,
    task: JoinHandle<()>,
}

pub struct ReconStore {
    snapshot: Mutex<ReconSnapshot>,
    running: Mutex<Option<RunningJob>>,
    endpoint_index: Mutex<HashMap<(String, String), usize>>,
}

impl ReconStore {
    pub fn from_snapshot(mut snapshot: ReconSnapshot) -> Self {
        // A process restart cannot resume network work implicitly. Keep evidence
        // and make the interrupted state visible instead of claiming completion.
        for job in &mut snapshot.jobs {
            if job.status == "running" {
                job.status = "interrupted".into();
                job.finished_at = Some(Utc::now());
                for source in &mut job.sources {
                    if source.status == "running" || source.status == "queued" {
                        source.status = "interrupted".into();
                    }
                }
            }
        }
        let endpoint_index = snapshot
            .endpoints
            .iter()
            .enumerate()
            .map(|(index, endpoint)| ((endpoint.url.clone(), endpoint.method.clone()), index))
            .collect();
        Self {
            snapshot: Mutex::new(snapshot),
            running: Mutex::new(None),
            endpoint_index: Mutex::new(endpoint_index),
        }
    }

    pub fn snapshot(&self) -> ReconSnapshot {
        self.snapshot.lock().unwrap().clone()
    }

    /// Project only the metadata needed by Target's site map, leaving full raw
    /// URL spellings and evidence in the session inventory.
    pub fn site_map_endpoints(&self) -> Vec<crate::target::ReconSiteMapEndpoint> {
        self.snapshot
            .lock()
            .unwrap()
            .endpoints
            .iter()
            .map(|endpoint| {
                let mut sources: Vec<_> =
                    endpoint.evidence.iter().map(|e| e.source.clone()).collect();
                sources.sort_unstable();
                sources.dedup();
                let mut kinds: Vec<_> = endpoint.evidence.iter().map(|e| e.kind.clone()).collect();
                kinds.sort_unstable();
                kinds.dedup();
                crate::target::ReconSiteMapEndpoint {
                    url: endpoint.url.clone(),
                    method: endpoint.method.clone(),
                    last_seen: endpoint.last_seen,
                    sources,
                    kinds,
                }
            })
            .collect()
    }

    pub fn is_running(&self) -> bool {
        self.snapshot
            .lock()
            .unwrap()
            .jobs
            .iter()
            .any(|job| job.status == "running")
    }

    fn update_source(&self, id: Uuid, name: &str, update: impl FnOnce(&mut ReconSource)) {
        if let Some(source) = self
            .snapshot
            .lock()
            .unwrap()
            .jobs
            .iter_mut()
            .find(|job| job.id == id)
            .and_then(|job| job.sources.iter_mut().find(|source| source.source == name))
        {
            update(source);
        }
    }

    #[cfg(test)]
    fn merge(
        &self,
        job: Uuid,
        scope: &ReconScope,
        source: &str,
        findings: Vec<Discovery>,
        limit: usize,
    ) -> (usize, bool) {
        self.merge_with_cancel(job, scope, source, findings, limit, None)
    }

    /// An optional budget counts only this job's new endpoints. Zero leaves the
    /// inventory unbounded, and existing endpoints always retain new evidence.
    fn merge_with_cancel(
        &self,
        job: Uuid,
        scope: &ReconScope,
        source: &str,
        findings: Vec<Discovery>,
        limit: usize,
        cancel: Option<&AtomicBool>,
    ) -> (usize, bool) {
        let mut snapshot = self.snapshot.lock().unwrap();
        let mut endpoint_index = self.endpoint_index.lock().unwrap();
        let found_before: usize = snapshot
            .jobs
            .iter()
            .find(|item| item.id == job)
            .map_or(0, |item| {
                item.sources.iter().map(|source| source.discovered).sum()
            });
        let remaining = (limit != 0).then(|| limit.saturating_sub(found_before));
        let mut added = 0;
        let mut truncated = false;
        for finding in findings {
            if cancel.is_some_and(|cancel| cancel.load(Ordering::Acquire)) {
                truncated = true;
                break;
            }
            let Ok(mut url) = Url::parse(&finding.url) else {
                continue;
            };
            if !scope.contains_evidence(&url) {
                continue;
            }
            url.set_fragment(None);
            let key = url.to_string();
            let method = if http::Method::from_bytes(finding.method.as_bytes()).is_ok() {
                finding.method.to_ascii_uppercase()
            } else {
                "GET".into()
            };
            let evidence = ReconEvidence {
                source: source.into(),
                kind: finding.kind,
                location: finding.location,
                timestamp: finding.timestamp,
                status: finding.status,
            };
            let identity = (key.clone(), method.clone());
            if let Some(index) = endpoint_index.get(&identity) {
                let endpoint = &mut snapshot.endpoints[*index];
                if !endpoint.raw_urls.contains(&finding.url) {
                    endpoint.raw_urls.push(finding.url);
                }
                if !endpoint.evidence.contains(&evidence) {
                    endpoint.evidence.push(evidence);
                }
                endpoint.last_seen = Utc::now();
            } else {
                if remaining.is_some_and(|remaining| added >= remaining) {
                    truncated = true;
                    continue;
                }
                let now = Utc::now();
                endpoint_index.insert(identity, snapshot.endpoints.len());
                snapshot.endpoints.push(ReconEndpoint {
                    url: key,
                    method,
                    raw_urls: vec![finding.url],
                    evidence: vec![evidence],
                    first_seen: now,
                    last_seen: now,
                });
                added += 1;
            }
        }
        (added, truncated)
    }

    pub async fn stop(&self, id: Option<Uuid>) -> bool {
        let running = {
            let mut guard = self.running.lock().unwrap();
            if id.is_some_and(|id| guard.as_ref().is_none_or(|job| job.id != id)) {
                return false;
            }
            guard.take()
        };
        let Some(running) = running else { return false };
        running.cancel.store(true, Ordering::Release);
        running.task.abort();
        // Await abort before deletion/persistence: no old worker may write after
        // its session is removed, or race a new run's inventory.
        let _ = running.task.await;
        if let Some(job) = self
            .snapshot
            .lock()
            .unwrap()
            .jobs
            .iter_mut()
            .find(|job| job.id == running.id)
        {
            if job.status == "running" {
                job.status = "cancelled".into();
                job.finished_at = Some(Utc::now());
                for source in &mut job.sources {
                    if source.status == "running" || source.status == "queued" {
                        source.status = "cancelled".into();
                        source.warnings.push(
                            "Stopped; an in-flight provider page may not have been saved.".into(),
                        );
                        if source.source == "urlscan_submit" {
                            source.warnings.push("Stopping local polling cannot cancel a scan already accepted by urlscan.".into());
                        }
                    }
                }
            }
        }
        true
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StartRecon {
    pub session_id: Uuid,
    pub target_url: String,
    #[serde(default)]
    pub include_subdomains: bool,
    pub sources: Vec<String>,
    /// Optional collection budget; zero (the default) is unbounded.
    #[serde(default)]
    pub max_requests: usize,
    /// Optional collection budget; zero (the default) is unbounded.
    #[serde(default)]
    pub max_depth: usize,
    /// Optional collection budget; zero (the default) is unbounded.
    #[serde(default)]
    pub max_endpoints: usize,
    /// Optional collection budget; zero (the default) is unbounded.
    #[serde(default)]
    pub max_pages: usize,
    #[serde(default)]
    pub history_acknowledged: bool,
    #[serde(default)]
    pub scan_acknowledged: bool,
    #[serde(default)]
    pub scan_visibility: Option<String>,
}
impl StartRecon {
    /// Apply the server's scope and provider-consent checks without network work.
    /// The CLI uses the same validation before an offline dry-run or confirmation.
    pub fn validate(&self) -> Result<(), String> {
        validate(self).map(|_| ())
    }
}

#[derive(Clone)]
struct ReconScope {
    target: Url,
    host_pattern: String,
}

impl ReconScope {
    fn new(target: &str, subdomains: bool) -> Result<Self, String> {
        let url =
            Url::parse(target).map_err(|_| "Enter an absolute http:// or https:// target URL.")?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.port_or_known_default() == Some(0)
            || target.chars().any(char::is_control)
        {
            return Err(
                "Target must be an HTTP(S) URL without credentials, with a valid port.".into(),
            );
        }
        let host = url.host_str().unwrap();
        if host.contains('*') {
            return Err("Target hostname cannot contain wildcard characters.".into());
        }
        if subdomains
            && url
                .host()
                .is_some_and(|host| !matches!(host, url::Host::Domain(_)))
        {
            return Err("Subdomain scope is only available for DNS names.".into());
        }
        let host_pattern = if subdomains {
            format!("*.{host}")
        } else {
            host.into()
        };
        Ok(Self {
            target: url,
            host_pattern,
        })
    }

    fn contains_evidence(&self, candidate: &Url) -> bool {
        if matches!(candidate.scheme(), "ws" | "wss") {
            let mut http = candidate.clone();
            let scheme = if candidate.scheme() == "ws" {
                "http"
            } else {
                "https"
            };
            if http.set_scheme(scheme).is_err() {
                return false;
            }
            self.contains(&http)
        } else {
            self.contains(candidate)
        }
    }

    fn contains(&self, candidate: &Url) -> bool {
        if !matches!(candidate.scheme(), "http" | "https")
            || !candidate.username().is_empty()
            || candidate.password().is_some()
        {
            return false;
        }
        let Some(host) = candidate.host_str() else {
            return false;
        };
        // Host semantics stay in the shared matcher. Recon additionally requires
        // an explicit target and binds the port, unlike empty proxy include lists.
        if !crate::scope::host_matches_pattern(host, &self.host_pattern) {
            return false;
        }
        let same_origin_port = candidate.scheme() == self.target.scheme()
            && candidate.port_or_known_default() == self.target.port_or_known_default();
        let secure_upgrade = self.target.scheme() == "http"
            && self.target.port_or_known_default() == Some(80)
            && candidate.scheme() == "https"
            && candidate.port_or_known_default() == Some(443);
        same_origin_port || secure_upgrade
    }
}

pub(crate) fn discovery_in_scope(target: &Url, subdomains: bool, raw: &str) -> bool {
    match (
        ReconScope::new(target.as_str(), subdomains),
        Url::parse(raw),
    ) {
        (Ok(scope), Ok(url)) => scope.contains_evidence(&url),
        _ => false,
    }
}

fn validate(request: &StartRecon) -> Result<ReconScope, String> {
    let scope = ReconScope::new(&request.target_url, request.include_subdomains)?;
    if request.sources.is_empty()
        || request.sources.len() > 4
        || request
            .sources
            .iter()
            .any(|s| !["crawler", "urlscan", "wayback", "urlscan_submit"].contains(&s.as_str()))
        || request.sources.iter().collect::<HashSet<_>>().len() != request.sources.len()
    {
        return Err("Choose one or more distinct Recon sources.".into());
    }
    if request
        .sources
        .iter()
        .any(|s| s == "urlscan" || s == "wayback")
        && !request.history_acknowledged
    {
        return Err("Acknowledge sharing the target hostname with the history providers.".into());
    }
    if request.sources.iter().any(|s| s == "urlscan_submit") {
        if !request.scan_acknowledged
            || !matches!(
                request.scan_visibility.as_deref(),
                Some("private" | "unlisted" | "public")
            )
        {
            return Err(
                "New urlscan scans require an explicit visibility and sharing acknowledgment."
                    .into(),
            );
        }
        if scope.target.query().is_some() || scope.target.fragment().is_some() {
            return Err(
                "Remove query strings and fragments before sharing a new scan URL with urlscan."
                    .into(),
            );
        }
    }
    Ok(scope)
}

type ApiError = (StatusCode, Json<serde_json::Value>);

/// Only a missing session is "not found"; one that failed to load from disk
/// read as a wrong ID to the caller and to anyone reading the logs.
fn session_load_error(error: anyhow::Error) -> ApiError {
    if error.to_string().contains("was not found") {
        return api_error(StatusCode::NOT_FOUND, "Session not found.");
    }
    tracing::warn!(%error, "failed to load session for Recon");
    api_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Session could not be loaded.",
    )
}
fn api_error(status: StatusCode, message: &str) -> ApiError {
    (status, Json(serde_json::json!({"error": message})))
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
    let snapshot = session.recon.snapshot();
    Ok(Json(
        serde_json::json!({"session_id": session.id(), "jobs": snapshot.jobs, "endpoints": snapshot.endpoints}),
    ))
}

pub async fn start(
    State(state): State<Arc<AppState>>,
    Json(request): Json<StartRecon>,
) -> Result<Json<ReconJob>, ApiError> {
    let scope = validate(&request).map_err(|e| api_error(StatusCode::BAD_REQUEST, &e))?;
    let session = state
        .session_context_for_id(request.session_id)
        .await
        .map_err(session_load_error)?;
    let operation_lock = state.session_operation_lock(session.id()).await;
    let _operation_guard = operation_lock.lock_owned().await;
    if !state.sessions.contains_session(session.id())
        || !state.is_current_session_context(&session).await
    {
        return Err(api_error(
            StatusCode::CONFLICT,
            "Session changed or was deleted; reload Recon.",
        ));
    }
    let _guard = session.owned_mutation_guard().await;
    if session.recon.is_running() {
        return Err(api_error(
            StatusCode::CONFLICT,
            "A Recon job is already running in this session.",
        ));
    }
    let upstream = session.runtime.upstream_proxy().await;
    let crawler = upstream
        .apply(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(15))
                .user_agent(concat!("Sniper-Recon/", env!("CARGO_PKG_VERSION"))),
        )
        .and_then(|builder| builder.build().map_err(Into::into))
        .map_err(|_| {
            api_error(
                StatusCode::BAD_REQUEST,
                "Unable to configure the Recon client.",
            )
        })?;
    // No captured request headers, cookies, target credentials, or insecure TLS
    // settings are copied into provider requests.
    let provider = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .user_agent(concat!("Sniper-Recon/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|_| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to configure the provider client.",
            )
        })?;
    let job = ReconJob {
        id: Uuid::new_v4(),
        target_url: request.target_url.clone(),
        status: "running".into(),
        started_at: Utc::now(),
        finished_at: None,
        error: None,
        sources: request
            .sources
            .iter()
            .map(|source| ReconSource {
                source: source.clone(),
                status: "queued".into(),
                requests: 0,
                discovered: 0,
                truncated: false,
                warnings: Vec::new(),
            })
            .collect(),
    };
    {
        let mut snapshot = session.recon.snapshot.lock().unwrap();
        snapshot.jobs.push(job.clone());
    }
    session.schedule_state_persist();
    let cancel = Arc::new(AtomicBool::new(false));
    let task = tokio::spawn(run(
        session.clone(),
        job.id,
        request,
        scope,
        crawler,
        provider,
        cancel.clone(),
    ));
    *session.recon.running.lock().unwrap() = Some(RunningJob {
        id: job.id,
        cancel,
        task,
    });
    Ok(Json(job))
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
    let _guard = session.owned_mutation_guard().await;
    if !session.recon.stop(Some(id)).await {
        return Err(api_error(StatusCode::NOT_FOUND, "Recon job not found."));
    }
    session.schedule_state_persist();
    Ok(Json(
        serde_json::json!({"stopped": true, "session_id": session.id()}),
    ))
}

async fn run(
    session: Arc<SessionContext>,
    id: Uuid,
    request: StartRecon,
    scope: ReconScope,
    crawler: reqwest::Client,
    provider: reqwest::Client,
    cancel: Arc<AtomicBool>,
) {
    let mut failed = false;
    for source in &request.sources {
        if cancel.load(Ordering::Acquire) {
            break;
        }
        session
            .recon
            .update_source(id, source, |s| s.status = "running".into());
        let report = if source == "crawler" {
            crawl(&session, id, &request, &scope, &crawler, &cancel).await
        } else {
            // A provider can have many completed pages before its final return.
            // Commit each batch before the next await so Stop cannot discard it.
            let checkpoint = |findings: &[Discovery], report: &SourceReport| {
                checkpoint_provider_batch(
                    &session,
                    id,
                    &scope,
                    source,
                    findings,
                    report,
                    request.max_endpoints,
                    &cancel,
                );
            };
            match source.as_str() {
                "urlscan" => {
                    recon_sources::urlscan(
                        &provider,
                        &scope.target,
                        request.include_subdomains,
                        request.max_pages,
                        request.max_endpoints,
                        &cancel,
                        checkpoint,
                    )
                    .await
                    .1
                }
                "urlscan_submit" => {
                    let (findings, report) = recon_sources::submit_urlscan(&provider, &scope.target, request.include_subdomains,
                        request.scan_visibility.as_deref().unwrap_or("private"), request.max_endpoints, &cancel,
                        |result_url| {
                            session.recon.update_source(id, source, |s| s.warnings.push(format!("Accepted scan result: {result_url}. Stop cancels local polling only.")));
                            session.schedule_state_persist();
                        }).await;
                    checkpoint(&findings, &report);
                    report
                }
                _ => {
                    recon_sources::wayback(
                        &provider,
                        &scope.target,
                        request.include_subdomains,
                        request.max_pages,
                        request.max_endpoints,
                        &cancel,
                        checkpoint,
                    )
                    .await
                    .1
                }
            }
        };
        failed |= report.error.is_some();
        session.recon.update_source(id, source, |s| {
            s.status = if report.error.is_some() {
                "failed"
            } else {
                "completed"
            }
            .into();
            s.requests = report.requests;
            s.truncated |= report.truncated;
            for warning in report.warnings {
                if !s.warnings.contains(&warning) {
                    s.warnings.push(warning);
                }
            }
            if let Some(error) = report.error {
                s.warnings.push(error);
            }
            if s.truncated {
                s.warnings
                    .push("Collection is partial; more evidence may exist.".into());
            }
        });
        session.schedule_state_persist();
    }
    if let Some(job) = session
        .recon
        .snapshot
        .lock()
        .unwrap()
        .jobs
        .iter_mut()
        .find(|job| job.id == id)
    {
        job.status = if failed { "failed" } else { "completed" }.into();
        job.finished_at = Some(Utc::now());
        if failed {
            job.error =
                Some("One or more sources failed; retained results may be incomplete.".into());
        }
    }
    session.schedule_state_persist();
}

fn checkpoint_provider_batch(
    session: &Arc<SessionContext>,
    id: Uuid,
    scope: &ReconScope,
    source: &str,
    findings: &[Discovery],
    report: &SourceReport,
    limit: usize,
    cancel: &AtomicBool,
) {
    let (added, truncated) =
        session
            .recon
            .merge_with_cancel(id, scope, source, findings.to_vec(), limit, Some(cancel));
    checkpoint_source_progress(session, id, source, report, added, truncated);
}

fn checkpoint_source_progress(
    session: &Arc<SessionContext>,
    id: Uuid,
    source: &str,
    report: &SourceReport,
    added: usize,
    truncated: bool,
) {
    session.recon.update_source(id, source, |s| {
        s.requests = report.requests;
        s.discovered += added;
        s.truncated |= truncated || report.truncated;
        for warning in &report.warnings {
            if !s.warnings.contains(warning) {
                s.warnings.push(warning.clone());
            }
        }
    });
    session.schedule_state_persist();
}

// These limits apply only to newly supported compressed response work, not to
// Recon's existing raw body reader or its request/endpoint collection budgets.
const RECON_DECODED_STAGE_LIMIT: usize = 16 * 1024 * 1024;
const RECON_DECODE_TIMEOUT: Duration = Duration::from_secs(15);
const RECON_DECODE_WORKERS: usize = 2;
const RECON_DECODE_INPUT_CHUNK: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReconCoding {
    Gzip,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReconDecodeError {
    Unsupported,
    Malformed,
    Limit,
    Timeout,
    Cancelled,
    Worker,
}

impl ReconDecodeError {
    fn warning(self) -> &'static str {
        match self {
            Self::Unsupported => "Unsupported or invalid Content-Encoding; static extraction was skipped.",
            Self::Malformed => "Compressed response could not be decoded completely; static extraction was skipped.",
            Self::Limit => "Compressed response exceeded the 16 MiB decoded-stage limit; static extraction was skipped.",
            Self::Timeout => "Compressed response decoding exceeded 15 seconds; static extraction was skipped.",
            Self::Cancelled => "Compressed response decoding was cancelled; static extraction was skipped.",
            Self::Worker => "Compressed response decoding could not finish; static extraction was skipped.",
        }
    }
}

fn recon_content_codings(
    headers: &reqwest::header::HeaderMap,
) -> Result<Vec<ReconCoding>, ReconDecodeError> {
    let mut codings = Vec::new();
    for value in headers.get_all(reqwest::header::CONTENT_ENCODING) {
        let value = value.to_str().map_err(|_| ReconDecodeError::Unsupported)?;
        for coding in value.split(',') {
            let coding = coding.trim_matches([' ', '\t']);
            if coding.is_empty() || coding.eq_ignore_ascii_case("identity") {
                continue;
            }
            if coding.eq_ignore_ascii_case("gzip") || coding.eq_ignore_ascii_case("x-gzip") {
                codings.push(ReconCoding::Gzip);
            } else {
                return Err(ReconDecodeError::Unsupported);
            }
        }
    }
    Ok(codings)
}

#[derive(Clone)]
struct ReconDecodeControl {
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
}

impl ReconDecodeControl {
    fn check(&self) -> Result<(), ReconDecodeError> {
        if self.cancelled.load(Ordering::Acquire) {
            Err(ReconDecodeError::Cancelled)
        } else if Instant::now() >= self.deadline {
            Err(ReconDecodeError::Timeout)
        } else {
            Ok(())
        }
    }

    fn check_io(&self) -> io::Result<()> {
        self.check().map_err(|error| {
            io::Error::new(
                if error == ReconDecodeError::Timeout {
                    io::ErrorKind::TimedOut
                } else {
                    io::ErrorKind::Other
                },
                "Recon decoding stopped",
            )
        })
    }
}

struct ReconDecodeOwner {
    cancelled: Arc<AtomicBool>,
    abort: Option<tokio::task::AbortHandle>,
}

impl Drop for ReconDecodeOwner {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        if let Some(abort) = &self.abort {
            // Prevent queued work from starting; running blocking work exits
            // cooperatively and retains its permit until the worker returns.
            abort.abort();
        }
    }
}

struct ReconDecodeInput {
    bytes: io::Cursor<Vec<u8>>,
    control: ReconDecodeControl,
}

impl Read for ReconDecodeInput {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.control.check_io()?;
        let length = output.len().min(RECON_DECODE_INPUT_CHUNK);
        self.bytes.read(&mut output[..length])
    }
}

impl BufRead for ReconDecodeInput {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.control.check_io()?;
        let bytes = self.bytes.fill_buf()?;
        Ok(&bytes[..bytes.len().min(RECON_DECODE_INPUT_CHUNK)])
    }

    fn consume(&mut self, amount: usize) {
        self.bytes.consume(amount);
    }
}

fn decode_recon_stages(
    mut bytes: Vec<u8>,
    codings: &[ReconCoding],
    limit: usize,
    control: &ReconDecodeControl,
) -> Result<Vec<u8>, ReconDecodeError> {
    for coding in codings.iter().rev() {
        control.check()?;
        let input = ReconDecodeInput {
            bytes: io::Cursor::new(bytes),
            control: control.clone(),
        };
        let mut decoder = match coding {
            ReconCoding::Gzip => flate2::bufread::MultiGzDecoder::new(input),
        };
        let mut decoded = Vec::new();
        let mut chunk = [0; 8 * 1024];
        loop {
            control.check()?;
            let count = decoder
                .read(&mut chunk)
                .map_err(|_| control.check().err().unwrap_or(ReconDecodeError::Malformed))?;
            if count == 0 {
                break;
            }
            if count > limit.saturating_sub(decoded.len()) {
                return Err(ReconDecodeError::Limit);
            }
            decoded.extend_from_slice(&chunk[..count]);
        }
        bytes = decoded;
    }
    control.check()?;
    Ok(bytes)
}

async fn dispatch_recon_decode<F>(
    permits: Arc<tokio::sync::Semaphore>,
    timeout: Duration,
    work: F,
) -> Result<Vec<u8>, ReconDecodeError>
where
    F: FnOnce(ReconDecodeControl) -> Result<Vec<u8>, ReconDecodeError> + Send + 'static,
{
    let cancelled = Arc::new(AtomicBool::new(false));
    let control = ReconDecodeControl {
        cancelled: cancelled.clone(),
        deadline: Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now),
    };
    let mut owner = ReconDecodeOwner {
        cancelled,
        abort: None,
    };
    match tokio::time::timeout(timeout, async {
        let permit = permits
            .acquire_owned()
            .await
            .map_err(|_| ReconDecodeError::Worker)?;
        control.check()?;
        let worker = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            control.check()?;
            work(control)
        });
        owner.abort = Some(worker.abort_handle());
        worker.await.map_err(|_| ReconDecodeError::Worker)?
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(ReconDecodeError::Timeout),
    }
}

async fn read_body(mut response: reqwest::Response) -> Result<String, &'static str> {
    let bodyless_status = matches!(response.status().as_u16(), 204 | 205);
    let codings = recon_content_codings(response.headers());
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "Response body could not be read.")?
    {
        bytes.extend_from_slice(&chunk);
    }
    if bodyless_status && bytes.is_empty() {
        // Metadata on an empty 204/205 is not malformed gzip. Nonempty raw
        // responses retain the existing reader behavior, even for status 205.
        return Ok(String::new());
    }
    let codings = codings.map_err(ReconDecodeError::warning)?;
    if !codings.is_empty() {
        static PERMITS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
        let permits = PERMITS
            .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(RECON_DECODE_WORKERS)))
            .clone();
        bytes = dispatch_recon_decode(permits, RECON_DECODE_TIMEOUT, move |control| {
            decode_recon_stages(bytes, &codings, RECON_DECODED_STAGE_LIMIT, &control)
        })
        .await
        .map_err(ReconDecodeError::warning)?;
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

async fn crawl(
    session: &Arc<SessionContext>,
    id: Uuid,
    request: &StartRecon,
    scope: &ReconScope,
    client: &reqwest::Client,
    cancel: &AtomicBool,
) -> SourceReport {
    let mut report = SourceReport::default();
    let mut seed = scope.target.clone();
    seed.set_fragment(None);
    let mut queue = VecDeque::from([(seed.clone(), 0usize, 0usize)]);
    for path in ["/robots.txt", "/sitemap.xml"] {
        if let Ok(url) = seed.join(path) {
            queue.push_back((url, 0, 0));
        }
    }
    // Deduplicate when scheduling, so repeated links cannot inflate an unlimited queue.
    let mut scheduled: HashSet<String> = queue.iter().map(|(url, _, _)| url.to_string()).collect();
    let mut seen = HashSet::new();
    let mut successful_responses = 0;
    while let Some((mut url, depth, redirects)) = queue.pop_front() {
        if cancel.load(Ordering::Acquire) {
            break;
        }
        url.set_fragment(None);
        if !scope.contains(&url) || !seen.insert(url.to_string()) {
            continue;
        }
        if request.max_requests != 0 && report.requests >= request.max_requests {
            report.truncated = true;
            report
                .warnings
                .push("Crawler request budget reached.".into());
            break;
        }
        report.requests += 1;
        // Stop aborts the worker at await points. Retain completed work and
        // known limits before waiting for another response or its body.
        checkpoint_source_progress(session, id, "crawler", &report, 0, false);
        let response = match client.get(url.clone()).send().await {
            Ok(response) => response,
            Err(_) => {
                report.truncated = true;
                let warning = "A scoped crawl request failed (network/TLS/timeout).";
                if !report.warnings.iter().any(|item| item == warning) {
                    report.warnings.push(warning.into());
                }
                continue;
            }
        };
        successful_responses += 1;
        let status = response.status().as_u16();
        let (added, truncated) = session.recon.merge_with_cancel(
            id,
            scope,
            "crawler",
            vec![Discovery {
                url: url.to_string(),
                method: "GET".into(),
                kind: "live".into(),
                location: "HTTP response observed by crawler".into(),
                timestamp: Some(Utc::now().to_rfc3339()),
                status: Some(status),
            }],
            request.max_endpoints,
            Some(cancel),
        );
        report.truncated |= truncated;
        checkpoint_source_progress(session, id, "crawler", &report, added, truncated);
        if response.status().is_redirection() {
            if let Some(location) = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|h| h.to_str().ok())
            {
                if let Ok(mut next) = url.join(location) {
                    next.set_fragment(None);
                    let in_scope = scope.contains(&next);
                    if in_scope && redirects < 5 {
                        if scheduled.insert(next.to_string()) {
                            queue.push_front((next, depth, redirects + 1));
                        }
                    } else {
                        report.truncated |= in_scope && !scheduled.contains(next.as_str());
                        let warning = "A redirect was not followed because it left scope or exceeded five hops.";
                        if !report.warnings.iter().any(|item| item == warning) {
                            report.warnings.push(warning.into());
                        }
                    }
                }
            }
            continue;
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !(content_type.contains("html")
            || recon_sources::is_javascript_document(&url, &content_type)
            || content_type.contains("xml")
            || content_type.contains("text/plain")
            || url.path().ends_with("robots.txt"))
        {
            continue;
        }
        let body = match read_body(response).await {
            Ok(body) => body,
            Err(error) => {
                report.truncated = true;
                if !report.warnings.iter().any(|item| item == error) {
                    report.warnings.push(error.into());
                }
                checkpoint_source_progress(session, id, "crawler", &report, 0, false);
                continue;
            }
        };
        let (findings, clipped) =
            recon_sources::extract_document_cancellable(&url, &content_type, &body, cancel);
        if clipped {
            report.truncated = true;
            let warning = "Static document extraction was partial; more evidence may exist.";
            if !report.warnings.iter().any(|item| item == warning) {
                report.warnings.push(warning.into());
            }
        }
        for finding in &findings {
            if cancel.load(Ordering::Acquire) {
                break;
            }
            if !recon_sources::is_followable(finding) {
                continue;
            }
            let Ok(mut next) = Url::parse(&finding.url) else {
                continue;
            };
            next.set_fragment(None);
            if !scope.contains(&next) || scheduled.contains(next.as_str()) {
                continue;
            }
            if request.max_depth != 0 && depth >= request.max_depth {
                report.truncated = true;
                let warning = "Crawl depth budget reached.";
                if !report.warnings.iter().any(|item| item == warning) {
                    report.warnings.push(warning.into());
                }
            } else {
                scheduled.insert(next.to_string());
                queue.push_back((next, depth.saturating_add(1), 0));
            }
        }
        let (added, truncated) = session.recon.merge_with_cancel(
            id,
            scope,
            "crawler",
            findings,
            request.max_endpoints,
            Some(cancel),
        );
        report.truncated |= truncated;
        checkpoint_source_progress(session, id, "crawler", &report, added, truncated);
        // Deliberately sequential and paced; forms and JS guesses are retained
        // as candidates only, never automatically executed.
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if successful_responses == 0 && report.requests > 0 {
        report.error =
            Some("No crawl response was received; check target connectivity and TLS.".into());
    }
    report.warnings.push("Static extraction only: no JavaScript execution, login, form submission, or live validation of archive results. GET requests may still have site-specific side effects.".into());
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_scope_binds_host_scheme_port_and_credentials() {
        assert!(ReconScope::new("", false).is_err());
        for wildcard in [
            "https://*/",
            "https://*.example.com/",
            "https://%2A.example.com/",
        ] {
            assert!(ReconScope::new(wildcard, false).is_err());
        }
        let scope = ReconScope::new("http://example.com/start", false).unwrap();
        for allowed in ["http://example.com/a", "https://example.com/a"] {
            assert!(scope.contains(&Url::parse(allowed).unwrap()));
        }
        for denied in [
            "http://example.com.evil.test/a",
            "http://api.example.com/a",
            "http://example.com:8080/",
            "http://user:pass@example.com/",
            "file:///tmp/a",
        ] {
            assert!(!scope.contains(&Url::parse(denied).unwrap()));
        }
        let subdomains = ReconScope::new("https://example.com", true).unwrap();
        assert!(subdomains.contains(&Url::parse("https://api.example.com/").unwrap()));
        assert!(!subdomains.contains(&Url::parse("http://api.example.com/").unwrap()));
    }

    #[test]
    fn budgets_default_to_unbounded_and_accept_values_above_the_old_ceilings() {
        let mut request: StartRecon = serde_json::from_value(serde_json::json!({
            "session_id": Uuid::new_v4(), "target_url": "https://example.com/",
            "sources": ["crawler"]
        }))
        .unwrap();
        assert_eq!(
            (
                request.max_requests,
                request.max_depth,
                request.max_endpoints,
                request.max_pages
            ),
            (0, 0, 0, 0)
        );
        assert!(validate(&request).is_ok());
        request.max_requests = 10_000;
        request.max_depth = 100;
        request.max_endpoints = 50_000;
        request.max_pages = 200;
        request.target_url = format!("https://example.com/{}", "a".repeat(20_000));
        assert!(validate(&request).is_ok());
    }

    #[test]
    fn inventory_preserves_large_collections_long_urls_and_all_evidence() {
        let store = ReconStore::from_snapshot(ReconSnapshot::default());
        let scope = ReconScope::new("https://example.com", false).unwrap();
        let findings: Vec<_> = (0..5_100)
            .map(|index| Discovery {
                url: format!(
                    "https://example.com/{index}/{}",
                    "a".repeat(if index == 0 { 20_000 } else { 0 })
                ),
                method: "GET".into(),
                kind: "history".into(),
                location: "x".repeat(1_800),
                timestamp: Some("t".repeat(100)),
                status: None,
            })
            .collect();
        let long_url = findings[0].url.clone();
        assert_eq!(
            store.merge(Uuid::new_v4(), &scope, "wayback", findings, 0),
            (5_100, false)
        );
        let variants = (0..30)
            .map(|index| Discovery {
                url: format!("{long_url}#fragment-{index}"),
                method: "GET".into(),
                kind: "history".into(),
                location: format!("{index}{}", "x".repeat(2_000)),
                timestamp: Some("t".repeat(100)),
                status: None,
            })
            .collect();
        assert_eq!(
            store.merge(Uuid::new_v4(), &scope, "urlscan", variants, 0),
            (0, false)
        );
        let snapshot = store.snapshot();
        assert_eq!(snapshot.endpoints.len(), 5_100);
        assert!(serde_json::to_vec(&snapshot.endpoints).unwrap().len() > 8 * 1024 * 1024);
        let endpoint = &snapshot.endpoints[0];
        assert_eq!(endpoint.url, long_url);
        assert_eq!(endpoint.raw_urls.len(), 31);
        assert_eq!(endpoint.evidence.len(), 31);
        assert_eq!(endpoint.evidence[0].location.len(), 1_800);
        assert_eq!(endpoint.evidence[0].timestamp.as_ref().unwrap().len(), 100);
        let restored = ReconStore::from_snapshot(snapshot);
        assert_eq!(restored.site_map_endpoints().len(), 5_100);
        assert_eq!(
            restored.site_map_endpoints()[0].sources,
            vec!["urlscan", "wayback"]
        );
        assert_eq!(
            restored.merge(
                Uuid::new_v4(),
                &scope,
                "wayback",
                vec![Discovery {
                    url: long_url,
                    method: "GET".into(),
                    kind: "history".into(),
                    location: "after restart".into(),
                    timestamp: None,
                    status: None,
                }],
                0
            ),
            (0, false)
        );
        assert_eq!(restored.snapshot().endpoints[0].evidence.len(), 32);
    }

    #[test]
    fn inventory_preserves_query_order_raw_urls_methods_and_provenance() {
        let store = ReconStore::from_snapshot(ReconSnapshot::default());
        let scope = ReconScope::new("https://example.com", false).unwrap();
        let discovery = |url: &str, method: &str| Discovery {
            url: url.into(),
            method: method.into(),
            kind: "history".into(),
            location: "fixture".into(),
            timestamp: None,
            status: None,
        };
        store.merge(
            Uuid::new_v4(),
            &scope,
            "wayback",
            vec![
                discovery("https://example.com/a?b=2&a=1#part", "GET"),
                discovery("https://example.com/a?a=1&b=2", "GET"),
                discovery("https://example.com/a?a=1&b=2", "POST"),
            ],
            10,
        );
        store.merge(
            Uuid::new_v4(),
            &scope,
            "urlscan",
            vec![discovery("https://example.com/a?a=1&b=2", "GET")],
            10,
        );
        let snapshot = store.snapshot();
        assert_eq!(snapshot.endpoints.len(), 3);
        assert!(snapshot.endpoints[0].raw_urls[0].ends_with("#part"));
        assert_eq!(snapshot.endpoints[1].evidence.len(), 2);
        assert!(!snapshot
            .endpoints
            .iter()
            .any(|endpoint| endpoint.evidence.iter().any(|e| e.kind == "live")));
    }

    #[test]
    fn inventory_form_actions_normalize_fragments_without_losing_raw_evidence() {
        let store = ReconStore::from_snapshot(ReconSnapshot::default());
        let document = Url::parse("https://example.com/form?b=2&a=1").unwrap();
        let scope = ReconScope::new(document.as_str(), false).unwrap();
        let (found, clipped) = crate::recon_sources::extract_document(
            &document,
            "text/html",
            r##"<form method="POST" action="#one"></form>
                <form method="POST" action="#two"></form>
                <form method="DELETE" action="#get"></form>"##,
        );
        assert!(!clipped);
        assert_eq!(
            store.merge(Uuid::new_v4(), &scope, "crawler", found, 0),
            (2, false)
        );
        let snapshot = store.snapshot();
        assert_eq!(snapshot.endpoints.len(), 2);
        let post = snapshot
            .endpoints
            .iter()
            .find(|item| item.method == "POST")
            .unwrap();
        let get = snapshot
            .endpoints
            .iter()
            .find(|item| item.method == "GET")
            .unwrap();
        assert_eq!(post.url, "https://example.com/form?b=2&a=1");
        assert_eq!(get.url, post.url);
        assert_eq!(
            post.raw_urls,
            [
                "https://example.com/form?b=2&a=1#one",
                "https://example.com/form?b=2&a=1#two"
            ]
        );
        assert_eq!(get.raw_urls, ["https://example.com/form?b=2&a=1#get"]);
        assert!(snapshot
            .endpoints
            .iter()
            .all(|item| item.evidence.iter().all(|e| {
                e.source == "crawler"
                    && e.kind == "candidate"
                    && e.status.is_none()
                    && e.location == format!("form: {document}")
            })));
    }

    #[test]
    fn a_jobs_endpoint_limit_counts_its_own_finds_not_the_inventory() {
        let store = ReconStore::from_snapshot(ReconSnapshot::default());
        let scope = ReconScope::new("https://example.com", false).unwrap();
        let found = |paths: &[&str]| {
            paths
                .iter()
                .map(|path| Discovery {
                    url: format!("https://example.com{path}"),
                    method: "GET".into(),
                    kind: "history".into(),
                    location: "fixture".into(),
                    timestamp: None,
                    status: None,
                })
                .collect::<Vec<_>>()
        };
        let first = found(&["/a", "/b", "/c"]);
        assert_eq!(
            store.merge(Uuid::new_v4(), &scope, "wayback", first, 10),
            (3, false)
        );
        // A later job with a smaller limit than the inventory still adds its own.
        let second = found(&["/d", "/e", "/f"]);
        assert_eq!(
            store.merge(Uuid::new_v4(), &scope, "wayback", second, 2),
            (2, true)
        );
    }

    #[test]
    fn cancelled_collection_does_not_merge_pending_findings() {
        let store = ReconStore::from_snapshot(ReconSnapshot::default());
        let scope = ReconScope::new("https://example.com", false).unwrap();
        assert_eq!(
            store.merge_with_cancel(
                Uuid::new_v4(),
                &scope,
                "wayback",
                vec![Discovery {
                    url: "https://example.com/pending".into(),
                    method: "GET".into(),
                    kind: "history".into(),
                    location: "fixture".into(),
                    timestamp: None,
                    status: None,
                }],
                0,
                Some(&AtomicBool::new(true))
            ),
            (0, true)
        );
        assert!(store.snapshot().endpoints.is_empty());
    }

    #[test]
    fn restart_marks_running_jobs_interrupted() {
        let store = ReconStore::from_snapshot(ReconSnapshot {
            endpoints: vec![],
            jobs: vec![ReconJob {
                id: Uuid::new_v4(),
                target_url: "https://example.com".into(),
                status: "running".into(),
                started_at: Utc::now(),
                finished_at: None,
                sources: vec![],
                error: None,
            }],
        });
        assert_eq!(store.snapshot().jobs[0].status, "interrupted");
    }

    #[test]
    fn sharing_requires_explicit_acknowledgment_and_visibility() {
        let mut request: StartRecon = serde_json::from_value(serde_json::json!({"session_id": Uuid::new_v4(), "target_url":"https://example.com/", "sources":["urlscan"]})).unwrap();
        assert!(validate(&request).is_err());
        request.history_acknowledged = true;
        assert!(validate(&request).is_ok());
        request.sources = vec!["urlscan_submit".into()];
        assert!(validate(&request).is_err());
        request.scan_acknowledged = true;
        request.scan_visibility = Some("private".into());
        assert!(validate(&request).is_ok());
    }

    #[tokio::test]
    async fn inventories_round_trip_in_their_original_sessions() {
        let dir = std::env::temp_dir().join(format!("sniper-recon-persist-{}", Uuid::new_v4()));
        let (registry, first) =
            crate::session::SessionRegistry::load_or_create(&dir, 32, 32).unwrap();
        let second_id = registry.create_session(Some("Second".into())).unwrap().id;
        let second = registry.load_context(second_id).unwrap();
        let scope = ReconScope::new("https://example.com", false).unwrap();
        first.recon.merge(
            Uuid::new_v4(),
            &scope,
            "wayback",
            vec![Discovery {
                url: "https://example.com/first".into(),
                method: "GET".into(),
                kind: "history".into(),
                location: "fixture".into(),
                timestamp: None,
                status: Some(404),
            }],
            10,
        );
        first.persist_state_only().await.unwrap();
        second.persist_state_only().await.unwrap();
        let restored = registry.load_context(first.id()).unwrap();
        assert_eq!(
            restored.recon.snapshot().endpoints[0].url,
            "https://example.com/first"
        );
        assert!(registry
            .load_context(second_id)
            .unwrap()
            .recon
            .snapshot()
            .endpoints
            .is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn cancellation_joins_the_worker_before_returning() {
        let store = ReconStore::from_snapshot(ReconSnapshot::default());
        let id = Uuid::new_v4();
        store.snapshot.lock().unwrap().jobs.push(ReconJob {
            id,
            target_url: "https://example.com".into(),
            status: "running".into(),
            started_at: Utc::now(),
            finished_at: None,
            sources: vec![],
            error: None,
        });
        let task = tokio::spawn(async {
            std::future::pending::<()>().await;
        });
        *store.running.lock().unwrap() = Some(RunningJob {
            id,
            cancel: Arc::new(AtomicBool::new(false)),
            task,
        });
        assert!(
            tokio::time::timeout(Duration::from_secs(1), store.stop(Some(id)))
                .await
                .unwrap()
        );
        assert_eq!(store.snapshot().jobs[0].status, "cancelled");
        assert!(!store.is_running());
    }

    #[tokio::test]
    async fn stopped_provider_checkpoints_keep_counts_evidence_and_restart_state() {
        let dir = std::env::temp_dir().join(format!("sniper-recon-checkpoint-{}", Uuid::new_v4()));
        let (registry, session) =
            crate::session::SessionRegistry::load_or_create(&dir, 32, 32).unwrap();
        let id = Uuid::new_v4();
        session.recon.snapshot.lock().unwrap().jobs.push(ReconJob {
            id,
            target_url: "https://example.com/".into(),
            status: "running".into(),
            started_at: Utc::now(),
            finished_at: None,
            error: None,
            sources: vec![ReconSource {
                source: "wayback".into(),
                status: "running".into(),
                requests: 0,
                discovered: 0,
                truncated: false,
                warnings: vec![],
            }],
        });
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        let worker_session = session.clone();
        let (checkpointed, ready) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let scope = ReconScope::new("https://example.com/", false).unwrap();
            let found = |path: &str, page: &str| Discovery {
                url: format!("https://example.com/{path}"),
                method: "GET".into(),
                kind: "history".into(),
                location: page.into(),
                timestamp: None,
                status: Some(404),
            };
            checkpoint_provider_batch(
                &worker_session,
                id,
                &scope,
                "wayback",
                &[
                    found("retained", "page one"),
                    found("over-budget", "page one"),
                ],
                &SourceReport {
                    requests: 1,
                    truncated: true,
                    warnings: vec!["Known provider limit".into()],
                    ..SourceReport::default()
                },
                1,
                &worker_cancel,
            );
            checkpoint_provider_batch(
                &worker_session,
                id,
                &scope,
                "wayback",
                &[found("retained", "page two")],
                &SourceReport {
                    requests: 2,
                    ..SourceReport::default()
                },
                1,
                &worker_cancel,
            );
            checkpointed.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        *session.recon.running.lock().unwrap() = Some(RunningJob { id, cancel, task });
        ready.await.unwrap();
        assert!(session.recon.stop(Some(id)).await);
        session.persist_state_only().await.unwrap();
        let restored = registry.load_context(session.id()).unwrap();
        let snapshot = restored.recon.snapshot();
        assert_eq!(snapshot.jobs[0].status, "cancelled");
        assert_eq!(snapshot.jobs[0].sources[0].status, "cancelled");
        assert_eq!(snapshot.jobs[0].sources[0].requests, 2);
        assert_eq!(snapshot.jobs[0].sources[0].discovered, 1);
        assert!(snapshot.jobs[0].sources[0].truncated);
        assert!(snapshot.jobs[0].sources[0]
            .warnings
            .iter()
            .any(|warning| warning == "Known provider limit"));
        assert_eq!(snapshot.endpoints.len(), 1);
        assert_eq!(snapshot.endpoints[0].url, "https://example.com/retained");
        assert_eq!(snapshot.endpoints[0].evidence.len(), 2);
        assert!(snapshot.endpoints[0]
            .evidence
            .iter()
            .all(|item| item.kind == "history"));
        assert_eq!(
            restored.recon.site_map_endpoints()[0].kinds,
            vec!["history"]
        );
    }

    #[tokio::test]
    async fn crawl_obeys_redirect_scope_and_never_executes_forms_or_js_candidates() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requested = Arc::new(Mutex::new(Vec::<String>::new()));
        let captured = requested.clone();
        let server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let captured = captured.clone();
                tokio::spawn(async move {
                    let mut bytes = [0u8; 8192];
                    let count = socket.read(&mut bytes).await.unwrap();
                    let request = String::from_utf8_lossy(&bytes[..count]);
                    let path = request.split_whitespace().nth(1).unwrap_or("/").to_string();
                    captured.lock().unwrap().push(path.clone());
                    let (status, headers, body) = match path.as_str() {
                        "/" => ("200 OK", "Content-Type: text/html\r\n", "<a href='/ok'>ok</a><a href='/redirect'>redirect</a><form action='/post' method='POST'><input name='secret'></form><script>fetch('/candidate')</script>".to_string()),
                        "/redirect" => ("302 Found", "", String::new()),
                        _ => ("200 OK", "Content-Type: text/plain\r\n", "done".to_string()),
                    };
                    let redirect = if path == "/redirect" {
                        format!("Location: http://localhost:{}/outside\r\n", addr.port())
                    } else {
                        String::new()
                    };
                    let response = format!("HTTP/1.1 {status}\r\n{headers}{redirect}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                    socket.write_all(response.as_bytes()).await.unwrap();
                });
            }
        });
        let dir = std::env::temp_dir().join(format!("sniper-recon-crawl-{}", Uuid::new_v4()));
        let (_, session) = crate::session::SessionRegistry::load_or_create(&dir, 32, 32).unwrap();
        let request: StartRecon = serde_json::from_value(serde_json::json!({
            "session_id": session.id(), "target_url": format!("http://{addr}/"), "sources": ["crawler"], "max_requests": 10
        })).unwrap();
        let scope = validate(&request).unwrap();
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let report = crawl(
            &session,
            Uuid::new_v4(),
            &request,
            &scope,
            &client,
            &AtomicBool::new(false),
        )
        .await;
        let paths = requested.lock().unwrap().clone();
        assert!(paths.contains(&"/ok".to_string()));
        assert!(!paths
            .iter()
            .any(|path| ["/post", "/candidate", "/outside"].contains(&path.as_str())));
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("redirect")));
        let endpoints = session.recon.snapshot().endpoints;
        assert!(endpoints
            .iter()
            .any(|endpoint| endpoint.method == "POST" && endpoint.evidence[0].kind == "candidate"));
        server.abort();
        let _ = server.await;
        // The debounced writer may still own this isolated directory; unlike a
        // real session it is left for the OS temporary-directory cleanup.
    }

    #[tokio::test]
    async fn in_scope_redirect_hop_exhaustion_is_partial_but_scope_rejection_is_not() {
        use axum::{routing::get, Router};
        for exhaust_hops in [true, false] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let requested = Arc::new(Mutex::new(Vec::new()));
            let captured = requested.clone();
            let router = Router::new().fallback(get(move |uri: axum::http::Uri| {
                captured.lock().unwrap().push(uri.path().to_string());
                async move {
                    let redirect = if uri.path() == "/outside-redirect" {
                        Some(format!("http://localhost:{}/outside", address.port()))
                    } else {
                        uri.path()
                            .strip_prefix("/redirect/")
                            .and_then(|part| part.parse::<usize>().ok())
                            .filter(|hop| *hop < 7)
                            .map(|hop| format!("/redirect/{}", hop + 1))
                    };
                    (
                        if redirect.is_some() {
                            StatusCode::FOUND
                        } else {
                            StatusCode::OK
                        },
                        [(axum::http::header::LOCATION, redirect.unwrap_or_default())],
                        "",
                    )
                }
            }));
            let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
            let dir =
                std::env::temp_dir().join(format!("sniper-recon-redirect-{}", Uuid::new_v4()));
            let (_, session) =
                crate::session::SessionRegistry::load_or_create(&dir, 32, 32).unwrap();
            let path = if exhaust_hops {
                "/redirect/0"
            } else {
                "/outside-redirect"
            };
            let request: StartRecon = serde_json::from_value(serde_json::json!({
                "session_id":session.id(),"target_url":format!("http://{address}{path}"),"sources":["crawler"]
            })).unwrap();
            let client = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap();
            let report = crawl(
                &session,
                Uuid::new_v4(),
                &request,
                &validate(&request).unwrap(),
                &client,
                &AtomicBool::new(false),
            )
            .await;
            assert_eq!(report.truncated, exhaust_hops);
            assert!(report.error.is_none());
            assert!(report
                .warnings
                .iter()
                .any(|warning| warning.contains("redirect")));
            let paths = requested.lock().unwrap();
            if exhaust_hops {
                assert!(paths.iter().any(|path| path == "/redirect/5"));
                assert!(!paths.iter().any(|path| path == "/redirect/6"));
            }
            assert!(!paths.iter().any(|path| path == "/outside"));
            drop(paths);
            server.abort();
            let _ = server.await;
        }
    }

    async fn crawl_static_fixture(
        content_type: &str,
        body: &str,
        path: &str,
    ) -> (SourceReport, ReconSnapshot, Vec<String>) {
        crawl_wire_fixture(content_type, body.as_bytes(), &[], path).await
    }

    async fn crawl_wire_fixture(
        content_type: &str,
        body: &[u8],
        encodings: &[&str],
        path: &str,
    ) -> (SourceReport, ReconSnapshot, Vec<String>) {
        use axum::{routing::get, Router};
        let requested = Arc::new(Mutex::new(Vec::<String>::new()));
        let captured = requested.clone();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            content_type.parse().unwrap(),
        );
        for encoding in encodings {
            headers.append(
                axum::http::header::CONTENT_ENCODING,
                encoding.parse().unwrap(),
            );
        }
        let body = body.to_vec();
        let fixture_path = path.to_string();
        let router = Router::new().fallback(get(move |uri: axum::http::Uri| {
            let captured = captured.clone();
            let headers = headers.clone();
            let body = body.clone();
            let fixture_path = fixture_path.clone();
            async move {
                captured.lock().unwrap().push(uri.path().to_string());
                if uri.path() == fixture_path {
                    (headers, body)
                } else {
                    let mut plain = axum::http::HeaderMap::new();
                    plain.insert(
                        axum::http::header::CONTENT_TYPE,
                        "text/plain".parse().unwrap(),
                    );
                    (plain, Vec::new())
                }
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let dir = std::env::temp_dir().join(format!("sniper-recon-static-{}", Uuid::new_v4()));
        let (_, session) = crate::session::SessionRegistry::load_or_create(&dir, 32, 32).unwrap();
        let request: StartRecon = serde_json::from_value(serde_json::json!({
            "session_id": session.id(), "target_url": format!("http://{address}{path}"),
            "sources": ["crawler"]
        }))
        .unwrap();
        let scope = validate(&request).unwrap();
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let report = crawl(
            &session,
            Uuid::new_v4(),
            &request,
            &scope,
            &client,
            &AtomicBool::new(false),
        )
        .await;
        let snapshot = session.recon.snapshot();
        let paths = requested.lock().unwrap().clone();
        server.abort();
        let _ = server.await;
        (report, snapshot, paths)
    }

    fn encoded_fixture_gzip(body: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(body).unwrap();
        encoder.finish().unwrap()
    }

    fn decode_test_control() -> ReconDecodeControl {
        ReconDecodeControl {
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + Duration::from_secs(5),
        }
    }

    #[test]
    fn recon_decode_limits_apply_to_each_compressed_stage_and_all_members_only() {
        assert_eq!(RECON_DECODED_STAGE_LIMIT, 16 * 1024 * 1024);
        assert_eq!(RECON_DECODE_WORKERS, 2);
        assert_eq!(RECON_DECODE_TIMEOUT, Duration::from_secs(15));
        let decode = |bytes, codings: &[ReconCoding]| {
            decode_recon_stages(bytes, codings, 64, &decode_test_control())
        };
        let gzip = [ReconCoding::Gzip];
        assert_eq!(
            decode(encoded_fixture_gzip(&[7; 64]), &gzip).unwrap(),
            vec![7; 64]
        );
        assert_eq!(
            decode(encoded_fixture_gzip(&[7; 65]), &gzip),
            Err(ReconDecodeError::Limit)
        );
        let members = |second| {
            [
                encoded_fixture_gzip(&[1; 32]),
                encoded_fixture_gzip(&vec![2; second]),
            ]
            .concat()
        };
        assert_eq!(decode(members(32), &gzip).unwrap().len(), 64);
        assert_eq!(decode(members(33), &gzip), Err(ReconDecodeError::Limit));
        let raw: Vec<u8> = (0..64).collect();
        let inner = encoded_fixture_gzip(&raw);
        assert!(inner.len() > 64);
        assert_eq!(
            decode(encoded_fixture_gzip(&inner), &[ReconCoding::Gzip; 2]),
            Err(ReconDecodeError::Limit)
        );
        // The existing raw/identity reader has no decoded-body limit.
        assert_eq!(decode(vec![9; 65], &[]).unwrap(), vec![9; 65]);
        // Even an empty member must validate its trailer and true stream EOF.
        assert_eq!(
            decode(encoded_fixture_gzip(b""), &gzip).unwrap(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn recon_decode_header_lists_are_local_strict_and_do_not_echo_values() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.append(
            reqwest::header::CONTENT_ENCODING,
            " GZip, identity,".parse().unwrap(),
        );
        headers.append(reqwest::header::CONTENT_ENCODING, "x-gzip".parse().unwrap());
        assert_eq!(
            recon_content_codings(&headers).unwrap(),
            vec![ReconCoding::Gzip; 2]
        );
        for value in [b"secret-custom".as_slice(), b"gzip; secret", b"\xff"] {
            headers.insert(
                reqwest::header::CONTENT_ENCODING,
                reqwest::header::HeaderValue::from_bytes(value).unwrap(),
            );
            assert_eq!(
                recon_content_codings(&headers),
                Err(ReconDecodeError::Unsupported)
            );
            assert!(!ReconDecodeError::Unsupported.warning().contains("secret"));
        }
    }

    #[test]
    fn recon_decode_guard_bounds_input_and_uses_non_retriable_cancellation() {
        let control = decode_test_control();
        let mut input = ReconDecodeInput {
            bytes: io::Cursor::new(vec![0; 40_000]),
            control: control.clone(),
        };
        assert_eq!(input.fill_buf().unwrap().len(), RECON_DECODE_INPUT_CHUNK);
        let mut buffer = [0; 40_000];
        assert_eq!(input.read(&mut buffer).unwrap(), RECON_DECODE_INPUT_CHUNK);
        control.cancelled.store(true, Ordering::Release);
        assert_eq!(
            input.read(&mut buffer).unwrap_err().kind(),
            io::ErrorKind::Other
        );
        assert_eq!(
            decode_recon_stages(
                encoded_fixture_gzip(b"small"),
                &[ReconCoding::Gzip],
                64,
                &control
            ),
            Err(ReconDecodeError::Cancelled)
        );
        let expired = ReconDecodeControl {
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now(),
        };
        assert_eq!(
            decode_recon_stages(
                encoded_fixture_gzip(b"small"),
                &[ReconCoding::Gzip],
                64,
                &expired
            ),
            Err(ReconDecodeError::Timeout)
        );
    }

    #[tokio::test]
    async fn recon_decode_queued_owner_drop_and_timeout_never_start_work() {
        for timed_out in [false, true] {
            let permits = Arc::new(tokio::sync::Semaphore::new(1));
            let occupied = permits.clone().acquire_owned().await.unwrap();
            let started = Arc::new(AtomicBool::new(false));
            let observed = started.clone();
            let worker_permits = permits.clone();
            let (waiting_tx, waiting_rx) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(async move {
                waiting_tx.send(()).unwrap();
                dispatch_recon_decode(worker_permits, Duration::from_millis(30), move |_| {
                    observed.store(true, Ordering::Release);
                    Ok(vec![])
                })
                .await
            });
            // The spawned future has polled through to the held semaphore.
            waiting_rx.await.unwrap();
            if timed_out {
                assert_eq!(task.await.unwrap(), Err(ReconDecodeError::Timeout));
            } else {
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
            }
            drop(occupied);
            tokio::task::yield_now().await;
            assert_eq!(permits.available_permits(), 1);
            assert!(!started.load(Ordering::Acquire));
        }
    }

    #[tokio::test]
    async fn recon_decode_running_owner_keeps_permit_until_exit_without_late_publication() {
        for timed_out in [false, true] {
            let permits = Arc::new(tokio::sync::Semaphore::new(1));
            let worker_permits = permits.clone();
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let (observed_tx, observed_rx) = tokio::sync::oneshot::channel();
            let published = Arc::new(AtomicBool::new(false));
            let late_publication = published.clone();
            let task = tokio::spawn(async move {
                let result =
                    dispatch_recon_decode(worker_permits, Duration::from_secs(2), move |control| {
                        ready_tx.send(()).unwrap();
                        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                        let checked = control.check();
                        observed_tx.send(checked).unwrap();
                        checked?;
                        Ok(vec![1])
                    })
                    .await;
                if result.is_ok() {
                    late_publication.store(true, Ordering::Release);
                }
                result
            });
            tokio::time::timeout(Duration::from_secs(1), ready_rx)
                .await
                .unwrap()
                .unwrap();
            if timed_out {
                assert_eq!(task.await.unwrap(), Err(ReconDecodeError::Timeout));
            } else {
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
            }
            // A dropped awaiting task must not release a still-running worker's slot.
            assert_eq!(permits.available_permits(), 0);
            release_tx.send(()).unwrap();
            assert_eq!(observed_rx.await.unwrap(), Err(ReconDecodeError::Cancelled));
            let permit =
                tokio::time::timeout(Duration::from_secs(2), permits.clone().acquire_owned())
                    .await
                    .unwrap()
                    .unwrap();
            drop(permit);
            assert_eq!(permits.available_permits(), 1);
            assert!(!published.load(Ordering::Acquire));
        }
    }

    #[test]
    fn recon_decode_blocking_pool_queued_task_is_aborted_before_work() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let occupied = tokio::task::spawn_blocking(move || {
                ready_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            });
            ready_rx.await.unwrap();
            let permits = Arc::new(tokio::sync::Semaphore::new(1));
            let started = Arc::new(AtomicBool::new(false));
            let observed = started.clone();
            let task = tokio::spawn(dispatch_recon_decode(
                permits.clone(),
                Duration::from_secs(2),
                move |_| {
                    observed.store(true, Ordering::Release);
                    Ok(vec![])
                },
            ));
            tokio::time::timeout(Duration::from_secs(2), async {
                while permits.available_permits() != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            release_tx.send(()).unwrap();
            occupied.await.unwrap();
            let permit =
                tokio::time::timeout(Duration::from_secs(2), permits.clone().acquire_owned())
                    .await
                    .unwrap()
                    .unwrap();
            drop(permit);
            assert!(!started.load(Ordering::Acquire));
        });
    }

    async fn encoded_body_fixture(
        status: u16,
        encodings: &[&str],
        body: &[u8],
    ) -> Result<String, &'static str> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut response = format!(
            "HTTP/1.1 {status} Fixture\r\nContent-Type: text/html\r\nConnection: close\r\n"
        );
        if status != 204 {
            response.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        for encoding in encodings {
            response.push_str(&format!("Content-Encoding: {encoding}\r\n"));
        }
        response.push_str("\r\n");
        let mut response = response.into_bytes();
        response.extend_from_slice(body);
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                let mut bytes = [0; 1024];
                let read = socket.read(&mut bytes).await.unwrap();
                assert!(read > 0 && request.len() < 8192);
                request.extend_from_slice(&bytes[..read]);
            }
            socket.write_all(&response).await.unwrap();
        });
        let response = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap()
            .get(format!("http://{address}/"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            response
                .headers()
                .get_all(reqwest::header::CONTENT_ENCODING)
                .iter()
                .count(),
            encodings.len()
        );
        let result = read_body(response).await;
        server.await.unwrap();
        result
    }

    #[tokio::test]
    async fn recon_encoded_body_preserves_identity_and_bodyless_responses() {
        let raw = b"unchanged\xffidentity";
        for encodings in [vec![], vec!["identity"], vec![""], vec![" , identity, "]] {
            assert_eq!(
                encoded_body_fixture(200, &encodings, raw).await.unwrap(),
                String::from_utf8_lossy(raw)
            );
        }
        for encodings in [vec![], vec!["identity"]] {
            assert_eq!(
                encoded_body_fixture(205, &encodings, raw).await.unwrap(),
                String::from_utf8_lossy(raw)
            );
        }
        for status in [204, 205] {
            assert_eq!(
                encoded_body_fixture(status, &["gzip"], b"").await.unwrap(),
                ""
            );
        }
    }

    #[tokio::test]
    async fn recon_encoded_body_decodes_gzip_aliases_without_altering_static_text() {
        let raw =
            b"<a href='/found?q=1&amp;q=2'>link</a><form method='POST' action='/form'></form>";
        let encoded = encoded_fixture_gzip(raw);
        for encoding in ["gzip", "GZip", "x-gzip", " identity , gzip , "] {
            assert_eq!(
                encoded_body_fixture(200, &[encoding], &encoded)
                    .await
                    .unwrap()
                    .as_bytes(),
                raw,
                "{encoding}"
            );
        }
    }

    #[tokio::test]
    async fn recon_encoded_body_keeps_stacked_fields_and_all_concatenated_members() {
        let raw = b"<a href='/first'>first</a><a href='/second'>second</a>";
        let stacked = encoded_fixture_gzip(&encoded_fixture_gzip(raw));
        for encodings in [vec!["gzip, gzip"], vec!["gzip", "x-gzip"]] {
            assert_eq!(
                encoded_body_fixture(200, &encodings, &stacked)
                    .await
                    .unwrap()
                    .as_bytes(),
                raw
            );
        }
        let mut concatenated = encoded_fixture_gzip(&raw[..24]);
        concatenated.extend(encoded_fixture_gzip(&raw[24..]));
        assert_eq!(
            encoded_body_fixture(200, &["gzip"], &concatenated)
                .await
                .unwrap()
                .as_bytes(),
            raw
        );
    }

    #[tokio::test]
    async fn recon_encoded_body_rejects_incomplete_or_unsupported_content_without_raw_fallback() {
        let raw = b"<a href='/must-not-follow'>wire bytes</a>";
        let encoded = encoded_fixture_gzip(raw);
        let mut trailing = encoded.clone();
        trailing.extend_from_slice(b"not-a-member");
        let mut bad_crc = encoded.clone();
        let crc = bad_crc.len() - 8;
        bad_crc[crc] ^= 1;
        for body in [
            Vec::new(),
            raw.to_vec(),
            encoded[..encoded.len() - 2].to_vec(),
            trailing,
            bad_crc,
        ] {
            assert!(encoded_body_fixture(200, &["gzip"], &body).await.is_err());
        }
        for encodings in [
            vec!["br"],
            vec!["deflate"],
            vec!["zstd"],
            vec!["gzip, unknown"],
            vec!["gzip;level=1"],
        ] {
            assert!(
                encoded_body_fixture(200, &encodings, raw).await.is_err(),
                "{encodings:?}"
            );
        }
    }

    #[tokio::test]
    async fn crawl_encoded_body_marks_partial_and_retains_live_response_without_false_links() {
        let (report, snapshot, paths) = crawl_wire_fixture(
            "text/html",
            b"<a href='/must-not-follow'>not gzip</a>",
            &["gzip"],
            "/encoded",
        )
        .await;
        assert!(report.truncated, "{report:?}");
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.to_ascii_lowercase().contains("decod")),
            "{report:?}"
        );
        assert_eq!(report.requests, 3);
        assert!(report.error.is_none());
        assert!(!paths.iter().any(|path| path == "/must-not-follow"));
        assert!(snapshot
            .endpoints
            .iter()
            .any(|endpoint| endpoint.url.ends_with("/encoded")
                && endpoint
                    .evidence
                    .iter()
                    .any(|evidence| evidence.kind == "live" && evidence.status == Some(200))));
        assert!(snapshot.endpoints.iter().all(|endpoint| endpoint
            .evidence
            .iter()
            .all(|evidence| evidence.kind == "live")));
    }

    #[tokio::test]
    async fn crawl_extracts_ecmascript_and_javascript_aliases_without_executing_candidates() {
        for content_type in [
            "application/ecmascript",
            "text/ecmascript",
            "APPLICATION/ECMASCRIPT; charset=UTF-8",
            "application/javascript",
            "text/javascript; charset=utf-8",
            "application/x-javascript",
        ] {
            let (report, snapshot, paths) =
                crawl_static_fixture(content_type, "fetch('/candidate')", "/extensionless").await;
            assert_eq!(report.requests, 3, "{content_type}");
            assert!(!report.truncated, "{content_type}");
            assert!(
                snapshot
                    .endpoints
                    .iter()
                    .any(|endpoint| endpoint.url.ends_with("/candidate")
                        && endpoint
                            .evidence
                            .iter()
                            .any(|evidence| evidence.kind == "candidate")),
                "{content_type}"
            );
            assert!(!paths.contains(&"/candidate".into()), "{content_type}");
        }
        let (_, snapshot, _) =
            crawl_static_fixture("", "fetch('/extension-candidate')", "/bundle.js").await;
        assert!(snapshot
            .endpoints
            .iter()
            .any(|endpoint| endpoint.url.ends_with("/extension-candidate")));
    }

    #[tokio::test]
    async fn crawl_extracts_links_beyond_former_token_and_body_caps() {
        for body in [
            format!(
                "{}<a href='/late-link'>link</a>",
                "<span></span>".repeat(10_001)
            ),
            format!(
                "{}<a href='/late-link'>link</a>",
                "😀".repeat(2 * 1024 * 1024 / 4 + 1)
            ),
        ] {
            let (report, snapshot, paths) = crawl_static_fixture("text/html", &body, "/tags").await;
            assert!(!report.truncated);
            assert!(snapshot
                .endpoints
                .iter()
                .any(|endpoint| endpoint.url.ends_with("/late-link")));
            assert!(paths.contains(&"/late-link".into()));
            assert_eq!(report.requests, 4);
            assert!(!report
                .warnings
                .iter()
                .any(|warning| warning.contains("extraction limit")));
        }
    }

    #[tokio::test]
    async fn crawl_has_no_default_depth_budget_and_deduplicates_cycles() {
        use axum::{routing::get, Router};
        let router = Router::new().fallback(get(|uri: axum::http::Uri| async move {
            let body = match uri.path().trim_start_matches('/').parse::<usize>() {
                Ok(depth) if depth < 12 => format!(
                    "<a href='/{}'>next</a><a href='/0#again'>cycle</a><a href='/{}'>duplicate</a>",
                    depth + 1,
                    depth + 1
                ),
                _ => String::new(),
            };
            ([(axum::http::header::CONTENT_TYPE, "text/html")], body)
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let dir = std::env::temp_dir().join(format!("sniper-recon-depth-{}", Uuid::new_v4()));
        let (_, session) = crate::session::SessionRegistry::load_or_create(&dir, 32, 32).unwrap();
        let mut request: StartRecon = serde_json::from_value(serde_json::json!({
            "session_id": session.id(), "target_url": format!("http://{address}/0"), "sources": ["crawler"]
        })).unwrap();
        let scope = validate(&request).unwrap();
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let report = crawl(
            &session,
            Uuid::new_v4(),
            &request,
            &scope,
            &client,
            &AtomicBool::new(false),
        )
        .await;
        assert!(!report.truncated);
        assert_eq!(report.requests, 15);
        assert!(session
            .recon
            .snapshot()
            .endpoints
            .iter()
            .any(|endpoint| endpoint.url.ends_with("/12")));
        request.max_depth = 1;
        let report = crawl(
            &session,
            Uuid::new_v4(),
            &request,
            &scope,
            &client,
            &AtomicBool::new(false),
        )
        .await;
        assert!(report.truncated);
        assert_eq!(report.requests, 4);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("depth budget")));
        request.max_depth = 0;
        request.max_requests = 2;
        let report = crawl(
            &session,
            Uuid::new_v4(),
            &request,
            &scope,
            &client,
            &AtomicBool::new(false),
        )
        .await;
        assert!(report.truncated);
        assert_eq!(report.requests, 2);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("request budget")));
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn start_and_stop_serialize_with_session_switch_without_deadlock() {
        let dir = std::env::temp_dir().join(format!("sniper-recon-switch-{}", Uuid::new_v4()));
        let config = crate::config::AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 32,
            max_transaction_entries: 32,
            body_preview_bytes: 4096,
            data_dir: dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let first = state.session().await;
        for _ in 0..25 {
            first.recon.snapshot.lock().unwrap().jobs.push(ReconJob {
                id: Uuid::new_v4(),
                target_url: "https://example.com/".into(),
                status: "completed".into(),
                started_at: Utc::now(),
                finished_at: Some(Utc::now()),
                sources: Vec::new(),
                error: None,
            });
        }
        let second = state
            .sessions
            .create_session(Some("Second".into()))
            .unwrap();
        let operation = state.session_operation_lock(first.id()).await;
        let held = operation.lock_owned().await;
        // A cancelled provider request is not sent: the queued start waits on
        // the same operation gate used by activation and deletion.
        let request: StartRecon = serde_json::from_value(serde_json::json!({
            "session_id": first.id(), "target_url": "http://127.0.0.1:1/", "sources": ["crawler"], "max_requests": 1
        })).unwrap();
        let start_state = state.clone();
        let starting = tokio::spawn(async move { start(State(start_state), Json(request)).await });
        let switch_state = state.clone();
        let switching = tokio::spawn(async move { switch_state.activate_session(second.id).await });
        drop(held);
        let job = tokio::time::timeout(Duration::from_secs(5), starting)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .0;
        assert_eq!(first.recon.snapshot().jobs.len(), 26);
        let stopping = stop(
            State(state.clone()),
            Path(job.id),
            Json(SessionQuery {
                session_id: first.id(),
            }),
        );
        // Whether it was still running is a race; only finishing matters here.
        let _ = tokio::time::timeout(Duration::from_secs(5), stopping)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), switching)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(state.session().await.recon.snapshot().endpoints.is_empty());
        state.stop_background_jobs().await.unwrap();
    }
}
