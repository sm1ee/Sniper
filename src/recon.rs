//! Explicitly scoped, session-owned endpoint discovery. Findings are evidence,
//! not proxy transactions: archived and static candidates never imply liveness.
use std::{
    collections::{HashSet, VecDeque},
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
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;
use url::Url;
use uuid::Uuid;

use crate::{
    recon_sources::{self, Discovery, SourceReport},
    session::SessionContext,
    state::AppState,
};

const MAX_INVENTORY: usize = 5_000;
const MAX_INVENTORY_BYTES: usize = 8 * 1024 * 1024;
const MAX_URL_BYTES: usize = 4_096;
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_JOBS: usize = 20;

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
    inventory_bytes: AtomicUsize,
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
        let inventory_bytes =
            serde_json::to_vec(&snapshot.endpoints).map_or(MAX_INVENTORY_BYTES, |v| v.len());
        Self {
            snapshot: Mutex::new(snapshot),
            running: Mutex::new(None),
            inventory_bytes: AtomicUsize::new(inventory_bytes),
        }
    }

    pub fn snapshot(&self) -> ReconSnapshot {
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

    /// `limit` is this job's own: the endpoints it may add, as its Discovery
    /// limits say. Comparing it with the whole inventory left a later job with
    /// a smaller limit than what earlier jobs had found unable to add any.
    fn merge(
        &self,
        job: Uuid,
        scope: &ReconScope,
        source: &str,
        findings: Vec<Discovery>,
        limit: usize,
    ) -> (usize, bool) {
        let mut snapshot = self.snapshot.lock().unwrap();
        let mut bytes = self.inventory_bytes.load(Ordering::Relaxed);
        let found_before: usize = snapshot
            .jobs
            .iter()
            .find(|item| item.id == job)
            .map_or(0, |item| {
                item.sources.iter().map(|source| source.discovered).sum()
            });
        let remaining = limit.saturating_sub(found_before);
        let mut added = 0;
        let mut truncated = false;
        for finding in findings {
            let Ok(mut url) = Url::parse(&finding.url) else {
                continue;
            };
            if finding.url.len() > MAX_URL_BYTES || !scope.contains_evidence(&url) {
                continue;
            }
            url.set_fragment(None);
            let key = url.to_string();
            let method = if finding.method.len() <= 32
                && http::Method::from_bytes(finding.method.as_bytes()).is_ok()
            {
                finding.method.to_ascii_uppercase()
            } else {
                "GET".into()
            };
            let evidence = ReconEvidence {
                source: source.into(),
                kind: finding.kind,
                location: finding.location.chars().take(1024).collect(),
                timestamp: finding.timestamp.map(|s| s.chars().take(64).collect()),
                status: finding.status,
            };
            let charge = key.len() + finding.url.len() + evidence.location.len() + 512;
            if bytes.saturating_add(charge) > MAX_INVENTORY_BYTES {
                truncated = true;
                break;
            }
            let mut charged = false;
            if let Some(endpoint) = snapshot
                .endpoints
                .iter_mut()
                .find(|entry| entry.url == key && entry.method == method)
            {
                if !endpoint.raw_urls.contains(&finding.url) {
                    if endpoint.raw_urls.len() < 8 {
                        endpoint.raw_urls.push(finding.url);
                        charged = true;
                    } else {
                        truncated = true;
                    }
                }
                if !endpoint.evidence.contains(&evidence) {
                    if endpoint.evidence.len() < 16 {
                        endpoint.evidence.push(evidence);
                        charged = true;
                    } else {
                        truncated = true;
                    }
                }
                endpoint.last_seen = Utc::now();
            } else {
                if added >= remaining || snapshot.endpoints.len() >= MAX_INVENTORY {
                    truncated = true;
                    continue;
                }
                let now = Utc::now();
                snapshot.endpoints.push(ReconEndpoint {
                    url: key,
                    method,
                    raw_urls: vec![finding.url],
                    evidence: vec![evidence],
                    first_seen: now,
                    last_seen: now,
                });
                added += 1;
                charged = true;
            }
            if charged {
                bytes += charge;
            }
        }
        self.inventory_bytes.store(bytes, Ordering::Relaxed);
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

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartRecon {
    pub session_id: Uuid,
    pub target_url: String,
    #[serde(default)]
    pub include_subdomains: bool,
    pub sources: Vec<String>,
    #[serde(default = "default_requests")]
    pub max_requests: usize,
    #[serde(default = "default_depth")]
    pub max_depth: usize,
    #[serde(default = "default_endpoints")]
    pub max_endpoints: usize,
    #[serde(default = "default_pages")]
    pub max_pages: usize,
    #[serde(default)]
    pub history_acknowledged: bool,
    #[serde(default)]
    pub scan_acknowledged: bool,
    #[serde(default)]
    pub scan_visibility: Option<String>,
}
fn default_requests() -> usize {
    100
}
fn default_depth() -> usize {
    3
}
fn default_endpoints() -> usize {
    5_000
}
fn default_pages() -> usize {
    5
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
        if target.len() > MAX_URL_BYTES
            || !matches!(url.scheme(), "http" | "https")
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
    if !(1..=1_000).contains(&request.max_requests)
        || request.max_depth > 10
        || !(1..=MAX_INVENTORY).contains(&request.max_endpoints)
        || !(1..=20).contains(&request.max_pages)
    {
        return Err("Recon limits are outside their supported ranges.".into());
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
                .user_agent("Sniper-Recon/0.3.1"),
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
        .user_agent("Sniper-Recon/0.3.1")
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
        if snapshot.jobs.len() >= MAX_JOBS {
            snapshot.jobs.remove(0);
        }
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
            let (findings, mut report) = match source.as_str() {
                "urlscan" => recon_sources::urlscan(&provider, &scope.target, request.include_subdomains,
                    request.max_pages, request.max_endpoints, &cancel).await,
                "urlscan_submit" => recon_sources::submit_urlscan(&provider, &scope.target, request.include_subdomains,
                    request.scan_visibility.as_deref().unwrap_or("private"), request.max_endpoints, &cancel,
                    |result_url| {
                        session.recon.update_source(id, source, |s| s.warnings.push(format!("Accepted scan result: {result_url}. Stop cancels local polling only.")));
                        session.schedule_state_persist();
                    }).await,
                _ => recon_sources::wayback(&provider, &scope.target, request.include_subdomains,
                    request.max_pages, request.max_endpoints, &cancel).await,
            };
            let (added, truncated) =
                session
                    .recon
                    .merge(id, &scope, source, findings, request.max_endpoints);
            report.truncated |= truncated;
            session
                .recon
                .update_source(id, source, |s| s.discovered += added);
            report
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
            s.warnings.extend(report.warnings);
            if let Some(error) = report.error {
                s.warnings.push(error);
            }
            if s.truncated {
                s.warnings
                    .push("Collection was bounded; more evidence may exist.".into());
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

async fn read_body(mut response: reqwest::Response) -> Result<String, &'static str> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "Response body could not be read.")?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_BODY_BYTES {
            return Err("Response exceeds the 2 MiB extraction limit.");
        }
        bytes.extend_from_slice(&chunk);
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
    let mut seen = HashSet::new();
    let mut successful_responses = 0;
    while let Some((mut url, depth, redirects)) = queue.pop_front() {
        if cancel.load(Ordering::Acquire) {
            break;
        }
        if report.requests >= request.max_requests {
            report.truncated = true;
            break;
        }
        url.set_fragment(None);
        if !scope.contains(&url) || !seen.insert(url.to_string()) {
            continue;
        }
        report.requests += 1;
        let response = match client.get(url.clone()).send().await {
            Ok(response) => response,
            Err(_) => {
                report.truncated = true;
                if report.warnings.len() < 20 {
                    report
                        .warnings
                        .push("A scoped crawl request failed (network/TLS/timeout).".into());
                }
                continue;
            }
        };
        successful_responses += 1;
        let status = response.status().as_u16();
        let (added, truncated) = session.recon.merge(
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
        );
        report.truncated |= truncated;
        session.recon.update_source(id, "crawler", |s| {
            s.requests = report.requests;
            s.discovered += added;
        });
        if response.status().is_redirection() {
            if let Some(location) = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|h| h.to_str().ok())
            {
                if let Ok(next) = url.join(location) {
                    if scope.contains(&next) && redirects < 5 {
                        queue.push_front((next, depth, redirects + 1));
                    } else if report.warnings.len() < 20 {
                        report.warnings.push("A redirect was not followed because it left scope or exceeded five hops.".into());
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
                if report.warnings.len() < 20 {
                    report.warnings.push(error.into());
                }
                continue;
            }
        };
        let (findings, clipped) = recon_sources::extract_document(&url, &content_type, &body);
        if clipped {
            report.truncated = true;
            let warning =
                "A static document extraction limit was reached; more evidence may exist.";
            if report.warnings.len() < 20 && !report.warnings.iter().any(|item| item == warning) {
                report.warnings.push(warning.into());
            }
        }
        for finding in &findings {
            if !recon_sources::is_followable(finding) {
                continue;
            }
            let Ok(next) = Url::parse(&finding.url) else {
                continue;
            };
            if !scope.contains(&next) || seen.contains(next.as_str()) {
                continue;
            }
            if depth >= request.max_depth || queue.len() >= request.max_requests.saturating_mul(4) {
                report.truncated = true;
            } else {
                queue.push_back((next, depth + 1, 0));
            }
        }
        let (added, truncated) =
            session
                .recon
                .merge(id, scope, "crawler", findings, request.max_endpoints);
        report.truncated |= truncated;
        session
            .recon
            .update_source(id, "crawler", |s| s.discovered += added);
        session.schedule_state_persist();
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

    async fn crawl_static_fixture(
        content_type: &str,
        body: &str,
        path: &str,
    ) -> (SourceReport, ReconSnapshot, Vec<String>) {
        use axum::{routing::get, Router};
        let requested = Arc::new(Mutex::new(Vec::<String>::new()));
        let captured = requested.clone();
        let content_type = content_type.to_string();
        let body = body.to_string();
        let fixture_path = path.to_string();
        let router = Router::new().fallback(get(move |uri: axum::http::Uri| {
            let captured = captured.clone();
            let content_type = content_type.clone();
            let body = body.clone();
            let fixture_path = fixture_path.clone();
            async move {
                captured.lock().unwrap().push(uri.path().to_string());
                if uri.path() == fixture_path {
                    ([(axum::http::header::CONTENT_TYPE, content_type)], body)
                } else {
                    (
                        [(axum::http::header::CONTENT_TYPE, "text/plain".into())],
                        String::new(),
                    )
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
            "sources": ["crawler"], "max_requests": 8
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
    async fn crawl_reports_html_token_clipping_without_relaxing_the_bound() {
        for spans in [4999, 5000] {
            let body = format!(
                "{}<a href='/late-link'>link</a>",
                "<span></span>".repeat(spans)
            );
            let (report, snapshot, paths) = crawl_static_fixture("text/html", &body, "/tags").await;
            let clipped = spans == 5000;
            assert_eq!(report.truncated, clipped, "{spans} spans");
            assert_eq!(
                snapshot
                    .endpoints
                    .iter()
                    .any(|endpoint| endpoint.url.ends_with("/late-link")),
                !clipped
            );
            assert_eq!(paths.contains(&"/late-link".into()), !clipped);
            assert_eq!(report.requests, if clipped { 3 } else { 4 });
            assert_eq!(
                report
                    .warnings
                    .iter()
                    .any(|warning| warning.contains("extraction limit")),
                clipped
            );
        }
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
        let stopping = stop(
            State(state.clone()),
            Path(job.id),
            Json(SessionQuery {
                session_id: first.id(),
            }),
        );
        tokio::time::timeout(Duration::from_secs(5), stopping)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), switching)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(state.session().await.recon.snapshot().endpoints.is_empty());
        state.stop_recon_jobs().await.unwrap();
    }
}
