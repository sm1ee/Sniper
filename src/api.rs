use std::{
    convert::Infallible,
    path::{Component, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use async_stream::stream;
use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderValue, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        Html, IntoResponse, Response,
    },
    routing::{get, patch, post},
    Json, Router,
};
use indexmap::IndexMap;
use rust_embed::RustEmbed;
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    config::{StartupSettingsUpdate, StartupSettingsView},
    event_log::EventLogEntry,
    intercept::{InterceptRecord, InterceptSummary},
    fuzzer::{self, FuzzerAttackPayload, FuzzerAttackRecord, FuzzerAttackSummary},
    match_replace::{MatchReplaceRule, MatchReplaceRulesPayload},
    model::{EditableRequest, RequestTargetOverride},
    proxy,
    runtime::{RuntimeSettingsSnapshot, RuntimeSettingsUpdate},
    session::SessionSummary,
    state::AppState,
    store::ListFilters,
    target::{TargetHostNode, TargetPathNode},
    ui_settings::AppUiSettingsSnapshot,
    workspace::WorkspaceStateSnapshot,
};

#[derive(RustEmbed)]
#[folder = "web/decoder/"]
struct DecoderAssets;

pub async fn run_api(state: Arc<AppState>) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(state.config.ui_addr)
        .await
        .with_context(|| format!("failed to bind UI listener to {}", state.config.ui_addr))?;

    serve_api(listener, state).await
}

pub async fn serve_api(listener: tokio::net::TcpListener, state: Arc<AppState>) -> Result<()> {
    let app = router(state);
    tracing::info!(ui_addr = %listener.local_addr()?, "ui listener ready");
    axum::serve(listener, app)
        .await
        .context("ui server stopped unexpectedly")
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/decoder", get(decoder_index))
        .route("/decoder/", get(decoder_index))
        .route("/decoder/*path", get(decoder_asset))
        .route("/app.js", get(app_js))
        .route("/styles.css", get(styles_css))
        .route("/favicon.svg", get(favicon_svg))
        .route("/logo.svg", get(logo_svg))
        .route("/fonts/Bungee-Regular.ttf", get(bungee_font))
        .route("/api/settings", get(get_settings))
        .route("/api/app-version", get(get_app_version))
        .route("/api/sessions", get(list_sessions).post(create_session))
        .route("/api/sessions/:id/activate", post(activate_session))
        .route(
            "/api/runtime",
            get(get_runtime_settings).post(update_runtime_settings),
        )
        .route(
            "/api/workspace-state",
            get(get_workspace_state).post(update_workspace_state),
        )
        .route(
            "/api/startup-settings",
            get(get_startup_settings).post(update_startup_settings),
        )
        .route(
            "/api/ui-settings",
            get(get_ui_settings).post(update_ui_settings),
        )
        .route(
            "/api/event-log",
            get(list_event_log).delete(clear_event_log),
        )
        .route("/api/certificates/root.pem", get(download_root_pem))
        .route("/api/certificates/root.der", get(download_root_der))
        .route(
            "/api/match-replace",
            get(list_match_replace_rules).post(update_match_replace_rules),
        )
        .route("/api/target/site-map", get(get_target_site_map))
        .route("/api/transactions", get(list_transactions))
        .route("/api/transactions/:id", get(get_transaction))
        .route(
            "/api/transactions/:id/annotations",
            patch(update_transaction_annotations),
        )
        .route("/api/intercepts", get(list_intercepts))
        .route("/api/intercepts/:id", get(get_intercept))
        .route("/api/intercepts/forward-all", post(forward_all_intercepts))
        .route("/api/intercepts/:id/forward", post(forward_intercept))
        .route("/api/intercepts/:id/drop", post(drop_intercept))
        .route("/api/replay/send", post(send_replay))
        .route(
            "/api/fuzzer/attacks",
            get(list_fuzzer_attacks).post(run_fuzzer_attack),
        )
        .route("/api/fuzzer/attacks/:id", get(get_fuzzer_attack))
        .route("/api/websockets", get(list_websockets))
        .route("/api/websockets/:id", get(get_websocket))
        .route("/api/events", get(events))
        .fallback(get(index))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct TransactionQuery {
    q: Option<String>,
    method: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct WebSocketQuery {
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct EventLogQuery {
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct FuzzerQuery {
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct InterceptForwardPayload {
    request: EditableRequest,
}

#[derive(Debug, Deserialize)]
struct ReplaySendPayload {
    request: EditableRequest,
    target: Option<RequestTargetOverride>,
    source_transaction_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
struct CreateSessionPayload {
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AnnotationsPayload {
    color_tag: Option<Option<String>>,
    user_note: Option<Option<String>>,
}

async fn get_settings(State(state): State<Arc<AppState>>) -> Json<crate::state::RuntimeInfo> {
    Json(state.runtime_info().await)
}

async fn get_app_version(State(state): State<Arc<AppState>>) -> Json<crate::state::AppVersionInfo> {
    Json(state.app_version_info().await)
}

async fn list_sessions(State(state): State<Arc<AppState>>) -> Json<Vec<SessionSummary>> {
    Json(state.list_sessions())
}

async fn create_session(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateSessionPayload>,
) -> Response {
    match state.create_session(payload.name).await {
        Ok(summary) => {
            persist_session_quiet(&state).await;
            Json(summary).into_response()
        }
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

async fn activate_session(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    match state.activate_session(id).await {
        Ok(summary) => Json(summary).into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

async fn get_runtime_settings(State(state): State<Arc<AppState>>) -> Json<RuntimeSettingsSnapshot> {
    let session = state.session().await;
    Json(session.runtime.snapshot().await)
}

async fn get_workspace_state(State(state): State<Arc<AppState>>) -> Json<WorkspaceStateSnapshot> {
    let session = state.session().await;
    Json(session.workspace.snapshot().await)
}

async fn update_workspace_state(
    State(state): State<Arc<AppState>>,
    Json(snapshot): Json<WorkspaceStateSnapshot>,
) -> Json<WorkspaceStateSnapshot> {
    let session = state.session().await;
    let snapshot = session.workspace.replace_snapshot(snapshot).await;
    persist_session_quiet(&state).await;
    Json(snapshot)
}

async fn update_runtime_settings(
    State(state): State<Arc<AppState>>,
    Json(update): Json<RuntimeSettingsUpdate>,
) -> Json<RuntimeSettingsSnapshot> {
    let session = state.session().await;
    let snapshot = session.runtime.update(update).await;
    state
        .log_info(
            "runtime",
            "Runtime settings updated",
            format!(
                "intercept={}, websocket_capture={}, scope_entries={}",
                snapshot.intercept_enabled,
                snapshot.websocket_capture_enabled,
                snapshot.scope_patterns.len()
            ),
        )
        .await;
    persist_session_quiet(&state).await;
    Json(snapshot)
}

async fn get_startup_settings(State(state): State<Arc<AppState>>) -> Json<StartupSettingsView> {
    let active_addr = state.get_active_proxy_addr().await;
    Json(state.startup.view(active_addr).await)
}

async fn get_ui_settings(State(state): State<Arc<AppState>>) -> Json<AppUiSettingsSnapshot> {
    Json(state.ui_settings.snapshot().await)
}

async fn update_ui_settings(
    State(state): State<Arc<AppState>>,
    Json(snapshot): Json<AppUiSettingsSnapshot>,
) -> Response {
    match state.ui_settings.replace_snapshot(snapshot).await {
        Ok(snapshot) => Json(snapshot).into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

async fn update_startup_settings(
    State(state): State<Arc<AppState>>,
    Json(update): Json<StartupSettingsUpdate>,
) -> Response {
    match state.startup.update(update).await {
        Ok(snapshot) => {
            let active_addr = state.get_active_proxy_addr().await;
            let desired_addr = match snapshot.proxy_addr() {
                Ok(addr) => addr,
                Err(e) => {
                    return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
                }
            };

            // Try hot-rebind if address changed
            let (rebound, rebind_error) = if desired_addr != active_addr {
                match crate::proxy::rebind_proxy(state.clone(), desired_addr).await {
                    Ok(()) => (Some(true), None),
                    Err(err) => (Some(false), Some(err)),
                }
            } else {
                (None, None)
            };

            let new_active = state.get_active_proxy_addr().await;
            let mut view = state.startup.view(new_active).await;
            view.rebound = rebound;
            view.rebind_error = rebind_error.clone();

            // Log appropriate message
            match (rebound, &rebind_error) {
                (Some(true), _) => {
                    state
                        .log_info(
                            "config",
                            "Proxy listener rebound",
                            format!("Proxy listener moved to {}", view.active_proxy_addr),
                        )
                        .await;
                }
                (Some(false), Some(err)) => {
                    state
                        .log_warn(
                            "config",
                            "Proxy rebind failed",
                            format!(
                                "Could not rebind to {}: {}. Saved for next launch.",
                                view.proxy_addr, err
                            ),
                        )
                        .await;
                }
                _ => {}
            }

            Json(view).into_response()
        }
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

async fn list_event_log(
    State(state): State<Arc<AppState>>,
    Query(query): Query<EventLogQuery>,
) -> Json<Vec<EventLogEntry>> {
    let session = state.session().await;
    Json(session.event_log.list(query.limit).await)
}

async fn clear_event_log(State(state): State<Arc<AppState>>) -> StatusCode {
    let session = state.session().await;
    session.event_log.clear().await;
    persist_session_quiet(&state).await;
    StatusCode::NO_CONTENT
}

async fn download_root_pem(State(state): State<Arc<AppState>>) -> Response {
    download_bytes_response(
        state.certificates.root_pem_bytes(),
        "application/x-pem-file",
        "attachment; filename=\"sniper-root-ca.pem\"",
    )
}

async fn download_root_der(State(state): State<Arc<AppState>>) -> Response {
    download_bytes_response(
        state.certificates.root_der_bytes(),
        "application/pkix-cert",
        "attachment; filename=\"sniper-root-ca.der\"",
    )
}

async fn list_match_replace_rules(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<MatchReplaceRule>> {
    let session = state.session().await;
    Json(session.match_replace.snapshot().await)
}

async fn update_match_replace_rules(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<MatchReplaceRulesPayload>,
) -> Json<Vec<MatchReplaceRule>> {
    let session = state.session().await;
    let rules = session.match_replace.replace_all(payload.rules).await;
    state
        .log_info(
            "match_replace",
            "Rules updated",
            format!("{} rule(s) active in configuration", rules.len()),
        )
        .await;
    persist_session_quiet(&state).await;
    Json(rules)
}

async fn get_target_site_map(State(state): State<Arc<AppState>>) -> Json<Vec<TargetHostNode>> {
    let session = state.session().await;
    let records = session.store.snapshot(Some(state.config.max_entries)).await;
    let mut hosts = IndexMap::<String, TargetHostAccumulator>::new();

    for record in records
        .into_iter()
        .filter(|record| record.method != "CONNECT" && !record.host.is_empty())
    {
        let host = hosts
            .entry(record.host.clone())
            .or_insert_with(|| TargetHostAccumulator {
                host: record.host.clone(),
                schemes: Vec::new(),
                request_count: 0,
                paths: IndexMap::new(),
            });

        host.request_count += 1;
        push_unique(&mut host.schemes, record.scheme.clone());

        let path = host
            .paths
            .entry(record.path.clone())
            .or_insert_with(|| TargetPathAccumulator {
                path: record.path.clone(),
                methods: Vec::new(),
                last_seen: record.started_at,
                status: record.status,
                note_count: 0,
                is_websocket: record.is_websocket(),
            });
        push_unique(&mut path.methods, record.method.clone());
        if record.started_at > path.last_seen {
            path.last_seen = record.started_at;
            path.status = record.status;
        }
        path.note_count += record.notes.len();
        path.is_websocket = path.is_websocket || record.is_websocket();
    }

    let mut site_map = Vec::with_capacity(hosts.len());
    for (_, host) in hosts {
        let mut paths = host
            .paths
            .into_iter()
            .map(|(_, path)| TargetPathNode {
                path: path.path,
                methods: path.methods,
                last_seen: path.last_seen,
                status: path.status,
                note_count: path.note_count,
                is_websocket: path.is_websocket,
            })
            .collect::<Vec<_>>();
        paths.sort_by(|left, right| right.last_seen.cmp(&left.last_seen));

        site_map.push(TargetHostNode {
            host: host.host.clone(),
            schemes: host.schemes,
            request_count: host.request_count,
            in_scope: session.runtime.is_in_scope(&host.host).await,
            paths,
        });
    }

    Json(site_map)
}

async fn list_transactions(
    State(state): State<Arc<AppState>>,
    Query(query): Query<TransactionQuery>,
) -> Json<Vec<crate::model::TransactionSummary>> {
    let session = state.session().await;
    Json(
        session
            .store
            .list(&ListFilters {
                query: query.q,
                method: query.method,
                limit: query.limit,
            })
            .await,
    )
}

async fn get_transaction(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<crate::model::TransactionRecord>, StatusCode> {
    let id = Uuid::parse_str(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let session = state.session().await;
    session
        .store
        .get(id)
        .await
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn update_transaction_annotations(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(payload): Json<AnnotationsPayload>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let session = state.session().await;
    match session
        .store
        .update_annotations(id, payload.color_tag, payload.user_note)
        .await
    {
        Some(summary) => {
            persist_session_quiet(&state).await;
            Json(summary).into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn list_intercepts(State(state): State<Arc<AppState>>) -> Json<Vec<InterceptSummary>> {
    let session = state.session().await;
    Json(session.intercepts.list().await)
}

async fn get_intercept(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<InterceptRecord>, StatusCode> {
    let id = Uuid::parse_str(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let session = state.session().await;
    session
        .intercepts
        .get(id)
        .await
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn forward_intercept(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(payload): Json<InterceptForwardPayload>,
) -> Result<StatusCode, StatusCode> {
    let id = Uuid::parse_str(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let session = state.session().await;
    if session.intercepts.get(id).await.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    session
        .intercepts
        .forward(id, payload.request)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    state
        .log_info(
            "intercept",
            "Request forwarded",
            format!("Intercept item {id} forwarded"),
        )
        .await;
    persist_session_quiet(&state).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn drop_intercept(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let id = Uuid::parse_str(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let session = state.session().await;
    if session.intercepts.get(id).await.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    session
        .intercepts
        .drop_request(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    state
        .log_warn(
            "intercept",
            "Request dropped",
            format!("Intercept item {id} dropped"),
        )
        .await;
    persist_session_quiet(&state).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn forward_all_intercepts(State(state): State<Arc<AppState>>) -> StatusCode {
    let session = state.session().await;
    let count = session.intercepts.forward_all().await;
    if count > 0 {
        state
            .log_info(
                "intercept",
                "All requests forwarded",
                format!("{count} intercepted request(s) forwarded"),
            )
            .await;
        persist_session_quiet(&state).await;
    }
    StatusCode::NO_CONTENT
}

async fn send_replay(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ReplaySendPayload>,
) -> Response {
    match proxy::send_replay_request(
        state,
        payload.request,
        payload.target,
        payload.source_transaction_id,
    )
    .await
    {
        Ok(record) => Json(record).into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

async fn list_fuzzer_attacks(
    State(state): State<Arc<AppState>>,
    Query(query): Query<FuzzerQuery>,
) -> Json<Vec<FuzzerAttackSummary>> {
    let session = state.session().await;
    Json(session.fuzzer.list(query.limit).await)
}

async fn get_fuzzer_attack(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<FuzzerAttackRecord>, StatusCode> {
    let id = Uuid::parse_str(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let session = state.session().await;
    session
        .fuzzer
        .get(id)
        .await
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn run_fuzzer_attack(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<FuzzerAttackPayload>,
) -> Response {
    match fuzzer::run_attack(
        state,
        payload.template,
        payload.payloads,
        payload.source_transaction_id,
    )
    .await
    {
        Ok(record) => Json(record).into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

async fn list_websockets(
    State(state): State<Arc<AppState>>,
    Query(query): Query<WebSocketQuery>,
) -> Json<Vec<crate::model::WebSocketSessionSummary>> {
    let session = state.session().await;
    Json(session.websockets.list(query.limit).await)
}

async fn get_websocket(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<crate::model::WebSocketSessionRecord>, StatusCode> {
    let id = Uuid::parse_str(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let session = state.session().await;
    session
        .websockets
        .get(id)
        .await
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn events(
    State(state): State<Arc<AppState>>,
) -> Sse<impl futures_core::Stream<Item = Result<Event, Infallible>>> {
    let session = state.session().await;
    let mut transaction_receiver = session.store.subscribe();
    let mut log_receiver = session.event_log.subscribe();

    let stream = stream! {
        loop {
            tokio::select! {
                result = transaction_receiver.recv() => {
                    match result {
                        Ok(summary) => {
                            if let Ok(payload) = serde_json::to_string(&summary) {
                                yield Ok(Event::default().event("transaction").data(payload));
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
                result = log_receiver.recv() => {
                    match result {
                        Ok(entry) => {
                            if let Ok(payload) = serde_json::to_string(&entry) {
                                yield Ok(Event::default().event("event_log").data(payload));
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        }
    };

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(10))
            .text("keepalive"),
    )
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../web/index.html"))
}

async fn decoder_index() -> Response {
    serve_decoder_asset("popup.html").await
}

async fn decoder_asset(Path(path): Path<String>) -> Response {
    serve_decoder_asset(&path).await
}

async fn favicon_svg() -> Response {
    asset_response(
        "image/svg+xml",
        include_str!("../web/favicon.svg"),
    )
}

async fn logo_svg() -> Response {
    asset_response(
        "image/svg+xml",
        include_str!("../web/logo.svg"),
    )
}

async fn bungee_font() -> Response {
    binary_asset_response("font/ttf", include_bytes!("../web/fonts/Bungee-Regular.ttf"))
}

async fn styles_css() -> Response {
    asset_response("text/css; charset=utf-8", include_str!("../web/styles.css"))
}

async fn app_js() -> Response {
    asset_response(
        "application/javascript; charset=utf-8",
        include_str!("../web/app.js"),
    )
}

fn asset_response(content_type: &'static str, body: &'static str) -> Response {
    (
        [(header::CONTENT_TYPE, HeaderValue::from_static(content_type))],
        body,
    )
        .into_response()
}

fn binary_asset_response(content_type: &'static str, body: &'static [u8]) -> Response {
    (
        [(header::CONTENT_TYPE, HeaderValue::from_static(content_type))],
        body,
    )
        .into_response()
}

async fn serve_decoder_asset(path: &str) -> Response {
    let relative = match sanitize_relative_path(path) {
        Some(path) => path,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    let key = relative.to_string_lossy().replace('\\', "/");
    match DecoderAssets::get(&key) {
        Some(content) => {
            let content_type = content_type_for_path(&relative);
            (
                [(header::CONTENT_TYPE, HeaderValue::from_static(content_type))],
                content.data.into_owned(),
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn sanitize_relative_path(path: &str) -> Option<PathBuf> {
    let normalized = if path.is_empty() { "popup.html" } else { path };
    let mut output = PathBuf::new();

    for component in PathBuf::from(normalized).components() {
        match component {
            Component::Normal(segment) => output.push(segment),
            Component::CurDir => {}
            _ => return None,
        }
    }

    if output.as_os_str().is_empty() {
        output.push("popup.html");
    }

    Some(output)
}

fn content_type_for_path(path: &std::path::Path) -> &'static str {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn download_bytes_response(
    bytes: &[u8],
    content_type: &'static str,
    content_disposition: &'static str,
) -> Response {
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (
                header::CONTENT_DISPOSITION,
                HeaderValue::from_static(content_disposition),
            ),
        ],
        bytes.to_vec(),
    )
        .into_response()
}

struct TargetHostAccumulator {
    host: String,
    schemes: Vec<String>,
    request_count: usize,
    paths: IndexMap<String, TargetPathAccumulator>,
}

struct TargetPathAccumulator {
    path: String,
    methods: Vec<String>,
    last_seen: chrono::DateTime<chrono::Utc>,
    status: Option<u16>,
    note_count: usize,
    is_websocket: bool,
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

async fn persist_session_quiet(state: &Arc<AppState>) {
    if let Err(error) = state.persist_active_session().await {
        tracing::warn!(?error, "failed to persist active session");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::extract::State;
    use chrono::Utc;

    use super::get_target_site_map;
    use crate::{
        config::AppConfig,
        model::{BodyEncoding, HeaderRecord, MessageRecord, TransactionRecord},
        state::AppState,
    };

    #[tokio::test]
    async fn target_site_map_counts_notes_once_per_record() {
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            upstream_insecure: false,
            data_dir: std::env::temp_dir()
                .join(format!("sniper-test-target-notes-{}", uuid::Uuid::new_v4())),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let message = MessageRecord {
            headers: vec![HeaderRecord {
                name: "host".to_string(),
                value: "example.test".to_string(),
            }],
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            preview_truncated: false,
            content_type: None,
        };

        let session = state.session().await;
        session
            .store
            .insert(TransactionRecord::http(
                Utc::now(),
                "GET".to_string(),
                "https".to_string(),
                "example.test".to_string(),
                "/hello".to_string(),
                Some(200),
                1,
                message.clone(),
                Some(message),
                vec!["one note".to_string()],
                None,
                None,
            ))
            .await;

        let site_map = get_target_site_map(State(state)).await.0;
        assert_eq!(site_map.len(), 1);
        assert_eq!(site_map[0].paths.len(), 1);
        assert_eq!(site_map[0].paths[0].note_count, 1);
    }
}
