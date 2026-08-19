use std::{
    collections::HashSet,
    convert::Infallible,
    io::IsTerminal,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::{Component, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use async_stream::stream;
use axum::{
    extract::{connect_info::ConnectInfo, Path, Query, Request, State},
    http::{
        header,
        uri::{Authority, PathAndQuery},
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri,
    },
    middleware::{self, Next},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{any, delete, get, patch, post},
    Json, Router,
};
use base64::Engine;
use indexmap::IndexMap;
use rand::{rngs::OsRng, RngCore};
use regex::RegexBuilder;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use tokio::sync::OwnedMutexGuard;
use uuid::Uuid;

use crate::{
    config::{StartupSettingsUpdate, StartupSettingsView},
    event_log::{EventLevel, EventLogEntry},
    fuzzer::{self, FuzzerAttackPayload},
    match_replace::{MatchReplaceRule, MatchReplaceRulesPayload},
    model::{BodyEncoding, EditableRequest, EditableResponse, HeaderRecord, RequestTargetOverride},
    proxy,
    runtime::RuntimeSettingsUpdate,
    runtime_state::{self, RuntimeStateSnapshot},
    sequence::{self, SequenceDefinition},
    session::{SessionContext, SessionSummary},
    state::AppState,
    store::{ListFilters, TransactionListPage},
    target::{TargetHostNode, TargetPathNode},
    ui_settings::AppUiSettingsSnapshot,
    websocket::WebSocketListFilters,
    workspace::{
        can_replace_snapshot, validate_workspace_serialized_size, FuzzerWorkspaceState,
        ReplayTabState, WorkspaceReplaceError, WorkspaceStateSnapshot,
        MAX_WORKSPACE_SERIALIZED_BYTES,
    },
};

const MAX_WORKSPACE_WS_FRAMES: usize = 1_000;
const MAX_WORKSPACE_WS_FRAME_BODY_BYTES: usize = 16 * 1024;
const MAX_WORKSPACE_WS_TOTAL_FRAMES: usize = 2_000;
const MAX_WORKSPACE_WS_TOTAL_FRAME_BODY_BYTES: usize = 12 * 1024 * 1024;
use crate::workspace::MAX_WORKSPACE_REPLAY_TABS;
const MAX_WORKSPACE_REPLAY_HISTORY_ENTRIES_PER_TAB: usize = 500;
const MAX_WORKSPACE_TEXT_FIELD_BYTES: usize = 2 * 1024 * 1024;
const MAX_WORKSPACE_FUZZER_PAYLOAD_TEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_WORKSPACE_FUZZER_PAYLOAD_LINES: usize = 5_000;
const MAX_WORKSPACE_WS_HEADERS: usize = 200;
const MAX_WORKSPACE_WS_HEADER_BYTES: usize = 64 * 1024;
const MAX_WORKSPACE_WS_HEADERS_BYTES: usize = 256 * 1024;
const MAX_WS_REPLAY_SCHEME_BYTES: usize = 16;
const MAX_WS_REPLAY_HOST_BYTES: usize = 1024;
const MAX_WS_REPLAY_PATH_BYTES: usize = 64 * 1024;
const MAX_WORKSPACE_WS_SETUP_QUEUE_ITEMS: usize = 250;
const MAX_WORKSPACE_WS_SETUP_ITEM_BYTES: usize = 64 * 1024;
const MAX_WORKSPACE_EDITABLE_MESSAGE_BYTES: usize = 2 * 1024 * 1024;
// Must clear what capture itself is willing to keep, or a replay of a perfectly
// ordinary large response is rejected and every later workspace save fails with
// it. `body_preview_bytes` defaults to 10 MB and a binary body is stored base64,
// which costs a third more again, so 4 MB rejected responses the app had already
// captured in full.
const MAX_WORKSPACE_EMBEDDED_RECORD_BYTES: usize = 16 * 1024 * 1024;
const MAX_WORKSPACE_STORED_BYTES: usize = MAX_WORKSPACE_SERIALIZED_BYTES;
const MAX_WORKSPACE_CLIENT_ID_BYTES: usize = 128;
const MAX_WORKSPACE_REPLAY_TAB_ID_BYTES: usize = 128;
const MAX_WORKSPACE_REPLAY_TAB_TYPE_BYTES: usize = 32;
const MAX_WORKSPACE_REPLAY_ACTIVE_TAB_ID_BYTES: usize = 128;
const MAX_WORKSPACE_REPLAY_TARGET_FIELD_BYTES: usize = 4 * 1024;
const MAX_SEQUENCE_STEPS: usize = 250;
const MAX_SEQUENCE_EXTRACTIONS_PER_STEP: usize = 50;
const MAX_SEQUENCE_TEXT_FIELD_BYTES: usize = 64 * 1024;
const MAX_SEQUENCE_DEFINITION_BYTES: usize = 8 * 1024 * 1024;
const MAX_SCANNER_CUSTOM_RULES: usize = crate::scanner::MAX_SCANNER_CUSTOM_RULES;
const MAX_SCANNER_FIELD_BYTES: usize = crate::scanner::MAX_SCANNER_FIELD_BYTES;
const MAX_SCANNER_CONFIG_BYTES: usize = crate::scanner::MAX_SCANNER_CONFIG_BYTES;
const MAX_MATCH_REPLACE_RULES: usize = crate::match_replace::MAX_MATCH_REPLACE_RULES;
const MAX_MATCH_REPLACE_FIELD_BYTES: usize = crate::match_replace::MAX_MATCH_REPLACE_FIELD_BYTES;
const MAX_MATCH_REPLACE_RULES_BYTES: usize = crate::match_replace::MAX_MATCH_REPLACE_RULES_BYTES;
const MAX_ANNOTATION_NOTE_BYTES: usize = 32 * 1024;
const MAX_WS_REPLAY_OUTBOUND_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
const ALLOWED_COLOR_TAGS: &[&str] = &["red", "orange", "yellow", "green", "blue", "purple"];
const DEFAULT_WEBSOCKET_DETAIL_FRAME_LIMIT: usize = 1_000;
const MAX_WEBSOCKET_DETAIL_FRAME_LIMIT: usize = 1_000;
const OPEN_PATH: &str = "/usr/bin/open";
const REMOTE_UI_SESSION_COOKIE: &str = "sniper_ui_session";
const REMOTE_UI_TOKEN_BYTES: usize = 32;
const REMOTE_UI_TOKEN_FILE: &str = "remote-ui-token";

#[derive(Clone, Default)]
struct UiAccessControl {
    remote: Option<Arc<RemoteUiAuth>>,
    same_host_ips: Arc<HashSet<IpAddr>>,
}

struct RemoteUiAuth {
    bootstrap_token: Mutex<Option<String>>,
    session_token: String,
}

impl UiAccessControl {
    fn for_listener(addr: SocketAddr) -> Self {
        if addr.ip().is_loopback() {
            return Self::default();
        }
        let mut same_host_ips: HashSet<IpAddr> = proxy::local_interface_ips().into_iter().collect();
        if !addr.ip().is_unspecified() {
            same_host_ips.insert(addr.ip());
        }
        Self {
            remote: Some(Arc::new(RemoteUiAuth::new())),
            same_host_ips: Arc::new(same_host_ips),
        }
    }

    fn bootstrap_url(&self, addr: SocketAddr) -> Option<String> {
        let token = self.remote.as_ref()?.bootstrap_token_for_log()?;
        Some(format!("http://{addr}/?token={token}"))
    }

    fn peer_is_same_host(&self, peer: SocketAddr) -> bool {
        peer.ip().is_loopback() || self.same_host_ips.contains(&peer.ip())
    }
}

impl RemoteUiAuth {
    fn new() -> Self {
        Self {
            bootstrap_token: Mutex::new(Some(random_remote_ui_token())),
            session_token: random_remote_ui_token(),
        }
    }

    fn bootstrap_token_for_log(&self) -> Option<String> {
        self.bootstrap_token
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn redeem_bootstrap_token(&self, candidate: &str) -> bool {
        let mut token = self
            .bootstrap_token
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if token
            .as_deref()
            .is_some_and(|expected| constant_time_token_eq(expected, candidate))
        {
            token.take();
            true
        } else {
            false
        }
    }

    fn has_session_cookie(&self, headers: &HeaderMap) -> bool {
        headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(';'))
            .filter_map(|cookie| cookie.trim().split_once('='))
            .any(|(name, value)| {
                name == REMOTE_UI_SESSION_COOKIE
                    && constant_time_token_eq(&self.session_token, value)
            })
    }
}

#[derive(Clone, Copy)]
struct AuthorizedNonLoopbackUiRequest;

fn random_remote_ui_token() -> String {
    let mut bytes = [0_u8; REMOTE_UI_TOKEN_BYTES];
    OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn constant_time_token_eq(expected: &str, candidate: &str) -> bool {
    let expected = expected.as_bytes();
    let candidate = candidate.as_bytes();
    let mut difference = expected.len() ^ candidate.len();
    for (index, expected_byte) in expected.iter().enumerate() {
        difference |= usize::from(*expected_byte ^ candidate.get(index).copied().unwrap_or(0));
    }
    difference == 0
}

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
    let ui_addr = listener
        .local_addr()
        .context("failed to read bound UI listener address")?;
    let advertised_ui_addr = runtime_state::advertise_local_api_addr(ui_addr);
    // From the bound address, not the advertised one: a wildcard bind is advertised
    // as 127.0.0.1, and reading exposure from that reports "local" for the one bind
    // that is reachable from the network.
    state.set_remote_ui_exposed_from_bound_addr(ui_addr);
    state.set_active_ui_addr(advertised_ui_addr).await;
    if let Err(error) = persist_bound_runtime_state(&state, advertised_ui_addr).await {
        tracing::warn!(?error, "failed to persist runtime-state.json");
    }
    let app = router_for_ui_addr(state.clone(), ui_addr);
    tracing::info!(ui_addr = %ui_addr, advertised_ui_addr = %advertised_ui_addr, "ui listener ready");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("ui server stopped unexpectedly")
}

async fn persist_bound_runtime_state(
    state: &Arc<AppState>,
    ui_addr: std::net::SocketAddr,
) -> Result<()> {
    runtime_state::persist_runtime_state(
        &state.config.data_dir,
        &RuntimeStateSnapshot::with_proxy_status_and_instance(
            state.get_active_proxy_addr().await,
            ui_addr,
            state.is_proxy_online(),
            state.runtime_instance_id,
        ),
    )
}

pub fn router(state: Arc<AppState>) -> Router {
    let ui_addr = state.config.ui_addr;
    router_for_ui_addr(state, ui_addr)
}

fn router_for_ui_addr(state: Arc<AppState>, ui_addr: SocketAddr) -> Router {
    let access_control = UiAccessControl::for_listener(ui_addr);
    if let Some(auth_url) = access_control.bootstrap_url(ui_addr) {
        announce_remote_ui_exposure(&state.config.data_dir, ui_addr, &auth_url);
    }
    router_with_access_control(state, access_control)
}

/// Tell the operator, on stdout, that the UI is no longer local — and hand over the
/// one-time token without putting it through `tracing`.
///
/// The token is a live credential. `tracing` output is stdout today, but a service
/// manager captures stdout to a journal and any future log layer would ship it, so
/// the token only goes to a terminal a person is actually looking at. With no
/// terminal it goes to a private file instead and only the path is announced.
fn announce_remote_ui_exposure(data_dir: &std::path::Path, ui_addr: SocketAddr, auth_url: &str) {
    let host_hint = if ui_addr.ip().is_unspecified() {
        format!(
            "\n  The listener is on every interface. Replace the wildcard host in the\n  URL below with this machine's reachable address."
        )
    } else {
        String::new()
    };
    eprintln!(
        "\n================================ SNIPER =================================\n  The Sniper UI is listening on {ui_addr}, which is NOT loopback.\n  It is reachable from the network, and it is served over plain HTTP.\n\n  Anyone who can reach this port and observe the network can read every\n  request this session has captured, including cookies and tokens.\n  Across an untrusted network, use an SSH tunnel or a TLS reverse proxy\n  instead of exposing this listener directly.{host_hint}\n========================================================================="
    );

    match remote_ui_token_delivery(data_dir, auth_url) {
        RemoteUiTokenDelivery::Terminal => {
            eprintln!("\n  Open this one-time URL to sign in:\n\n    {auth_url}\n");
        }
        RemoteUiTokenDelivery::File(path) => {
            eprintln!(
                "\n  No terminal attached, so the one-time URL was written to:\n\n    {}\n\n  It is readable only by this user. Restart Sniper to issue a new one.\n",
                path.display()
            );
        }
        RemoteUiTokenDelivery::Failed(error) => {
            // Falling back to stdout beats leaving the operator unable to sign in.
            eprintln!(
                "\n  Could not write the one-time URL to a file ({error}).\n  Open this URL to sign in:\n\n    {auth_url}\n"
            );
        }
    }
}

enum RemoteUiTokenDelivery {
    Terminal,
    File(PathBuf),
    Failed(String),
}

fn remote_ui_token_delivery(data_dir: &std::path::Path, auth_url: &str) -> RemoteUiTokenDelivery {
    if std::io::stderr().is_terminal() {
        return RemoteUiTokenDelivery::Terminal;
    }
    let path = data_dir.join(REMOTE_UI_TOKEN_FILE);
    match write_remote_ui_token_file(&path, auth_url) {
        Ok(()) => RemoteUiTokenDelivery::File(path),
        Err(error) => RemoteUiTokenDelivery::Failed(format!("{error:#}")),
    }
}

fn write_remote_ui_token_file(path: &std::path::Path, auth_url: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    use std::io::Write as _;
    writeln!(file, "{auth_url}").with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn router_with_access_control(state: Arc<AppState>, access_control: UiAccessControl) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/decoder", get(decoder_index))
        .route("/decoder/", get(decoder_index))
        .route("/decoder/*path", get(decoder_asset))
        .route("/app.js", get(app_js))
        .route("/codemirror.js", get(codemirror_js))
        .route("/styles.css", get(styles_css))
        .route("/favicon.svg", get(favicon_svg))
        .route("/logo.svg", get(logo_svg))
        .route("/fonts/Bungee-Regular.ttf", get(bungee_font))
        .route("/api/settings", get(get_settings))
        .route("/api/app-version", get(get_app_version))
        .route("/api/self-update", post(self_update))
        .route("/api/sessions", get(list_sessions).post(create_session))
        .route("/api/sessions/:id/activate", post(activate_session))
        .route("/api/sessions/:id", delete(delete_session))
        .route("/api/sessions/:id/reveal", post(reveal_session_folder))
        .route(
            "/api/runtime",
            get(get_runtime_settings).post(update_runtime_settings),
        )
        .route(
            "/api/workspace-state",
            get(get_workspace_state).post(update_workspace_state),
        )
        .route(
            "/api/workspace-state/keepalive",
            post(update_workspace_state_keepalive),
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
        .route("/api/certificates/reveal", post(reveal_certificate_folder))
        .route(
            "/api/match-replace",
            get(list_match_replace_rules).post(update_match_replace_rules),
        )
        .route("/api/findings", get(list_findings))
        .route("/api/findings/count", get(count_findings))
        .route("/api/findings/:id", get(get_finding))
        .route("/api/findings/clear", post(clear_findings))
        .route(
            "/api/scanner-config",
            get(get_scanner_config).post(update_scanner_config),
        )
        .route("/api/oast/callbacks", get(list_oast_callbacks))
        .route("/api/oast/callbacks/:id", get(get_oast_callback))
        .route("/api/oast/callbacks/clear", post(clear_oast_callbacks))
        .route("/api/oast/generate", post(generate_oast_payload))
        .route("/api/oast/status", get(oast_status))
        .route("/api/target/site-map", get(get_target_site_map))
        .route("/api/transactions", get(list_transactions))
        .route("/api/transactions-page", get(list_transactions_page))
        .route("/api/transactions/:id", get(get_transaction))
        .route(
            "/api/transactions/:id/annotations",
            patch(update_transaction_annotations),
        )
        .route("/api/intercepts", get(list_intercepts))
        .route("/api/intercepts/forward-all", post(forward_all_intercepts))
        .route("/api/intercepts/:id", get(get_intercept))
        .route("/api/intercepts/:id/forward", post(forward_intercept))
        .route("/api/intercepts/:id/drop", post(drop_intercept))
        .route(
            "/api/intercept-rules",
            get(list_intercept_rules).post(upsert_intercept_rule),
        )
        .route("/api/intercept-rules/:id", delete(delete_intercept_rule))
        .route("/api/response-intercepts", get(list_response_intercepts))
        .route(
            "/api/response-intercepts/forward-all",
            post(forward_all_response_intercepts),
        )
        .route("/api/response-intercepts/:id", get(get_response_intercept))
        .route(
            "/api/response-intercepts/:id/forward",
            post(forward_response_intercept),
        )
        .route(
            "/api/response-intercepts/:id/drop",
            post(drop_response_intercept),
        )
        .route("/api/replay/send", post(send_replay))
        .route(
            "/api/fuzzer/attacks",
            get(list_fuzzer_attacks).post(run_fuzzer_attack),
        )
        .route("/api/fuzzer/attacks/:id", get(get_fuzzer_attack))
        .route("/api/sequences", get(list_sequences).post(upsert_sequence))
        .route(
            "/api/sequences/:id",
            get(get_sequence).delete(delete_sequence),
        )
        .route("/api/sequences/:id/run", post(run_sequence))
        .route("/api/sequence-runs", get(list_sequence_runs))
        .route("/api/sequence-runs/:id", get(get_sequence_run))
        .route("/api/websockets", get(list_websockets))
        .route("/api/websockets-page", get(list_websockets_page))
        .route("/api/websockets/:id", get(get_websocket))
        .route("/api/replay/ws-connect", post(ws_replay_connect))
        .route("/api/replay/ws-send", post(ws_replay_send))
        .route("/api/replay/ws-disconnect", post(ws_replay_disconnect))
        .route("/api/replay/ws-snapshot/:id", get(ws_replay_snapshot))
        .route("/api/replay/ws-frames/:id", get(ws_replay_frames))
        .route("/api/events", get(events))
        .fallback(any(spa_or_api_not_found))
        .layer(middleware::from_fn(local_api_write_guard))
        .layer(middleware::from_fn_with_state(
            access_control,
            remote_ui_auth_guard,
        ))
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024 * 1024)) // 64 MB
        .with_state(state)
}

async fn remote_ui_auth_guard(
    State(access_control): State<UiAccessControl>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(auth) = access_control.remote.as_ref() else {
        return next.run(request).await;
    };
    let bootstrap_query = (request.method() == Method::GET && request.uri().path() == "/")
        .then(|| bootstrap_token_query(request.uri()));
    if let Some(Ok(Some(token))) = bootstrap_query.as_ref() {
        if auth.redeem_bootstrap_token(token) {
            return remote_ui_auth_redirect(Some(&auth.session_token));
        }
    }
    let token_was_supplied = matches!(bootstrap_query.as_ref(), Some(Ok(Some(_))) | Some(Err(())));
    if request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .is_some_and(|peer| access_control.peer_is_same_host(peer.0))
    {
        if token_was_supplied {
            return remote_ui_auth_redirect(None);
        }
        request
            .extensions_mut()
            .insert(AuthorizedNonLoopbackUiRequest);
        return next.run(request).await;
    }

    let has_session = auth.has_session_cookie(request.headers());
    if token_was_supplied {
        if has_session {
            return remote_ui_auth_redirect(None);
        }
        return remote_ui_unauthorized();
    }

    if !has_session {
        return remote_ui_unauthorized();
    }
    request
        .extensions_mut()
        .insert(AuthorizedNonLoopbackUiRequest);
    next.run(request).await
}

fn bootstrap_token_query(uri: &Uri) -> std::result::Result<Option<String>, ()> {
    let Some(query) = uri.query() else {
        return Ok(None);
    };
    let mut tokens = url::form_urlencoded::parse(query.as_bytes())
        .filter(|(name, _)| name == "token")
        .map(|(_, value)| value.into_owned());
    let Some(token) = tokens.next() else {
        return Ok(None);
    };
    if tokens.next().is_some() {
        return Err(());
    }
    Ok(Some(token))
}

fn remote_ui_auth_redirect(session_token: Option<&str>) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    response
        .headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static("/"));
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    if let Some(session_token) = session_token {
        let cookie = format!(
            "{REMOTE_UI_SESSION_COOKIE}={session_token}; Path=/; HttpOnly; SameSite=Strict"
        );
        response.headers_mut().insert(
            header::SET_COOKIE,
            HeaderValue::from_str(&cookie)
                .expect("random UI session token should be a valid cookie"),
        );
    }
    response
}

fn remote_ui_unauthorized() -> Response {
    let mut response = (
        StatusCode::UNAUTHORIZED,
        "Remote Sniper UI authentication required. Open the one-time URL printed by the Sniper process.",
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn local_api_write_guard(request: Request, next: Next) -> Response {
    if is_api_path(request.uri().path()) {
        if request
            .extensions()
            .get::<AuthorizedNonLoopbackUiRequest>()
            .is_none()
            && !request_host_is_allowed_local_api(request.headers(), request.uri())
        {
            return (
                StatusCode::FORBIDDEN,
                "requests to the local Sniper API must use a loopback Host",
            )
                .into_response();
        }
        if !matches!(
            *request.method(),
            Method::GET | Method::HEAD | Method::OPTIONS
        ) && !is_allowed_browser_write(request.headers(), request.uri())
        {
            return (
                StatusCode::FORBIDDEN,
                "cross-origin writes to the local Sniper API are blocked",
            )
                .into_response();
        }
    }
    next.run(request).await
}

async fn spa_or_api_not_found(request: Request) -> Response {
    if is_api_path(request.uri().path()) {
        return (StatusCode::NOT_FOUND, "API endpoint not found").into_response();
    }
    if !matches!(*request.method(), Method::GET | Method::HEAD) {
        return (StatusCode::NOT_FOUND, "Route not found").into_response();
    }
    index().await.into_response()
}

fn is_api_path(path: &str) -> bool {
    path == "/api" || path.starts_with("/api/")
}

fn request_host_is_allowed_local_api(headers: &HeaderMap, uri: &Uri) -> bool {
    let Some(authority) = request_authority(headers, uri) else {
        return false;
    };
    let Some(host) = host_from_request_authority(&authority) else {
        return false;
    };
    host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

fn host_from_request_authority(authority: &str) -> Option<String> {
    let authority = authority.trim();
    if authority.is_empty() {
        return None;
    }
    if authority.contains('@') {
        return None;
    }
    if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, rest) = bracketed.split_once(']')?;
        if host.is_empty() || rest.contains(']') {
            return None;
        }
        if !rest.is_empty() {
            let port = rest.strip_prefix(':')?;
            if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
        }
    } else if authority.matches(':').count() > 1 {
        return None;
    } else if let Some((host, port)) = authority.split_once(':') {
        if host.is_empty() || port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
    }

    let parsed = authority.parse::<Authority>().ok()?;
    let host = parsed
        .host()
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or_else(|| parsed.host())
        .to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

fn is_allowed_browser_write(headers: &HeaderMap, uri: &Uri) -> bool {
    if request_has_cross_site_fetch_metadata(headers) {
        return false;
    }
    if let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    {
        return request_origin_matches(origin, headers, uri);
    }
    if let Some(referer) = headers
        .get(header::REFERER)
        .and_then(|value| value.to_str().ok())
    {
        return request_origin_matches(referer, headers, uri);
    }
    true
}

fn request_has_cross_site_fetch_metadata(headers: &HeaderMap) -> bool {
    headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("cross-site"))
}

fn request_origin_matches(origin: &str, headers: &HeaderMap, uri: &Uri) -> bool {
    let Some(request_authority) = request_authority(headers, uri) else {
        return false;
    };
    let Ok(parsed) = url::Url::parse(origin) else {
        return false;
    };
    let Some(origin_host) = parsed.host_str() else {
        return false;
    };
    let origin_scheme = parsed.scheme();
    if origin_scheme != "http" && origin_scheme != "https" {
        return false;
    }
    let origin_port = parsed
        .port()
        .unwrap_or(if origin_scheme == "https" { 443 } else { 80 });
    let origin_authority = format_authority_for_origin(origin_host, origin_port, origin_scheme);
    authorities_equivalent_for_origin(&request_authority, &origin_authority, origin_scheme)
}

fn request_authority(headers: &HeaderMap, uri: &Uri) -> Option<String> {
    let uri_authority = uri.authority().map(|authority| authority.as_str());
    let host_authority = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok());
    match (uri_authority, host_authority) {
        (Some(uri_authority), Some(host_authority)) => {
            let scheme = uri.scheme_str().unwrap_or("http");
            authorities_equivalent_for_origin(uri_authority, host_authority, scheme)
                .then(|| host_authority.to_string())
        }
        (Some(uri_authority), None) => Some(uri_authority.to_string()),
        (None, Some(host_authority)) => Some(host_authority.to_string()),
        (None, None) => None,
    }
}

fn format_authority_for_origin(host: &str, port: u16, scheme: &str) -> String {
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if (scheme == "https" && port == 443) || (scheme == "http" && port == 80) {
        host
    } else {
        format!("{host}:{port}")
    }
}

fn authorities_equivalent_for_origin(left: &str, right: &str, scheme: &str) -> bool {
    let left = authority_to_origin_parts(left, scheme);
    let right = authority_to_origin_parts(right, scheme);
    left == right
}

fn authority_to_origin_parts(authority: &str, scheme: &str) -> Option<(String, u16)> {
    if authority.contains('@') {
        return None;
    }
    let parsed = url::Url::parse(&format!("{scheme}://{authority}")).ok()?;
    let host = parsed.host_str()?.to_ascii_lowercase();
    let port = parsed
        .port()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });
    Some((host, port))
}

#[derive(Debug, Default, Deserialize)]
struct TransactionQuery {
    session_id: Option<Uuid>,
    q: Option<String>,
    method: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
    before_sequence: Option<u64>,
    sort_key: Option<String>,
    sort_direction: Option<String>,
    in_scope_only: Option<bool>,
    hide_without_responses: Option<bool>,
    only_parameterized: Option<bool>,
    only_notes: Option<bool>,
    status_classes: Option<String>,
    mime_types: Option<String>,
    hidden_extensions: Option<String>,
    port: Option<String>,
    color_tags: Option<String>,
    advanced_search: Option<String>,
    advanced_regex: Option<bool>,
    advanced_case_sensitive: Option<bool>,
    advanced_negative: Option<bool>,
    hide_connect: Option<bool>,
    host: Option<String>,
    status: Option<u16>,
    status_range: Option<String>,
    since: Option<String>,
    mime: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TransactionGetQuery {
    session_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
struct WorkspaceStateQuery {
    session_id: Option<Uuid>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TransactionPageResponse {
    items: Vec<crate::model::TransactionSummary>,
    total: usize,
    filtered_total: Option<usize>,
    hidden_connect_total: Option<usize>,
    offset: usize,
    limit: usize,
    has_more: bool,
}

fn csv_param(value: Option<String>) -> Vec<String> {
    value
        .unwrap_or_default()
        .split(',')
        .map(|item| item.trim().to_ascii_lowercase())
        .filter(|item| !item.is_empty())
        .collect()
}

fn optional_csv_param(value: Option<String>) -> Option<Vec<String>> {
    value.and_then(|raw| {
        let values: Vec<String> = raw
            .split(',')
            .map(|item| item.trim().to_ascii_lowercase())
            .filter(|item| !item.is_empty())
            .collect();
        (!values.is_empty()).then_some(values)
    })
}

fn transaction_list_filters(
    query: TransactionQuery,
    scope_patterns: Vec<String>,
    excluded_scope_patterns: Vec<String>,
) -> ListFilters {
    ListFilters {
        query: query.q,
        method: query.method,
        limit: query.limit,
        offset: query.offset,
        before_sequence: query.before_sequence,
        sort_key: query.sort_key,
        sort_direction: normalize_sort_direction(query.sort_direction.as_deref()),
        scope_patterns,
        excluded_scope_patterns,
        in_scope_only: query.in_scope_only.unwrap_or(false),
        hide_connect: query.hide_connect.unwrap_or(false),
        hide_without_responses: query.hide_without_responses.unwrap_or(false),
        only_parameterized: query.only_parameterized.unwrap_or(false),
        only_notes: query.only_notes.unwrap_or(false),
        status_classes: optional_csv_param(query.status_classes),
        mime_types: optional_csv_param(query.mime_types),
        hidden_extensions: csv_param(query.hidden_extensions),
        host: query.host,
        status: query.status,
        status_range: query.status_range,
        since: query.since,
        mime: query.mime,
        port: query.port,
        color_tags: csv_param(query.color_tags),
        advanced_search: query.advanced_search,
        advanced_regex: query.advanced_regex.unwrap_or(false),
        advanced_case_sensitive: query.advanced_case_sensitive.unwrap_or(false),
        advanced_negative: query.advanced_negative.unwrap_or(false),
    }
}

fn websocket_list_filters(
    query: &WebSocketQuery,
    scope_patterns: Vec<String>,
    excluded_scope_patterns: Vec<String>,
) -> WebSocketListFilters {
    WebSocketListFilters {
        query: query.q.clone(),
        limit: query.limit,
        offset: query.offset,
        after_id: query.after_id,
        sort_key: query.sort_key.clone(),
        sort_direction: normalize_sort_direction(query.sort_direction.as_deref()),
        scope_patterns,
        excluded_scope_patterns,
        in_scope_only: query.in_scope_only.unwrap_or(false),
        live_only: query.live_only.unwrap_or(false),
    }
}

fn validate_transaction_query(query: &TransactionQuery) -> std::result::Result<(), String> {
    validate_optional_limit(query.limit)?;
    validate_sort_direction(query.sort_direction.as_deref())?;
    validate_transaction_sort_key(query.sort_key.as_deref())?;
    validate_transaction_cursor_sort(query)?;

    if let Some(value) = query.status_range.as_deref() {
        validate_status_range(value)
            .ok_or_else(|| format!("invalid status_range filter: {value}"))?;
    }
    if let Some(status) = query.status {
        validate_status_code(status).ok_or_else(|| format!("invalid status filter: {status}"))?;
    }

    if let Some(value) = query.since.as_deref() {
        validate_since(value).ok_or_else(|| format!("invalid since filter: {value}"))?;
    }

    if query.advanced_regex.unwrap_or(false) {
        if let Some(term) = query.advanced_search.as_deref().map(str::trim) {
            if !term.is_empty() {
                RegexBuilder::new(term)
                    .case_insensitive(!query.advanced_case_sensitive.unwrap_or(false))
                    .build()
                    .map_err(|error| format!("invalid advanced_search regex: {error}"))?;
            }
        }
    }

    Ok(())
}

fn validate_transaction_sort_key(sort_key: Option<&str>) -> std::result::Result<(), String> {
    let Some(sort_key) = sort_key.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    match sort_key {
        "index" | "host" | "method" | "path" | "status" | "length" | "mime" | "notes" | "tls"
        | "edited" | "started_at" => Ok(()),
        _ => Err(format!("invalid transaction sort_key: {sort_key}")),
    }
}

fn validate_transaction_cursor_sort(query: &TransactionQuery) -> std::result::Result<(), String> {
    if query.before_sequence.is_none() {
        return Ok(());
    }

    if query.offset.is_some() {
        return Err("before_sequence cannot be combined with offset".to_string());
    }

    let sort_key = query
        .sort_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("index");
    let sort_direction = normalize_sort_direction(query.sort_direction.as_deref())
        .unwrap_or_else(|| "desc".to_string());
    if sort_key != "index" || sort_direction != "desc" {
        return Err("before_sequence requires sort_key=index and sort_direction=desc".to_string());
    }

    Ok(())
}

fn validate_websocket_query(query: &WebSocketQuery) -> std::result::Result<(), String> {
    validate_optional_limit(query.limit)?;
    validate_sort_direction(query.sort_direction.as_deref())?;
    validate_websocket_sort_key(query.sort_key.as_deref())
}

fn validate_websocket_sort_key(sort_key: Option<&str>) -> std::result::Result<(), String> {
    let Some(sort_key) = sort_key.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    match sort_key {
        "index" | "host" | "path" | "status" | "frame_count" | "duration_ms" | "started_at" => {
            Ok(())
        }
        _ => Err(format!("invalid websocket sort_key: {sort_key}")),
    }
}

fn validate_sort_direction(direction: Option<&str>) -> std::result::Result<(), String> {
    let Some(direction) = direction.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    match direction.to_ascii_lowercase().as_str() {
        "asc" | "desc" => Ok(()),
        _ => Err(format!("invalid sort_direction: {direction}")),
    }
}

fn normalize_sort_direction(direction: Option<&str>) -> Option<String> {
    direction
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
}

fn validate_status_code(status: u16) -> Option<()> {
    (100..=599).contains(&status).then_some(())
}

fn validate_optional_limit(limit: Option<usize>) -> std::result::Result<(), String> {
    if limit == Some(0) {
        return Err("limit must be greater than zero".to_string());
    }
    Ok(())
}

fn validate_status_range(input: &str) -> Option<()> {
    let trimmed = input.trim();
    if trimmed.len() == 3 && trimmed.ends_with("xx") {
        let class = trimmed[..1].parse::<u16>().ok()?;
        return (1..=5).contains(&class).then_some(());
    }
    let (low, high) = trimmed.split_once('-')?;
    let low = low.trim().parse::<u16>().ok()?;
    let high = high.trim().parse::<u16>().ok()?;
    (low <= high && (100..=599).contains(&low) && (100..=599).contains(&high)).then_some(())
}

fn validate_since(input: &str) -> Option<()> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    for suffix in ['h', 'm', 'd', 's'] {
        if let Some(value) = trimmed.strip_suffix(suffix) {
            return value
                .parse::<i64>()
                .ok()
                .filter(|value| *value > 0)
                .map(|_| ());
        }
    }
    if chrono::NaiveDate::parse_from_str(trimmed, "%Y-%m-%d").is_ok() {
        return Some(());
    }
    chrono::DateTime::parse_from_rfc3339(trimmed)
        .ok()
        .map(|_| ())
}

pub(crate) fn validate_editable_request(
    request: &EditableRequest,
) -> std::result::Result<(), String> {
    validate_http_scheme_field(&request.scheme, "request scheme")?;
    validate_editable_request_host(&request.host)?;
    validate_editable_request_path(&request.path)?;
    validate_http_method(&request.method)?;
    for header in &request.headers {
        validate_editable_header(header)?;
    }
    validate_unique_host_header(&request.headers)?;
    let body = request
        .try_body_bytes()
        .map_err(|_| "request body is not valid base64".to_string())?;
    validate_editable_body_framing(&request.headers, body.len(), false)
}

pub(crate) fn validate_runnable_editable_request(
    request: &EditableRequest,
) -> std::result::Result<(), String> {
    validate_editable_request(request)?;
    if request.preview_truncated {
        return Err("request body preview is truncated and cannot be replayed safely".to_string());
    }
    Ok(())
}

fn validate_http_scheme_field(scheme: &str, label: &str) -> std::result::Result<(), String> {
    let trimmed = scheme.trim();
    if trimmed != scheme {
        return Err(format!("{label} must not include surrounding whitespace"));
    }
    if !matches!(trimmed, "http" | "https") {
        return Err(format!("unsupported {label}: {scheme}"));
    }
    Ok(())
}

fn validate_editable_request_host(host: &str) -> std::result::Result<(), String> {
    let trimmed = host.trim();
    if trimmed != host {
        return Err("request host must not include surrounding whitespace".to_string());
    }
    if trimmed.is_empty() {
        return Err("request host is required".to_string());
    }
    if trimmed.chars().any(char::is_whitespace)
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains('@')
        || trimmed.contains('?')
        || trimmed.contains('#')
    {
        return Err(format!("invalid request host: {host}"));
    }
    if trimmed.starts_with('[') {
        let Some(end) = trimmed.find(']') else {
            return Err(format!("invalid request host: {host}"));
        };
        let inner = &trimmed[1..end];
        inner
            .parse::<IpAddr>()
            .map_err(|_| format!("invalid request host: {host}"))?;
        let suffix = &trimmed[end + 1..];
        if suffix.is_empty() {
            return Ok(());
        }
        let Some(port) = suffix.strip_prefix(':') else {
            return Err(format!("invalid request host: {host}"));
        };
        validate_port_text(port, "request host port")?;
        return Ok(());
    }
    if trimmed.contains(':') && trimmed.parse::<IpAddr>().is_ok() {
        return Err("IPv6 request hosts must be bracketed".to_string());
    }
    if trimmed.contains(':') {
        if trimmed.matches(':').count() != 1 {
            return Err("request host must not include multiple port separators".to_string());
        }
        let Some((host_part, port_part)) = trimmed.rsplit_once(':') else {
            return Err(format!("invalid request host: {host}"));
        };
        if host_part.is_empty() {
            return Err(format!("invalid request host: {host}"));
        }
        validate_port_text(port_part, "request host port")?;
    }
    Ok(())
}

fn validate_editable_request_path(path: &str) -> std::result::Result<(), String> {
    if path.is_empty() {
        return Err("request path is required".to_string());
    }
    if path.chars().any(|ch| ch.is_control() || ch.is_whitespace()) {
        return Err(format!("invalid request path: {path}"));
    }
    if path.contains('#') {
        return Err("request path must not include a fragment".to_string());
    }
    if path != "*" && !path.starts_with('/') {
        return Err("request path must start with '/'".to_string());
    }
    if path != "*" {
        path.parse::<PathAndQuery>()
            .map_err(|_| format!("invalid request path: {path}"))?;
    }
    Ok(())
}

fn validate_http_method(method: &str) -> std::result::Result<(), String> {
    let raw_method = method;
    let method = raw_method.trim();
    if method != raw_method {
        return Err("request method must not include surrounding whitespace".to_string());
    }
    if method.is_empty() {
        return Err("request method is required".to_string());
    }
    if method.eq_ignore_ascii_case("CONNECT") {
        return Err("CONNECT requests are not supported by Replay".to_string());
    }
    if !method.bytes().all(is_http_token_byte) {
        return Err(format!("invalid request method: {method}"));
    }
    Ok(())
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

#[cfg(test)]
fn validate_editable_response(response: &EditableResponse) -> std::result::Result<(), String> {
    validate_editable_response_for_request_method(response, "GET")
}

fn validate_editable_response_for_request_method(
    response: &EditableResponse,
    request_method: &str,
) -> std::result::Result<(), String> {
    if !(100..=599).contains(&response.status) {
        return Err(format!("invalid response status: {}", response.status));
    }
    for header in &response.headers {
        validate_editable_header(header)?;
    }
    let body = response
        .try_body_bytes()
        .map_err(|_| "response body is not valid base64".to_string())?;
    if response_must_not_include_body(response.status, request_method) && !body.is_empty() {
        return Err(format!(
            "response status {} must not include a body",
            response.status
        ));
    }
    validate_editable_body_framing(
        &response.headers,
        body.len(),
        response_content_length_may_describe_representation(response.status, request_method),
    )
}

fn response_status_must_not_include_body(status: u16) -> bool {
    status < 200 || status == 204 || status == 205 || status == 304
}

fn response_must_not_include_body(status: u16, request_method: &str) -> bool {
    response_status_must_not_include_body(status) || request_method.eq_ignore_ascii_case("HEAD")
}

fn response_content_length_may_describe_representation(status: u16, request_method: &str) -> bool {
    status == 304
        || (request_method.eq_ignore_ascii_case("HEAD") && !matches!(status, 100..=199 | 204 | 205))
}

fn canonicalize_intercept_forward_request(
    mut request: EditableRequest,
) -> std::result::Result<EditableRequest, String> {
    let body = request
        .try_body_bytes()
        .map_err(|_| "request body is not valid base64".to_string())?;
    canonicalize_plain_chunked_transfer_encoding(&mut request.headers, body.len())?;
    validate_editable_request(&request)?;
    Ok(request)
}

fn canonicalize_intercept_forward_response(
    mut response: EditableResponse,
    request_method: &str,
) -> std::result::Result<EditableResponse, String> {
    let body = response
        .try_body_bytes()
        .map_err(|_| "response body is not valid base64".to_string())?;
    canonicalize_plain_chunked_transfer_encoding(&mut response.headers, body.len())?;
    validate_editable_response_for_request_method(&response, request_method)?;
    Ok(response)
}

fn canonicalize_plain_chunked_transfer_encoding(
    headers: &mut Vec<HeaderRecord>,
    body_len: usize,
) -> std::result::Result<(), String> {
    let codings = editable_transfer_encoding_tokens(headers)?;
    if codings.is_empty() {
        return Ok(());
    }
    if codings.len() != 1 || !codings[0].eq_ignore_ascii_case("chunked") {
        return Err(format!(
            "unsupported Transfer-Encoding chain for editable message: {}",
            codings.join(", ")
        ));
    }

    headers.retain(|header| {
        !header.name.eq_ignore_ascii_case("transfer-encoding")
            && !header.name.eq_ignore_ascii_case("content-length")
    });
    headers.push(HeaderRecord {
        name: header::CONTENT_LENGTH.as_str().to_string(),
        value: body_len.to_string(),
    });
    Ok(())
}

fn editable_transfer_encoding_tokens(
    headers: &[HeaderRecord],
) -> std::result::Result<Vec<String>, String> {
    let mut codings = Vec::new();
    for header in headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("transfer-encoding"))
    {
        HeaderValue::from_str(&header.value)
            .map_err(|_| "invalid Transfer-Encoding header".to_string())?;
        codings.extend(
            header
                .value
                .split(',')
                .map(|coding| coding.trim().to_ascii_lowercase())
                .filter(|coding| !coding.is_empty()),
        );
    }
    Ok(codings)
}

fn validate_editable_body_framing(
    headers: &[HeaderRecord],
    body_len: usize,
    allow_representation_content_length: bool,
) -> std::result::Result<(), String> {
    if headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("transfer-encoding")
            && header
                .value
                .split(',')
                .any(|value| value.trim().eq_ignore_ascii_case("chunked"))
    }) {
        return Err(
            "Transfer-Encoding: chunked is not supported for editable messages".to_string(),
        );
    }

    let mut content_length: Option<usize> = None;
    for header in headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("content-length"))
    {
        let parsed = header
            .value
            .trim()
            .parse::<usize>()
            .map_err(|_| format!("invalid Content-Length: {}", header.value))?;
        if let Some(previous) = content_length {
            if previous != parsed {
                return Err("conflicting Content-Length headers".to_string());
            }
        }
        content_length = Some(parsed);
    }

    if let Some(expected) = content_length {
        if expected != body_len {
            if allow_representation_content_length && body_len == 0 {
                return Ok(());
            }
            return Err(format!(
                "Content-Length {expected} does not match body length {body_len}"
            ));
        }
    }
    Ok(())
}

fn validate_editable_header(header: &HeaderRecord) -> std::result::Result<(), String> {
    let raw_name = header.name.as_str();
    let name = raw_name.trim();
    if name != raw_name {
        return Err(format!(
            "request header name must not include surrounding whitespace: {}",
            header.name
        ));
    }
    if name.is_empty() {
        return Err("request header name is required".to_string());
    }
    HeaderName::from_bytes(name.as_bytes())
        .map_err(|_| format!("invalid request header name: {}", header.name))?;
    HeaderValue::from_str(&header.value)
        .map_err(|_| format!("invalid request header value for {name}"))?;
    Ok(())
}

fn validate_unique_host_header(headers: &[HeaderRecord]) -> std::result::Result<(), String> {
    let host_count = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("host"))
        .count();
    if host_count > 1 {
        return Err("request must not include multiple Host headers".to_string());
    }
    Ok(())
}

fn validate_request_target_override(
    target: &RequestTargetOverride,
) -> std::result::Result<(), String> {
    validate_workspace_target_fields(&target.scheme, &target.host, &target.port)
}

fn request_has_target_validation_authority(request: &EditableRequest) -> bool {
    !request.scheme.trim().is_empty() && !request.host.trim().is_empty()
}

pub(crate) fn validate_request_target_override_for_request(
    request: &EditableRequest,
    target: &RequestTargetOverride,
) -> std::result::Result<(), String> {
    validate_request_target_override(target)?;
    if target.host.trim().is_empty()
        && target.port.trim().is_empty()
        && target.scheme.trim().is_empty()
    {
        return Ok(());
    }

    let request_scheme = request.scheme.trim();
    validate_http_scheme_field(request_scheme, "request scheme")?;
    let effective_scheme = if target.scheme.trim().is_empty() {
        request_scheme
    } else {
        target.scheme.trim()
    };
    validate_http_scheme_field(effective_scheme, "replay target scheme")?;
    let request_authority = parse_replay_validation_authority(&request.host, request_scheme)
        .map_err(|error| format!("invalid request host for replay target: {error}"))?;
    let target_authority = if target.host.trim().is_empty() {
        None
    } else {
        Some(parse_replay_validation_target_authority(
            target.host.trim(),
            effective_scheme,
        )?)
    };
    let target_port = replay_validation_target_port(
        target.port.trim(),
        effective_scheme,
        target_authority
            .as_ref()
            .and_then(|authority| authority.port)
            .or(request_authority.port),
    )?;
    let request_port = request_authority
        .port
        .unwrap_or(default_replay_validation_port(request_scheme)?);
    let dial_host = target_authority
        .as_ref()
        .map(|authority| authority.host.as_str())
        .unwrap_or(request_authority.host.as_str());
    if effective_scheme.eq_ignore_ascii_case(request_scheme)
        && dial_host.eq_ignore_ascii_case(&request_authority.host)
        && target_port == request_port
    {
        return Ok(());
    }
    if request_authority.host.parse::<IpAddr>().is_ok() {
        return Err(
            "Replay target override is not supported when the request host is an IP address"
                .to_string(),
        );
    }
    Ok(())
}

struct ReplayValidationAuthority {
    host: String,
    port: Option<u16>,
}

fn parse_replay_validation_authority(
    authority: &str,
    scheme: &str,
) -> std::result::Result<ReplayValidationAuthority, String> {
    let parsed = url::Url::parse(&format!("{scheme}://{authority}"))
        .map_err(|_| format!("failed to parse authority {authority}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "authority is missing a valid host".to_string())?
        .to_string();
    Ok(ReplayValidationAuthority {
        host,
        port: parsed.port(),
    })
}

fn parse_replay_validation_target_authority(
    authority: &str,
    scheme: &str,
) -> std::result::Result<ReplayValidationAuthority, String> {
    let normalized = if authority.contains(':')
        && !authority.starts_with('[')
        && authority.parse::<IpAddr>().is_ok()
    {
        format!("[{authority}]")
    } else {
        authority.to_string()
    };
    parse_replay_validation_authority(&normalized, scheme)
}

fn replay_validation_target_port(
    target_port: &str,
    scheme: &str,
    request_port: Option<u16>,
) -> std::result::Result<u16, String> {
    if target_port.is_empty() {
        return Ok(request_port.unwrap_or(default_replay_validation_port(scheme)?));
    }
    let port = target_port
        .parse::<u16>()
        .map_err(|_| format!("invalid replay target port: {target_port}"))?;
    if port == 0 {
        return Err(format!("invalid replay target port: {target_port}"));
    }
    Ok(port)
}

fn default_replay_validation_port(scheme: &str) -> std::result::Result<u16, String> {
    match scheme.to_ascii_lowercase().as_str() {
        "http" => Ok(80),
        "https" => Ok(443),
        other => Err(format!("unsupported replay target scheme: {other}")),
    }
}

fn validate_fuzzer_target_request_authority(
    authority: &str,
    base_request: Option<&EditableRequest>,
) -> std::result::Result<(), String> {
    let parsed = url::Url::parse(authority.trim())
        .map_err(|_| "fuzzer target request authority must be a valid URL".to_string())?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err("fuzzer target request authority scheme must be HTTP or HTTPS".to_string());
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || (parsed.path() != "/" && !parsed.path().is_empty())
    {
        return Err(
            "fuzzer target request authority must not include path, query, fragment, or credentials"
                .to_string(),
        );
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "fuzzer target request authority host is required".to_string())?;
    if let Some(base_request) = base_request {
        if !scheme.eq_ignore_ascii_case(&base_request.scheme) {
            return Err(
                "fuzzer target request authority scheme must match fuzzer base request".to_string(),
            );
        }
        let parsed_port = parsed
            .port()
            .unwrap_or(if scheme == "https" { 443 } else { 80 });
        let parsed_authority = format_authority_for_origin(host, parsed_port, &scheme);
        if !authorities_equivalent_for_origin(
            &parsed_authority,
            &base_request.host,
            &base_request.scheme,
        ) {
            return Err(
                "fuzzer target request authority must match fuzzer base request".to_string(),
            );
        }
    }
    Ok(())
}

pub(crate) fn validate_workspace_state(
    snapshot: &WorkspaceStateSnapshot,
) -> std::result::Result<(), String> {
    validate_workspace_serialized_size(snapshot)?;
    let mut tab_ids = HashSet::new();
    let mut ws_frame_total = 0usize;
    let mut ws_frame_body_total = 0usize;
    let mut stored_bytes_total = 0usize;
    if let Some(client_id) = snapshot.client_id.as_deref() {
        validate_workspace_string_bytes(
            "workspace client id",
            client_id,
            MAX_WORKSPACE_CLIENT_ID_BYTES,
        )?;
    }
    if snapshot.replay.tabs.len() > MAX_WORKSPACE_REPLAY_TABS {
        return Err(format!(
            "workspace has too many replay tabs: {}",
            snapshot.replay.tabs.len()
        ));
    }
    if snapshot.replay.tab_sequence == usize::MAX {
        return Err("replay tab sequence is too large".to_string());
    }
    if let Some(active_tab_id) = snapshot.replay.active_tab_id.as_deref() {
        validate_workspace_string_bytes(
            "active replay tab id",
            active_tab_id,
            MAX_WORKSPACE_REPLAY_ACTIVE_TAB_ID_BYTES,
        )?;
    }
    for tab in &snapshot.replay.tabs {
        if tab.id.trim().is_empty() {
            return Err("replay tab id is required".to_string());
        }
        validate_workspace_string_bytes(
            "replay tab id",
            &tab.id,
            MAX_WORKSPACE_REPLAY_TAB_ID_BYTES,
        )?;
        validate_workspace_string_bytes(
            "replay tab type",
            &tab.tab_type,
            MAX_WORKSPACE_REPLAY_TAB_TYPE_BYTES,
        )?;
        if tab.sequence == usize::MAX {
            return Err(format!("replay tab {} sequence is too large", tab.id));
        }
        if !tab_ids.insert(tab.id.as_str()) {
            return Err(format!("duplicate replay tab id: {}", tab.id));
        }
        if tab.tab_type == "websocket" && Uuid::parse_str(&tab.id).is_err() {
            return Err(format!("websocket replay tab {} id must be a UUID", tab.id));
        }
        if tab.custom_label.chars().count() > 80 {
            return Err(format!("replay tab {} custom label is too long", tab.id));
        }
        let is_websocket_tab = tab.tab_type == "websocket";
        if !is_websocket_tab && replay_tab_has_websocket_payload(tab) {
            return Err(format!(
                "non-websocket replay tab {} must not include websocket state",
                tab.id
            ));
        }
        if is_websocket_tab && replay_tab_has_http_replay_payload(tab) {
            return Err(format!(
                "websocket replay tab {} must not include HTTP replay state",
                tab.id
            ));
        }
        add_workspace_text_bytes(
            &mut stored_bytes_total,
            "replay tab request text",
            &tab.request_text,
            MAX_WORKSPACE_TEXT_FIELD_BYTES,
        )?;
        add_workspace_text_bytes(
            &mut stored_bytes_total,
            "replay tab notice",
            &tab.notice,
            MAX_WORKSPACE_TEXT_FIELD_BYTES,
        )?;
        add_workspace_text_bytes(
            &mut stored_bytes_total,
            "websocket handshake text",
            &tab.ws_handshake_text,
            MAX_WORKSPACE_TEXT_FIELD_BYTES,
        )?;
        add_workspace_text_bytes(
            &mut stored_bytes_total,
            "websocket editor text",
            &tab.ws_editor_text,
            MAX_WORKSPACE_TEXT_FIELD_BYTES,
        )?;
        add_workspace_text_bytes(
            &mut stored_bytes_total,
            "websocket setup notice",
            &tab.ws_setup_notice,
            MAX_WORKSPACE_TEXT_FIELD_BYTES,
        )?;
        if is_websocket_tab {
            if tab.ws_headers.len() > MAX_WORKSPACE_WS_HEADERS {
                return Err(format!(
                    "WebSocket replay tab has too many headers: {}",
                    tab.ws_headers.len()
                ));
            }
            let mut ws_headers_bytes_total = 0usize;
            for header in &tab.ws_headers {
                let header_bytes = add_workspace_json_bytes(
                    &mut stored_bytes_total,
                    "WebSocket header",
                    header,
                    MAX_WORKSPACE_WS_HEADER_BYTES,
                )?;
                ws_headers_bytes_total = ws_headers_bytes_total.saturating_add(header_bytes);
                if ws_headers_bytes_total > MAX_WORKSPACE_WS_HEADERS_BYTES {
                    return Err(format!(
                        "WebSocket replay headers exceed {MAX_WORKSPACE_WS_HEADERS_BYTES} stored bytes"
                    ));
                }
            }
        }
        if tab.history_entries.len() > MAX_WORKSPACE_REPLAY_HISTORY_ENTRIES_PER_TAB {
            return Err(format!(
                "replay tab {} has too many history entries: {}",
                tab.id,
                tab.history_entries.len()
            ));
        }
        if let Some(index) = tab.history_index {
            if index >= tab.history_entries.len() {
                return Err(format!("invalid replay history index for tab {}", tab.id));
            }
        }
        if tab.ws_setup_queue.len() > MAX_WORKSPACE_WS_SETUP_QUEUE_ITEMS {
            return Err(format!(
                "WebSocket setup queue has too many items: {}",
                tab.ws_setup_queue.len()
            ));
        }
        for item in &tab.ws_setup_queue {
            add_workspace_json_bytes(
                &mut stored_bytes_total,
                "WebSocket setup item",
                item,
                MAX_WORKSPACE_WS_SETUP_ITEM_BYTES,
            )?;
        }
        if is_websocket_tab {
            let ws_stats = validate_workspace_ws_tab(tab)
                .map_err(|error| format!("invalid websocket replay tab: {error}"))?;
            ws_frame_total = ws_frame_total.saturating_add(ws_stats.frames);
            ws_frame_body_total = ws_frame_body_total.saturating_add(ws_stats.body_bytes);
            if ws_frame_total > MAX_WORKSPACE_WS_TOTAL_FRAMES {
                return Err(format!(
                    "workspace has too many persisted WebSocket replay frames: {ws_frame_total}"
                ));
            }
            if ws_frame_body_total > MAX_WORKSPACE_WS_TOTAL_FRAME_BODY_BYTES {
                return Err(format!(
                    "workspace WebSocket replay frames exceed {MAX_WORKSPACE_WS_TOTAL_FRAME_BODY_BYTES} stored bytes"
                ));
            }
        }
        if let Some(request) = &tab.base_request {
            validate_workspace_draft_request(request)
                .map_err(|error| format!("invalid replay base request: {error}"))?;
            add_workspace_json_bytes(
                &mut stored_bytes_total,
                "replay base request",
                request,
                MAX_WORKSPACE_EDITABLE_MESSAGE_BYTES,
            )?;
        }
        if let Some(record) = &tab.response_record {
            add_workspace_json_bytes(
                &mut stored_bytes_total,
                "replay response record",
                record,
                MAX_WORKSPACE_EMBEDDED_RECORD_BYTES,
            )?;
        }
        validate_workspace_target_fields(&tab.target_scheme, &tab.target_host, &tab.target_port)
            .map_err(|error| format!("invalid replay target: {error}"))?;
        if let Some(request) = &tab.base_request {
            let target = RequestTargetOverride {
                scheme: tab.target_scheme.clone(),
                host: tab.target_host.clone(),
                port: tab.target_port.clone(),
            };
            if request_has_target_validation_authority(request) {
                validate_request_target_override_for_request(request, &target)
                    .map_err(|error| format!("invalid replay target: {error}"))?;
            }
        }
        for entry in &tab.history_entries {
            add_workspace_text_bytes(
                &mut stored_bytes_total,
                "replay history request text",
                &entry.request_text,
                MAX_WORKSPACE_TEXT_FIELD_BYTES,
            )?;
            add_workspace_text_bytes(
                &mut stored_bytes_total,
                "replay history notice",
                &entry.notice,
                MAX_WORKSPACE_TEXT_FIELD_BYTES,
            )?;
            if let Some(request) = &entry.request {
                validate_editable_request(request)
                    .map_err(|error| format!("invalid replay history request: {error}"))?;
                add_workspace_json_bytes(
                    &mut stored_bytes_total,
                    "replay history request",
                    request,
                    MAX_WORKSPACE_EDITABLE_MESSAGE_BYTES,
                )?;
            }
            if let Some(record) = &entry.response_record {
                add_workspace_json_bytes(
                    &mut stored_bytes_total,
                    "replay history response record",
                    record,
                    MAX_WORKSPACE_EMBEDDED_RECORD_BYTES,
                )?;
            }
            validate_workspace_target_fields(
                &entry.target_scheme,
                &entry.target_host,
                &entry.target_port,
            )
            .map_err(|error| format!("invalid replay history target: {error}"))?;
            if let Some(request) = &entry.request {
                let target = RequestTargetOverride {
                    scheme: entry.target_scheme.clone(),
                    host: entry.target_host.clone(),
                    port: entry.target_port.clone(),
                };
                validate_request_target_override_for_request(request, &target)
                    .map_err(|error| format!("invalid replay history target: {error}"))?;
            }
        }
    }
    if let Some(active_tab_id) = snapshot.replay.active_tab_id.as_deref() {
        if !active_tab_id.is_empty() && !tab_ids.contains(active_tab_id) {
            return Err(format!("active replay tab does not exist: {active_tab_id}"));
        }
    }
    if let Some(request) = &snapshot.fuzzer.base_request {
        validate_workspace_draft_request(request)
            .map_err(|error| format!("invalid fuzzer base request: {error}"))?;
        add_workspace_json_bytes(
            &mut stored_bytes_total,
            "fuzzer base request",
            request,
            MAX_WORKSPACE_EDITABLE_MESSAGE_BYTES,
        )?;
    }
    if let Some(target) = &snapshot.fuzzer.target {
        let target_result = if let Some(request) = &snapshot.fuzzer.base_request {
            if !request_has_target_validation_authority(request) {
                validate_request_target_override(target)
            } else {
                validate_request_target_override_for_request(request, target)
            }
        } else {
            validate_request_target_override(target)
        };
        target_result.map_err(|error| format!("invalid fuzzer target: {error}"))?;
    }
    if let Some(authority) = snapshot.fuzzer.target_request_authority.as_deref() {
        validate_fuzzer_target_request_authority(authority, snapshot.fuzzer.base_request.as_ref())
            .map_err(|error| format!("invalid fuzzer target request authority: {error}"))?;
    }
    add_workspace_text_bytes(
        &mut stored_bytes_total,
        "fuzzer notice",
        &snapshot.fuzzer.notice,
        MAX_WORKSPACE_TEXT_FIELD_BYTES,
    )?;
    add_workspace_text_bytes(
        &mut stored_bytes_total,
        "fuzzer request text",
        &snapshot.fuzzer.request_text,
        MAX_WORKSPACE_TEXT_FIELD_BYTES,
    )?;
    add_workspace_text_bytes(
        &mut stored_bytes_total,
        "fuzzer payload text",
        &snapshot.fuzzer.payloads_text,
        MAX_WORKSPACE_FUZZER_PAYLOAD_TEXT_BYTES,
    )?;
    if snapshot.fuzzer.payloads_text.lines().count() > MAX_WORKSPACE_FUZZER_PAYLOAD_LINES {
        return Err(format!(
            "fuzzer payload text cannot contain more than {MAX_WORKSPACE_FUZZER_PAYLOAD_LINES} lines"
        ));
    }
    Ok(())
}

fn replay_tab_has_websocket_payload(tab: &crate::workspace::ReplayTabState) -> bool {
    !tab.ws_scheme.is_empty()
        || !tab.ws_host.is_empty()
        || !tab.ws_port.is_null()
        || !tab.ws_path.is_empty()
        || !tab.ws_headers.is_empty()
        || !tab.ws_handshake_text.is_empty()
        || tab.ws_handshake_edited
        || !tab.ws_editor_text.is_empty()
        || !tab.ws_message_type.is_empty()
        || tab.ws_editor_body_encoded
        || !tab.ws_setup_notice.is_empty()
        || !tab.ws_setup_queue.is_empty()
        || !tab.ws_frames.is_empty()
        || tab.ws_frames_truncated
        || tab.ws_selected_frame_index.is_some()
        || tab.ws_frame_window_start.is_some()
}

fn replay_tab_has_http_replay_payload(tab: &crate::workspace::ReplayTabState) -> bool {
    tab.base_request.is_some()
        || tab.source_transaction_id.is_some()
        || !tab.notice.is_empty()
        || !tab.request_text.is_empty()
        || !tab.http_version_mode.is_empty()
        || tab.response_record.is_some()
        || tab.response_record_complete.is_some()
        || !tab.target_scheme.is_empty()
        || !tab.target_host.is_empty()
        || !tab.target_port.is_empty()
        || tab.target_manually_edited
        || !tab.history_entries.is_empty()
        || tab.history_index.is_some()
        || tab.history_entries_complete.is_some()
}

fn add_workspace_text_bytes(
    total: &mut usize,
    label: &str,
    value: &str,
    field_limit: usize,
) -> std::result::Result<(), String> {
    let bytes = value.len();
    if bytes > field_limit {
        return Err(format!("{label} cannot exceed {field_limit} bytes"));
    }
    add_workspace_stored_bytes(total, label, bytes)
}

fn add_workspace_json_bytes<T: Serialize>(
    total: &mut usize,
    label: &str,
    value: &T,
    field_limit: usize,
) -> std::result::Result<usize, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("failed to measure {label}: {error}"))?
        .len();
    if bytes > field_limit {
        return Err(format!("{label} cannot exceed {field_limit} stored bytes"));
    }
    add_workspace_stored_bytes(total, label, bytes)?;
    Ok(bytes)
}

fn add_workspace_stored_bytes(
    total: &mut usize,
    label: &str,
    bytes: usize,
) -> std::result::Result<(), String> {
    *total = total.saturating_add(bytes);
    if *total > MAX_WORKSPACE_STORED_BYTES {
        return Err(format!(
            "workspace stored state exceeds {MAX_WORKSPACE_STORED_BYTES} bytes while adding {label}"
        ));
    }
    Ok(())
}

fn validate_workspace_string_bytes(
    label: &str,
    value: &str,
    limit: usize,
) -> std::result::Result<(), String> {
    if value.len() > limit {
        return Err(format!("{label} cannot exceed {limit} bytes"));
    }
    Ok(())
}

fn validate_workspace_draft_request(request: &EditableRequest) -> std::result::Result<(), String> {
    if !request.host.trim().is_empty() {
        return validate_editable_request(request);
    }
    if request.host.trim() != request.host {
        return Err("draft request host must not include whitespace".to_string());
    }
    if !request.scheme.trim().is_empty() {
        validate_http_scheme_field(&request.scheme, "request scheme")?;
    }
    if !request.path.trim().is_empty() {
        validate_editable_request_path(&request.path)?;
    }
    if !request.method.trim().is_empty() {
        validate_http_method(&request.method)?;
    }
    for header in &request.headers {
        validate_editable_header(header)?;
    }
    let body = request
        .try_body_bytes()
        .map_err(|_| "request body is not valid base64".to_string())?;
    validate_editable_body_framing(&request.headers, body.len(), false)
}

fn validate_workspace_target_fields(
    scheme: &str,
    host: &str,
    port: &str,
) -> std::result::Result<(), String> {
    validate_workspace_string_bytes(
        "replay target scheme",
        scheme,
        MAX_WORKSPACE_REPLAY_TARGET_FIELD_BYTES,
    )?;
    validate_workspace_string_bytes(
        "replay target host",
        host,
        MAX_WORKSPACE_REPLAY_TARGET_FIELD_BYTES,
    )?;
    validate_workspace_string_bytes(
        "replay target port",
        port,
        MAX_WORKSPACE_REPLAY_TARGET_FIELD_BYTES,
    )?;
    let raw_scheme = scheme;
    let raw_host = host;
    let raw_port = port;
    let scheme = raw_scheme.trim();
    let host = raw_host.trim();
    let port = raw_port.trim();
    if scheme != raw_scheme {
        return Err("replay target scheme must not include surrounding whitespace".to_string());
    }
    if host != raw_host {
        return Err("replay target host must not include surrounding whitespace".to_string());
    }
    if port != raw_port {
        return Err("replay target port must not include surrounding whitespace".to_string());
    }
    if !scheme.is_empty() {
        validate_http_scheme_field(scheme, "replay target scheme")?;
    }
    if host.is_empty() {
        if !port.is_empty() {
            validate_port_text(port, "replay target port")?;
        }
        return Ok(());
    }
    if scheme.is_empty() || port.is_empty() {
        return Err("replay target scheme, host, and port must be saved together".to_string());
    }
    validate_replay_target_host(host)?;
    if !port.is_empty() {
        validate_port_text(port, "replay target port")?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default)]
struct WorkspaceWsFrameStats {
    frames: usize,
    body_bytes: usize,
}

fn validate_workspace_ws_tab(
    tab: &crate::workspace::ReplayTabState,
) -> std::result::Result<WorkspaceWsFrameStats, String> {
    let scheme = tab.ws_scheme.trim();
    if scheme != tab.ws_scheme {
        return Err("WebSocket scheme must not include surrounding whitespace".to_string());
    }
    if !scheme.is_empty() {
        validate_workspace_ws_scheme(scheme)?;
    }

    let host = tab.ws_host.trim();
    if host != tab.ws_host {
        return Err("WebSocket host must not include surrounding whitespace".to_string());
    }
    let port = validate_workspace_ws_port(&tab.ws_port)?;
    if !tab.ws_path.trim().is_empty() {
        normalize_ws_replay_path(&tab.ws_path)?;
    }

    if !host.is_empty() {
        let scheme = if scheme.is_empty() { "wss" } else { scheme };
        let port = port.unwrap_or_else(|| default_ws_replay_port(scheme));
        build_ws_replay_url(scheme, host, port, &tab.ws_path)?;
    }

    let mut headers = Vec::with_capacity(tab.ws_headers.len());
    for (index, value) in tab.ws_headers.iter().enumerate() {
        let header: HeaderRecord = serde_json::from_value(value.clone())
            .map_err(|_| format!("invalid WebSocket header at index {index}"))?;
        headers.push(header);
    }
    validate_ws_replay_headers(&headers)?;

    if !tab.ws_message_type.trim().is_empty() {
        validate_ws_message_kind(&tab.ws_message_type)?;
    }
    for (index, item) in tab.ws_setup_queue.iter().enumerate() {
        validate_workspace_ws_setup_item(item, index)?;
    }
    if tab.ws_frames.len() > MAX_WORKSPACE_WS_FRAMES {
        return Err(format!(
            "WebSocket replay tab has too many frames: {}",
            tab.ws_frames.len()
        ));
    }
    let mut stats = WorkspaceWsFrameStats {
        frames: tab.ws_frames.len(),
        body_bytes: 0,
    };
    for (index, frame) in tab.ws_frames.iter().enumerate() {
        stats.body_bytes = stats
            .body_bytes
            .saturating_add(validate_workspace_ws_frame(frame, index)?);
    }

    Ok(stats)
}

fn validate_workspace_ws_frame(
    frame: &crate::ws_replay::WsReplayFrame,
    index: usize,
) -> std::result::Result<usize, String> {
    chrono::DateTime::parse_from_rfc3339(&frame.captured_at)
        .map_err(|_| format!("WebSocket frame {index} has an invalid timestamp"))?;
    let body_len = match &frame.body_encoding {
        BodyEncoding::Utf8 => frame.body.len(),
        BodyEncoding::Base64 => decode_ws_replay_payload(&frame.body)
            .map_err(|error| format!("invalid WebSocket frame {index}: {error}"))?
            .len(),
    };
    if body_len > MAX_WORKSPACE_WS_FRAME_BODY_BYTES {
        return Err(format!(
            "WebSocket frame {index} body cannot exceed {MAX_WORKSPACE_WS_FRAME_BODY_BYTES} bytes"
        ));
    }
    if frame.body_size < body_len {
        return Err(format!(
            "WebSocket frame {index} body_size is smaller than the stored body"
        ));
    }
    if !frame.preview_truncated && frame.body_size != body_len {
        return Err(format!(
            "WebSocket frame {index} body_size must match the stored body when it is not truncated"
        ));
    }
    Ok(body_len)
}

fn validate_workspace_ws_scheme(scheme: &str) -> std::result::Result<(), String> {
    match scheme.to_ascii_lowercase().as_str() {
        "ws" | "wss" => Ok(()),
        _ => Err(format!("unsupported WebSocket scheme: {scheme}")),
    }
}

fn validate_workspace_ws_port(
    value: &serde_json::Value,
) -> std::result::Result<Option<u16>, String> {
    match value {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Number(number) => {
            let Some(port) = number.as_u64() else {
                return Err("invalid WebSocket port".to_string());
            };
            let port =
                u16::try_from(port).map_err(|_| format!("invalid WebSocket port: {port}"))?;
            if port == 0 {
                return Err("WebSocket port must be greater than zero".to_string());
            }
            Ok(Some(port))
        }
        serde_json::Value::String(port) => {
            if port.trim().is_empty() {
                Ok(None)
            } else {
                parse_ws_replay_port(port).map(Some)
            }
        }
        _ => Err("invalid WebSocket port".to_string()),
    }
}

fn validate_workspace_ws_setup_item(
    item: &serde_json::Value,
    index: usize,
) -> std::result::Result<(), String> {
    let object = item
        .as_object()
        .ok_or_else(|| format!("WebSocket setup item {index} must be an object"))?;
    let kind = object
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("text");
    let kind = validate_ws_message_kind(kind)?;
    let body = match object.get("body") {
        Some(value) => value
            .as_str()
            .ok_or_else(|| format!("WebSocket setup item {index} body must be a string"))?,
        None => "",
    };
    let body_encoded = object
        .get("body_encoded")
        .or_else(|| object.get("bodyEncoded"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if body_encoded {
        match kind {
            "text" => {}
            "binary" => {
                decode_ws_replay_payload(body)
                    .map_err(|error| format!("invalid WebSocket setup item {index}: {error}"))?;
            }
            "ping" | "pong" => {
                decode_ws_replay_control_payload(body)
                    .map_err(|error| format!("invalid WebSocket setup item {index}: {error}"))?;
            }
            _ => unreachable!(),
        }
    }
    for field in ["label"] {
        if let Some(value) = object.get(field) {
            if !value.is_string() {
                return Err(format!(
                    "WebSocket setup item {index} {field} must be a string"
                ));
            }
        }
    }
    for field in ["autoSend", "sent", "body_encoded", "bodyEncoded"] {
        if let Some(value) = object.get(field) {
            if !value.is_boolean() {
                return Err(format!(
                    "WebSocket setup item {index} {field} must be a boolean"
                ));
            }
        }
    }
    Ok(())
}

fn validate_ws_message_kind(kind: &str) -> std::result::Result<&'static str, String> {
    match kind.trim().to_ascii_lowercase().as_str() {
        "text" => Ok("text"),
        "binary" => Ok("binary"),
        "ping" => Ok("ping"),
        "pong" => Ok("pong"),
        _ => Err(format!("unsupported WebSocket message type: {kind}")),
    }
}

fn validate_replay_target_host(host: &str) -> std::result::Result<(), String> {
    let trimmed = host.trim();
    if trimmed != host {
        return Err("replay target host must not include surrounding whitespace".to_string());
    }
    if trimmed.is_empty() {
        return Err("replay target host is required".to_string());
    }
    if trimmed.chars().any(char::is_whitespace)
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains('@')
        || trimmed.contains('?')
        || trimmed.contains('#')
    {
        return Err(format!("invalid replay target host: {trimmed}"));
    }
    if trimmed.starts_with('[') {
        let Some(end) = trimmed.find(']') else {
            return Err(format!("invalid replay target host: {trimmed}"));
        };
        if end != trimmed.len() - 1 {
            return Err("replay target host must not include a port; use target.port".to_string());
        }
        let inner = &trimmed[1..end];
        return inner
            .parse::<IpAddr>()
            .map(|_| ())
            .map_err(|_| format!("invalid replay target host: {trimmed}"));
    }
    if trimmed.contains(':') && trimmed.parse::<IpAddr>().is_err() {
        return Err("replay target host must not include a port; use target.port".to_string());
    }
    Ok(())
}

fn validate_port_text(port: &str, label: &str) -> std::result::Result<(), String> {
    let trimmed = port.trim();
    if trimmed != port {
        return Err(format!("{label} must not include surrounding whitespace"));
    }
    let parsed = trimmed
        .parse::<u16>()
        .map_err(|_| format!("invalid {label}: {port}"))?;
    if parsed == 0 {
        return Err(format!("invalid {label}: {port}"));
    }
    Ok(())
}

pub(crate) fn validate_sequence_definition(
    definition: &SequenceDefinition,
) -> std::result::Result<(), String> {
    validate_serialized_size(
        definition,
        "sequence definition",
        MAX_SEQUENCE_DEFINITION_BYTES,
    )?;
    validate_text_field(
        "sequence name",
        &definition.name,
        MAX_SEQUENCE_TEXT_FIELD_BYTES,
    )?;
    if definition.steps.len() > MAX_SEQUENCE_STEPS {
        return Err(format!(
            "sequence cannot contain more than {MAX_SEQUENCE_STEPS} steps"
        ));
    }
    for step in &definition.steps {
        validate_text_field(
            "sequence step label",
            &step.label,
            MAX_SEQUENCE_TEXT_FIELD_BYTES,
        )?;
        if let Some(request_text) = &step.request_text {
            validate_text_field(
                "sequence step request text",
                request_text,
                MAX_SEQUENCE_TEXT_FIELD_BYTES,
            )?;
        }
        let has_request_parse_error = step
            .request_parse_error
            .as_deref()
            .map(str::trim)
            .is_some_and(|error| !error.is_empty());
        if let Some(parse_error) = &step.request_parse_error {
            validate_text_field(
                "sequence step parse error",
                parse_error,
                MAX_SEQUENCE_TEXT_FIELD_BYTES,
            )?;
        }
        if step.extractions.len() > MAX_SEQUENCE_EXTRACTIONS_PER_STEP {
            return Err(format!(
                "sequence step {} cannot contain more than {MAX_SEQUENCE_EXTRACTIONS_PER_STEP} extractions",
                step.label
            ));
        }
        if !has_request_parse_error {
            validate_editable_request(&step.request).map_err(|error| {
                format!("invalid request in sequence step {}: {error}", step.label)
            })?;
        }
        normalize_replay_http_version(step.http_version.as_deref()).map_err(|error| {
            format!(
                "invalid HTTP version in sequence step {}: {error}",
                step.label
            )
        })?;
        if let Some(target) = &step.target {
            let target_result = if has_request_parse_error {
                validate_request_target_override(target)
            } else {
                validate_request_target_override_for_request(&step.request, target)
            };
            target_result.map_err(|error| {
                format!("invalid target in sequence step {}: {error}", step.label)
            })?;
        }
        for rule in &step.extractions {
            validate_text_field(
                "sequence extraction variable name",
                &rule.variable_name,
                MAX_SEQUENCE_TEXT_FIELD_BYTES,
            )?;
            validate_text_field(
                "sequence extraction pattern",
                &rule.pattern,
                MAX_SEQUENCE_TEXT_FIELD_BYTES,
            )?;
            if rule.variable_name.trim().is_empty() {
                return Err(format!(
                    "sequence step {} has an extraction with an empty variable name",
                    step.label
                ));
            }
            match rule.source {
                crate::sequence::ExtractionSource::ResponseBody => {
                    let regex = RegexBuilder::new(&rule.pattern).build().map_err(|error| {
                        format!(
                            "sequence step {} extraction {} has invalid regex: {error}",
                            step.label, rule.variable_name
                        )
                    })?;
                    if rule.group >= regex.captures_len() {
                        return Err(format!(
                            "sequence step {} extraction {} references missing capture group {}",
                            step.label, rule.variable_name, rule.group
                        ));
                    }
                }
                crate::sequence::ExtractionSource::ResponseHeader => {
                    let header_name = rule.pattern.trim();
                    if header_name.is_empty() || header_name != rule.pattern {
                        return Err(format!(
                            "sequence step {} extraction {} has an invalid response header name",
                            step.label, rule.variable_name
                        ));
                    }
                    HeaderName::from_bytes(header_name.as_bytes()).map_err(|_| {
                        format!(
                            "sequence step {} extraction {} has an invalid response header name",
                            step.label, rule.variable_name
                        )
                    })?;
                }
            }
        }
    }
    Ok(())
}

fn validate_scanner_config(
    config: &crate::scanner::ScannerConfig,
) -> std::result::Result<(), String> {
    validate_serialized_size(config, "scanner config", MAX_SCANNER_CONFIG_BYTES)?;
    if config.custom_rules.len() > MAX_SCANNER_CUSTOM_RULES {
        return Err(format!(
            "scanner config cannot contain more than {MAX_SCANNER_CUSTOM_RULES} custom rules"
        ));
    }
    let mut custom_rule_ids = HashSet::new();
    for rule in &config.custom_rules {
        validate_text_field("custom scanner rule id", &rule.id, MAX_SCANNER_FIELD_BYTES)?;
        validate_text_field(
            "custom scanner rule name",
            &rule.name,
            MAX_SCANNER_FIELD_BYTES,
        )?;
        validate_text_field(
            "custom scanner rule target",
            &rule.target,
            MAX_SCANNER_FIELD_BYTES,
        )?;
        validate_text_field(
            "custom scanner rule header name",
            &rule.header_name,
            MAX_SCANNER_FIELD_BYTES,
        )?;
        validate_text_field(
            "custom scanner rule pattern",
            &rule.pattern,
            MAX_SCANNER_FIELD_BYTES,
        )?;
        validate_text_field(
            "custom scanner rule category",
            &rule.category,
            MAX_SCANNER_FIELD_BYTES,
        )?;
        validate_text_field(
            "custom scanner rule description",
            &rule.description,
            MAX_SCANNER_FIELD_BYTES,
        )?;
        if rule.id.trim().is_empty() {
            return Err("custom scanner rule id is required".to_string());
        }
        if !custom_rule_ids.insert(rule.id.trim().to_string()) {
            return Err(format!(
                "custom scanner rule {} id is duplicated",
                rule.id.trim()
            ));
        }
        if rule.name.trim().is_empty() {
            return Err(format!("custom scanner rule {} name is required", rule.id));
        }
        if rule.pattern.trim().is_empty() {
            return Err(format!(
                "custom scanner rule {} pattern is required",
                rule.id
            ));
        }
        match rule.target.as_str() {
            "response_body" | "response_header" | "request_header" => {}
            other => {
                return Err(format!(
                    "custom scanner rule {} has invalid target {}",
                    rule.id, other
                ));
            }
        }
        RegexBuilder::new(&rule.pattern).build().map_err(|error| {
            format!("custom scanner rule {} has invalid regex: {error}", rule.id)
        })?;
    }
    Ok(())
}

fn validate_match_replace_rules(rules: &[MatchReplaceRule]) -> std::result::Result<(), String> {
    validate_serialized_size(&rules, "match-replace rules", MAX_MATCH_REPLACE_RULES_BYTES)?;
    if rules.len() > MAX_MATCH_REPLACE_RULES {
        return Err(format!(
            "match-replace cannot contain more than {MAX_MATCH_REPLACE_RULES} rules"
        ));
    }
    for rule in rules {
        validate_text_field(
            "match-replace description",
            &rule.description,
            MAX_MATCH_REPLACE_FIELD_BYTES,
        )?;
        validate_text_field(
            "match-replace search",
            &rule.search,
            MAX_MATCH_REPLACE_FIELD_BYTES,
        )?;
        validate_text_field(
            "match-replace replacement",
            &rule.replace,
            MAX_MATCH_REPLACE_FIELD_BYTES,
        )?;
        if rule.regex && !rule.search.is_empty() {
            RegexBuilder::new(&rule.search)
                .case_insensitive(!rule.case_sensitive)
                .build()
                .map_err(|error| {
                    format!(
                        "match-replace rule {} has invalid regex: {error}",
                        rule.description
                    )
                })?;
        }
    }
    Ok(())
}

fn validate_text_field(label: &str, value: &str, limit: usize) -> std::result::Result<(), String> {
    if value.len() > limit {
        return Err(format!("{label} cannot exceed {limit} bytes"));
    }
    Ok(())
}

fn validate_serialized_size<T: Serialize>(
    value: &T,
    label: &str,
    limit: usize,
) -> std::result::Result<(), String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("failed to measure {label}: {error}"))?
        .len();
    if bytes > limit {
        return Err(format!("{label} cannot exceed {limit} stored bytes"));
    }
    Ok(())
}

fn normalize_replay_http_version(
    value: Option<&str>,
) -> std::result::Result<Option<String>, String> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    match value {
        "HTTP/1.0" | "1.0" => Ok(Some("HTTP/1.0".to_string())),
        "HTTP/1.1" | "1.1" => Ok(Some("HTTP/1.1".to_string())),
        "HTTP/2" | "HTTP/2.0" | "2" | "2.0" => Ok(Some("HTTP/2".to_string())),
        other => Err(format!("unsupported replay http_version: {other}")),
    }
}

impl From<TransactionListPage> for TransactionPageResponse {
    fn from(page: TransactionListPage) -> Self {
        Self {
            items: page.items,
            total: page.total,
            filtered_total: page.filtered_total,
            hidden_connect_total: page.hidden_connect_total,
            offset: page.offset,
            limit: page.limit,
            has_more: page.has_more,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct WebSocketQuery {
    session_id: Option<Uuid>,
    q: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
    after_id: Option<Uuid>,
    frame_limit: Option<usize>,
    before_index: Option<usize>,
    sort_key: Option<String>,
    sort_direction: Option<String>,
    in_scope_only: Option<bool>,
    live_only: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WebSocketPageResponse {
    items: Vec<crate::model::WebSocketSessionSummary>,
    total: usize,
    filtered_total: Option<usize>,
    offset: usize,
    limit: usize,
    has_more: bool,
}

#[derive(Debug, Deserialize)]
struct EventLogQuery {
    session_id: Option<Uuid>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct EventsQuery {
    session_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
struct FuzzerQuery {
    session_id: Option<Uuid>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct OastQuery {
    session_id: Option<Uuid>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct RuntimeQuery {
    session_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
struct TargetSiteMapQuery {
    session_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
struct SessionScopedQuery {
    session_id: Option<Uuid>,
}

#[derive(Clone, Debug, Deserialize)]
struct SessionWriteQuery {
    session_id: Option<Uuid>,
    #[serde(default)]
    expected_active_session_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
struct TransactionWriteQuery {
    session_id: Option<Uuid>,
    #[serde(default)]
    expected_active_session_id: Option<Uuid>,
}

fn reconcile_write_session_id(
    query_session_id: Option<Uuid>,
    body_session_id: Option<Uuid>,
) -> std::result::Result<(Option<Uuid>, bool), &'static str> {
    match (query_session_id, body_session_id) {
        (Some(query_session_id), Some(body_session_id)) if query_session_id != body_session_id => {
            Err("query session_id conflicts with JSON session_id")
        }
        (Some(session_id), _) | (None, Some(session_id)) => Ok((Some(session_id), true)),
        (None, None) => Ok((None, false)),
    }
}

#[derive(Debug, Deserialize)]
struct InterceptRulePayload {
    #[serde(default)]
    session_id: Option<Uuid>,
    #[serde(flatten)]
    rule: crate::intercept::InterceptRule,
}

impl From<crate::intercept::InterceptRule> for InterceptRulePayload {
    fn from(rule: crate::intercept::InterceptRule) -> Self {
        Self {
            session_id: None,
            rule,
        }
    }
}

#[derive(Debug, Deserialize)]
struct InterceptForwardPayload {
    #[serde(default)]
    session_id: Option<Uuid>,
    request: EditableRequest,
    /// Whether the operator changed the request in the editor. Reported by the
    /// client because only it knows what it displayed: rendering the held request
    /// and parsing it back can differ on its own.
    #[serde(default)]
    edited: bool,
}

#[derive(Debug, Deserialize)]
struct ResponseInterceptForwardPayload {
    #[serde(default)]
    session_id: Option<Uuid>,
    response: EditableResponse,
    #[serde(default)]
    edited: bool,
}

#[derive(Debug, Default, Deserialize)]
struct SessionActionPayload {
    #[serde(default)]
    session_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
struct ReplaySendPayload {
    session_id: Option<Uuid>,
    #[serde(default)]
    expected_active_session_id: Option<Uuid>,
    #[serde(default)]
    expected_workspace_revision: Option<u64>,
    request: EditableRequest,
    target: Option<RequestTargetOverride>,
    source_transaction_id: Option<Uuid>,
    http_version: Option<String>,
}

#[derive(Debug, Serialize)]
struct ReplaySendErrorResponse {
    error: String,
    record: Option<crate::model::TransactionRecord>,
}

fn replay_send_error_response(error: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ReplaySendErrorResponse {
            error: error.into(),
            record: None,
        }),
    )
        .into_response()
}

async fn expected_workspace_revision_conflict_response(
    session: &Arc<crate::session::SessionContext>,
    expected_revision: Option<u64>,
) -> Option<Response> {
    let expected_revision = expected_revision?;
    let mut current = session.workspace.snapshot().await;
    if current.revision == expected_revision {
        return None;
    }
    current.session_id = Some(session.id());
    Some((StatusCode::CONFLICT, Json(current)).into_response())
}

fn ws_replay_send_error_response(error: anyhow::Error) -> Response {
    let status = if matches!(
        error.downcast_ref::<crate::ws_replay::WsReplaySendError>(),
        Some(crate::ws_replay::WsReplaySendError::QueueFull)
    ) {
        StatusCode::TOO_MANY_REQUESTS
    } else if error
        .to_string()
        .contains("WebSocket replay message cannot exceed")
    {
        StatusCode::PAYLOAD_TOO_LARGE
    } else {
        StatusCode::BAD_REQUEST
    };
    (status, error.to_string()).into_response()
}

#[derive(Debug, Deserialize)]
struct CreateSessionPayload {
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AnnotationsPayload {
    #[serde(default)]
    session_id: Option<Uuid>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    color_tag: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    user_note: Option<Option<String>>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_version: Option<u64>,
}

fn validate_annotations_payload(payload: &AnnotationsPayload) -> std::result::Result<(), String> {
    if let Some(Some(color_tag)) = payload.color_tag.as_ref() {
        if !ALLOWED_COLOR_TAGS.contains(&color_tag.as_str()) {
            return Err("unsupported color tag".to_string());
        }
    }
    if let Some(Some(user_note)) = payload.user_note.as_ref() {
        validate_text_field("user note", user_note, MAX_ANNOTATION_NOTE_BYTES)?;
    }
    if let Some(client_id) = payload.client_id.as_deref() {
        if client_id.is_empty() {
            return Err("annotation client id is required".to_string());
        }
        validate_text_field(
            "annotation client id",
            client_id,
            MAX_WORKSPACE_CLIENT_ID_BYTES,
        )?;
        if payload.client_version.is_none() {
            return Err("annotation client version is required".to_string());
        }
    }
    if let Some(client_version) = payload.client_version {
        if client_version == 0 {
            return Err("annotation client version must be greater than zero".to_string());
        }
        if payload.client_id.as_deref().is_none_or(str::is_empty) {
            return Err("annotation client id is required".to_string());
        }
    }
    Ok(())
}

fn deserialize_double_option<'de, D>(deserializer: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(Some)
}

async fn get_settings(State(state): State<Arc<AppState>>) -> Json<crate::state::RuntimeInfo> {
    Json(state.runtime_info().await)
}

async fn get_app_version(State(state): State<Arc<AppState>>) -> Json<crate::state::AppVersionInfo> {
    Json(state.app_version_info().await)
}

async fn self_update(
    State(state): State<Arc<AppState>>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::state::UpdateProgress>(32);

    tokio::spawn(async move {
        if let Err(err) = state.self_update(tx.clone()).await {
            let _ = tx
                .send(crate::state::UpdateProgress {
                    step: format!("error:{err:#}"),
                    percent: None,
                    downloaded: None,
                    total: None,
                })
                .await;
        }
    });

    Sse::new(stream! {
        while let Some(progress) = rx.recv().await {
            let data = serde_json::to_string(&progress).unwrap_or_default();
            yield Ok(Event::default().data(data));
        }
    })
}

async fn list_sessions(State(state): State<Arc<AppState>>) -> Json<Vec<SessionSummary>> {
    Json(state.list_sessions().await)
}

async fn create_session(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateSessionPayload>,
) -> Response {
    match state.create_session(payload.name).await {
        Ok(summary) => Json(summary).into_response(),
        Err(error) => session_operation_error_response(error),
    }
}

#[derive(Debug, Default, Deserialize)]
struct ActivateSessionParams {
    /// Cut in-flight proxy connections instead of refusing the switch. A streamed
    /// response holds its session open for as long as it lasts, so without this a
    /// browser pointed at the proxy can block switching indefinitely.
    #[serde(default)]
    force: bool,
}

async fn activate_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<ActivateSessionParams>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    match state.activate_session_with_options(id, params.force).await {
        Ok(summary) => Json(summary).into_response(),
        Err(error) => session_operation_error_response(error),
    }
}

async fn delete_session(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    match state.delete_session(id).await {
        Ok(()) => Json(serde_json::json!({ "ok": true })).into_response(),
        Err(error) => session_operation_error_response(error),
    }
}

fn session_operation_error_response(error: anyhow::Error) -> Response {
    let message = error.to_string();
    let status = if message.contains("was not found") {
        StatusCode::NOT_FOUND
    } else if message.contains("cannot delete the active session")
        || message.contains("live captures are active")
        || message.contains("proxy activity is still running")
        || message.contains("capture persistence is pending")
    {
        StatusCode::CONFLICT
    } else if message.contains("failed to") {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::BAD_REQUEST
    };
    (status, message).into_response()
}

async fn reveal_session_folder(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    match state.session_storage_path(id) {
        Ok(path) => {
            if let Err(error) = spawn_open_command(OPEN_PATH, std::iter::once(path.as_os_str())) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!(
                        "failed to reveal session folder {}: {error}",
                        path.display()
                    ),
                )
                    .into_response();
            }
            Json(serde_json::json!({ "ok": true, "path": path.display().to_string() }))
                .into_response()
        }
        Err(error) => session_operation_error_response(error),
    }
}

async fn get_runtime_settings(
    State(state): State<Arc<AppState>>,
    Query(query): Query<RuntimeQuery>,
) -> Response {
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    Json(session.runtime.snapshot().await.redacted_for_read()).into_response()
}

async fn get_workspace_state(
    State(state): State<Arc<AppState>>,
    Query(query): Query<WorkspaceStateQuery>,
) -> Response {
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let mut snapshot = session.workspace.snapshot().await;
    snapshot.session_id = Some(session.id());
    Json(snapshot).into_response()
}

async fn update_workspace_state(
    State(state): State<Arc<AppState>>,
    Json(snapshot): Json<WorkspaceStateSnapshot>,
) -> Response {
    let mut snapshot = snapshot;
    let Some(target_session_id) = snapshot.session_id else {
        let active_session = state.session().await;
        let mut current = active_session.workspace.snapshot().await;
        current.session_id = Some(active_session.id());
        return (StatusCode::CONFLICT, Json(current)).into_response();
    };
    let expected_active_session_id = snapshot.expected_active_session_id;
    if let Some(response) = expected_active_session_conflict_response(
        &state,
        expected_active_session_id,
        Some(target_session_id),
    ) {
        return response;
    }
    snapshot.expected_active_session_id = None;
    let active_session = state.session().await;
    if target_session_id != active_session.id()
        && proxy::live_websocket_session_context(target_session_id).is_none()
        && proxy::pending_session_context(target_session_id).is_none()
        && !proxy::session_has_active_proxy_work(target_session_id)
        && !state.sessions.contains_session(target_session_id)
    {
        let mut current = active_session.workspace.snapshot().await;
        current.session_id = Some(active_session.id());
        return (StatusCode::CONFLICT, Json(current)).into_response();
    }
    let workspace_update_lock = state.workspace_update_lock(target_session_id).await;
    let _workspace_update_guard = workspace_update_lock.lock().await;
    if let Some(response) = expected_active_session_conflict_response(
        &state,
        expected_active_session_id,
        Some(target_session_id),
    ) {
        return response;
    }
    let active_session = state.session().await;
    let session = if target_session_id == active_session.id() {
        active_session
    } else if proxy::session_has_active_proxy_work(target_session_id) {
        let mut current = active_session.workspace.snapshot().await;
        current.session_id = Some(active_session.id());
        return (StatusCode::CONFLICT, Json(current)).into_response();
    } else if let Some(session) = proxy::live_websocket_session_context(target_session_id) {
        session
    } else if let Some(session) = proxy::pending_session_context(target_session_id) {
        session
    } else if !state.sessions.contains_session(target_session_id) {
        let mut current = active_session.workspace.snapshot().await;
        current.session_id = Some(active_session.id());
        return (StatusCode::CONFLICT, Json(current)).into_response();
    } else {
        match state
            .session_context_for_id_operation_locked(target_session_id)
            .await
        {
            Ok(session) => session,
            Err(error) => return session_load_failure_response(target_session_id, error),
        }
    };
    snapshot.fuzzer.migrate_attack_record_to_id();
    let mut current = session.workspace.snapshot().await;
    current.session_id = Some(session.id());
    if !can_replace_snapshot(&snapshot, &current) {
        return (StatusCode::CONFLICT, Json(current)).into_response();
    }
    merge_incomplete_workspace_update_ws_frames(&mut snapshot, &current);
    if let Err(error) = validate_workspace_state(&snapshot) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    snapshot.session_id = Some(session.id());
    match state
        .replace_workspace_state_and_persist(&session, snapshot)
        .await
    {
        Ok(mut snapshot) => {
            snapshot.session_id = Some(session.id());
            Json(snapshot).into_response()
        }
        Err(WorkspaceReplaceError::Conflict(current)) => {
            let mut current = *current;
            current.session_id = Some(session.id());
            (StatusCode::CONFLICT, Json(current)).into_response()
        }
        Err(WorkspaceReplaceError::Persist(error)) => {
            tracing::warn!(%error, "failed to persist workspace state update");
            (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response()
        }
    }
}

async fn update_workspace_state_keepalive(
    State(state): State<Arc<AppState>>,
    Json(update): Json<WorkspaceKeepaliveUpdate>,
) -> Response {
    let mut snapshot = update.snapshot;
    let keepalive = update.keepalive;
    let Some(target_session_id) = snapshot.session_id else {
        return StatusCode::CONFLICT.into_response();
    };
    let expected_active_session_id = snapshot.expected_active_session_id;
    if let Some(response) = expected_active_session_conflict_response(
        &state,
        expected_active_session_id,
        Some(target_session_id),
    ) {
        return response;
    }
    snapshot.expected_active_session_id = None;
    let active_session = state.session().await;
    if target_session_id != active_session.id()
        && proxy::live_websocket_session_context(target_session_id).is_none()
        && proxy::pending_session_context(target_session_id).is_none()
        && !proxy::session_has_active_proxy_work(target_session_id)
        && !state.sessions.contains_session(target_session_id)
    {
        return StatusCode::CONFLICT.into_response();
    }
    let workspace_update_lock = state.workspace_update_lock(target_session_id).await;
    let _workspace_update_guard = workspace_update_lock.lock().await;
    if let Some(response) = expected_active_session_conflict_response(
        &state,
        expected_active_session_id,
        Some(target_session_id),
    ) {
        return response;
    }
    let active_session = state.session().await;
    let session = if target_session_id == active_session.id() {
        active_session
    } else if proxy::session_has_active_proxy_work(target_session_id) {
        return StatusCode::CONFLICT.into_response();
    } else if let Some(session) = proxy::live_websocket_session_context(target_session_id) {
        session
    } else if let Some(session) = proxy::pending_session_context(target_session_id) {
        session
    } else if !state.sessions.contains_session(target_session_id) {
        return StatusCode::CONFLICT.into_response();
    } else {
        match state
            .session_context_for_id_operation_locked(target_session_id)
            .await
        {
            Ok(session) => session,
            Err(error) => return session_load_failure_response(target_session_id, error),
        }
    };

    let mut incoming = snapshot;
    incoming.fuzzer.migrate_attack_record_to_id();
    let mut current = session.workspace.snapshot().await;
    current.session_id = Some(session.id());
    if !can_replace_snapshot(&incoming, &current) {
        return StatusCode::CONFLICT.into_response();
    }
    let mut merged = merge_workspace_keepalive_snapshot(current, incoming, keepalive);
    merged.session_id = Some(session.id());
    if let Err(error) = validate_workspace_state(&merged) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    match state
        .replace_workspace_state_and_persist(&session, merged)
        .await
    {
        Ok(mut snapshot) => {
            snapshot.session_id = Some(session.id());
            Json(snapshot).into_response()
        }
        Err(WorkspaceReplaceError::Conflict(_)) => StatusCode::CONFLICT.into_response(),
        Err(WorkspaceReplaceError::Persist(error)) => {
            tracing::warn!(%error, "failed to persist workspace keepalive update");
            (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response()
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct WorkspaceKeepaliveUpdate {
    #[serde(flatten)]
    snapshot: WorkspaceStateSnapshot,
    #[serde(default)]
    keepalive: WorkspaceKeepaliveMetadata,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct WorkspaceKeepaliveMetadata {
    #[serde(default)]
    replay_tabs_complete: bool,
    #[serde(default)]
    replay_tab_ids: Option<Vec<String>>,
    #[serde(default)]
    fuzzer_complete: bool,
    #[serde(default)]
    text_complete: Option<bool>,
    #[serde(default)]
    ws_text_complete: Option<bool>,
}

impl WorkspaceKeepaliveMetadata {
    fn text_complete(&self) -> bool {
        self.text_complete.unwrap_or(true)
    }

    fn ws_text_complete(&self) -> bool {
        self.ws_text_complete.unwrap_or(true)
    }
}

fn merge_workspace_keepalive_snapshot(
    mut current: WorkspaceStateSnapshot,
    incoming: WorkspaceStateSnapshot,
    keepalive: WorkspaceKeepaliveMetadata,
) -> WorkspaceStateSnapshot {
    current.client_id = incoming.client_id;
    current.client_version = incoming.client_version;
    let previous_active_tab_id = current.replay.active_tab_id.clone();
    if keepalive.replay_tabs_complete || incoming.replay.active_tab_id.is_some() {
        current.replay.active_tab_id = incoming.replay.active_tab_id.clone();
    }
    current.replay.tab_sequence = current
        .replay
        .tab_sequence
        .max(incoming.replay.tab_sequence);

    let mut incoming_payload_tab_ids = HashSet::new();
    let mut skipped_new_tab_ids = HashSet::new();
    for incoming_tab in incoming.replay.tabs {
        let incoming_tab_id = incoming_tab.id.clone();
        incoming_payload_tab_ids.insert(incoming_tab_id.clone());
        match current
            .replay
            .tabs
            .iter_mut()
            .find(|tab| tab.id == incoming_tab.id)
        {
            Some(current_tab) => {
                merge_workspace_keepalive_tab(current_tab, incoming_tab, &keepalive)
            }
            None => match keepalive_new_replay_tab(incoming_tab, &keepalive) {
                Some(tab) => current.replay.tabs.push(tab),
                None => {
                    skipped_new_tab_ids.insert(incoming_tab_id);
                }
            },
        }
    }
    if current
        .replay
        .active_tab_id
        .as_ref()
        .is_some_and(|id| skipped_new_tab_ids.contains(id))
    {
        current.replay.active_tab_id = previous_active_tab_id
            .filter(|id| current.replay.tabs.iter().any(|tab| tab.id == *id))
            .or_else(|| current.replay.tabs.first().map(|tab| tab.id.clone()));
    }
    let retain_replay_tab_ids = if keepalive.replay_tabs_complete {
        Some(incoming_payload_tab_ids)
    } else {
        keepalive_replay_tab_membership_ids(&keepalive)
    };
    if let Some(retain_replay_tab_ids) = retain_replay_tab_ids {
        current
            .replay
            .tabs
            .retain(|tab| retain_replay_tab_ids.contains(&tab.id));
        if current
            .replay
            .active_tab_id
            .as_ref()
            .is_some_and(|id| !current.replay.tabs.iter().any(|tab| tab.id == *id))
        {
            current.replay.active_tab_id = current.replay.tabs.first().map(|tab| tab.id.clone());
        }
    }

    if keepalive.fuzzer_complete {
        current.fuzzer =
            complete_workspace_keepalive_fuzzer(incoming.fuzzer, &current.fuzzer, &keepalive);
    } else if fuzzer_keepalive_has_payload(&incoming.fuzzer) {
        current.fuzzer =
            merge_workspace_keepalive_fuzzer(current.fuzzer, incoming.fuzzer, &keepalive);
    }

    current
}

fn keepalive_replay_tab_membership_ids(
    keepalive: &WorkspaceKeepaliveMetadata,
) -> Option<HashSet<String>> {
    let ids = keepalive.replay_tab_ids.as_ref()?;
    let mut membership = HashSet::new();
    for id in ids.iter().take(MAX_WORKSPACE_REPLAY_TABS) {
        if id.trim().is_empty() || id.len() > MAX_WORKSPACE_REPLAY_TAB_ID_BYTES {
            continue;
        }
        membership.insert(id.clone());
    }
    Some(membership)
}

fn keepalive_new_replay_tab(
    mut tab: ReplayTabState,
    keepalive: &WorkspaceKeepaliveMetadata,
) -> Option<ReplayTabState> {
    if tab.tab_type == "websocket" {
        if !keepalive.ws_text_complete() {
            return None;
        }
        if tab.ws_setup_queue_complete.is_none() || tab.ws_frames_complete.is_none() {
            return None;
        }
        if tab.ws_setup_queue_complete == Some(false) {
            tab.ws_setup_queue.clear();
        }
        if tab.ws_frames_complete == Some(false) {
            tab.ws_frames_truncated = true;
        }
        return Some(tab);
    }
    if !keepalive.text_complete() {
        return None;
    }
    if tab.history_entries_complete == Some(false) {
        tab.history_entries.clear();
        tab.history_index = None;
    }
    if tab.response_record_complete == Some(false) {
        tab.response_record = None;
    }
    Some(tab)
}

fn complete_workspace_keepalive_fuzzer(
    mut incoming: FuzzerWorkspaceState,
    current: &FuzzerWorkspaceState,
    keepalive: &WorkspaceKeepaliveMetadata,
) -> FuzzerWorkspaceState {
    if !keepalive.text_complete() {
        incoming = current.clone();
        incoming.attack_record = None;
        return incoming;
    }
    incoming.attack_record = None;
    incoming
}

fn merge_workspace_keepalive_ws_frames(
    current_frames: Vec<crate::ws_replay::WsReplayFrame>,
    incoming_frames: Vec<crate::ws_replay::WsReplayFrame>,
    current_truncated: bool,
    incoming_truncated: bool,
) -> (Vec<crate::ws_replay::WsReplayFrame>, bool) {
    let mut by_index = IndexMap::new();
    for frame in current_frames.into_iter().chain(incoming_frames) {
        by_index.insert(frame.index, frame);
    }
    let mut frames: Vec<_> = by_index.into_values().collect();
    frames.sort_by_key(|frame| frame.index);
    let mut truncated = current_truncated || incoming_truncated;
    if frames.len() > MAX_WORKSPACE_WS_FRAMES {
        let overflow = frames.len() - MAX_WORKSPACE_WS_FRAMES;
        frames.drain(..overflow);
        truncated = true;
    }
    (frames, truncated)
}

fn merge_incomplete_workspace_update_ws_frames(
    snapshot: &mut WorkspaceStateSnapshot,
    current: &WorkspaceStateSnapshot,
) {
    let current_tabs = current
        .replay
        .tabs
        .iter()
        .filter(|tab| tab.tab_type == "websocket")
        .map(|tab| (tab.id.as_str(), tab))
        .collect::<IndexMap<_, _>>();
    for tab in &mut snapshot.replay.tabs {
        if tab.tab_type != "websocket" || tab.ws_frames_complete != Some(false) {
            continue;
        }
        let Some(current_tab) = current_tabs.get(tab.id.as_str()) else {
            tab.ws_frames_truncated = true;
            continue;
        };
        let incoming_frames = std::mem::take(&mut tab.ws_frames);
        let (merged_frames, merged_truncated) = merge_workspace_keepalive_ws_frames(
            current_tab.ws_frames.clone(),
            incoming_frames,
            current_tab.ws_frames_truncated,
            tab.ws_frames_truncated,
        );
        tab.ws_frames = merged_frames;
        tab.ws_frames_truncated = merged_truncated;
        if tab.ws_selected_frame_index.is_none() {
            tab.ws_selected_frame_index = current_tab.ws_selected_frame_index;
        }
        if tab.ws_frame_window_start.is_none() {
            tab.ws_frame_window_start = current_tab.ws_frame_window_start;
        }
        tab.ws_frames_complete = Some(true);
    }
}

fn merge_workspace_keepalive_tab(
    current: &mut ReplayTabState,
    incoming: ReplayTabState,
    keepalive: &WorkspaceKeepaliveMetadata,
) {
    let request_text_changed =
        keepalive.text_complete() && incoming.request_text != current.request_text;
    let preserve_http_request_bound_state =
        current.tab_type != "websocket" && !keepalive.text_complete();
    let current_base_request = current.base_request.clone();
    let current_source_transaction_id = current.source_transaction_id;
    let current_request_text = current.request_text.clone();
    let current_http_version_mode = current.http_version_mode.clone();
    let current_history_entries = std::mem::take(&mut current.history_entries);
    let current_history_index = current.history_index;
    let current_response_record = current.response_record.take();
    let current_ws_handshake_text = std::mem::take(&mut current.ws_handshake_text);
    let current_ws_editor_text = std::mem::take(&mut current.ws_editor_text);
    let current_ws_setup_queue = std::mem::take(&mut current.ws_setup_queue);
    let current_ws_frames = std::mem::take(&mut current.ws_frames);
    let current_ws_selected_frame_index = current.ws_selected_frame_index;
    let current_ws_frame_window_start = current.ws_frame_window_start;
    let current_ws_frames_truncated = current.ws_frames_truncated;
    let incoming_response_record_complete = incoming.response_record_complete.unwrap_or(false);
    let incoming_history_entries_complete = incoming.history_entries_complete.unwrap_or(false);
    let incoming_ws_setup_queue_complete = incoming.ws_setup_queue_complete.unwrap_or(false);
    let incoming_ws_frames_complete = incoming.ws_frames_complete.unwrap_or(false);

    *current = incoming;

    let preserve_history_entries = preserve_http_request_bound_state
        || (current.history_entries.is_empty() && !incoming_history_entries_complete);
    if preserve_history_entries {
        current.history_entries = current_history_entries;
        if preserve_http_request_bound_state || current.history_index.is_none() {
            current.history_index = current_history_index;
        }
    }
    let preserve_response_record = preserve_http_request_bound_state
        || (current.response_record.is_none()
            && !request_text_changed
            && !incoming_response_record_complete);
    if preserve_response_record {
        current.response_record = current_response_record;
    }
    if current.tab_type != "websocket" && !keepalive.text_complete() {
        current.base_request = current_base_request;
        current.source_transaction_id = current_source_transaction_id;
        current.request_text = current_request_text;
        current.http_version_mode = current_http_version_mode;
    }
    if current.tab_type == "websocket" && !keepalive.ws_text_complete() {
        current.ws_handshake_text = current_ws_handshake_text;
        current.ws_editor_text = current_ws_editor_text;
    }
    let preserve_websocket_state = current.tab_type == "websocket";
    if preserve_websocket_state
        && current.ws_setup_queue.is_empty()
        && !incoming_ws_setup_queue_complete
    {
        current.ws_setup_queue = current_ws_setup_queue;
    }
    if preserve_websocket_state && !incoming_ws_frames_complete {
        let incoming_ws_frames = std::mem::take(&mut current.ws_frames);
        let incoming_ws_frames_truncated = current.ws_frames_truncated;
        let (merged_ws_frames, merged_ws_frames_truncated) = merge_workspace_keepalive_ws_frames(
            current_ws_frames,
            incoming_ws_frames,
            current_ws_frames_truncated,
            incoming_ws_frames_truncated,
        );
        current.ws_frames = merged_ws_frames;
        if current.ws_selected_frame_index.is_none() {
            current.ws_selected_frame_index = current_ws_selected_frame_index;
        }
        if current.ws_frame_window_start.is_none() {
            current.ws_frame_window_start = current_ws_frame_window_start;
        }
        current.ws_frames_truncated = merged_ws_frames_truncated;
    }
}

fn fuzzer_keepalive_has_payload(fuzzer: &FuzzerWorkspaceState) -> bool {
    fuzzer.base_request.is_some()
        || fuzzer.source_transaction_id.is_some()
        || fuzzer.target.is_some()
        || fuzzer.target_request_authority.is_some()
        || !fuzzer.notice.is_empty()
        || !fuzzer.request_text.is_empty()
        || !fuzzer.payloads_text.is_empty()
        || fuzzer.attack_record_id.is_some()
}

fn merge_workspace_keepalive_fuzzer(
    mut current: FuzzerWorkspaceState,
    incoming: FuzzerWorkspaceState,
    keepalive: &WorkspaceKeepaliveMetadata,
) -> FuzzerWorkspaceState {
    if !keepalive.text_complete() {
        current.attack_record = None;
        return current;
    }
    if incoming.base_request.is_some() {
        current.base_request = incoming.base_request;
    }
    if incoming.source_transaction_id.is_some() {
        current.source_transaction_id = incoming.source_transaction_id;
    }
    if incoming.target.is_some() {
        current.target = incoming.target;
    }
    if incoming.target_request_authority.is_some() {
        current.target_request_authority = incoming.target_request_authority;
    }
    if !incoming.notice.is_empty() {
        current.notice = incoming.notice;
    }
    if !incoming.request_text.is_empty() {
        current.request_text = incoming.request_text;
    }
    if !incoming.payloads_text.is_empty() {
        current.payloads_text = incoming.payloads_text;
    }
    if incoming.attack_record_id.is_some() {
        current.attack_record_id = incoming.attack_record_id;
    }
    current.attack_record = None;
    current
}

fn action_session_conflict_response(session: &Arc<SessionContext>) -> Response {
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({
            "error": "active session changed",
            "session_id": session.id(),
        })),
    )
        .into_response()
}

fn active_session_conflict_response(state: &AppState) -> Response {
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({
            "error": "active session changed",
            "session_id": state.sessions.active_session_id(),
        })),
    )
        .into_response()
}

fn expected_active_session_conflict_response(
    state: &AppState,
    expected_active_session_id: Option<Uuid>,
    target_session_id: Option<Uuid>,
) -> Option<Response> {
    let expected_active_session_id = expected_active_session_id?;
    (state.sessions.active_session_id() != expected_active_session_id
        || target_session_id
            .is_some_and(|target_session_id| target_session_id != expected_active_session_id))
    .then(|| active_session_conflict_response(state))
}

fn session_proxy_work_conflict_response(session_id: Uuid) -> Response {
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({
            "error": "session has active proxy work",
            "session_id": session_id,
        })),
    )
        .into_response()
}

fn ws_replay_connection_owner_conflict_response(owner_session_id: Uuid) -> Response {
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({
            "error": "websocket replay connection belongs to another session",
            "owner_session_id": owner_session_id,
        })),
    )
        .into_response()
}

fn session_load_failure_response(session_id: Uuid, error: anyhow::Error) -> Response {
    if error.to_string().contains("was not found") {
        return StatusCode::NOT_FOUND.into_response();
    }
    tracing::warn!(
        %error,
        session_id = %session_id,
        "failed to load session context"
    );
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("failed to load session {session_id}: {error}"),
    )
        .into_response()
}

async fn resolve_session_for_optional_id(
    state: &Arc<AppState>,
    target_session_id: Option<Uuid>,
) -> std::result::Result<Arc<SessionContext>, Response> {
    let active_session = state.session().await;
    let Some(target_session_id) = target_session_id else {
        return Ok(active_session);
    };
    if target_session_id == active_session.id() {
        return Ok(active_session);
    }
    if proxy::session_has_active_proxy_work(target_session_id) {
        return Err(session_proxy_work_conflict_response(target_session_id));
    }
    if let Some(session) = proxy::live_websocket_session_context(target_session_id) {
        return Ok(session);
    }
    if let Some(session) = proxy::pending_session_context(target_session_id) {
        return Ok(session);
    }
    if !state.sessions.contains_session(target_session_id) {
        return Err(StatusCode::NOT_FOUND.into_response());
    }
    state
        .session_context_for_id(target_session_id)
        .await
        .map_err(|error| session_load_failure_response(target_session_id, error))
}

async fn resolve_read_session_for_optional_id(
    state: &Arc<AppState>,
    target_session_id: Option<Uuid>,
) -> std::result::Result<Arc<SessionContext>, Response> {
    let active_session = state.session().await;
    let Some(target_session_id) = target_session_id else {
        return Ok(active_session);
    };
    if target_session_id == active_session.id() {
        return Ok(active_session);
    }
    if let Some(session) = proxy::live_websocket_session_context(target_session_id) {
        return Ok(session);
    }
    if let Some(session) = proxy::pending_session_context(target_session_id) {
        return Ok(session);
    }
    if !state.sessions.contains_session(target_session_id) {
        return Err(StatusCode::NOT_FOUND.into_response());
    }
    state
        .read_session_context_for_id(target_session_id)
        .await
        .map_err(|error| session_load_failure_response(target_session_id, error))
}

async fn guard_session_write_operation(
    state: &Arc<AppState>,
    session: &Arc<SessionContext>,
    require_still_active: bool,
) -> std::result::Result<OwnedMutexGuard<()>, Response> {
    let operation_lock = state.session_operation_lock(session.id()).await;
    let guard = operation_lock.lock_owned().await;
    if !state.sessions.contains_session(session.id()) {
        return Err(StatusCode::NOT_FOUND.into_response());
    }
    if require_still_active && state.sessions.active_session_id() != session.id() {
        return Err(active_session_conflict_response(state));
    }
    if !require_still_active
        && state.sessions.active_session_id() != session.id()
        && proxy::session_has_active_proxy_work(session.id())
    {
        return Err(session_proxy_work_conflict_response(session.id()));
    }
    Ok(guard)
}

async fn begin_session_proxy_operation(
    state: &Arc<AppState>,
    session: &Arc<SessionContext>,
    expected_active_session_id: Option<Uuid>,
    expected_workspace_revision: Option<u64>,
) -> std::result::Result<proxy::ActiveProxySessionGuard, Response> {
    let operation_lock = state.session_operation_lock(session.id()).await;
    let _operation_guard = operation_lock.lock().await;
    if !state.sessions.contains_session(session.id()) {
        return Err(StatusCode::NOT_FOUND.into_response());
    }
    if let Some(response) = expected_active_session_conflict_response(
        state,
        expected_active_session_id,
        Some(session.id()),
    ) {
        return Err(response);
    }
    if state.sessions.active_session_id() != session.id()
        && proxy::session_has_active_proxy_work(session.id())
    {
        return Err(session_proxy_work_conflict_response(session.id()));
    }
    if let Some(response) =
        expected_workspace_revision_conflict_response(session, expected_workspace_revision).await
    {
        return Err(response);
    }
    Ok(proxy::remember_active_proxy_session_owner(
        session.id(),
        proxy::PROXY_WORK_REPLAY,
    ))
}

async fn resolve_session_for_required_id(
    state: &Arc<AppState>,
    target_session_id: Option<Uuid>,
) -> std::result::Result<Arc<SessionContext>, Response> {
    let Some(target_session_id) = target_session_id else {
        let active_session = state.session().await;
        return Err(action_session_conflict_response(&active_session));
    };
    resolve_session_for_optional_id(state, Some(target_session_id)).await
}

async fn guard_ws_replay_connection_owner_read(
    state: &Arc<AppState>,
    id: Uuid,
    session_id: Uuid,
) -> std::result::Result<OwnedMutexGuard<()>, Response> {
    if !state.sessions.contains_session(session_id) {
        return Err(StatusCode::NOT_FOUND.into_response());
    }
    let operation_lock = state.session_operation_lock(session_id).await;
    let guard = operation_lock.lock_owned().await;
    if !state.sessions.contains_session(session_id) {
        return Err(StatusCode::NOT_FOUND.into_response());
    }
    match state.ws_replay.owner_session_id(id).await {
        Some(owner_session_id) if owner_session_id == session_id => Ok(guard),
        Some(owner_session_id) => Err(ws_replay_connection_owner_conflict_response(
            owner_session_id,
        )),
        None => Err(StatusCode::NOT_FOUND.into_response()),
    }
}

async fn guard_ws_replay_connection_owner_operation(
    state: &Arc<AppState>,
    id: Uuid,
    session: &Arc<SessionContext>,
    expected_active_session_id: Option<Uuid>,
    expected_workspace_revision: Option<u64>,
) -> std::result::Result<OwnedMutexGuard<()>, Response> {
    let session_id = session.id();
    if !state.sessions.contains_session(session_id) {
        return Err(StatusCode::NOT_FOUND.into_response());
    }
    let operation_lock = state.session_operation_lock(session_id).await;
    let guard = operation_lock.lock_owned().await;
    if !state.sessions.contains_session(session_id) {
        return Err(StatusCode::NOT_FOUND.into_response());
    }
    if let Some(response) = expected_active_session_conflict_response(
        state,
        expected_active_session_id,
        Some(session_id),
    ) {
        return Err(response);
    }
    if state.sessions.active_session_id() != session_id
        && proxy::session_has_active_proxy_work(session_id)
    {
        return Err(session_proxy_work_conflict_response(session_id));
    }
    if let Some(response) =
        expected_workspace_revision_conflict_response(session, expected_workspace_revision).await
    {
        return Err(response);
    }
    match state.ws_replay.owner_session_id(id).await {
        Some(owner_session_id) if owner_session_id == session_id => Ok(guard),
        Some(owner_session_id) => Err(ws_replay_connection_owner_conflict_response(
            owner_session_id,
        )),
        None => Err(StatusCode::NOT_FOUND.into_response()),
    }
}

async fn update_runtime_settings(
    State(state): State<Arc<AppState>>,
    Json(update): Json<RuntimeSettingsUpdate>,
) -> Response {
    let target_session_id = update.session_id;
    let expected_active_session_id = update.expected_active_session_id;
    if let Some(response) = expected_active_session_conflict_response(
        &state,
        expected_active_session_id,
        target_session_id,
    ) {
        return response;
    }
    let session = match resolve_session_for_optional_id(&state, target_session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let require_still_active = target_session_id.is_none() || expected_active_session_id.is_some();
    let _operation_guard =
        match guard_session_write_operation(&state, &session, require_still_active).await {
            Ok(guard) => guard,
            Err(response) => return response,
        };
    let _mutation_guard = session.mutation_guard().await;
    let previous = session.runtime.snapshot().await;
    let previous_events = session
        .event_log
        .snapshot(Some(state.config.max_entries))
        .await;
    let snapshot = match session.runtime.update(update).await {
        Ok(snapshot) => snapshot,
        Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    };
    session
        .event_log
        .push(
            EventLevel::Info,
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
    // Sync OAST config when runtime settings change
    session
        .oast
        .update_config(crate::oast::OastConfig {
            enabled: snapshot.oast_enabled,
            server_url: snapshot.oast_server_url.clone(),
            token: snapshot.oast_token.clone(),
            polling_interval_secs: snapshot.oast_polling_interval_secs,
            provider: snapshot.oast_provider.clone(),
        })
        .await;

    if let Err(response) = persist_session_mutation_locked_or_response(&state, &session).await {
        session.runtime.replace_snapshot(previous.clone()).await;
        session.event_log.replace_all(previous_events).await;
        session
            .oast
            .update_config(crate::oast::OastConfig {
                enabled: previous.oast_enabled,
                server_url: previous.oast_server_url,
                token: previous.oast_token,
                polling_interval_secs: previous.oast_polling_interval_secs,
                provider: previous.oast_provider,
            })
            .await;
        persist_rolled_back_session_snapshot(&state, &session, "runtime settings update").await;
        return response;
    }
    Json(snapshot.redacted_for_read()).into_response()
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
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

async fn update_startup_settings(
    State(state): State<Arc<AppState>>,
    Json(update): Json<StartupSettingsUpdate>,
) -> Response {
    let expected_active_session_id = update.expected_active_session_id;
    if let Some(response) =
        expected_active_session_conflict_response(&state, expected_active_session_id, None)
    {
        return response;
    }
    let _startup_guard = state.startup_settings_lock.lock().await;
    let _rebind_guard = state.proxy_rebind_lock.lock().await;
    if let Some(response) =
        expected_active_session_conflict_response(&state, expected_active_session_id, None)
    {
        return response;
    }
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
                match crate::proxy::rebind_proxy_locked(state.clone(), desired_addr).await {
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

            let rebind_event = match (rebound, &rebind_error) {
                (Some(true), _) => Some((
                    EventLevel::Info,
                    "Proxy listener rebound",
                    format!("Proxy listener moved to {}", view.active_proxy_addr),
                )),
                (Some(false), Some(err)) => Some((
                    EventLevel::Warn,
                    "Proxy rebind failed",
                    format!(
                        "Could not rebind to {}: {}. Saved for next launch.",
                        view.proxy_addr, err
                    ),
                )),
                _ => None,
            };
            if let Some((level, title, message)) = rebind_event {
                let event_session = state.session().await;
                let operation_guard =
                    guard_session_write_operation(&state, &event_session, true).await;
                if let Ok(_operation_guard) = operation_guard {
                    let _mutation_guard = event_session.mutation_guard().await;
                    let previous_events = event_session
                        .event_log
                        .snapshot(Some(state.config.max_entries))
                        .await;
                    event_session
                        .event_log
                        .push(level, "config", title, message)
                        .await;
                    if let Err(error) = state
                        .persist_session_context_mutation_locked(&event_session)
                        .await
                    {
                        event_session.event_log.replace_all(previous_events).await;
                        persist_rolled_back_session_snapshot(
                            &state,
                            &event_session,
                            "proxy rebind event log update",
                        )
                        .await;
                        tracing::warn!(
                            %error,
                            "failed to persist proxy rebind event log entry"
                        );
                    }
                }
            }

            Json(view).into_response()
        }
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

async fn list_event_log(
    State(state): State<Arc<AppState>>,
    Query(query): Query<EventLogQuery>,
) -> Response {
    if let Err(error) = validate_optional_limit(query.limit) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    Json(session.event_log.list(query.limit).await).into_response()
}

async fn clear_event_log(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionWriteQuery>,
) -> Response {
    if let Some(response) = expected_active_session_conflict_response(
        &state,
        query.expected_active_session_id,
        query.session_id,
    ) {
        return response;
    }
    let session = match resolve_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let _operation_guard = match guard_session_write_operation(
        &state,
        &session,
        query.session_id.is_none() || query.expected_active_session_id.is_some(),
    )
    .await
    {
        Ok(guard) => guard,
        Err(response) => return response,
    };
    let _mutation_guard = session.mutation_guard().await;
    let previous = session
        .event_log
        .snapshot(Some(state.config.max_entries))
        .await;
    session.event_log.clear().await;
    if persist_session_mutation_locked_or_status(&state, &session)
        .await
        .is_err()
    {
        session.event_log.replace_all(previous).await;
        persist_rolled_back_session_snapshot(&state, &session, "event log clear").await;
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    StatusCode::NO_CONTENT.into_response()
}

// ── Scanner findings ──

#[derive(Debug, Deserialize)]
struct FindingsQuery {
    session_id: Option<Uuid>,
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct FindingsCountResponse {
    count: usize,
}

#[derive(Debug, Deserialize)]
struct ScannerConfigPayload {
    #[serde(default)]
    session_id: Option<Uuid>,
    #[serde(flatten)]
    config: crate::scanner::ScannerConfig,
}

impl From<crate::scanner::ScannerConfig> for ScannerConfigPayload {
    fn from(config: crate::scanner::ScannerConfig) -> Self {
        Self {
            session_id: None,
            config,
        }
    }
}

async fn list_findings(
    State(state): State<Arc<AppState>>,
    Query(query): Query<FindingsQuery>,
) -> Response {
    if let Err(error) = validate_optional_limit(query.limit) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    Json(session.scanner.list(query.limit).await).into_response()
}

async fn count_findings(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionScopedQuery>,
) -> Response {
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    Json(FindingsCountResponse {
        count: session.scanner.count().await,
    })
    .into_response()
}

async fn get_finding(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<SessionScopedQuery>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    match session.scanner.get(id).await {
        Some(finding) => Json(finding).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn clear_findings(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionWriteQuery>,
) -> Response {
    if let Some(response) = expected_active_session_conflict_response(
        &state,
        query.expected_active_session_id,
        query.session_id,
    ) {
        return response;
    }
    let session = match resolve_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let _operation_guard = match guard_session_write_operation(
        &state,
        &session,
        query.session_id.is_none() || query.expected_active_session_id.is_some(),
    )
    .await
    {
        Ok(guard) => guard,
        Err(response) => return response,
    };
    let _mutation_guard = session.mutation_guard().await;
    let previous = session
        .scanner
        .snapshot(Some(state.config.max_entries))
        .await;
    let previous_generation = session.scanner.clear_generation();
    session.scanner.clear().await;
    if persist_session_mutation_locked_or_status(&state, &session)
        .await
        .is_err()
    {
        session.scanner.replace_all(previous).await;
        session
            .scanner
            .restore_clear_generation(previous_generation);
        persist_rolled_back_session_snapshot(&state, &session, "scanner findings clear").await;
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn get_scanner_config(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionScopedQuery>,
) -> Response {
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    Json(session.scanner.get_config().await).into_response()
}

async fn update_scanner_config(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionWriteQuery>,
    Json(payload): Json<ScannerConfigPayload>,
) -> Response {
    let (target_session_id, session_id_is_explicit) =
        match reconcile_write_session_id(query.session_id, payload.session_id) {
            Ok(value) => value,
            Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
        };
    if let Some(response) = expected_active_session_conflict_response(
        &state,
        query.expected_active_session_id,
        target_session_id,
    ) {
        return response;
    }
    let session = match resolve_session_for_optional_id(&state, target_session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(error) = validate_scanner_config(&payload.config) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    let _operation_guard = match guard_session_write_operation(
        &state,
        &session,
        !session_id_is_explicit || query.expected_active_session_id.is_some(),
    )
    .await
    {
        Ok(guard) => guard,
        Err(response) => return response,
    };
    let _mutation_guard = session.mutation_guard().await;
    let previous = session.scanner.get_config().await;
    session.scanner.update_config(payload.config).await;
    if let Err(response) = persist_session_mutation_locked_or_response(&state, &session).await {
        session.scanner.update_config(previous).await;
        persist_rolled_back_session_snapshot(&state, &session, "scanner config update").await;
        return response;
    }
    StatusCode::NO_CONTENT.into_response()
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

async fn reveal_certificate_folder(State(state): State<Arc<AppState>>) -> Response {
    let export = state.certificates.export();
    match spawn_open_command(OPEN_PATH, ["-R", export.pem_path.as_str()]) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to reveal certificate folder: {error}"),
        )
            .into_response(),
    }
}

fn spawn_open_command<I, S>(program: &str, args: I) -> std::io::Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    std::process::Command::new(program)
        .args(args)
        .spawn()
        .map(|_| ())
}

async fn list_match_replace_rules(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionScopedQuery>,
) -> Response {
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    Json(session.match_replace.snapshot().await).into_response()
}

async fn update_match_replace_rules(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionWriteQuery>,
    Json(payload): Json<MatchReplaceRulesPayload>,
) -> Response {
    let (target_session_id, session_id_is_explicit) =
        match reconcile_write_session_id(query.session_id, payload.session_id) {
            Ok(value) => value,
            Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
        };
    if let Some(response) = expected_active_session_conflict_response(
        &state,
        query.expected_active_session_id,
        target_session_id,
    ) {
        return response;
    }
    let session = match resolve_session_for_optional_id(&state, target_session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(error) = validate_match_replace_rules(&payload.rules) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    let _operation_guard = match guard_session_write_operation(
        &state,
        &session,
        !session_id_is_explicit || query.expected_active_session_id.is_some(),
    )
    .await
    {
        Ok(guard) => guard,
        Err(response) => return response,
    };
    let _mutation_guard = session.mutation_guard().await;
    let previous_rules = session.match_replace.snapshot().await;
    let previous_events = session
        .event_log
        .snapshot(Some(state.config.max_entries))
        .await;
    let rules = session.match_replace.replace_all(payload.rules).await;
    session
        .event_log
        .push(
            EventLevel::Info,
            "match_replace",
            "Rules updated",
            format!("{} rule(s) active in configuration", rules.len()),
        )
        .await;
    if let Err(response) = persist_session_mutation_locked_or_response(&state, &session).await {
        session.match_replace.replace_all(previous_rules).await;
        session.event_log.replace_all(previous_events).await;
        persist_rolled_back_session_snapshot(&state, &session, "match/replace rules update").await;
        return response;
    }
    Json(rules).into_response()
}

async fn get_target_site_map(
    State(state): State<Arc<AppState>>,
    Query(query): Query<TargetSiteMapQuery>,
) -> Response {
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let records = session.store.site_map_records().await;
    let mut hosts = IndexMap::<String, TargetHostAccumulator>::new();

    for record in records {
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
                is_websocket: record.is_websocket,
            });
        push_unique(&mut path.methods, record.method.clone());
        if record.started_at > path.last_seen {
            path.last_seen = record.started_at;
            path.status = record.status;
        }
        path.note_count += record.note_count;
        path.is_websocket = path.is_websocket || record.is_websocket;
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
        paths.sort_by_key(|path| std::cmp::Reverse(path.last_seen));

        site_map.push(TargetHostNode {
            host: host.host.clone(),
            schemes: host.schemes,
            request_count: host.request_count,
            in_scope: session.runtime.is_in_scope(&host.host).await,
            paths,
        });
    }

    Json(site_map).into_response()
}

async fn list_transactions(
    State(state): State<Arc<AppState>>,
    Query(mut query): Query<TransactionQuery>,
) -> Response {
    const MAX_PAGE_LIMIT: usize = 10000;

    if let Err(error) = validate_transaction_query(&query) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    if let Some(limit) = query.limit {
        query.limit = Some(limit.clamp(1, MAX_PAGE_LIMIT));
    }
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let runtime = session.runtime.snapshot().await;
    let filters = transaction_list_filters(
        query,
        runtime.scope_patterns,
        runtime.excluded_scope_patterns,
    );
    Json(session.store.list(&filters).await).into_response()
}

async fn list_transactions_page(
    State(state): State<Arc<AppState>>,
    Query(mut query): Query<TransactionQuery>,
) -> Response {
    const DEFAULT_PAGE_LIMIT: usize = 5000;
    const MAX_PAGE_LIMIT: usize = 10000;

    if let Err(error) = validate_transaction_query(&query) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    query.limit = Some(
        query
            .limit
            .unwrap_or(DEFAULT_PAGE_LIMIT)
            .clamp(1, MAX_PAGE_LIMIT),
    );
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let runtime = session.runtime.snapshot().await;
    let filters = transaction_list_filters(
        query,
        runtime.scope_patterns,
        runtime.excluded_scope_patterns,
    );
    let page = session.store.list_page(&filters).await;
    Json(TransactionPageResponse::from(page)).into_response()
}

async fn get_transaction(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<TransactionGetQuery>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    match session.store.get(id).await {
        Some(record) => Json(record).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn update_transaction_annotations(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<TransactionWriteQuery>,
    Json(payload): Json<AnnotationsPayload>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let (target_session_id, session_id_is_explicit) =
        match reconcile_write_session_id(query.session_id, payload.session_id) {
            Ok(value) => value,
            Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
        };
    if let Some(response) = expected_active_session_conflict_response(
        &state,
        query.expected_active_session_id,
        target_session_id,
    ) {
        return response;
    }
    let session = match resolve_session_for_optional_id(&state, target_session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let _operation_guard = match guard_session_write_operation(
        &state,
        &session,
        !session_id_is_explicit || query.expected_active_session_id.is_some(),
    )
    .await
    {
        Ok(guard) => guard,
        Err(response) => return response,
    };
    if let Err(message) = validate_annotations_payload(&payload) {
        return (StatusCode::BAD_REQUEST, message).into_response();
    }
    let _mutation_guard = session.mutation_guard().await;
    match session
        .store
        .update_annotations_durable_with_client(
            id,
            payload.color_tag,
            payload.user_note,
            payload.client_id,
            payload.client_version,
        )
        .await
    {
        Ok(Some(update)) => Json(update.summary).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::warn!(
                ?error,
                transaction_id = %id,
                "failed to persist transaction annotation journal entry"
            );
            (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response()
        }
    }
}

async fn list_intercepts(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionScopedQuery>,
) -> Response {
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    Json(session.intercepts.list().await).into_response()
}

async fn get_intercept(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<SessionScopedQuery>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    match session.intercepts.get(id).await {
        Some(record) => Json(record).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn forward_intercept(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<SessionWriteQuery>,
    Json(payload): Json<InterceptForwardPayload>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let (target_session_id, session_id_is_explicit) =
        match reconcile_write_session_id(query.session_id, payload.session_id) {
            Ok(value) => value,
            Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
        };
    if let Some(response) = expected_active_session_conflict_response(
        &state,
        query.expected_active_session_id,
        target_session_id,
    ) {
        return response;
    }
    let session = match resolve_session_for_optional_id(&state, target_session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if session.intercepts.get(id).await.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let payload_edited = payload.edited;
    let request = match canonicalize_intercept_forward_request(payload.request) {
        Ok(request) => request,
        Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
    };

    let _operation_guard = match guard_session_write_operation(
        &state,
        &session,
        !session_id_is_explicit || query.expected_active_session_id.is_some(),
    )
    .await
    {
        Ok(guard) => guard,
        Err(response) => return response,
    };
    let _mutation_guard = session.mutation_guard().await;
    let previous_events = session
        .event_log
        .snapshot(Some(state.config.max_entries))
        .await;
    if let Err(error) = session
        .intercepts
        .forward(id, request, payload_edited)
        .await
    {
        return intercept_action_error_status(&error).into_response();
    }
    session
        .event_log
        .push(
            EventLevel::Info,
            "intercept",
            "Request forwarded",
            format!("Intercept item {id} forwarded"),
        )
        .await;
    persist_nonrollbackable_event_log_mutation(
        &state,
        &session,
        previous_events,
        "request intercept forward",
    )
    .await;
    StatusCode::NO_CONTENT.into_response()
}

async fn drop_intercept(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<SessionWriteQuery>,
    payload: Option<Json<SessionActionPayload>>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let (target_session_id, session_id_is_explicit) = match reconcile_write_session_id(
        query.session_id,
        payload
            .map(|Json(payload)| payload.session_id)
            .unwrap_or(None),
    ) {
        Ok(value) => value,
        Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
    };
    if let Some(response) = expected_active_session_conflict_response(
        &state,
        query.expected_active_session_id,
        target_session_id,
    ) {
        return response;
    }
    let session = match resolve_session_for_optional_id(&state, target_session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if session.intercepts.get(id).await.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }

    let _operation_guard = match guard_session_write_operation(
        &state,
        &session,
        !session_id_is_explicit || query.expected_active_session_id.is_some(),
    )
    .await
    {
        Ok(guard) => guard,
        Err(response) => return response,
    };
    let _mutation_guard = session.mutation_guard().await;
    let previous_events = session
        .event_log
        .snapshot(Some(state.config.max_entries))
        .await;
    if let Err(error) = session.intercepts.drop_request(id).await {
        return intercept_action_error_status(&error).into_response();
    }
    session
        .event_log
        .push(
            EventLevel::Warn,
            "intercept",
            "Request dropped",
            format!("Intercept item {id} dropped"),
        )
        .await;
    persist_nonrollbackable_event_log_mutation(
        &state,
        &session,
        previous_events,
        "request intercept drop",
    )
    .await;
    StatusCode::NO_CONTENT.into_response()
}

async fn forward_all_intercepts(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionWriteQuery>,
    payload: Option<Json<SessionActionPayload>>,
) -> Response {
    let (target_session_id, session_id_is_explicit) = match reconcile_write_session_id(
        query.session_id,
        payload
            .map(|Json(payload)| payload.session_id)
            .unwrap_or(None),
    ) {
        Ok(value) => value,
        Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
    };
    if let Some(response) = expected_active_session_conflict_response(
        &state,
        query.expected_active_session_id,
        target_session_id,
    ) {
        return response;
    }
    let session = match resolve_session_for_optional_id(&state, target_session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let _operation_guard = match guard_session_write_operation(
        &state,
        &session,
        !session_id_is_explicit || query.expected_active_session_id.is_some(),
    )
    .await
    {
        Ok(guard) => guard,
        Err(response) => return response,
    };
    let _mutation_guard = session.mutation_guard().await;
    let previous_events = session
        .event_log
        .snapshot(Some(state.config.max_entries))
        .await;
    let count = session.intercepts.forward_all().await;
    if count > 0 {
        session
            .event_log
            .push(
                EventLevel::Info,
                "intercept",
                "All requests forwarded",
                format!("{count} intercepted request(s) forwarded"),
            )
            .await;
        persist_nonrollbackable_event_log_mutation(
            &state,
            &session,
            previous_events,
            "request intercept forward all",
        )
        .await;
    }
    Json(serde_json::json!({
        "ok": true,
        "action": "forward-all",
        "forwarded": count,
    }))
    .into_response()
}

async fn list_intercept_rules(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionScopedQuery>,
) -> Response {
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    Json(session.intercept_rules.list().await).into_response()
}

async fn upsert_intercept_rule(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionWriteQuery>,
    Json(payload): Json<InterceptRulePayload>,
) -> Response {
    let (target_session_id, session_id_is_explicit) =
        match reconcile_write_session_id(query.session_id, payload.session_id) {
            Ok(value) => value,
            Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
        };
    if let Some(response) = expected_active_session_conflict_response(
        &state,
        query.expected_active_session_id,
        target_session_id,
    ) {
        return response;
    }
    let session = match resolve_session_for_optional_id(&state, target_session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let _operation_guard = match guard_session_write_operation(
        &state,
        &session,
        !session_id_is_explicit || query.expected_active_session_id.is_some(),
    )
    .await
    {
        Ok(guard) => guard,
        Err(response) => return response,
    };
    let _mutation_guard = session.mutation_guard().await;
    let previous = session.intercept_rules.snapshot().await;
    session.intercept_rules.upsert(payload.rule).await;
    if persist_session_mutation_locked_or_status(&state, &session)
        .await
        .is_err()
    {
        session.intercept_rules.replace_all(previous).await;
        persist_rolled_back_session_snapshot(&state, &session, "intercept rule upsert").await;
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn delete_intercept_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<SessionWriteQuery>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    if let Some(response) = expected_active_session_conflict_response(
        &state,
        query.expected_active_session_id,
        query.session_id,
    ) {
        return response;
    }
    let session = match resolve_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let _operation_guard = match guard_session_write_operation(
        &state,
        &session,
        query.session_id.is_none() || query.expected_active_session_id.is_some(),
    )
    .await
    {
        Ok(guard) => guard,
        Err(response) => return response,
    };
    let _mutation_guard = session.mutation_guard().await;
    let previous = session.intercept_rules.snapshot().await;
    if session.intercept_rules.delete(id).await {
        if let Err(response) = persist_session_mutation_locked_or_response(&state, &session).await {
            session.intercept_rules.replace_all(previous).await;
            persist_rolled_back_session_snapshot(&state, &session, "intercept rule delete").await;
            return response;
        }
        StatusCode::NO_CONTENT.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

// ── Response Intercepts ──

async fn list_response_intercepts(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionScopedQuery>,
) -> Response {
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    Json(session.response_intercepts.list().await).into_response()
}

async fn get_response_intercept(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<SessionScopedQuery>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    match session.response_intercepts.get(id).await {
        Some(record) => Json(record).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn forward_response_intercept(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<SessionWriteQuery>,
    Json(payload): Json<ResponseInterceptForwardPayload>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let (target_session_id, session_id_is_explicit) =
        match reconcile_write_session_id(query.session_id, payload.session_id) {
            Ok(value) => value,
            Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
        };
    if let Some(response) = expected_active_session_conflict_response(
        &state,
        query.expected_active_session_id,
        target_session_id,
    ) {
        return response;
    }
    let session = match resolve_session_for_optional_id(&state, target_session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let Some(intercept_record) = session.response_intercepts.get(id).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let payload_edited = payload.edited;
    let response_payload =
        match canonicalize_intercept_forward_response(payload.response, &intercept_record.method) {
            Ok(response) => response,
            Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
        };

    let _operation_guard = match guard_session_write_operation(
        &state,
        &session,
        !session_id_is_explicit || query.expected_active_session_id.is_some(),
    )
    .await
    {
        Ok(guard) => guard,
        Err(response) => return response,
    };
    let _mutation_guard = session.mutation_guard().await;
    let previous_events = session
        .event_log
        .snapshot(Some(state.config.max_entries))
        .await;
    if let Err(error) = session
        .response_intercepts
        .forward(id, response_payload, payload_edited)
        .await
    {
        return intercept_action_error_status(&error).into_response();
    }
    session
        .event_log
        .push(
            EventLevel::Info,
            "intercept",
            "Response forwarded",
            format!("Response intercept item {id} forwarded"),
        )
        .await;
    persist_nonrollbackable_event_log_mutation(
        &state,
        &session,
        previous_events,
        "response intercept forward",
    )
    .await;
    StatusCode::NO_CONTENT.into_response()
}

async fn drop_response_intercept(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<SessionWriteQuery>,
    payload: Option<Json<SessionActionPayload>>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let (target_session_id, session_id_is_explicit) = match reconcile_write_session_id(
        query.session_id,
        payload
            .map(|Json(payload)| payload.session_id)
            .unwrap_or(None),
    ) {
        Ok(value) => value,
        Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
    };
    if let Some(response) = expected_active_session_conflict_response(
        &state,
        query.expected_active_session_id,
        target_session_id,
    ) {
        return response;
    }
    let session = match resolve_session_for_optional_id(&state, target_session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if session.response_intercepts.get(id).await.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }

    let _operation_guard = match guard_session_write_operation(
        &state,
        &session,
        !session_id_is_explicit || query.expected_active_session_id.is_some(),
    )
    .await
    {
        Ok(guard) => guard,
        Err(response) => return response,
    };
    let _mutation_guard = session.mutation_guard().await;
    let previous_events = session
        .event_log
        .snapshot(Some(state.config.max_entries))
        .await;
    if let Err(error) = session.response_intercepts.drop_response(id).await {
        return intercept_action_error_status(&error).into_response();
    }
    session
        .event_log
        .push(
            EventLevel::Warn,
            "intercept",
            "Response dropped",
            format!("Response intercept item {id} dropped"),
        )
        .await;
    persist_nonrollbackable_event_log_mutation(
        &state,
        &session,
        previous_events,
        "response intercept drop",
    )
    .await;
    StatusCode::NO_CONTENT.into_response()
}

async fn forward_all_response_intercepts(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionWriteQuery>,
    payload: Option<Json<SessionActionPayload>>,
) -> Response {
    let (target_session_id, session_id_is_explicit) = match reconcile_write_session_id(
        query.session_id,
        payload
            .map(|Json(payload)| payload.session_id)
            .unwrap_or(None),
    ) {
        Ok(value) => value,
        Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
    };
    if let Some(response) = expected_active_session_conflict_response(
        &state,
        query.expected_active_session_id,
        target_session_id,
    ) {
        return response;
    }
    let session = match resolve_session_for_optional_id(&state, target_session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let _operation_guard = match guard_session_write_operation(
        &state,
        &session,
        !session_id_is_explicit || query.expected_active_session_id.is_some(),
    )
    .await
    {
        Ok(guard) => guard,
        Err(response) => return response,
    };
    let _mutation_guard = session.mutation_guard().await;
    let previous_events = session
        .event_log
        .snapshot(Some(state.config.max_entries))
        .await;
    let count = session.response_intercepts.forward_all().await;
    if count > 0 {
        session
            .event_log
            .push(
                EventLevel::Info,
                "intercept",
                "All responses forwarded",
                format!("{count} intercepted response(s) forwarded"),
            )
            .await;
        persist_nonrollbackable_event_log_mutation(
            &state,
            &session,
            previous_events,
            "response intercept forward all",
        )
        .await;
    }
    Json(serde_json::json!({
        "ok": true,
        "action": "forward-all",
        "forwarded": count,
    }))
    .into_response()
}

// ── Sequences ──

#[derive(Debug, Deserialize)]
struct SequenceQuery {
    limit: Option<usize>,
    session_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
struct SequenceSessionQuery {
    session_id: Option<Uuid>,
    #[serde(default)]
    expected_active_session_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
struct SequenceUpsertPayload {
    session_id: Option<Uuid>,
    #[serde(default)]
    expected_active_session_id: Option<Uuid>,
    #[serde(flatten)]
    definition: SequenceDefinition,
}

#[derive(Debug, Deserialize)]
struct SequenceRunPayload {
    session_id: Option<Uuid>,
    expected_active_session_id: Option<Uuid>,
}

async fn list_sequences(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SequenceSessionQuery>,
) -> Response {
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    Json(session.sequence.list_definitions().await).into_response()
}

async fn get_sequence(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<SequenceSessionQuery>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    match session.sequence.get_definition(id).await {
        Some(definition) => Json(definition).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn upsert_sequence(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SequenceUpsertPayload>,
) -> Response {
    let session = match resolve_session_for_required_id(&state, payload.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Some(response) = expected_active_session_conflict_response(
        &state,
        payload.expected_active_session_id,
        Some(session.id()),
    ) {
        return response;
    }
    let definition = payload.definition;
    if let Err(error) = validate_sequence_definition(&definition) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    let _operation_guard = match guard_session_write_operation(
        &state,
        &session,
        payload.expected_active_session_id.is_some(),
    )
    .await
    {
        Ok(guard) => guard,
        Err(response) => return response,
    };
    let _mutation_guard = session.mutation_guard().await;
    let previous = session.sequence.snapshot_definitions().await;
    session.sequence.upsert_definition(definition).await;
    if let Err(response) = persist_session_mutation_locked_or_response(&state, &session).await {
        session.sequence.replace_definitions(previous).await;
        persist_rolled_back_session_snapshot(&state, &session, "sequence upsert").await;
        return response;
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn delete_sequence(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<SequenceSessionQuery>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let session = match resolve_session_for_required_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Some(response) = expected_active_session_conflict_response(
        &state,
        query.expected_active_session_id,
        Some(session.id()),
    ) {
        return response;
    }
    let _operation_guard = match guard_session_write_operation(
        &state,
        &session,
        query.expected_active_session_id.is_some(),
    )
    .await
    {
        Ok(guard) => guard,
        Err(response) => return response,
    };
    let _mutation_guard = session.mutation_guard().await;
    let previous = session.sequence.snapshot_definitions().await;
    if session.sequence.delete_definition(id).await {
        if let Err(response) = persist_session_mutation_locked_or_response(&state, &session).await {
            session.sequence.replace_definitions(previous).await;
            persist_rolled_back_session_snapshot(&state, &session, "sequence delete").await;
            return response;
        }
        StatusCode::NO_CONTENT.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

async fn run_sequence(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(payload): Json<SequenceRunPayload>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid sequence ID").into_response(),
    };
    let session = match resolve_session_for_required_id(&state, payload.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Some(response) = expected_active_session_conflict_response(
        &state,
        payload.expected_active_session_id,
        Some(session.id()),
    ) {
        return response;
    }
    let _session_owner = match begin_session_proxy_operation(
        &state,
        &session,
        payload.expected_active_session_id,
        None,
    )
    .await
    {
        Ok(owner) => owner,
        Err(response) => return response,
    };
    let definition = match session.sequence.get_definition(id).await {
        Some(def) => def,
        None => return (StatusCode::NOT_FOUND, "Sequence not found").into_response(),
    };
    if let Err(error) = validate_sequence_definition(&definition) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    match sequence::run_sequence(state, session, definition).await {
        Ok(record) => Json(record).into_response(),
        Err(error) => (sequence_run_error_status(&error), error.to_string()).into_response(),
    }
}

async fn list_sequence_runs(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SequenceQuery>,
) -> Response {
    if let Err(error) = validate_optional_limit(query.limit) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    Json(session.sequence.list_runs(query.limit).await).into_response()
}

async fn get_sequence_run(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<SequenceSessionQuery>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    match session.sequence.get_run(id).await {
        Some(run) => Json(run).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn send_replay(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ReplaySendPayload>,
) -> Response {
    let session = match resolve_session_for_required_id(&state, payload.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Some(response) = expected_active_session_conflict_response(
        &state,
        payload.expected_active_session_id,
        Some(session.id()),
    ) {
        return response;
    }
    if let Some(response) =
        expected_workspace_revision_conflict_response(&session, payload.expected_workspace_revision)
            .await
    {
        return response;
    }
    let http_version = match normalize_replay_http_version(payload.http_version.as_deref()) {
        Ok(value) => value,
        Err(error) => return replay_send_error_response(error),
    };
    if let Some(target) = payload.target.as_ref() {
        if let Err(error) = validate_request_target_override_for_request(&payload.request, target) {
            return replay_send_error_response(error);
        }
    }
    if let Err(error) = validate_runnable_editable_request(&payload.request) {
        return replay_send_error_response(error);
    }
    let _session_owner = match begin_session_proxy_operation(
        &state,
        &session,
        payload.expected_active_session_id,
        payload.expected_workspace_revision,
    )
    .await
    {
        Ok(owner) => owner,
        Err(response) => {
            return response;
        }
    };
    match proxy::try_send_replay_request_for_session(
        state,
        session,
        payload.request,
        payload.target,
        payload.source_transaction_id,
        http_version,
    )
    .await
    {
        Ok(record) => Json(record).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(ReplaySendErrorResponse {
                error: error.to_string(),
                record: error.record().cloned(),
            }),
        )
            .into_response(),
    }
}

fn fuzzer_attack_error_status(error: &anyhow::Error) -> StatusCode {
    if error
        .chain()
        .any(|cause| cause.is::<fuzzer::FuzzerPersistenceError>())
    {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::BAD_REQUEST
    }
}

fn intercept_action_error_status(error: &anyhow::Error) -> StatusCode {
    if error.to_string().contains("was not found") {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

fn sequence_run_error_status(error: &anyhow::Error) -> StatusCode {
    if error
        .chain()
        .any(|cause| cause.is::<sequence::SequencePersistenceError>())
    {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::BAD_REQUEST
    }
}

async fn list_fuzzer_attacks(
    State(state): State<Arc<AppState>>,
    Query(query): Query<FuzzerQuery>,
) -> Response {
    if let Err(error) = validate_optional_limit(query.limit) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    Json(session.fuzzer.list(query.limit).await).into_response()
}

async fn get_fuzzer_attack(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<FuzzerQuery>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    match session.fuzzer.get(id).await {
        Some(record) => Json(record).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn run_fuzzer_attack(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<FuzzerAttackPayload>,
) -> Response {
    let session = match resolve_session_for_required_id(&state, payload.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Some(response) = expected_active_session_conflict_response(
        &state,
        payload.expected_active_session_id,
        Some(session.id()),
    ) {
        return response;
    }
    if let Some(response) =
        expected_workspace_revision_conflict_response(&session, payload.expected_workspace_revision)
            .await
    {
        return response;
    }
    let http_version = match normalize_replay_http_version(payload.http_version.as_deref()) {
        Ok(value) => value,
        Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
    };
    if let Some(target) = payload.target.as_ref() {
        if let Err(error) = validate_request_target_override(target) {
            return (StatusCode::BAD_REQUEST, error).into_response();
        }
    }
    let target = payload.target.as_ref();
    if let Err(error) =
        fuzzer::validate_expanded_requests(&payload.template, &payload.payloads, |request| {
            validate_runnable_editable_request(request)?;
            if let Some(target) = target {
                validate_request_target_override_for_request(request, target)?;
            }
            Ok(())
        })
    {
        return (StatusCode::BAD_REQUEST, error.to_string()).into_response();
    }
    let _session_owner = match begin_session_proxy_operation(
        &state,
        &session,
        payload.expected_active_session_id,
        payload.expected_workspace_revision,
    )
    .await
    {
        Ok(owner) => owner,
        Err(response) => return response,
    };
    match fuzzer::run_attack_for_session(
        state,
        session,
        payload.template,
        payload.payloads,
        payload.source_transaction_id,
        http_version,
        payload.target,
    )
    .await
    {
        Ok(record) => Json(record).into_response(),
        Err(error) => (fuzzer_attack_error_status(&error), error.to_string()).into_response(),
    }
}

async fn list_websockets(
    State(state): State<Arc<AppState>>,
    Query(mut query): Query<WebSocketQuery>,
) -> Response {
    const MAX_PAGE_LIMIT: usize = 10_000;

    if let Err(error) = validate_websocket_query(&query) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    if let Some(limit) = query.limit {
        query.limit = Some(limit.clamp(1, MAX_PAGE_LIMIT));
    }
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let runtime = session.runtime.snapshot().await;
    let filters = websocket_list_filters(
        &query,
        runtime.scope_patterns,
        runtime.excluded_scope_patterns,
    );
    let page = session.websockets.list_page_filtered(&filters).await;
    Json(page.items).into_response()
}

async fn list_websockets_page(
    State(state): State<Arc<AppState>>,
    Query(mut query): Query<WebSocketQuery>,
) -> Response {
    const MAX_PAGE_LIMIT: usize = 10_000;

    if let Err(error) = validate_websocket_query(&query) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    if let Some(limit) = query.limit {
        query.limit = Some(limit.clamp(1, MAX_PAGE_LIMIT));
    }
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let runtime = session.runtime.snapshot().await;
    let filters = websocket_list_filters(
        &query,
        runtime.scope_patterns,
        runtime.excluded_scope_patterns,
    );
    let page = session.websockets.list_page_filtered(&filters).await;
    Json(WebSocketPageResponse {
        items: page.items,
        total: page.total,
        filtered_total: page.filtered_total,
        offset: page.offset,
        limit: page.limit,
        has_more: page.has_more,
    })
    .into_response()
}

async fn get_websocket(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<WebSocketQuery>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let frame_limit = Some(websocket_detail_frame_limit(query.frame_limit));
    match session
        .websockets
        .get_windowed(id, frame_limit, query.before_index)
        .await
    {
        Some(record) => Json(record).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn websocket_detail_frame_limit(frame_limit: Option<usize>) -> usize {
    frame_limit
        .unwrap_or(DEFAULT_WEBSOCKET_DETAIL_FRAME_LIMIT)
        .min(MAX_WEBSOCKET_DETAIL_FRAME_LIMIT)
}

// --- WebSocket Replay handlers ---

#[derive(Debug, Deserialize)]
struct WsReplayConnectPayload {
    session_id: Option<Uuid>,
    #[serde(default)]
    expected_active_session_id: Option<Uuid>,
    #[serde(default)]
    expected_workspace_revision: Option<u64>,
    id: Uuid,
    scheme: String,
    host: String,
    port: u16,
    path: String,
    #[serde(default)]
    headers: Vec<crate::model::HeaderRecord>,
}

async fn ws_replay_connect(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<WsReplayConnectPayload>,
) -> Response {
    if let Some(response) = expected_active_session_conflict_response(
        &state,
        payload.expected_active_session_id,
        payload.session_id,
    ) {
        return response;
    }
    let session = match resolve_session_for_required_id(&state, payload.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Some(response) =
        expected_workspace_revision_conflict_response(&session, payload.expected_workspace_revision)
            .await
    {
        return response;
    }
    let _operation_guard = match guard_session_write_operation(
        &state,
        &session,
        payload.expected_active_session_id.is_some(),
    )
    .await
    {
        Ok(guard) => guard,
        Err(response) => return response,
    };
    if let Some(response) =
        expected_workspace_revision_conflict_response(&session, payload.expected_workspace_revision)
            .await
    {
        return response;
    }
    if let Some(owner_session_id) = state.ws_replay.owner_session_id(payload.id).await {
        if owner_session_id != session.id() {
            return ws_replay_connection_owner_conflict_response(owner_session_id);
        }
    }
    if let Err(error) = validate_ws_replay_connect_payload(&payload) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    let url = match build_ws_replay_url(&payload.scheme, &payload.host, payload.port, &payload.path)
    {
        Ok(url) => url,
        Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
    };
    let extra_headers = match validate_ws_replay_headers(&payload.headers) {
        Ok(headers) => headers,
        Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
    };
    let upstream_insecure = session.runtime.upstream_insecure().await;

    match state
        .ws_replay
        .connect(
            payload.id,
            session.id(),
            &url,
            extra_headers,
            upstream_insecure,
        )
        .await
    {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(error) => match error.downcast_ref::<crate::ws_replay::WsReplayOwnerConflict>() {
            Some(owner_conflict) => {
                ws_replay_connection_owner_conflict_response(owner_conflict.owner_session_id)
            }
            None => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
        },
    }
}

fn validate_ws_replay_connect_payload(
    payload: &WsReplayConnectPayload,
) -> std::result::Result<(), String> {
    validate_text_field(
        "WebSocket replay scheme",
        &payload.scheme,
        MAX_WS_REPLAY_SCHEME_BYTES,
    )?;
    validate_text_field(
        "WebSocket replay host",
        &payload.host,
        MAX_WS_REPLAY_HOST_BYTES,
    )?;
    validate_text_field(
        "WebSocket replay path",
        &payload.path,
        MAX_WS_REPLAY_PATH_BYTES,
    )?;
    validate_ws_replay_header_limits(&payload.headers)
}

fn validate_ws_replay_header_limits(
    headers: &[crate::model::HeaderRecord],
) -> std::result::Result<(), String> {
    if headers.len() > MAX_WORKSPACE_WS_HEADERS {
        return Err(format!(
            "WebSocket replay cannot include more than {MAX_WORKSPACE_WS_HEADERS} headers"
        ));
    }
    let mut headers_bytes_total = 0usize;
    for header in headers {
        let header_bytes = serde_json::to_vec(header)
            .map_err(|error| format!("failed to measure WebSocket replay header: {error}"))?
            .len();
        if header_bytes > MAX_WORKSPACE_WS_HEADER_BYTES {
            return Err(format!(
                "WebSocket replay header cannot exceed {MAX_WORKSPACE_WS_HEADER_BYTES} stored bytes"
            ));
        }
        headers_bytes_total = headers_bytes_total.saturating_add(header_bytes);
        if headers_bytes_total > MAX_WORKSPACE_WS_HEADERS_BYTES {
            return Err(format!(
                "WebSocket replay headers cannot exceed {MAX_WORKSPACE_WS_HEADERS_BYTES} stored bytes"
            ));
        }
    }
    Ok(())
}

fn validate_ws_replay_headers(
    headers: &[crate::model::HeaderRecord],
) -> std::result::Result<Vec<(String, String)>, String> {
    validate_ws_replay_header_limits(headers)?;
    for header in headers {
        let name = header.name.trim();
        if name != header.name {
            return Err(format!(
                "WebSocket replay header name must not include surrounding whitespace: {}",
                header.name
            ));
        }
        HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| format!("invalid WebSocket replay header name: {name}"))?;
        HeaderValue::from_str(&header.value)
            .map_err(|_| format!("invalid WebSocket replay header value for {name}"))?;
    }
    let sanitized = proxy::websocket_forward_headers_from_records(headers);
    let extra_headers = sanitized
        .iter()
        .map(|(name, value)| {
            Ok((
                name.as_str().to_string(),
                value
                    .to_str()
                    .map_err(|_| format!("invalid WebSocket replay header value for {name}"))?
                    .to_string(),
            ))
        })
        .collect::<std::result::Result<Vec<_>, String>>()?;
    Ok(extra_headers)
}

fn build_ws_replay_url(
    scheme: &str,
    host: &str,
    port: u16,
    path: &str,
) -> std::result::Result<String, String> {
    if port == 0 {
        return Err("WebSocket port must be greater than zero".to_string());
    }
    let ws_scheme = match scheme.trim().to_ascii_lowercase().as_str() {
        "wss" | "https" => "wss",
        "ws" | "http" => "ws",
        value => return Err(format!("unsupported WebSocket scheme: {value}")),
    };
    let host = host.trim();
    if host.is_empty() {
        return Err("WebSocket host is required".to_string());
    }
    if host.chars().any(char::is_whitespace)
        || host.contains('/')
        || host.contains('\\')
        || host.contains('@')
        || host.contains('?')
        || host.contains('#')
    {
        return Err("WebSocket host must not include URL components".to_string());
    }
    let (authority_host, port) = normalize_ws_replay_authority(host, port)?;
    let path = normalize_ws_replay_path(path)?;

    Ok(format!("{ws_scheme}://{authority_host}:{port}{path}"))
}

fn normalize_ws_replay_path(path: &str) -> std::result::Result<String, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Ok("/".to_string());
    }
    if trimmed != path {
        return Err("WebSocket path must not include surrounding whitespace".to_string());
    }
    if !trimmed.starts_with('/') || trimmed.starts_with("//") {
        return Err("WebSocket path must start with a single '/'".to_string());
    }
    if trimmed
        .chars()
        .any(|char| char.is_control() || char.is_whitespace())
    {
        return Err("WebSocket path must not include whitespace".to_string());
    }
    if trimmed.contains('#') {
        return Err("WebSocket path must not include a fragment".to_string());
    }
    trimmed
        .parse::<PathAndQuery>()
        .map_err(|_| format!("invalid WebSocket path: {path}"))?;
    Ok(trimmed.to_string())
}

fn default_ws_replay_port(scheme: &str) -> u16 {
    match scheme.to_ascii_lowercase().as_str() {
        "ws" | "http" => 80,
        _ => 443,
    }
}

fn normalize_ws_replay_authority(
    host: &str,
    fallback_port: u16,
) -> std::result::Result<(String, u16), String> {
    if host.starts_with('[') {
        let Some(end) = host.find(']') else {
            return Err("invalid bracketed IPv6 host".to_string());
        };
        let inner = &host[1..end];
        if inner.trim().is_empty() {
            return Err("WebSocket host is required".to_string());
        }
        if inner.parse::<Ipv6Addr>().is_err() {
            return Err("invalid bracketed IPv6 host".to_string());
        }
        let suffix = &host[end + 1..];
        let port = if suffix.is_empty() {
            fallback_port
        } else if let Some(port) = suffix.strip_prefix(':') {
            parse_ws_replay_port(port)?
        } else {
            return Err("invalid bracketed IPv6 host".to_string());
        };
        return Ok((format!("[{inner}]"), port));
    }

    if host.parse::<IpAddr>().is_ok() && host.contains(':') {
        return Ok((format!("[{host}]"), fallback_port));
    }

    if host.matches(':').count() == 1 {
        let Some((host_part, port_part)) = host.rsplit_once(':') else {
            return Err("invalid WebSocket host".to_string());
        };
        if host_part.trim().is_empty() {
            return Err("WebSocket host is required".to_string());
        }
        return Ok((host_part.to_string(), parse_ws_replay_port(port_part)?));
    }

    if host.contains(':') {
        return Err("IPv6 WebSocket hosts with ports must be bracketed".to_string());
    }

    Ok((host.to_string(), fallback_port))
}

fn parse_ws_replay_port(port: &str) -> std::result::Result<u16, String> {
    let port = port
        .parse::<u16>()
        .map_err(|_| format!("invalid WebSocket port: {port}"))?;
    if port == 0 {
        return Err("WebSocket port must be greater than zero".to_string());
    }
    Ok(port)
}

#[derive(Debug, Deserialize)]
struct WsReplaySendPayload {
    session_id: Option<Uuid>,
    #[serde(default)]
    expected_active_session_id: Option<Uuid>,
    #[serde(default)]
    expected_workspace_revision: Option<u64>,
    id: Uuid,
    body: String,
    #[serde(default)]
    binary: bool,
    kind: Option<WsReplaySendKind>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WsReplaySendKind {
    Text,
    Binary,
    Ping,
    Pong,
}

async fn ws_replay_send(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<WsReplaySendPayload>,
) -> Response {
    let Some(session_id) = payload.session_id else {
        return active_session_conflict_response(&state);
    };
    let session = match resolve_session_for_required_id(&state, Some(session_id)).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Some(response) =
        expected_workspace_revision_conflict_response(&session, payload.expected_workspace_revision)
            .await
    {
        return response;
    }
    let _operation_guard = match guard_ws_replay_connection_owner_operation(
        &state,
        payload.id,
        &session,
        payload.expected_active_session_id,
        payload.expected_workspace_revision,
    )
    .await
    {
        Ok(guard) => guard,
        Err(response) => return response,
    };
    let kind = payload.kind.unwrap_or(if payload.binary {
        WsReplaySendKind::Binary
    } else {
        WsReplaySendKind::Text
    });
    let result = match kind {
        WsReplaySendKind::Text => match validate_ws_replay_text_payload(&payload.body) {
            Ok(()) => state.ws_replay.send_text(payload.id, payload.body).await,
            Err(error) => Err(error),
        },
        WsReplaySendKind::Binary => match decode_ws_replay_payload(&payload.body) {
            Ok(data) => state.ws_replay.send_binary(payload.id, data).await,
            Err(error) => Err(error),
        },
        WsReplaySendKind::Ping => match decode_ws_replay_control_payload(&payload.body) {
            Ok(data) => state.ws_replay.send_ping(payload.id, data).await,
            Err(error) => Err(error),
        },
        WsReplaySendKind::Pong => match decode_ws_replay_control_payload(&payload.body) {
            Ok(data) => state.ws_replay.send_pong(payload.id, data).await,
            Err(error) => Err(error),
        },
    };

    match result {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(error) => ws_replay_send_error_response(error),
    }
}

fn validate_ws_replay_text_payload(body: &str) -> anyhow::Result<()> {
    if body.len() > MAX_WS_REPLAY_OUTBOUND_MESSAGE_BYTES {
        return Err(anyhow::anyhow!(
            "WebSocket replay message cannot exceed {} bytes",
            MAX_WS_REPLAY_OUTBOUND_MESSAGE_BYTES
        ));
    }
    Ok(())
}

fn decode_ws_replay_payload(body: &str) -> anyhow::Result<Vec<u8>> {
    use base64::Engine;
    let max_encoded_len = MAX_WS_REPLAY_OUTBOUND_MESSAGE_BYTES.div_ceil(3) * 4;
    if body.len() > max_encoded_len {
        return Err(anyhow::anyhow!(
            "WebSocket replay message cannot exceed {} bytes",
            MAX_WS_REPLAY_OUTBOUND_MESSAGE_BYTES
        ));
    }
    let data = base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|error| anyhow::anyhow!("invalid base64: {}", error))?;
    if data.len() > MAX_WS_REPLAY_OUTBOUND_MESSAGE_BYTES {
        return Err(anyhow::anyhow!(
            "WebSocket replay message cannot exceed {} bytes",
            MAX_WS_REPLAY_OUTBOUND_MESSAGE_BYTES
        ));
    }
    Ok(data)
}

fn decode_ws_replay_control_payload(body: &str) -> anyhow::Result<Vec<u8>> {
    let data = decode_ws_replay_payload(body)?;
    if data.len() > 125 {
        return Err(anyhow::anyhow!(
            "WebSocket control frame payloads cannot exceed 125 bytes"
        ));
    }
    Ok(data)
}

#[derive(Debug, Deserialize)]
struct WsReplayDisconnectPayload {
    session_id: Option<Uuid>,
    #[serde(default)]
    expected_active_session_id: Option<Uuid>,
    #[serde(default)]
    expected_workspace_revision: Option<u64>,
    id: Uuid,
    #[serde(default)]
    remove: bool,
}

async fn ws_replay_disconnect(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<WsReplayDisconnectPayload>,
) -> Response {
    let Some(session_id) = payload.session_id else {
        return active_session_conflict_response(&state);
    };
    let session = match resolve_session_for_required_id(&state, Some(session_id)).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Some(response) =
        expected_workspace_revision_conflict_response(&session, payload.expected_workspace_revision)
            .await
    {
        return response;
    }
    let _operation_guard = match guard_ws_replay_connection_owner_operation(
        &state,
        payload.id,
        &session,
        payload.expected_active_session_id,
        payload.expected_workspace_revision,
    )
    .await
    {
        Ok(guard) => guard,
        Err(response) => return response,
    };
    let result = if payload.remove {
        state.ws_replay.remove(payload.id).await;
        Ok(())
    } else {
        state.ws_replay.disconnect(payload.id).await
    };
    match result {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct WsFramesSinceQuery {
    #[serde(default)]
    since: usize,
    session_id: Option<Uuid>,
}

async fn ws_replay_snapshot(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<WsFramesSinceQuery>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let Some(session_id) = query.session_id else {
        return active_session_conflict_response(&state);
    };
    let _operation_guard = match guard_ws_replay_connection_owner_read(&state, id, session_id).await
    {
        Ok(guard) => guard,
        Err(response) => return response,
    };
    match state.ws_replay.snapshot(id).await {
        Some(snapshot) => Json(snapshot).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn ws_replay_frames(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<WsFramesSinceQuery>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let Some(session_id) = query.session_id else {
        return active_session_conflict_response(&state);
    };
    let _operation_guard = match guard_ws_replay_connection_owner_read(&state, id, session_id).await
    {
        Ok(guard) => guard,
        Err(response) => return response,
    };
    match state.ws_replay.frames_since(id, query.since).await {
        Some(frames) => Json(frames).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn events(
    State(state): State<Arc<AppState>>,
    Query(query): Query<EventsQuery>,
    headers: HeaderMap,
) -> Response {
    let explicit_event_session = query.session_id.is_some();
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let last_event_sequence = headers
        .get("last-event-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let session_id = session.id();
    let mut transaction_receiver = session.store.subscribe();
    let mut transaction_retention_receiver = session.store.subscribe_retention();
    let mut log_receiver = session.event_log.subscribe();
    let mut finding_receiver = session.scanner.subscribe();
    let mut websocket_receiver = session.websockets.subscribe();
    let mut websocket_retention_receiver = session.websockets.subscribe_retention();
    let mut workspace_receiver = session.workspace.subscribe();
    let latest_sequence = session.store.latest_event_sequence();
    let event_stream_started_for_active_session = state.sessions.active_session_id() == session_id;

    let stream = stream! {
        let mut session_check = tokio::time::interval(Duration::from_millis(500));
        session_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        if last_event_sequence.is_some_and(|last_sequence| latest_sequence > last_sequence) {
            yield Ok::<Event, Infallible>(Event::default()
                .event("transactions_gap")
                .data("reconnect"));
        }
        loop {
            tokio::select! {
                result = workspace_receiver.recv() => {
                    match result {
                        // Tells clients a newer workspace snapshot exists; the
                        // writer's client_id lets a client skip its own echo.
                        Ok(event) => {
                            if let Ok(payload) = serde_json::to_string(&event) {
                                yield Ok(Event::default()
                                    .event("workspace_state")
                                    .data(payload));
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
                result = transaction_receiver.recv() => {
                    match result {
                        Ok(event) => {
                            let summary = event.summary;
                            if let Ok(payload) = serde_json::to_string(&summary) {
                                yield Ok(Event::default()
                                    .event("transaction")
                                    .id(event.event_sequence.to_string())
                                    .data(payload));
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            yield Ok(Event::default()
                                .event("transactions_gap")
                                .data("lagged"));
                            continue;
                        },
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
                result = transaction_retention_receiver.recv() => {
                    match result {
                        Ok(()) => {
                            yield Ok(Event::default()
                                .event("transactions_gap")
                                .data("retention"));
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            yield Ok(Event::default()
                                .event("transactions_gap")
                                .data("lagged"));
                            continue;
                        },
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
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            yield Ok(Event::default()
                                .event("event_log_gap")
                                .data("lagged"));
                            continue;
                        },
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
                result = finding_receiver.recv() => {
                    match result {
                        Ok(summary) => {
                            if let Ok(payload) = serde_json::to_string(&summary) {
                                yield Ok(Event::default().event("finding").data(payload));
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            yield Ok(Event::default()
                                .event("findings_gap")
                                .data("lagged"));
                            continue;
                        },
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
                result = websocket_receiver.recv() => {
                    match result {
                        Ok(summary) => {
                            if let Ok(payload) = serde_json::to_string(&summary) {
                                yield Ok(Event::default().event("websocket").data(payload));
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            yield Ok(Event::default()
                                .event("websockets_gap")
                                .data("lagged"));
                            continue;
                        },
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
                result = websocket_retention_receiver.recv() => {
                    match result {
                        Ok(()) => {
                            yield Ok(Event::default()
                                .event("websockets_gap")
                                .data("retention"));
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            yield Ok(Event::default()
                                .event("websockets_gap")
                                .data("lagged"));
                            continue;
                        },
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
                _ = session_check.tick() => {
                    if !state.sessions.contains_session(session_id) {
                        yield Ok(Event::default()
                            .event("session_deleted")
                            .data(session_id.to_string()));
                        break;
                    }
                    if explicit_event_session && !state.is_current_session_context(&session).await {
                        yield Ok(Event::default()
                            .event("session_changed")
                            .data(session_id.to_string()));
                        break;
                    }
                    let active_session_id = state.sessions.active_session_id();
                    if should_reconnect_event_stream(
                        explicit_event_session,
                        event_stream_started_for_active_session,
                        session_id,
                        active_session_id,
                    ) {
                        yield Ok(Event::default()
                            .event("session_changed")
                            .data(active_session_id.to_string()));
                        break;
                    }
                }
            }
        }
    };

    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(10))
                .text("keepalive"),
        )
        .into_response()
}

fn should_reconnect_event_stream(
    explicit_event_session: bool,
    event_stream_started_for_active_session: bool,
    watched_session_id: Uuid,
    active_session_id: Uuid,
) -> bool {
    if active_session_id == watched_session_id {
        return explicit_event_session && !event_stream_started_for_active_session;
    }
    !explicit_event_session || event_stream_started_for_active_session
}

async fn index() -> Response {
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("no-cache, no-store, must-revalidate"),
            ),
        ],
        include_str!("../web/index.html"),
    )
        .into_response()
}

async fn decoder_index() -> Response {
    serve_decoder_asset("popup.html").await
}

async fn decoder_asset(Path(path): Path<String>) -> Response {
    serve_decoder_asset(&path).await
}

async fn favicon_svg() -> Response {
    asset_response("image/svg+xml", include_str!("../web/favicon.svg"))
}

async fn logo_svg() -> Response {
    asset_response("image/svg+xml", include_str!("../web/logo.svg"))
}

async fn bungee_font() -> Response {
    binary_asset_response(
        "font/ttf",
        include_bytes!("../web/fonts/Bungee-Regular.ttf"),
    )
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

async fn codemirror_js() -> Response {
    asset_response(
        "application/javascript; charset=utf-8",
        include_str!("../web/codemirror.bundle.js"),
    )
}

fn asset_response(content_type: &'static str, body: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("no-cache, no-store, must-revalidate"),
            ),
        ],
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

async fn persist_session_mutation_locked_result(
    state: &Arc<AppState>,
    session: &Arc<SessionContext>,
) -> std::result::Result<(), String> {
    state
        .persist_session_context_mutation_locked(session)
        .await
        .map(|_| ())
        .map_err(|error| {
            let message = error.to_string();
            tracing::warn!(
                ?error,
                session_id = %session.id(),
                "failed to persist session"
            );
            message
        })
}

async fn persist_session_mutation_locked_or_response(
    state: &Arc<AppState>,
    session: &Arc<SessionContext>,
) -> std::result::Result<(), Response> {
    persist_session_mutation_locked_result(state, session)
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error).into_response())
}

async fn persist_session_mutation_locked_or_status(
    state: &Arc<AppState>,
    session: &Arc<SessionContext>,
) -> std::result::Result<(), StatusCode> {
    persist_session_mutation_locked_result(state, session)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn persist_rolled_back_session_snapshot(
    state: &Arc<AppState>,
    session: &Arc<SessionContext>,
    action: &'static str,
) {
    if let Err(error) = state.persist_session_context_mutation_locked(session).await {
        tracing::warn!(
            %error,
            action,
            session_id = %session.id(),
            "failed to fully persist rolled back session state"
        );
    }
}

async fn persist_nonrollbackable_event_log_mutation(
    state: &Arc<AppState>,
    session: &Arc<SessionContext>,
    previous_events: Vec<EventLogEntry>,
    action: &'static str,
) {
    if let Err(error) = persist_session_mutation_locked_result(state, session).await {
        session.event_log.replace_all(previous_events).await;
        persist_rolled_back_session_snapshot(state, session, action).await;
        tracing::warn!(
            %error,
            action,
            session_id = %session.id(),
            "live action succeeded but event log persistence failed"
        );
    }
}

// ── OAST ──

async fn list_oast_callbacks(
    State(state): State<Arc<AppState>>,
    Query(query): Query<OastQuery>,
) -> Response {
    if let Err(error) = validate_optional_limit(query.limit) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    Json(session.oast.list(query.limit).await).into_response()
}

async fn get_oast_callback(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<OastQuery>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    match session.oast.get(id).await {
        Some(callback) => Json(callback).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn clear_oast_callbacks(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionWriteQuery>,
) -> Response {
    if let Some(response) = expected_active_session_conflict_response(
        &state,
        query.expected_active_session_id,
        query.session_id,
    ) {
        return response;
    }
    let session = match resolve_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let _operation_guard = match guard_session_write_operation(
        &state,
        &session,
        query.session_id.is_none() || query.expected_active_session_id.is_some(),
    )
    .await
    {
        Ok(guard) => guard,
        Err(response) => return response,
    };
    let _mutation_guard = session.mutation_guard().await;
    let previous = session.oast.snapshot().await;
    let previous_cleared_keys = session.oast.snapshot_cleared_keys().await;
    let previous_generation = session.oast.clear_generation();
    session.oast.clear().await;
    if persist_session_mutation_locked_or_status(&state, &session)
        .await
        .is_err()
    {
        session.oast.restore(previous).await;
        session
            .oast
            .restore_cleared_keys(previous_cleared_keys)
            .await;
        session.oast.restore_clear_generation(previous_generation);
        persist_rolled_back_session_snapshot(&state, &session, "OAST callbacks clear").await;
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Serialize)]
struct OastPayloadResponse {
    correlation_id: String,
    payload: String,
}

async fn generate_oast_payload(
    State(state): State<Arc<AppState>>,
    Query(query): Query<OastQuery>,
) -> Response {
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    // Try provider-aware generation first (uses registered Interactsh state)
    if let Some((cid, payload)) = crate::oast::generate_payload(&session.oast).await {
        return Json(OastPayloadResponse {
            correlation_id: cid,
            payload,
        })
        .into_response();
    }
    let config = session.runtime.snapshot().await;
    if !config.oast_enabled {
        return (
            StatusCode::CONFLICT,
            "OAST is disabled. Enable OAST before generating a payload.",
        )
            .into_response();
    }
    if config.oast_provider == crate::oast::OastProvider::Interactsh {
        return (
            StatusCode::CONFLICT,
            "Interactsh is not registered yet. Wait for OAST registration or check provider settings.",
        )
            .into_response();
    }
    if config.oast_server_url.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "OAST server URL is required before generating a payload.",
        )
            .into_response();
    }
    // Fallback: generic generation for BOAST/custom-compatible providers.
    let correlation_id = crate::oast::generate_correlation_id();
    let payload =
        match crate::oast::build_oast_payload_checked(&config.oast_server_url, &correlation_id) {
            Ok(payload) => payload,
            Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
        };
    Json(OastPayloadResponse {
        correlation_id,
        payload,
    })
    .into_response()
}

#[derive(Serialize)]
struct OastStatusResponse {
    provider: String,
    registered: bool,
    correlation_id: Option<String>,
    payload_domain: Option<String>,
}

async fn oast_status(
    State(state): State<Arc<AppState>>,
    Query(query): Query<OastQuery>,
) -> Response {
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let config = session.oast.get_config().await;
    let provider = format!("{}", config.provider);
    let reg = session.oast.get_registration_info().await;
    Json(OastStatusResponse {
        provider,
        registered: reg.is_some(),
        correlation_id: reg.as_ref().map(|(cid, _)| cid.clone()),
        payload_domain: reg.map(|(_, domain)| domain),
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::Arc, time::Duration};

    use axum::{
        extract::{Path, Query, State},
        http::{HeaderMap, HeaderValue, Request, StatusCode, Uri},
        Json,
    };
    use chrono::Utc;
    use http_body_util::BodyExt;
    use serde::de::DeserializeOwned;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use uuid::Uuid;

    // A replay tab embeds the whole response of the last send. Capture is willing
    // to keep `body_preview_bytes` of body, and a binary body is stored base64 at
    // four bytes per three, so a record can legitimately reach that much again by
    // a third. When the workspace cap sat below it the server rejected the save,
    // and because the oversized record stayed in the snapshot every later save
    // failed too — the operator got a wall of identical toasts and lost unrelated
    // edits.
    #[test]
    fn the_embedded_record_cap_clears_what_capture_is_willing_to_keep() {
        let default_preview_bytes = 10 * 1024 * 1024;
        let base64_worst_case = default_preview_bytes * 4 / 3;
        assert!(
            super::MAX_WORKSPACE_EMBEDDED_RECORD_BYTES >= base64_worst_case,
            "embedded record cap {} is below a base64 body at the default preview cap ({base64_worst_case})",
            super::MAX_WORKSPACE_EMBEDDED_RECORD_BYTES
        );
        // And a single record must still fit inside the whole-workspace budget,
        // or the two limits can never both be satisfied.
        assert!(
            super::MAX_WORKSPACE_EMBEDDED_RECORD_BYTES < super::MAX_WORKSPACE_STORED_BYTES,
            "a record that cannot fit in the workspace budget is unsavable"
        );
    }

    use super::{
        build_ws_replay_url, decode_ws_replay_control_payload, decode_ws_replay_payload,
        fuzzer_attack_error_status, get_target_site_map, normalize_replay_http_version,
        persist_bound_runtime_state, sequence_run_error_status, validate_annotations_payload,
        validate_editable_request, validate_editable_response, validate_match_replace_rules,
        validate_since, validate_status_code, validate_status_range, validate_transaction_query,
        validate_ws_replay_headers, validate_ws_replay_text_payload, AnnotationsPayload,
        TransactionQuery, MAX_WS_REPLAY_OUTBOUND_MESSAGE_BYTES,
    };
    use crate::{
        config::{AppConfig, StartupSettingsUpdate},
        event_log::EventLevel,
        fuzzer::{FuzzerAttackRecord, FuzzerAttackStatus},
        intercept::{
            InterceptRecord, InterceptResolution, InterceptRule, InterceptScope,
            ResponseInterceptRecord, ResponseInterceptResolution,
        },
        match_replace::{
            MatchReplaceRule, MatchReplaceRulesPayload, MatchReplaceScope, MatchReplaceTarget,
        },
        model::{
            BodyEncoding, EditableRequest, EditableResponse, HeaderRecord, MessageRecord,
            RequestTargetOverride, TransactionRecord, WebSocketFrameDirection, WebSocketFrameKind,
            WebSocketFrameRecord, WebSocketSessionRecord, WebSocketSessionSummary,
        },
        oast::{OastCallback, OastProvider},
        runtime::{RuntimeSettingsSnapshot, RuntimeSettingsUpdate},
        scanner::{CustomRule, FindingSummary, ScannerConfig, ScannerFinding, Severity},
        sequence::{ExtractionRule, ExtractionSource, SequenceDefinition, SequenceStep},
        state::AppState,
        workspace::{
            FuzzerWorkspaceState, ReplayHistoryEntryState, ReplayTabState, ReplayWorkspaceState,
            WorkspaceStateSnapshot,
        },
        ws_replay::WsReplayFrame,
    };

    #[test]
    fn spawn_open_command_reports_launch_failure() {
        let result = super::spawn_open_command(
            "/path/that/does/not/exist/sniper-open",
            std::iter::empty::<&str>(),
        );

        assert!(result.is_err());
    }

    async fn response_json<T: DeserializeOwned>(response: axum::response::Response) -> T {
        assert!(response.status().is_success());
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body should be readable");
        serde_json::from_slice(&body).expect("response body should be valid JSON")
    }

    async fn response_body_json(response: axum::response::Response) -> serde_json::Value {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body should be readable");
        serde_json::from_slice(&body).expect("response body should be valid JSON")
    }

    fn test_app_config(name: &str) -> AppConfig {
        AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: std::env::temp_dir().join(format!("{name}-{}", uuid::Uuid::new_v4())),
        }
    }

    fn test_ws_replay_frame(index: usize, body: &str) -> WsReplayFrame {
        WsReplayFrame {
            index,
            captured_at: Utc::now().to_rfc3339(),
            direction: WebSocketFrameDirection::ServerToClient,
            kind: WebSocketFrameKind::Text,
            body: body.to_string(),
            body_encoding: BodyEncoding::Utf8,
            body_size: body.len(),
            preview_truncated: false,
        }
    }

    fn test_editable_request(path: &str) -> EditableRequest {
        EditableRequest {
            scheme: "https".to_string(),
            host: "example.test".to_string(),
            method: "GET".to_string(),
            path: path.to_string(),
            headers: vec![HeaderRecord {
                name: "host".to_string(),
                value: "example.test".to_string(),
            }],
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        }
    }

    fn test_editable_response(status: u16) -> EditableResponse {
        EditableResponse {
            status,
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
        }
    }

    fn test_replay_response_record(path: &str, status: u16) -> TransactionRecord {
        TransactionRecord::http(
            chrono::Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "example.test".to_string(),
            path.to_string(),
            Some(status),
            1,
            MessageRecord::from_headers_and_body(&HeaderMap::new(), &[], 0),
            None,
            Vec::new(),
            None,
            None,
        )
    }

    fn test_state(name: &str) -> (Arc<AppState>, PathBuf) {
        let config = test_app_config(name);
        let data_dir = config.data_dir.clone();
        (Arc::new(AppState::new(config).unwrap()), data_dir)
    }

    async fn api_route_response(
        state: Arc<AppState>,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> (reqwest::StatusCode, String) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, super::router(state)).await.unwrap();
        });
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let mut request = client.request(method, format!("http://{addr}{path}"));
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.unwrap();
        let status = response.status();
        let body = response.text().await.unwrap();
        server.abort();
        (status, body)
    }

    async fn api_route_json(
        state: Arc<AppState>,
        method: reqwest::Method,
        path: &str,
        body: serde_json::Value,
    ) -> (reqwest::StatusCode, String) {
        api_route_response(state, method, path, Some(body)).await
    }

    fn assert_active_session_conflict_body(body: &str, active_session_id: Uuid) {
        let payload: serde_json::Value =
            serde_json::from_str(body).expect("conflict response should be JSON");
        let expected_session_id = active_session_id.to_string();
        assert_eq!(
            payload.get("error").and_then(serde_json::Value::as_str),
            Some("active session changed")
        );
        assert_eq!(
            payload
                .get("session_id")
                .and_then(serde_json::Value::as_str),
            Some(expected_session_id.as_str())
        );
    }

    fn assert_ws_replay_owner_conflict_body(body: &str, owner_session_id: Uuid) {
        let payload: serde_json::Value =
            serde_json::from_str(body).expect("owner conflict response should be JSON");
        let expected_owner_session_id = owner_session_id.to_string();
        assert_eq!(
            payload.get("error").and_then(serde_json::Value::as_str),
            Some("websocket replay connection belongs to another session")
        );
        assert_eq!(
            payload
                .get("owner_session_id")
                .and_then(serde_json::Value::as_str),
            Some(expected_owner_session_id.as_str())
        );
        assert!(payload.get("session_id").is_none());
    }

    #[tokio::test]
    async fn replay_send_route_enforces_session_id_contracts() {
        let (state, data_dir) = test_state("sniper-route-replay-send-session");
        let active_id = state.session().await.id();
        let unknown_id = Uuid::new_v4();
        let request = serde_json::to_value(test_editable_request("/")).unwrap();
        let base_payload = serde_json::json!({
            "request": request,
            "target": null,
            "source_transaction_id": null,
            "http_version": null,
        });

        let mut unknown_payload = base_payload.clone();
        unknown_payload["session_id"] = serde_json::json!(unknown_id);
        let (status, body) = api_route_json(
            state.clone(),
            reqwest::Method::POST,
            "/api/replay/send",
            unknown_payload,
        )
        .await;
        assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
        assert!(body.is_empty());

        let mut missing_payload = base_payload;
        missing_payload["session_id"] = serde_json::Value::Null;
        let (status, body) = api_route_json(
            state,
            reqwest::Method::POST,
            "/api/replay/send",
            missing_payload,
        )
        .await;
        assert_eq!(status, reqwest::StatusCode::CONFLICT);
        assert_active_session_conflict_body(&body, active_id);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn fuzzer_routes_enforce_session_id_contracts() {
        let (state, data_dir) = test_state("sniper-route-fuzzer-session");
        let active_id = state.session().await.id();
        let unknown_id = Uuid::new_v4();
        let attack_id = Uuid::new_v4();
        let template = serde_json::to_value(test_editable_request("/$payload$")).unwrap();
        let base_payload = serde_json::json!({
            "template": template,
            "payloads": ["one"],
            "source_transaction_id": null,
            "http_version": null,
            "target": null,
        });

        let mut unknown_payload = base_payload.clone();
        unknown_payload["session_id"] = serde_json::json!(unknown_id);
        let (status, body) = api_route_json(
            state.clone(),
            reqwest::Method::POST,
            "/api/fuzzer/attacks",
            unknown_payload,
        )
        .await;
        assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
        assert!(body.is_empty());

        let mut missing_payload = base_payload;
        missing_payload["session_id"] = serde_json::Value::Null;
        let (status, body) = api_route_json(
            state.clone(),
            reqwest::Method::POST,
            "/api/fuzzer/attacks",
            missing_payload,
        )
        .await;
        assert_eq!(status, reqwest::StatusCode::CONFLICT);
        assert_active_session_conflict_body(&body, active_id);

        for path in [
            format!("/api/fuzzer/attacks?session_id={unknown_id}"),
            format!("/api/fuzzer/attacks/{attack_id}?session_id={unknown_id}"),
        ] {
            let (status, body) =
                api_route_response(state.clone(), reqwest::Method::GET, &path, None).await;
            assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
            assert!(body.is_empty());
        }

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn sequence_routes_enforce_session_id_contracts() {
        let (state, data_dir) = test_state("sniper-route-sequence-session");
        let active_id = state.session().await.id();
        let unknown_id = Uuid::new_v4();
        let sequence_id = Uuid::new_v4();
        let run_id = Uuid::new_v4();
        let definition = serde_json::json!({
            "id": sequence_id,
            "name": "Route contract",
            "steps": [],
        });

        let mut missing_payload = definition.clone();
        missing_payload["session_id"] = serde_json::Value::Null;
        let (status, body) = api_route_json(
            state.clone(),
            reqwest::Method::POST,
            "/api/sequences",
            missing_payload,
        )
        .await;
        assert_eq!(status, reqwest::StatusCode::CONFLICT);
        assert_active_session_conflict_body(&body, active_id);

        for (method, path) in [
            (
                reqwest::Method::GET,
                format!("/api/sequences?session_id={unknown_id}"),
            ),
            (
                reqwest::Method::GET,
                format!("/api/sequences/{sequence_id}?session_id={unknown_id}"),
            ),
            (
                reqwest::Method::DELETE,
                format!("/api/sequences/{sequence_id}?session_id={unknown_id}"),
            ),
            (
                reqwest::Method::GET,
                format!("/api/sequence-runs?session_id={unknown_id}"),
            ),
            (
                reqwest::Method::GET,
                format!("/api/sequence-runs/{run_id}?session_id={unknown_id}"),
            ),
        ] {
            let (status, body) = api_route_response(state.clone(), method, &path, None).await;
            assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
            assert!(body.is_empty());
        }

        let (status, body) = api_route_json(
            state.clone(),
            reqwest::Method::POST,
            &format!("/api/sequences/{sequence_id}/run"),
            serde_json::json!({ "session_id": unknown_id }),
        )
        .await;
        assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
        assert!(body.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn ws_replay_routes_enforce_session_id_contracts() {
        let (state, data_dir) = test_state("sniper-route-ws-replay-session");
        let active_id = state.session().await.id();
        let unknown_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();

        let connect_payload = serde_json::json!({
            "id": connection_id,
            "scheme": "ws",
            "host": "127.0.0.1",
            "port": 80,
            "path": "/",
            "headers": [],
        });
        let send_payload = serde_json::json!({
            "id": connection_id,
            "body": "hello",
            "binary": false,
        });
        let disconnect_payload = serde_json::json!({
            "id": connection_id,
            "remove": true,
        });

        for (path, mut payload) in [
            ("/api/replay/ws-connect", connect_payload),
            ("/api/replay/ws-send", send_payload),
            ("/api/replay/ws-disconnect", disconnect_payload),
        ] {
            payload["session_id"] = serde_json::json!(unknown_id);
            let (status, body) =
                api_route_json(state.clone(), reqwest::Method::POST, path, payload).await;
            assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
            assert!(body.is_empty());
        }

        for (path, mut payload) in [
            (
                "/api/replay/ws-connect",
                serde_json::json!({
                    "id": connection_id,
                    "scheme": "ws",
                    "host": "127.0.0.1",
                    "port": 80,
                    "path": "/",
                    "headers": [],
                }),
            ),
            (
                "/api/replay/ws-connect",
                serde_json::json!({
                    "id": connection_id,
                    "scheme": "ws",
                    "host": "",
                    "port": 80,
                    "path": "/",
                    "headers": [],
                }),
            ),
            (
                "/api/replay/ws-send",
                serde_json::json!({
                    "id": connection_id,
                    "body": "hello",
                    "binary": false,
                }),
            ),
            (
                "/api/replay/ws-disconnect",
                serde_json::json!({
                    "id": connection_id,
                    "remove": true,
                }),
            ),
        ] {
            payload["session_id"] = serde_json::Value::Null;
            let (status, body) =
                api_route_json(state.clone(), reqwest::Method::POST, path, payload).await;
            assert_eq!(status, reqwest::StatusCode::CONFLICT);
            assert_active_session_conflict_body(&body, active_id);
        }

        for path in [
            format!("/api/replay/ws-snapshot/{connection_id}?session_id={unknown_id}"),
            format!("/api/replay/ws-frames/{connection_id}?since=0&session_id={unknown_id}"),
        ] {
            let (status, body) =
                api_route_response(state.clone(), reqwest::Method::GET, &path, None).await;
            assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
            assert!(body.is_empty());
        }

        for path in [
            format!("/api/replay/ws-snapshot/{connection_id}"),
            format!("/api/replay/ws-frames/{connection_id}?since=0"),
        ] {
            let (status, body) =
                api_route_response(state.clone(), reqwest::Method::GET, &path, None).await;
            assert_eq!(status, reqwest::StatusCode::CONFLICT);
            assert_active_session_conflict_body(&body, active_id);
        }

        state
            .ws_replay
            .remember_disconnected_connection_for_test(connection_id, active_id)
            .await;
        let other_id = state
            .create_session(Some("other".to_string()))
            .await
            .unwrap()
            .id;

        for (path, mut payload) in [
            (
                "/api/replay/ws-connect",
                serde_json::json!({
                    "id": connection_id,
                    "scheme": "ws",
                    "host": "127.0.0.1",
                    "port": 80,
                    "path": "/",
                    "headers": [],
                }),
            ),
            (
                "/api/replay/ws-send",
                serde_json::json!({
                    "id": connection_id,
                    "body": "hello",
                    "binary": false,
                }),
            ),
            (
                "/api/replay/ws-disconnect",
                serde_json::json!({
                    "id": connection_id,
                    "remove": true,
                }),
            ),
        ] {
            payload["session_id"] = serde_json::json!(other_id);
            let (status, body) =
                api_route_json(state.clone(), reqwest::Method::POST, path, payload).await;
            assert_eq!(status, reqwest::StatusCode::CONFLICT);
            assert_ws_replay_owner_conflict_body(&body, active_id);
        }

        for path in [
            format!("/api/replay/ws-snapshot/{connection_id}?session_id={other_id}"),
            format!("/api/replay/ws-frames/{connection_id}?since=0&session_id={other_id}"),
        ] {
            let (status, body) =
                api_route_response(state.clone(), reqwest::Method::GET, &path, None).await;
            assert_eq!(status, reqwest::StatusCode::CONFLICT);
            assert_ws_replay_owner_conflict_body(&body, active_id);
        }

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn local_api_write_guard_rejects_cross_site_fetch_metadata() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("127.0.0.1:8734"));
        headers.insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
        let uri = Uri::from_static("/api/self-update");

        assert!(!super::is_allowed_browser_write(&headers, &uri));
    }

    #[test]
    fn local_api_write_guard_allows_non_browser_writes_without_browser_origins() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("127.0.0.1:8734"));
        let uri = Uri::from_static("/api/self-update");

        assert!(super::is_allowed_browser_write(&headers, &uri));
    }

    // The advertised UI address rewrites a wildcard bind to 127.0.0.1, so exposure has
    // to be read from the bound address. Reading it from the advertised one reported
    // "local" for 0.0.0.0 — the one bind that is actually reachable.
    #[tokio::test]
    async fn exposure_is_read_from_the_bound_address_not_the_advertised_one() {
        let (state, data_dir) = test_state("sniper-remote-ui-exposure");

        for loopback in ["127.0.0.1:23001", "[::1]:23001"] {
            state.set_remote_ui_exposed_from_bound_addr(loopback.parse().unwrap());
            assert!(
                !state.remote_ui_exposed(),
                "{loopback} is loopback and must not be reported as exposed"
            );
            assert!(!state.runtime_info().await.remote_ui_exposed);
        }

        for exposed in ["0.0.0.0:23001", "[::]:23001", "192.0.2.10:23001"] {
            let bound: std::net::SocketAddr = exposed.parse().unwrap();
            state.set_remote_ui_exposed_from_bound_addr(bound);
            assert!(
                state.remote_ui_exposed(),
                "{exposed} is not loopback and must be reported as exposed"
            );
            assert!(state.runtime_info().await.remote_ui_exposed);
            // The guard the flag exists for: the advertised address hides a wildcard.
            if bound.ip().is_unspecified() {
                assert!(crate::runtime_state::advertise_local_api_addr(bound)
                    .ip()
                    .is_loopback());
            }
        }

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn remote_ui_requires_one_time_token_then_accepts_session_cookie() {
        let (state, data_dir) = test_state("sniper-remote-ui-auth");
        let access_control = super::UiAccessControl::for_listener(
            "192.0.2.10:23001"
                .parse()
                .expect("specific address should parse"),
        );
        let bootstrap_token = access_control
            .remote
            .as_ref()
            .and_then(|auth| auth.bootstrap_token_for_log())
            .expect("non-loopback listener should have a bootstrap token");
        let app = super::router_with_access_control(state, access_control).layer(
            axum::middleware::from_fn(
                |mut request: axum::extract::Request, next: axum::middleware::Next| async move {
                    request
                        .extensions_mut()
                        .insert(axum::extract::connect_info::ConnectInfo(
                            "192.0.2.11:45678".parse::<std::net::SocketAddr>().unwrap(),
                        ));
                    next.run(request).await
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        let response = client.get(format!("http://{addr}/")).send().await.unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);

        let response = client
            .get(format!("http://{addr}/?token=wrong"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);

        let response = client
            .get(format!("http://{addr}/?token={bootstrap_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::SEE_OTHER);
        assert_eq!(
            response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some("/")
        );
        let set_cookie = response
            .headers()
            .get(reqwest::header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .expect("successful bootstrap should set a session cookie");
        assert!(set_cookie.contains("; HttpOnly; SameSite=Strict"));
        let session_cookie = set_cookie
            .split(';')
            .next()
            .expect("session cookie should contain a name and value")
            .to_string();

        let response = client
            .get(format!("http://{addr}/?token={bootstrap_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);

        let response = client
            .get(format!("http://{addr}/api/runtime"))
            .header(reqwest::header::HOST, "example.test:23001")
            .header(reqwest::header::COOKIE, &session_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);

        let response = client
            .post(format!("http://{addr}/api/runtime"))
            .header(reqwest::header::HOST, "example.test:23001")
            .header(reqwest::header::COOKIE, &session_cookie)
            .header(reqwest::header::ORIGIN, "http://attacker.test")
            .json(&serde_json::json!({ "intercept_enabled": true }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);

        server.abort();
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn remote_ui_tokens_are_random_url_safe_values() {
        let first = super::random_remote_ui_token();
        let second = super::random_remote_ui_token();

        assert_eq!(first.len(), 43);
        assert!(first
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'));
        assert_ne!(first, second);
    }

    #[test]
    fn specific_non_loopback_listener_prints_exact_url_and_trusts_only_same_host() {
        let listener = "192.0.2.10:23001".parse().unwrap();
        let access_control = super::UiAccessControl::for_listener(listener);

        assert!(access_control
            .bootstrap_url(listener)
            .unwrap()
            .starts_with("http://192.0.2.10:23001/?token="));
        assert!(access_control.peer_is_same_host("192.0.2.10:45678".parse().unwrap()));
        assert!(access_control.peer_is_same_host("127.0.0.1:45678".parse().unwrap()));
        assert!(!access_control.peer_is_same_host("192.0.2.11:45678".parse().unwrap()));
    }

    #[test]
    fn local_api_host_guard_rejects_rebound_hostnames() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("attacker.test:23001"));
        let uri = Uri::from_static("/api/runtime");

        assert!(!super::request_host_is_allowed_local_api(&headers, &uri));
    }

    #[test]
    fn api_path_detection_matches_only_the_api_namespace() {
        assert!(super::is_api_path("/api"));
        assert!(super::is_api_path("/api/"));
        assert!(super::is_api_path("/api/runtime"));
        assert!(!super::is_api_path("/apiary"));
        assert!(!super::is_api_path("/decoder/api"));
    }

    #[tokio::test]
    async fn api_fallback_returns_not_found_for_unknown_api_paths() {
        let request = Request::builder()
            .uri("/api/not-real")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = super::spa_or_api_not_found(request).await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn api_fallback_returns_not_found_for_api_root_path() {
        let request = Request::builder()
            .uri("/api")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = super::spa_or_api_not_found(request).await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn local_api_guard_applies_to_api_root_path() {
        let (state, data_dir) = test_state("sniper-api-root-host-guard");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, super::router(state)).await.unwrap();
        });

        let response = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(format!("http://{addr}/api"))
            .header(reqwest::header::HOST, "attacker.test:23001")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
        server.abort();
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn api_fallback_handles_non_get_unknown_api_paths() {
        let config = test_app_config("sniper-api-fallback-post");
        let data_dir = config.data_dir.clone();
        let state = Arc::new(AppState::new(config).unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, super::router(state)).await.unwrap();
        });

        let response = reqwest::Client::new()
            .post(format!("http://{addr}/api/not-real"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
        server.abort();
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn spa_fallback_rejects_non_get_unknown_paths() {
        let request = Request::builder()
            .method("POST")
            .uri("/not-real")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = super::spa_or_api_not_found(request).await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn local_api_host_guard_allows_loopback_literals_and_localhost() {
        let mut headers = HeaderMap::new();
        let uri = Uri::from_static("/api/runtime");

        headers.insert("host", HeaderValue::from_static("127.0.0.1:23001"));
        assert!(super::request_host_is_allowed_local_api(&headers, &uri));

        headers.insert("host", HeaderValue::from_static("[::1]:23001"));
        assert!(super::request_host_is_allowed_local_api(&headers, &uri));

        headers.insert("host", HeaderValue::from_static("localhost:23001"));
        assert!(super::request_host_is_allowed_local_api(&headers, &uri));
    }

    #[test]
    fn local_api_host_guard_rejects_invalid_loopback_like_authorities() {
        let mut headers = HeaderMap::new();
        let uri = Uri::from_static("/api/runtime");

        headers.insert("host", HeaderValue::from_static("[::1]evil:23001"));
        assert!(!super::request_host_is_allowed_local_api(&headers, &uri));

        headers.insert("host", HeaderValue::from_static("127.0.0.1:23001:extra"));
        assert!(!super::request_host_is_allowed_local_api(&headers, &uri));

        headers.insert("host", HeaderValue::from_static("user@127.0.0.1:23001"));
        assert!(!super::request_host_is_allowed_local_api(&headers, &uri));

        headers.insert("host", HeaderValue::from_static("user@localhost:23001"));
        assert!(!super::request_host_is_allowed_local_api(&headers, &uri));
    }

    #[test]
    fn local_api_host_guard_rejects_absolute_uri_host_mismatch() {
        let mut headers = HeaderMap::new();
        let uri: Uri = "http://127.0.0.1:23001/api/runtime".parse().unwrap();

        headers.insert("host", HeaderValue::from_static("attacker.test:23001"));
        assert!(!super::request_host_is_allowed_local_api(&headers, &uri));

        headers.insert("origin", HeaderValue::from_static("http://127.0.0.1:23001"));
        assert!(!super::is_allowed_browser_write(&headers, &uri));

        headers.insert("host", HeaderValue::from_static("127.0.0.1:23001"));
        assert!(super::request_host_is_allowed_local_api(&headers, &uri));
        assert!(super::is_allowed_browser_write(&headers, &uri));
    }

    #[test]
    fn local_api_write_guard_rejects_origin_match_through_userinfo_authority() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("user@127.0.0.1:23001"));
        headers.insert("origin", HeaderValue::from_static("http://127.0.0.1:23001"));
        let uri = Uri::from_static("/api/runtime");

        assert!(!super::is_allowed_browser_write(&headers, &uri));
    }

    #[tokio::test]
    async fn runtime_state_persists_bound_ui_and_active_proxy_addresses() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-api-runtime-state-test-{}",
            uuid::Uuid::new_v4()
        ));
        let state = Arc::new(
            AppState::new(AppConfig {
                proxy_addr: "127.0.0.1:18080".parse().unwrap(),
                ui_addr: "127.0.0.1:23001".parse().unwrap(),
                max_entries: 32,
                max_transaction_entries: 32,
                body_preview_bytes: 1024,
                data_dir: data_dir.clone(),
            })
            .unwrap(),
        );
        let active_proxy = "127.0.0.1:18081".parse().unwrap();
        let bound_ui = "127.0.0.1:23002".parse().unwrap();
        state.set_active_proxy_addr(active_proxy).await;
        state.set_proxy_online(true);

        persist_bound_runtime_state(&state, bound_ui).await.unwrap();

        let snapshot = crate::runtime_state::load_runtime_state(&data_dir)
            .unwrap()
            .expect("runtime state should exist");
        assert_eq!(snapshot.proxy_addr, "127.0.0.1:18081");
        assert_eq!(snapshot.ui_addr, "127.0.0.1:23002");
        assert!(snapshot.proxy_online);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn transaction_filter_validation_rejects_invalid_ranges() {
        assert!(validate_status_range("2xx").is_some());
        assert!(validate_status_range("200-299").is_some());
        assert!(validate_status_range("0-999").is_none());
        assert!(validate_status_range("599-100").is_none());
        assert!(validate_status_code(200).is_some());
        assert!(validate_status_code(999).is_none());
        assert!(validate_since("1h").is_some());
        assert!(validate_since("-1h").is_none());
        assert!(validate_since("0m").is_none());
        assert_eq!(
            super::normalize_sort_direction(Some(" ASC ")).as_deref(),
            Some("asc")
        );
    }

    #[test]
    fn transaction_query_validation_rejects_zero_limit() {
        let query = TransactionQuery {
            limit: Some(0),
            ..TransactionQuery::default()
        };

        assert!(validate_transaction_query(&query).is_err());
    }

    #[test]
    fn event_stream_reconnects_when_explicit_inactive_session_becomes_active() {
        let watched = Uuid::new_v4();
        let other = Uuid::new_v4();

        assert!(!super::should_reconnect_event_stream(
            true, false, watched, other
        ));
        assert!(super::should_reconnect_event_stream(
            true, false, watched, watched
        ));
        assert!(super::should_reconnect_event_stream(
            true, true, watched, other
        ));
        assert!(super::should_reconnect_event_stream(
            false, true, watched, other
        ));
    }

    #[tokio::test]
    async fn list_endpoints_reject_invalid_sort_direction() {
        let (state, data_dir) = test_state("sniper-test-invalid-sort-direction");

        for path in [
            "/api/transactions-page?sort_key=host&sort_direction=up",
            "/api/websockets-page?sort_key=host&sort_direction=up",
        ] {
            let (status, body) =
                api_route_response(state.clone(), reqwest::Method::GET, path, None).await;
            assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
            assert!(body.contains("invalid sort_direction"));
        }

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn websocket_page_rejects_invalid_sort_key() {
        let (state, data_dir) = test_state("sniper-test-invalid-websocket-sort-key");

        let (status, body) = api_route_response(
            state,
            reqwest::Method::GET,
            "/api/websockets-page?sort_key=hst",
            None,
        )
        .await;

        assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
        assert!(body.contains("invalid websocket sort_key"));

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn transaction_page_rejects_invalid_sort_key() {
        let (state, data_dir) = test_state("sniper-test-invalid-transaction-sort-key");

        let (status, body) = api_route_response(
            state,
            reqwest::Method::GET,
            "/api/transactions-page?sort_key=hst",
            None,
        )
        .await;

        assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
        assert!(body.contains("invalid transaction sort_key"));

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn transaction_page_rejects_incompatible_before_sequence_sort() {
        let (state, data_dir) = test_state("sniper-test-invalid-before-sequence-sort");

        for path in [
            "/api/transactions-page?before_sequence=42&sort_key=host&sort_direction=asc",
            "/api/transactions-page?before_sequence=42&sort_key=index&sort_direction=asc",
            "/api/transactions-page?before_sequence=42&offset=0",
            "/api/transactions-page?before_sequence=42&offset=1",
        ] {
            let (status, body) =
                api_route_response(state.clone(), reqwest::Method::GET, path, None).await;
            assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
            assert!(
                body.contains("before_sequence"),
                "response body should explain before_sequence validation: {body}"
            );
        }

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn fuzzer_persistence_errors_are_reported_as_server_errors() {
        let persistence_error: anyhow::Error =
            crate::fuzzer::FuzzerPersistenceError::new(anyhow::anyhow!("session snapshot failed"))
                .into();
        assert_eq!(
            fuzzer_attack_error_status(&persistence_error),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            fuzzer_attack_error_status(&anyhow::anyhow!("Request template is missing markers")),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn sequence_persistence_errors_are_reported_as_server_errors() {
        let persistence_error: anyhow::Error = crate::sequence::SequencePersistenceError::new(
            anyhow::anyhow!("session snapshot failed"),
        )
        .into();
        assert_eq!(
            sequence_run_error_status(&persistence_error),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            sequence_run_error_status(&anyhow::anyhow!("Sequence has no steps")),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn replay_http_version_validation_rejects_unsupported_versions() {
        assert_eq!(
            normalize_replay_http_version(Some("HTTP/2")).unwrap(),
            Some("HTTP/2".to_string())
        );
        assert!(normalize_replay_http_version(Some("HTTP/3")).is_err());
    }

    #[test]
    fn editable_response_validation_rejects_invalid_status_and_headers() {
        let mut response = EditableResponse {
            status: 200,
            headers: vec![HeaderRecord {
                name: "X-Test".to_string(),
                value: "ok".to_string(),
            }],
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
        };
        assert!(validate_editable_response(&response).is_ok());

        response.status = 700;
        assert!(validate_editable_response(&response).is_err());

        response.status = 200;
        response.headers[0].name = "Bad Header".to_string();
        assert!(validate_editable_response(&response).is_err());

        response.headers[0].name = "X-Test".to_string();
        response.headers[0].value = "ok\r\nInjected: yes".to_string();
        assert!(validate_editable_response(&response).is_err());
    }

    #[test]
    fn editable_request_validation_rejects_invalid_body_framing() {
        let mut request = EditableRequest {
            scheme: "https".to_string(),
            host: "example.test".to_string(),
            method: "POST".to_string(),
            path: "/".to_string(),
            headers: vec![HeaderRecord {
                name: "Content-Length".to_string(),
                value: "2".to_string(),
            }],
            body: "body".to_string(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };

        assert!(validate_editable_request(&request)
            .unwrap_err()
            .contains("does not match body length"));

        request.headers = vec![HeaderRecord {
            name: "Transfer-Encoding".to_string(),
            value: "gzip, chunked".to_string(),
        }];
        assert!(validate_editable_request(&request)
            .unwrap_err()
            .contains("Transfer-Encoding: chunked"));
    }

    #[test]
    fn editable_request_validation_checks_base64_decoded_content_length() {
        let mut request = EditableRequest {
            scheme: "https".to_string(),
            host: "example.test".to_string(),
            method: "POST".to_string(),
            path: "/".to_string(),
            headers: vec![HeaderRecord {
                name: "Content-Length".to_string(),
                value: "2".to_string(),
            }],
            body: "/wA=".to_string(),
            body_encoding: BodyEncoding::Base64,
            preview_truncated: false,
        };

        assert!(validate_editable_request(&request).is_ok());

        request.headers[0].value = "4".to_string();
        assert!(validate_editable_request(&request)
            .unwrap_err()
            .contains("does not match body length"));
    }

    #[test]
    fn runnable_request_validation_rejects_preview_truncated_body() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "example.test".to_string(),
            method: "POST".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: "partial body".to_string(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: true,
        };

        assert!(validate_editable_request(&request).is_ok());
        assert!(super::validate_runnable_editable_request(&request)
            .unwrap_err()
            .contains("preview is truncated"));
    }

    #[test]
    fn editable_response_validation_rejects_invalid_body_framing() {
        let response = EditableResponse {
            status: 200,
            headers: vec![HeaderRecord {
                name: "Content-Length".to_string(),
                value: "2".to_string(),
            }],
            body: "body".to_string(),
            body_encoding: BodyEncoding::Utf8,
        };

        assert!(validate_editable_response(&response)
            .unwrap_err()
            .contains("does not match body length"));
    }

    #[test]
    fn editable_response_validation_rejects_body_for_no_body_status() {
        for status in [100, 101, 102, 103, 204, 205, 304] {
            let response = EditableResponse {
                status,
                headers: Vec::new(),
                body: "illegal".to_string(),
                body_encoding: BodyEncoding::Utf8,
            };

            assert!(
                validate_editable_response(&response)
                    .unwrap_err()
                    .contains("must not include a body"),
                "status {status}"
            );
        }

        let response = EditableResponse {
            status: 200,
            headers: Vec::new(),
            body: "ok".to_string(),
            body_encoding: BodyEncoding::Utf8,
        };
        assert!(validate_editable_response(&response).is_ok());
    }

    #[test]
    fn editable_response_validation_allows_304_representation_content_length() {
        let response = EditableResponse {
            status: 304,
            headers: vec![HeaderRecord {
                name: "Content-Length".to_string(),
                value: "55".to_string(),
            }],
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
        };

        assert!(validate_editable_response(&response).is_ok());

        let response = EditableResponse {
            status: 204,
            headers: vec![HeaderRecord {
                name: "Content-Length".to_string(),
                value: "55".to_string(),
            }],
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
        };

        assert!(validate_editable_response(&response)
            .unwrap_err()
            .contains("does not match body length"));
    }

    #[test]
    fn editable_response_validation_checks_base64_decoded_content_length() {
        let mut response = EditableResponse {
            status: 200,
            headers: vec![HeaderRecord {
                name: "Content-Length".to_string(),
                value: "2".to_string(),
            }],
            body: "/wA=".to_string(),
            body_encoding: BodyEncoding::Base64,
        };

        assert!(validate_editable_response(&response).is_ok());

        response.headers[0].value = "4".to_string();
        assert!(validate_editable_response(&response)
            .unwrap_err()
            .contains("does not match body length"));
    }

    #[test]
    fn ws_replay_control_payload_rejects_oversized_body() {
        use base64::Engine;

        let max_body = base64::engine::general_purpose::STANDARD.encode(vec![0_u8; 125]);
        assert_eq!(
            decode_ws_replay_control_payload(&max_body).unwrap().len(),
            125
        );

        let oversized_body = base64::engine::general_purpose::STANDARD.encode(vec![0_u8; 126]);
        let error = decode_ws_replay_control_payload(&oversized_body).unwrap_err();
        assert!(error.to_string().contains("cannot exceed 125 bytes"));
    }

    #[test]
    fn ws_replay_payload_rejects_oversized_messages() {
        use base64::Engine;

        let oversized_text = "a".repeat(MAX_WS_REPLAY_OUTBOUND_MESSAGE_BYTES + 1);
        let error = validate_ws_replay_text_payload(&oversized_text).unwrap_err();
        assert!(error.to_string().contains("cannot exceed"));

        let max_encoded_len = MAX_WS_REPLAY_OUTBOUND_MESSAGE_BYTES.div_ceil(3) * 4;
        let oversized_encoded = "A".repeat(max_encoded_len + 1);
        let error = decode_ws_replay_payload(&oversized_encoded).unwrap_err();
        assert!(error.to_string().contains("cannot exceed"));

        let oversized_binary = base64::engine::general_purpose::STANDARD.encode(vec![
            0_u8;
            MAX_WS_REPLAY_OUTBOUND_MESSAGE_BYTES
                + 1
        ]);
        let error = decode_ws_replay_payload(&oversized_binary).unwrap_err();
        assert!(error.to_string().contains("cannot exceed"));
    }

    #[test]
    fn ws_replay_send_error_response_uses_specific_status_codes() {
        let response = super::ws_replay_send_error_response(
            crate::ws_replay::WsReplaySendError::QueueFull.into(),
        );
        assert_eq!(response.status(), super::StatusCode::TOO_MANY_REQUESTS);

        let response = super::ws_replay_send_error_response(anyhow::anyhow!(
            "WebSocket replay message cannot exceed 1 bytes"
        ));
        assert_eq!(response.status(), super::StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn optional_csv_filters_ignore_empty_values() {
        assert_eq!(super::optional_csv_param(Some(" , ".to_string())), None);
        assert_eq!(
            super::optional_csv_param(Some("json, HTML ".to_string())),
            Some(vec!["json".to_string(), "html".to_string()])
        );
    }

    #[test]
    fn match_replace_validation_rejects_invalid_regex_search() {
        let mut rule = MatchReplaceRule {
            id: uuid::Uuid::new_v4(),
            enabled: true,
            description: "bad regex".to_string(),
            scope: MatchReplaceScope::Request,
            target: MatchReplaceTarget::Path,
            search: "(".to_string(),
            replace: "x".to_string(),
            regex: true,
            case_sensitive: true,
        };

        assert!(validate_match_replace_rules(&[rule.clone()]).is_err());
        rule.regex = false;
        assert!(validate_match_replace_rules(&[rule]).is_ok());
    }

    #[test]
    fn match_replace_validation_rejects_oversized_rule_sets() {
        let rule = MatchReplaceRule {
            id: uuid::Uuid::new_v4(),
            enabled: true,
            description: "large".to_string(),
            scope: MatchReplaceScope::Request,
            target: MatchReplaceTarget::Path,
            search: "x".repeat(super::MAX_MATCH_REPLACE_FIELD_BYTES + 1),
            replace: String::new(),
            regex: false,
            case_sensitive: true,
        };
        assert!(validate_match_replace_rules(&[rule])
            .unwrap_err()
            .contains("match-replace search"));

        let rules = (0..=super::MAX_MATCH_REPLACE_RULES)
            .map(|_| MatchReplaceRule {
                id: uuid::Uuid::new_v4(),
                enabled: true,
                description: "rule".to_string(),
                scope: MatchReplaceScope::Request,
                target: MatchReplaceTarget::Path,
                search: "x".to_string(),
                replace: String::new(),
                regex: false,
                case_sensitive: true,
            })
            .collect::<Vec<_>>();
        assert!(validate_match_replace_rules(&rules)
            .unwrap_err()
            .contains("more than"));
    }

    #[tokio::test]
    async fn match_replace_update_rejects_unknown_session_before_rule_validation() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-match-replace-unknown-session-{}",
            uuid::Uuid::new_v4()
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
        let active = state.session().await;

        let response = super::update_match_replace_rules(
            State(state.clone()),
            Query(super::SessionWriteQuery {
                session_id: Some(Uuid::new_v4()),
                expected_active_session_id: None,
            }),
            Json(MatchReplaceRulesPayload {
                session_id: None,
                rules: vec![MatchReplaceRule {
                    id: Uuid::new_v4(),
                    enabled: true,
                    description: "invalid regex".to_string(),
                    scope: MatchReplaceScope::Request,
                    target: MatchReplaceTarget::Path,
                    search: "(".to_string(),
                    replace: "x".to_string(),
                    regex: true,
                    case_sensitive: true,
                }],
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(active.match_replace.snapshot().await.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn annotation_validation_limits_color_and_note_size() {
        assert!(validate_annotations_payload(&AnnotationsPayload {
            session_id: None,
            color_tag: Some(Some("blue".to_string())),
            user_note: Some(Some("short note".to_string())),
            client_id: Some("browser-client".to_string()),
            client_version: Some(1),
        })
        .is_ok());
        assert!(validate_annotations_payload(&AnnotationsPayload {
            session_id: None,
            color_tag: Some(None),
            user_note: Some(None),
            client_id: None,
            client_version: None,
        })
        .is_ok());

        assert_eq!(
            validate_annotations_payload(&AnnotationsPayload {
                session_id: None,
                color_tag: Some(Some("chartreuse".to_string())),
                user_note: None,
                client_id: None,
                client_version: None,
            })
            .unwrap_err(),
            "unsupported color tag"
        );
        assert!(validate_annotations_payload(&AnnotationsPayload {
            session_id: None,
            color_tag: None,
            user_note: Some(Some("x".repeat(super::MAX_ANNOTATION_NOTE_BYTES + 1))),
            client_id: None,
            client_version: None,
        })
        .unwrap_err()
        .contains("user note"));
        assert!(validate_annotations_payload(&AnnotationsPayload {
            session_id: None,
            color_tag: None,
            user_note: None,
            client_id: Some("x".repeat(super::MAX_WORKSPACE_CLIENT_ID_BYTES + 1)),
            client_version: Some(1),
        })
        .unwrap_err()
        .contains("annotation client id"));
        assert_eq!(
            validate_annotations_payload(&AnnotationsPayload {
                session_id: None,
                color_tag: None,
                user_note: None,
                client_id: Some("browser-client".to_string()),
                client_version: Some(0),
            })
            .unwrap_err(),
            "annotation client version must be greater than zero"
        );
    }

    #[test]
    fn sequence_validation_rejects_invalid_response_header_extractions() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "example.test".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let mut definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "header extraction".to_string(),
            steps: vec![SequenceStep {
                id: uuid::Uuid::new_v4(),
                label: "step".to_string(),
                request,
                source_transaction_id: None,
                http_version: None,
                target: None,
                request_text: None,
                request_parse_error: None,
                extractions: vec![ExtractionRule {
                    variable_name: "session".to_string(),
                    source: ExtractionSource::ResponseHeader,
                    pattern: "Bad Header".to_string(),
                    group: 1,
                }],
            }],
        };

        assert!(super::validate_sequence_definition(&definition).is_err());
        definition.steps[0].extractions[0].pattern = "x-session".to_string();
        assert!(super::validate_sequence_definition(&definition).is_ok());
    }

    #[test]
    fn sequence_validation_rejects_oversized_definitions() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "example.test".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let step = SequenceStep {
            id: uuid::Uuid::new_v4(),
            label: "step".to_string(),
            request,
            source_transaction_id: None,
            http_version: None,
            target: None,
            request_text: None,
            request_parse_error: None,
            extractions: Vec::new(),
        };
        let mut definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "sequence".to_string(),
            steps: vec![step.clone(); super::MAX_SEQUENCE_STEPS + 1],
        };
        assert!(super::validate_sequence_definition(&definition)
            .unwrap_err()
            .contains("more than"));

        definition.steps = vec![SequenceStep {
            label: "x".repeat(super::MAX_SEQUENCE_TEXT_FIELD_BYTES + 1),
            ..step
        }];
        assert!(super::validate_sequence_definition(&definition)
            .unwrap_err()
            .contains("sequence step label"));
    }

    #[test]
    fn ws_replay_url_builder_handles_ipv6_and_paths() {
        assert_eq!(
            build_ws_replay_url("https", "::1", 9443, "/socket").unwrap(),
            "wss://[::1]:9443/socket"
        );
        assert_eq!(
            build_ws_replay_url("ws", "[2001:db8::1]", 80, "").unwrap(),
            "ws://[2001:db8::1]:80/"
        );
        assert_eq!(
            build_ws_replay_url("wss", "example.test:8443", 443, "/chat").unwrap(),
            "wss://example.test:8443/chat"
        );
        assert_eq!(
            build_ws_replay_url("wss", "[2001:db8::1]:9443", 443, "/").unwrap(),
            "wss://[2001:db8::1]:9443/"
        );
        assert!(build_ws_replay_url("ftp", "example.test", 80, "/").is_err());
        assert!(build_ws_replay_url("wss", "example.test", 0, "/").is_err());
        assert!(build_ws_replay_url("wss", "example.test", 443, "socket").is_err());
        assert!(build_ws_replay_url("wss", "example.test", 443, "//socket").is_err());
        assert!(build_ws_replay_url("wss", "example.test", 443, "/socket#frag").is_err());
        assert!(build_ws_replay_url("wss", "example.test/path", 443, "/").is_err());
        assert!(build_ws_replay_url("wss", "example.test?x=1", 443, "/").is_err());
        assert!(build_ws_replay_url("wss", "example.test#frag", 443, "/").is_err());
        assert!(build_ws_replay_url("wss", "bad host.test", 443, "/").is_err());
        assert!(build_ws_replay_url("wss", "example.test:notaport", 443, "/").is_err());
        assert!(build_ws_replay_url("wss", "[not-ip]", 443, "/").is_err());
        assert!(build_ws_replay_url("wss", "[2001:db8::1]:70000", 443, "/").is_err());
    }

    #[test]
    fn ws_replay_header_validation_rejects_invalid_values() {
        assert!(validate_ws_replay_headers(&[HeaderRecord {
            name: "Authorization".to_string(),
            value: "Bearer abc\ndef".to_string(),
        }])
        .is_err());
        assert!(validate_ws_replay_headers(&[HeaderRecord {
            name: " Authorization ".to_string(),
            value: "Bearer abc".to_string(),
        }])
        .is_err());

        let headers = validate_ws_replay_headers(&[
            HeaderRecord {
                name: "Connection".to_string(),
                value: "Upgrade, X-Hop".to_string(),
            },
            HeaderRecord {
                name: "Sec-WebSocket-Key".to_string(),
                value: "ignored".to_string(),
            },
            HeaderRecord {
                name: "Proxy-Authorization".to_string(),
                value: "Basic secret".to_string(),
            },
            HeaderRecord {
                name: "X-Hop".to_string(),
                value: "secret".to_string(),
            },
            HeaderRecord {
                name: "X-Test".to_string(),
                value: "ok".to_string(),
            },
        ])
        .expect("valid replay headers should pass");
        assert_eq!(headers, vec![("x-test".to_string(), "ok".to_string())]);
    }

    #[test]
    fn intercept_forward_canonicalizes_plain_chunked_request() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "example.test".to_string(),
            method: "POST".to_string(),
            path: "/submit".to_string(),
            headers: vec![
                HeaderRecord {
                    name: "host".to_string(),
                    value: "example.test".to_string(),
                },
                HeaderRecord {
                    name: "transfer-encoding".to_string(),
                    value: "chunked".to_string(),
                },
            ],
            body: "hello".to_string(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };

        let request = super::canonicalize_intercept_forward_request(request).unwrap();

        assert!(!request
            .headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("transfer-encoding")));
        assert_eq!(
            request
                .headers
                .iter()
                .find(|header| header.name.eq_ignore_ascii_case("content-length"))
                .map(|header| header.value.as_str()),
            Some("5")
        );
    }

    #[test]
    fn intercept_forward_rejects_unsupported_transfer_encoding_chain() {
        let mut request = test_editable_request("/submit");
        request.method = "POST".to_string();
        request.headers.push(HeaderRecord {
            name: "transfer-encoding".to_string(),
            value: "gzip, chunked".to_string(),
        });
        request.body = "compressed".to_string();

        let error = super::canonicalize_intercept_forward_request(request).unwrap_err();

        assert!(error.contains("unsupported Transfer-Encoding chain"));
    }

    #[test]
    fn response_intercept_forward_canonicalizes_plain_chunked_response() {
        let response = EditableResponse {
            status: 200,
            headers: vec![HeaderRecord {
                name: "transfer-encoding".to_string(),
                value: "chunked".to_string(),
            }],
            body: "hello".to_string(),
            body_encoding: BodyEncoding::Utf8,
        };

        let response = super::canonicalize_intercept_forward_response(response, "GET").unwrap();

        assert!(!response
            .headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("transfer-encoding")));
        assert_eq!(
            response
                .headers
                .iter()
                .find(|header| header.name.eq_ignore_ascii_case("content-length"))
                .map(|header| header.value.as_str()),
            Some("5")
        );
    }

    #[test]
    fn ws_replay_connect_payload_defaults_missing_headers() {
        let payload: super::WsReplayConnectPayload = serde_json::from_value(serde_json::json!({
            "id": "33333333-3333-3333-3333-333333333333",
            "scheme": "ws",
            "host": "127.0.0.1",
            "port": 8080,
            "path": "/"
        }))
        .expect("headers should default to empty");

        assert!(payload.headers.is_empty());
    }

    #[tokio::test]
    async fn ws_replay_owner_check_rejects_deleted_session() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-ws-replay-deleted-session-{}",
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
        let deleted_session_id = state.session().await.id();
        state
            .create_session(Some("replacement".to_string()))
            .await
            .unwrap();
        state.delete_session(deleted_session_id).await.unwrap();

        let response = super::guard_ws_replay_connection_owner_read(
            &state,
            Uuid::new_v4(),
            deleted_session_id,
        )
        .await
        .unwrap_err();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn session_write_guard_rejects_deleted_session_as_not_found() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-write-guard-deleted-session-{}",
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
        let deleted_session = state.session().await;
        state
            .create_session(Some("replacement".to_string()))
            .await
            .unwrap();
        state.delete_session(deleted_session.id()).await.unwrap();

        let response = super::guard_session_write_operation(&state, &deleted_session, false)
            .await
            .unwrap_err();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn scanner_config_rejects_empty_custom_rule_pattern() {
        let mut config = ScannerConfig::default();
        config.custom_rules.push(CustomRule {
            id: "empty-pattern".to_string(),
            name: "Empty pattern".to_string(),
            enabled: true,
            target: "response_body".to_string(),
            header_name: String::new(),
            pattern: "  ".to_string(),
            severity: Severity::Info,
            category: "custom".to_string(),
            description: String::new(),
        });

        assert!(super::validate_scanner_config(&config).is_err());
    }

    #[test]
    fn scanner_config_rejects_oversized_custom_rule_sets() {
        let rule = CustomRule {
            id: "custom".to_string(),
            name: "Custom".to_string(),
            enabled: true,
            target: "response_body".to_string(),
            header_name: String::new(),
            pattern: "x".to_string(),
            severity: Severity::Info,
            category: "custom".to_string(),
            description: String::new(),
        };
        let config = ScannerConfig {
            custom_rules: vec![rule.clone(); super::MAX_SCANNER_CUSTOM_RULES + 1],
            ..ScannerConfig::default()
        };
        assert!(super::validate_scanner_config(&config)
            .unwrap_err()
            .contains("custom rules"));

        let config = ScannerConfig {
            custom_rules: vec![CustomRule {
                pattern: "x".repeat(super::MAX_SCANNER_FIELD_BYTES + 1),
                ..rule
            }],
            ..ScannerConfig::default()
        };
        assert!(super::validate_scanner_config(&config)
            .unwrap_err()
            .contains("custom scanner rule pattern"));
    }

    #[test]
    fn scanner_config_rejects_duplicate_custom_rule_ids() {
        let rule = CustomRule {
            id: "duplicate".to_string(),
            name: "Custom".to_string(),
            enabled: true,
            target: "response_body".to_string(),
            header_name: String::new(),
            pattern: "x".to_string(),
            severity: Severity::Info,
            category: "custom".to_string(),
            description: String::new(),
        };
        let config = ScannerConfig {
            custom_rules: vec![
                rule.clone(),
                CustomRule {
                    name: "Other display name".to_string(),
                    ..rule
                },
            ],
            ..ScannerConfig::default()
        };

        assert!(super::validate_scanner_config(&config)
            .unwrap_err()
            .contains("duplicated"));
    }

    #[tokio::test]
    async fn scanner_config_update_rejects_unknown_session_before_config_validation() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-scanner-config-unknown-session-{}",
            uuid::Uuid::new_v4()
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
        let active = state.session().await;
        let mut invalid_config = active.scanner.get_config().await;
        invalid_config.custom_rules.push(CustomRule {
            id: "invalid".to_string(),
            name: "Invalid".to_string(),
            enabled: true,
            target: "response_body".to_string(),
            header_name: String::new(),
            pattern: "   ".to_string(),
            severity: Severity::Info,
            category: "custom".to_string(),
            description: String::new(),
        });

        let response = super::update_scanner_config(
            State(state.clone()),
            Query(super::SessionWriteQuery {
                session_id: Some(Uuid::new_v4()),
                expected_active_session_id: None,
            }),
            Json(super::ScannerConfigPayload::from(invalid_config)),
        )
        .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(active.scanner.get_config().await.custom_rules.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn sequence_validation_rejects_invalid_extraction_regex() {
        let request = crate::model::EditableRequest {
            scheme: "https".to_string(),
            host: "example.test".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "test".to_string(),
            steps: vec![SequenceStep {
                id: uuid::Uuid::new_v4(),
                label: "extract".to_string(),
                request,
                source_transaction_id: None,
                http_version: None,
                target: None,
                request_text: None,
                request_parse_error: None,
                extractions: vec![ExtractionRule {
                    variable_name: "token".to_string(),
                    source: ExtractionSource::ResponseBody,
                    pattern: "(".to_string(),
                    group: 1,
                }],
            }],
        };
        assert!(super::validate_sequence_definition(&definition).is_err());
    }

    #[test]
    fn sequence_validation_rejects_missing_response_body_capture_group() {
        let request = crate::model::EditableRequest {
            scheme: "https".to_string(),
            host: "example.test".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "test".to_string(),
            steps: vec![SequenceStep {
                id: uuid::Uuid::new_v4(),
                label: "extract".to_string(),
                request,
                source_transaction_id: None,
                http_version: None,
                target: None,
                request_text: None,
                request_parse_error: None,
                extractions: vec![ExtractionRule {
                    variable_name: "token".to_string(),
                    source: ExtractionSource::ResponseBody,
                    pattern: "csrf=[a-z]+".to_string(),
                    group: 1,
                }],
            }],
        };

        assert!(super::validate_sequence_definition(&definition)
            .unwrap_err()
            .contains("missing capture group 1"));
    }

    #[test]
    fn sequence_validation_rejects_invalid_http_version() {
        let request = crate::model::EditableRequest {
            scheme: "https".to_string(),
            host: "example.test".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let mut definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "test".to_string(),
            steps: vec![SequenceStep {
                id: uuid::Uuid::new_v4(),
                label: "h2".to_string(),
                request,
                source_transaction_id: None,
                http_version: Some("HTTP/2".to_string()),
                target: None,
                request_text: None,
                request_parse_error: None,
                extractions: Vec::new(),
            }],
        };

        assert!(super::validate_sequence_definition(&definition).is_ok());
        definition.steps[0].http_version = Some("HTTP/3".to_string());
        assert!(super::validate_sequence_definition(&definition).is_err());
    }

    #[test]
    fn sequence_validation_allows_invalid_request_draft_with_parse_error() {
        let request = crate::model::EditableRequest {
            scheme: "https".to_string(),
            host: String::new(),
            method: "GET".to_string(),
            path: String::new(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "draft".to_string(),
            steps: vec![SequenceStep {
                id: uuid::Uuid::new_v4(),
                label: "draft step".to_string(),
                request,
                source_transaction_id: None,
                http_version: Some("HTTP/1.1".to_string()),
                target: None,
                request_text: Some("GET / HTTP/1.1".to_string()),
                request_parse_error: Some("Request is missing a Host header".to_string()),
                extractions: Vec::new(),
            }],
        };

        assert!(super::validate_sequence_definition(&definition).is_ok());
    }

    #[test]
    fn sequence_validation_rejects_invalid_target_override() {
        let request = crate::model::EditableRequest {
            scheme: "https".to_string(),
            host: "example.test".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "test".to_string(),
            steps: vec![SequenceStep {
                id: uuid::Uuid::new_v4(),
                label: "bad target".to_string(),
                request,
                source_transaction_id: None,
                http_version: None,
                target: Some(RequestTargetOverride {
                    scheme: "ftp".to_string(),
                    host: "example.test".to_string(),
                    port: "443".to_string(),
                }),
                request_text: None,
                request_parse_error: None,
                extractions: Vec::new(),
            }],
        };

        assert!(super::validate_sequence_definition(&definition).is_err());
    }

    #[test]
    fn sequence_validation_rejects_ip_request_host_target_override() {
        let request = crate::model::EditableRequest {
            scheme: "https".to_string(),
            host: "127.0.0.1:443".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "test".to_string(),
            steps: vec![SequenceStep {
                id: uuid::Uuid::new_v4(),
                label: "bad target".to_string(),
                request,
                source_transaction_id: None,
                http_version: None,
                target: Some(RequestTargetOverride {
                    scheme: "https".to_string(),
                    host: "127.0.0.2".to_string(),
                    port: "9443".to_string(),
                }),
                request_text: None,
                request_parse_error: None,
                extractions: Vec::new(),
            }],
        };

        let error = super::validate_sequence_definition(&definition).unwrap_err();
        assert!(error.contains("request host is an IP address"));
    }

    #[test]
    fn replay_target_validation_rejects_ambiguous_hosts() {
        for target in [
            RequestTargetOverride {
                scheme: "https".to_string(),
                host: String::new(),
                port: "9443".to_string(),
            },
            RequestTargetOverride {
                scheme: String::new(),
                host: String::new(),
                port: "9443".to_string(),
            },
            RequestTargetOverride {
                scheme: "https".to_string(),
                host: String::new(),
                port: String::new(),
            },
        ] {
            assert!(super::validate_request_target_override(&target).is_ok());
        }

        for host in [
            "victim.test@127.0.0.1",
            "127.0.0.1/path",
            "127.0.0.1?x=1",
            "example.test:8443",
            "bad host.test",
            "https://example.test",
        ] {
            let target = RequestTargetOverride {
                scheme: "https".to_string(),
                host: host.to_string(),
                port: "443".to_string(),
            };

            assert!(
                super::validate_request_target_override(&target).is_err(),
                "{host} should be rejected"
            );
        }

        let target = RequestTargetOverride {
            scheme: "https".to_string(),
            host: "::1".to_string(),
            port: "443".to_string(),
        };
        assert!(super::validate_request_target_override(&target).is_ok());

        let target = RequestTargetOverride {
            scheme: " https ".to_string(),
            host: "example.test".to_string(),
            port: "443".to_string(),
        };
        assert!(super::validate_request_target_override(&target).is_err());

        let target = RequestTargetOverride {
            scheme: "https".to_string(),
            host: " example.test ".to_string(),
            port: "443".to_string(),
        };
        assert!(super::validate_request_target_override(&target).is_err());

        let target = RequestTargetOverride {
            scheme: "https".to_string(),
            host: "example.test".to_string(),
            port: " 443 ".to_string(),
        };
        assert!(super::validate_request_target_override(&target).is_err());
    }

    #[test]
    fn editable_request_validation_rejects_invalid_headers() {
        let mut request = crate::model::EditableRequest {
            scheme: "https".to_string(),
            host: "example.test".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: vec![HeaderRecord {
                name: "X-Test".to_string(),
                value: "ok".to_string(),
            }],
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        assert!(super::validate_editable_request(&request).is_ok());

        request.headers[0].name = "Bad Header".to_string();
        assert!(super::validate_editable_request(&request).is_err());

        request.headers[0].name.clear();
        assert!(super::validate_editable_request(&request).is_err());

        request.headers[0].name = "X-Test".to_string();
        request.headers[0].value = "ok\r\nInjected: yes".to_string();
        assert!(super::validate_editable_request(&request).is_err());

        request.headers[0].value = "ok".to_string();
        request.headers[0].name = " X-Test ".to_string();
        assert!(super::validate_editable_request(&request).is_err());

        request.headers[0].name = "X-Test".to_string();
        request.scheme = "ftp".to_string();
        assert!(super::validate_editable_request(&request).is_err());

        request.scheme = "https".to_string();
        request.host = "example.test/path".to_string();
        assert!(super::validate_editable_request(&request).is_err());

        request.host = "example.test:443:444".to_string();
        assert!(super::validate_editable_request(&request).is_err());

        request.host = "::1".to_string();
        assert!(super::validate_editable_request(&request).is_err());

        request.host = "example.test".to_string();
        request.path = "relative".to_string();
        assert!(super::validate_editable_request(&request).is_err());

        request.path = "/with#fragment".to_string();
        assert!(super::validate_editable_request(&request).is_err());

        request.path = "/".to_string();
        request.method = " GET ".to_string();
        assert!(super::validate_editable_request(&request).is_err());

        request.method = "GET".to_string();
        request.method = "GE/T".to_string();
        assert!(super::validate_editable_request(&request).is_err());

        request.method = "CONNECT".to_string();
        assert!(super::validate_editable_request(&request).is_err());

        request.method = "GET".to_string();
        request.headers = vec![
            HeaderRecord {
                name: "Host".to_string(),
                value: "first.example".to_string(),
            },
            HeaderRecord {
                name: "host".to_string(),
                value: "second.example".to_string(),
            },
        ];
        assert!(super::validate_editable_request(&request)
            .unwrap_err()
            .contains("multiple Host headers"));
    }

    #[test]
    fn workspace_validation_rejects_partial_replay_target_fields() {
        let mut snapshot = WorkspaceStateSnapshot::default();
        snapshot.replay.tabs.push(ReplayTabState {
            id: "partial-target".to_string(),
            sequence: 1,
            target_scheme: "https".to_string(),
            target_host: "example.test".to_string(),
            target_port: String::new(),
            ..ReplayTabState::default()
        });

        assert!(super::validate_workspace_state(&snapshot).is_err());
    }

    #[test]
    fn workspace_validation_rejects_ip_request_host_replay_target_override() {
        let mut snapshot = WorkspaceStateSnapshot::default();
        snapshot.replay.tabs.push(ReplayTabState {
            id: "ip-target".to_string(),
            sequence: 1,
            base_request: Some(EditableRequest {
                scheme: "https".to_string(),
                host: "127.0.0.1:443".to_string(),
                method: "GET".to_string(),
                path: "/".to_string(),
                headers: Vec::new(),
                body: String::new(),
                body_encoding: BodyEncoding::Utf8,
                preview_truncated: false,
            }),
            target_scheme: "https".to_string(),
            target_host: "127.0.0.2".to_string(),
            target_port: "9443".to_string(),
            ..ReplayTabState::default()
        });

        let error = super::validate_workspace_state(&snapshot).unwrap_err();
        assert!(error.contains("request host is an IP address"));
    }

    #[test]
    fn workspace_validation_rejects_ip_request_host_scheme_only_replay_target() {
        let mut snapshot = WorkspaceStateSnapshot::default();
        snapshot.replay.tabs.push(ReplayTabState {
            id: "ip-target".to_string(),
            sequence: 1,
            base_request: Some(EditableRequest {
                scheme: "https".to_string(),
                host: "127.0.0.1".to_string(),
                method: "GET".to_string(),
                path: "/".to_string(),
                headers: Vec::new(),
                body: String::new(),
                body_encoding: BodyEncoding::Utf8,
                preview_truncated: false,
            }),
            target_scheme: "http".to_string(),
            target_host: String::new(),
            target_port: String::new(),
            ..ReplayTabState::default()
        });

        let error = super::validate_workspace_state(&snapshot).unwrap_err();
        assert!(error.contains("request host is an IP address"));
    }

    #[test]
    fn workspace_validation_rejects_ip_request_host_replay_history_target_override() {
        let mut snapshot = WorkspaceStateSnapshot::default();
        snapshot.replay.tabs.push(ReplayTabState {
            id: "history-target".to_string(),
            sequence: 1,
            history_entries: vec![ReplayHistoryEntryState {
                request: Some(EditableRequest {
                    scheme: "https".to_string(),
                    host: "127.0.0.1:443".to_string(),
                    method: "GET".to_string(),
                    path: "/".to_string(),
                    headers: Vec::new(),
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                }),
                target_scheme: "https".to_string(),
                target_host: "127.0.0.2".to_string(),
                target_port: "9443".to_string(),
                ..ReplayHistoryEntryState::default()
            }],
            ..ReplayTabState::default()
        });

        let error = super::validate_workspace_state(&snapshot).unwrap_err();
        assert!(error.contains("request host is an IP address"));
    }

    #[test]
    fn workspace_validation_allows_equivalent_ip_request_host_replay_target() {
        let mut snapshot = WorkspaceStateSnapshot::default();
        snapshot.replay.tabs.push(ReplayTabState {
            id: "ip-target".to_string(),
            sequence: 1,
            base_request: Some(EditableRequest {
                scheme: "https".to_string(),
                host: "127.0.0.1:443".to_string(),
                method: "GET".to_string(),
                path: "/".to_string(),
                headers: Vec::new(),
                body: String::new(),
                body_encoding: BodyEncoding::Utf8,
                preview_truncated: false,
            }),
            target_scheme: "https".to_string(),
            target_host: "127.0.0.1".to_string(),
            target_port: "443".to_string(),
            ..ReplayTabState::default()
        });

        assert!(super::validate_workspace_state(&snapshot).is_ok());
    }

    #[test]
    fn workspace_validation_rejects_oversized_replay_custom_label() {
        let mut snapshot = WorkspaceStateSnapshot::default();
        snapshot.replay.tabs.push(ReplayTabState {
            id: "named-tab".to_string(),
            sequence: 1,
            custom_label: "x".repeat(81),
            ..ReplayTabState::default()
        });

        assert!(super::validate_workspace_state(&snapshot).is_err());
    }

    #[test]
    fn workspace_validation_rejects_truncated_websocket_marker_on_http_tab() {
        let mut snapshot = WorkspaceStateSnapshot::default();
        snapshot.replay.tabs.push(ReplayTabState {
            id: "http-tab".to_string(),
            sequence: 1,
            ws_frames_truncated: true,
            ..ReplayTabState::default()
        });

        assert!(super::validate_workspace_state(&snapshot).is_err());
    }

    #[test]
    fn workspace_keepalive_merge_preserves_state_missing_from_compact_payload() {
        let session_id = uuid::Uuid::new_v4();
        let current = WorkspaceStateSnapshot {
            revision: 7,
            session_id: Some(session_id),
            client_id: Some("browser".to_string()),
            client_version: 12,
            replay: crate::workspace::ReplayWorkspaceState {
                active_tab_id: Some("active".to_string()),
                tab_sequence: 3,
                tabs: vec![
                    ReplayTabState {
                        id: "active".to_string(),
                        sequence: 1,
                        base_request: Some(test_editable_request("/old")),
                        request_text: "GET /old HTTP/1.1\r\nHost: example.test\r\n\r\n".to_string(),
                        response_record: Some(crate::model::TransactionRecord::http(
                            chrono::Utc::now(),
                            "GET".to_string(),
                            "https".to_string(),
                            "example.test".to_string(),
                            "/old".to_string(),
                            Some(200),
                            1,
                            crate::model::MessageRecord::from_headers_and_body(
                                &HeaderMap::new(),
                                &[],
                                0,
                            ),
                            None,
                            Vec::new(),
                            None,
                            None,
                        )),
                        history_entries: vec![crate::workspace::ReplayHistoryEntryState {
                            request: Some(test_editable_request("/history")),
                            request_text: "GET /history HTTP/1.1\r\nHost: example.test\r\n\r\n"
                                .to_string(),
                            target_scheme: "https".to_string(),
                            target_host: "example.test".to_string(),
                            target_port: "443".to_string(),
                            ..crate::workspace::ReplayHistoryEntryState::default()
                        }],
                        history_index: Some(0),
                        target_scheme: "https".to_string(),
                        target_host: "example.test".to_string(),
                        target_port: "443".to_string(),
                        ..ReplayTabState::default()
                    },
                    ReplayTabState {
                        id: "inactive".to_string(),
                        sequence: 2,
                        request_text: "keep me".to_string(),
                        target_scheme: "https".to_string(),
                        target_host: "inactive.test".to_string(),
                        target_port: "443".to_string(),
                        ..ReplayTabState::default()
                    },
                ],
            },
            fuzzer: FuzzerWorkspaceState {
                request_text: "FUZZ /old HTTP/1.1".to_string(),
                payloads_text: "payload-one".to_string(),
                ..FuzzerWorkspaceState::default()
            },
            expected_active_session_id: None,
        };
        let incoming = WorkspaceStateSnapshot {
            revision: 7,
            session_id: Some(session_id),
            client_id: Some("browser".to_string()),
            client_version: 13,
            replay: crate::workspace::ReplayWorkspaceState {
                active_tab_id: Some("active".to_string()),
                tab_sequence: 3,
                tabs: vec![ReplayTabState {
                    id: "active".to_string(),
                    sequence: 1,
                    base_request: Some(test_editable_request("/edited")),
                    request_text: "GET /edited HTTP/1.1\r\nHost: example.test\r\n\r\n".to_string(),
                    response_record: None,
                    history_entries: Vec::new(),
                    target_scheme: "https".to_string(),
                    target_host: "example.test".to_string(),
                    target_port: "443".to_string(),
                    ..ReplayTabState::default()
                }],
            },
            fuzzer: FuzzerWorkspaceState::default(),
            expected_active_session_id: None,
        };

        let merged = super::merge_workspace_keepalive_snapshot(
            current,
            incoming,
            super::WorkspaceKeepaliveMetadata::default(),
        );

        assert_eq!(merged.replay.tabs.len(), 2);
        let active = merged
            .replay
            .tabs
            .iter()
            .find(|tab| tab.id == "active")
            .expect("active tab should still exist");
        assert!(active.request_text.contains("/edited"));
        assert!(active.response_record.is_none());
        assert_eq!(active.history_entries.len(), 1);
        assert_eq!(active.history_index, Some(0));
        assert!(merged.replay.tabs.iter().any(|tab| tab.id == "inactive"));
        assert_eq!(merged.fuzzer.payloads_text, "payload-one");
        assert_eq!(merged.client_version, 13);
    }

    #[test]
    fn workspace_keepalive_partial_payload_preserves_missing_active_tab_id() {
        let current = WorkspaceStateSnapshot {
            replay: ReplayWorkspaceState {
                active_tab_id: Some("active".to_string()),
                tab_sequence: 2,
                tabs: vec![
                    ReplayTabState {
                        id: "active".to_string(),
                        sequence: 1,
                        request_text: "GET /active HTTP/1.1\r\n\r\n".to_string(),
                        ..ReplayTabState::default()
                    },
                    ReplayTabState {
                        id: "inactive".to_string(),
                        sequence: 2,
                        request_text: "GET /inactive HTTP/1.1\r\n\r\n".to_string(),
                        ..ReplayTabState::default()
                    },
                ],
            },
            ..WorkspaceStateSnapshot::default()
        };
        let incoming = WorkspaceStateSnapshot {
            client_version: 2,
            replay: ReplayWorkspaceState {
                active_tab_id: None,
                tab_sequence: 2,
                tabs: Vec::new(),
            },
            ..WorkspaceStateSnapshot::default()
        };

        let merged = super::merge_workspace_keepalive_snapshot(
            current,
            incoming,
            super::WorkspaceKeepaliveMetadata {
                replay_tabs_complete: false,
                ..super::WorkspaceKeepaliveMetadata::default()
            },
        );

        assert_eq!(merged.replay.active_tab_id.as_deref(), Some("active"));
        assert_eq!(merged.replay.tabs.len(), 2);
        assert_eq!(merged.client_version, 2);
    }

    #[test]
    fn workspace_keepalive_merge_preserves_websocket_state_missing_from_compact_payload() {
        let frame = WsReplayFrame {
            index: 7,
            captured_at: Utc::now().to_rfc3339(),
            direction: WebSocketFrameDirection::ServerToClient,
            kind: WebSocketFrameKind::Text,
            body: "live-frame".to_string(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 10,
            preview_truncated: false,
        };
        let current = WorkspaceStateSnapshot {
            replay: ReplayWorkspaceState {
                active_tab_id: Some("ws".to_string()),
                tab_sequence: 1,
                tabs: vec![ReplayTabState {
                    id: "ws".to_string(),
                    tab_type: "websocket".to_string(),
                    sequence: 1,
                    ws_setup_queue: vec![serde_json::json!({
                        "id": "queued-message",
                        "body": "old"
                    })],
                    ws_frames: vec![frame.clone()],
                    ws_selected_frame_index: Some(0),
                    ws_frame_window_start: Some(4),
                    ws_frames_truncated: true,
                    ..ReplayTabState::default()
                }],
            },
            ..WorkspaceStateSnapshot::default()
        };
        let incoming = WorkspaceStateSnapshot {
            replay: ReplayWorkspaceState {
                active_tab_id: Some("ws".to_string()),
                tab_sequence: 1,
                tabs: vec![ReplayTabState {
                    id: "ws".to_string(),
                    tab_type: "websocket".to_string(),
                    sequence: 1,
                    ws_setup_queue: Vec::new(),
                    ws_frames: Vec::new(),
                    ws_selected_frame_index: None,
                    ws_frame_window_start: None,
                    ws_frames_truncated: false,
                    ..ReplayTabState::default()
                }],
            },
            ..WorkspaceStateSnapshot::default()
        };

        let merged = super::merge_workspace_keepalive_snapshot(
            current,
            incoming,
            super::WorkspaceKeepaliveMetadata::default(),
        );

        let tab = merged.replay.tabs.first().expect("merged tab");
        assert_eq!(tab.ws_setup_queue.len(), 1);
        assert_eq!(tab.ws_frames.len(), 1);
        assert_eq!(tab.ws_frames[0].index, frame.index);
        assert_eq!(tab.ws_frames[0].body, frame.body);
        assert_eq!(tab.ws_selected_frame_index, Some(0));
        assert_eq!(tab.ws_frame_window_start, Some(4));
        assert!(tab.ws_frames_truncated);
    }

    #[test]
    fn workspace_keepalive_merge_preserves_existing_partial_websocket_frames() {
        let current = WorkspaceStateSnapshot {
            replay: ReplayWorkspaceState {
                active_tab_id: Some("ws".to_string()),
                tab_sequence: 1,
                tabs: vec![ReplayTabState {
                    id: "ws".to_string(),
                    tab_type: "websocket".to_string(),
                    sequence: 1,
                    ws_frames: vec![
                        test_ws_replay_frame(1, "old-one"),
                        test_ws_replay_frame(2, "old-two"),
                    ],
                    ws_frames_complete: Some(true),
                    ws_selected_frame_index: Some(1),
                    ws_frame_window_start: Some(1),
                    ..ReplayTabState::default()
                }],
            },
            ..WorkspaceStateSnapshot::default()
        };
        let incoming = WorkspaceStateSnapshot {
            replay: ReplayWorkspaceState {
                active_tab_id: Some("ws".to_string()),
                tab_sequence: 1,
                tabs: vec![ReplayTabState {
                    id: "ws".to_string(),
                    tab_type: "websocket".to_string(),
                    sequence: 1,
                    ws_frames: vec![
                        test_ws_replay_frame(2, "new-two"),
                        test_ws_replay_frame(3, "new-three"),
                    ],
                    ws_frames_complete: Some(false),
                    ..ReplayTabState::default()
                }],
            },
            ..WorkspaceStateSnapshot::default()
        };

        let merged = super::merge_workspace_keepalive_snapshot(
            current,
            incoming,
            super::WorkspaceKeepaliveMetadata::default(),
        );

        let tab = merged.replay.tabs.first().expect("merged tab");
        let frames: Vec<_> = tab
            .ws_frames
            .iter()
            .map(|frame| (frame.index, frame.body.as_str()))
            .collect();
        assert_eq!(
            frames,
            vec![(1, "old-one"), (2, "new-two"), (3, "new-three")]
        );
        assert_eq!(tab.ws_selected_frame_index, Some(1));
        assert_eq!(tab.ws_frame_window_start, Some(1));
        assert!(!tab.ws_frames_truncated);
    }

    #[tokio::test]
    async fn workspace_full_update_merges_incomplete_websocket_frames() {
        let state =
            Arc::new(AppState::new(test_app_config("sniper-full-save-ws-frame-merge")).unwrap());
        let session = state.session().await;
        let session_id = session.id();
        let tab_id = Uuid::new_v4().to_string();
        let current = WorkspaceStateSnapshot {
            session_id: Some(session_id),
            client_id: Some("browser".to_string()),
            client_version: 1,
            replay: ReplayWorkspaceState {
                active_tab_id: Some(tab_id.clone()),
                tab_sequence: 1,
                tabs: vec![ReplayTabState {
                    id: tab_id.clone(),
                    tab_type: "websocket".to_string(),
                    sequence: 1,
                    ws_frames: vec![
                        test_ws_replay_frame(1, "old-one"),
                        test_ws_replay_frame(2, "old-two"),
                    ],
                    ws_frames_complete: Some(true),
                    ws_selected_frame_index: Some(1),
                    ws_frame_window_start: Some(1),
                    ..ReplayTabState::default()
                }],
            },
            ..WorkspaceStateSnapshot::default()
        };
        let current_response =
            super::update_workspace_state(State(state.clone()), Json(current)).await;
        assert_eq!(current_response.status(), StatusCode::OK);
        let saved_current: WorkspaceStateSnapshot = response_json(current_response).await;

        let incoming = WorkspaceStateSnapshot {
            session_id: Some(session_id),
            revision: saved_current.revision,
            client_id: Some("browser".to_string()),
            client_version: 2,
            replay: ReplayWorkspaceState {
                active_tab_id: Some(tab_id.clone()),
                tab_sequence: 1,
                tabs: vec![ReplayTabState {
                    id: tab_id,
                    tab_type: "websocket".to_string(),
                    sequence: 1,
                    ws_frames: vec![
                        test_ws_replay_frame(2, "new-two"),
                        test_ws_replay_frame(3, "new-three"),
                    ],
                    ws_frames_complete: Some(false),
                    ..ReplayTabState::default()
                }],
            },
            ..WorkspaceStateSnapshot::default()
        };
        let update_response =
            super::update_workspace_state(State(state.clone()), Json(incoming)).await;
        assert_eq!(update_response.status(), StatusCode::OK);

        let reloaded = state.sessions.load_context(session_id).unwrap();
        let snapshot = reloaded.workspace.snapshot().await;
        let tab = snapshot.replay.tabs.first().expect("ws tab should persist");
        let frames: Vec<_> = tab
            .ws_frames
            .iter()
            .map(|frame| (frame.index, frame.body.as_str()))
            .collect();
        assert_eq!(
            frames,
            vec![(1, "old-one"), (2, "new-two"), (3, "new-three")]
        );
        assert_eq!(tab.ws_selected_frame_index, Some(1));
        assert_eq!(tab.ws_frame_window_start, Some(1));
        assert!(!tab.ws_frames_truncated);
    }

    #[tokio::test]
    async fn workspace_full_update_missing_ws_frames_complete_replaces_frames() {
        let state =
            Arc::new(AppState::new(test_app_config("sniper-full-save-ws-frame-replace")).unwrap());
        let session = state.session().await;
        let session_id = session.id();
        let tab_id = Uuid::new_v4().to_string();
        let current = WorkspaceStateSnapshot {
            session_id: Some(session_id),
            client_id: Some("browser".to_string()),
            client_version: 1,
            replay: ReplayWorkspaceState {
                active_tab_id: Some(tab_id.clone()),
                tab_sequence: 1,
                tabs: vec![ReplayTabState {
                    id: tab_id.clone(),
                    tab_type: "websocket".to_string(),
                    sequence: 1,
                    ws_frames: vec![test_ws_replay_frame(1, "stale")],
                    ws_frames_complete: Some(true),
                    ws_selected_frame_index: Some(0),
                    ws_frame_window_start: Some(1),
                    ..ReplayTabState::default()
                }],
            },
            ..WorkspaceStateSnapshot::default()
        };
        let current_response =
            super::update_workspace_state(State(state.clone()), Json(current)).await;
        assert_eq!(current_response.status(), StatusCode::OK);
        let saved_current: WorkspaceStateSnapshot = response_json(current_response).await;

        let incoming = WorkspaceStateSnapshot {
            session_id: Some(session_id),
            revision: saved_current.revision,
            client_id: Some("browser".to_string()),
            client_version: 2,
            replay: ReplayWorkspaceState {
                active_tab_id: Some(tab_id.clone()),
                tab_sequence: 1,
                tabs: vec![ReplayTabState {
                    id: tab_id,
                    tab_type: "websocket".to_string(),
                    sequence: 1,
                    ws_frames: Vec::new(),
                    ws_frames_complete: None,
                    ws_selected_frame_index: None,
                    ws_frame_window_start: None,
                    ws_frames_truncated: false,
                    ..ReplayTabState::default()
                }],
            },
            ..WorkspaceStateSnapshot::default()
        };
        let update_response =
            super::update_workspace_state(State(state.clone()), Json(incoming)).await;
        assert_eq!(update_response.status(), StatusCode::OK);

        let reloaded = state.sessions.load_context(session_id).unwrap();
        let snapshot = reloaded.workspace.snapshot().await;
        let tab = snapshot.replay.tabs.first().expect("ws tab should persist");
        assert!(tab.ws_frames.is_empty());
        assert_eq!(tab.ws_selected_frame_index, None);
        assert_eq!(tab.ws_frame_window_start, None);
        assert!(!tab.ws_frames_truncated);
    }

    #[test]
    fn workspace_keepalive_merge_does_not_preserve_websocket_state_on_http_tab() {
        let frame = WsReplayFrame {
            index: 7,
            captured_at: Utc::now().to_rfc3339(),
            direction: WebSocketFrameDirection::ServerToClient,
            kind: WebSocketFrameKind::Text,
            body: "stale-frame".to_string(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 11,
            preview_truncated: false,
        };
        let current = WorkspaceStateSnapshot {
            replay: ReplayWorkspaceState {
                active_tab_id: Some("tab".to_string()),
                tab_sequence: 1,
                tabs: vec![ReplayTabState {
                    id: "tab".to_string(),
                    tab_type: "websocket".to_string(),
                    sequence: 1,
                    ws_setup_queue: vec![serde_json::json!({ "body": "stale" })],
                    ws_frames: vec![frame],
                    ws_selected_frame_index: Some(0),
                    ws_frame_window_start: Some(4),
                    ws_frames_truncated: true,
                    ..ReplayTabState::default()
                }],
            },
            ..WorkspaceStateSnapshot::default()
        };
        let incoming = WorkspaceStateSnapshot {
            replay: ReplayWorkspaceState {
                active_tab_id: Some("tab".to_string()),
                tab_sequence: 1,
                tabs: vec![ReplayTabState {
                    id: "tab".to_string(),
                    sequence: 1,
                    request_text: "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n".to_string(),
                    ..ReplayTabState::default()
                }],
            },
            ..WorkspaceStateSnapshot::default()
        };

        let merged = super::merge_workspace_keepalive_snapshot(
            current,
            incoming,
            super::WorkspaceKeepaliveMetadata::default(),
        );

        let tab = merged.replay.tabs.first().expect("merged tab");
        assert_ne!(tab.tab_type, "websocket");
        assert!(tab.ws_setup_queue.is_empty());
        assert!(tab.ws_frames.is_empty());
        assert_eq!(tab.ws_selected_frame_index, None);
        assert_eq!(tab.ws_frame_window_start, None);
        assert!(!tab.ws_frames_truncated);
    }

    #[test]
    fn workspace_keepalive_merge_honors_complete_empty_replay_arrays() {
        let frame = WsReplayFrame {
            index: 3,
            captured_at: Utc::now().to_rfc3339(),
            direction: WebSocketFrameDirection::ClientToServer,
            kind: WebSocketFrameKind::Text,
            body: "stale-frame".to_string(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 11,
            preview_truncated: false,
        };
        let current = WorkspaceStateSnapshot {
            replay: ReplayWorkspaceState {
                active_tab_id: Some("http".to_string()),
                tab_sequence: 2,
                tabs: vec![
                    ReplayTabState {
                        id: "http".to_string(),
                        sequence: 1,
                        history_entries: vec![ReplayHistoryEntryState {
                            request_text: "GET /stale HTTP/1.1\r\n\r\n".to_string(),
                            ..ReplayHistoryEntryState::default()
                        }],
                        history_index: Some(0),
                        ..ReplayTabState::default()
                    },
                    ReplayTabState {
                        id: "ws".to_string(),
                        tab_type: "websocket".to_string(),
                        sequence: 2,
                        ws_setup_queue: vec![serde_json::json!({ "body": "stale" })],
                        ws_frames: vec![frame],
                        ws_selected_frame_index: Some(0),
                        ws_frame_window_start: Some(8),
                        ws_frames_truncated: true,
                        ..ReplayTabState::default()
                    },
                ],
            },
            ..WorkspaceStateSnapshot::default()
        };
        let incoming = WorkspaceStateSnapshot {
            replay: ReplayWorkspaceState {
                active_tab_id: Some("http".to_string()),
                tab_sequence: 2,
                tabs: vec![
                    ReplayTabState {
                        id: "http".to_string(),
                        sequence: 1,
                        history_entries: Vec::new(),
                        history_index: None,
                        history_entries_complete: Some(true),
                        ..ReplayTabState::default()
                    },
                    ReplayTabState {
                        id: "ws".to_string(),
                        tab_type: "websocket".to_string(),
                        sequence: 2,
                        ws_setup_queue: Vec::new(),
                        ws_setup_queue_complete: Some(true),
                        ws_frames: Vec::new(),
                        ws_frames_complete: Some(true),
                        ws_selected_frame_index: None,
                        ws_frame_window_start: None,
                        ws_frames_truncated: false,
                        ..ReplayTabState::default()
                    },
                ],
            },
            ..WorkspaceStateSnapshot::default()
        };

        let merged = super::merge_workspace_keepalive_snapshot(
            current,
            incoming,
            super::WorkspaceKeepaliveMetadata::default(),
        );

        let http = merged
            .replay
            .tabs
            .iter()
            .find(|tab| tab.id == "http")
            .expect("http tab");
        assert!(http.history_entries.is_empty());
        assert_eq!(http.history_index, None);

        let ws = merged
            .replay
            .tabs
            .iter()
            .find(|tab| tab.id == "ws")
            .expect("ws tab");
        assert!(ws.ws_setup_queue.is_empty());
        assert!(ws.ws_frames.is_empty());
        assert_eq!(ws.ws_selected_frame_index, None);
        assert_eq!(ws.ws_frame_window_start, None);
        assert!(!ws.ws_frames_truncated);
    }

    #[test]
    fn workspace_keepalive_complete_replay_payload_removes_closed_tabs() {
        let current = WorkspaceStateSnapshot {
            replay: ReplayWorkspaceState {
                active_tab_id: Some("active".to_string()),
                tab_sequence: 2,
                tabs: vec![
                    ReplayTabState {
                        id: "active".to_string(),
                        sequence: 1,
                        request_text: "GET /active HTTP/1.1\r\n\r\n".to_string(),
                        ..ReplayTabState::default()
                    },
                    ReplayTabState {
                        id: "closed".to_string(),
                        sequence: 2,
                        request_text: "GET /closed HTTP/1.1\r\n\r\n".to_string(),
                        ..ReplayTabState::default()
                    },
                ],
            },
            ..WorkspaceStateSnapshot::default()
        };
        let incoming = WorkspaceStateSnapshot {
            replay: ReplayWorkspaceState {
                active_tab_id: Some("active".to_string()),
                tab_sequence: 2,
                tabs: vec![ReplayTabState {
                    id: "active".to_string(),
                    sequence: 1,
                    request_text: "GET /active-edited HTTP/1.1\r\n\r\n".to_string(),
                    ..ReplayTabState::default()
                }],
            },
            ..WorkspaceStateSnapshot::default()
        };

        let merged = super::merge_workspace_keepalive_snapshot(
            current,
            incoming,
            super::WorkspaceKeepaliveMetadata {
                replay_tabs_complete: true,
                fuzzer_complete: false,
                ..super::WorkspaceKeepaliveMetadata::default()
            },
        );

        assert_eq!(merged.replay.tabs.len(), 1);
        assert_eq!(merged.replay.tabs[0].id, "active");
        assert!(merged.replay.tabs[0]
            .request_text
            .contains("/active-edited"));
    }

    #[test]
    fn workspace_keepalive_partial_replay_membership_removes_closed_tabs() {
        let current = WorkspaceStateSnapshot {
            replay: ReplayWorkspaceState {
                active_tab_id: Some("active".to_string()),
                tab_sequence: 3,
                tabs: vec![
                    ReplayTabState {
                        id: "active".to_string(),
                        sequence: 1,
                        request_text: "GET /active HTTP/1.1\r\n\r\n".to_string(),
                        ..ReplayTabState::default()
                    },
                    ReplayTabState {
                        id: "inactive".to_string(),
                        sequence: 2,
                        request_text: "GET /inactive HTTP/1.1\r\n\r\n".to_string(),
                        ..ReplayTabState::default()
                    },
                    ReplayTabState {
                        id: "closed".to_string(),
                        sequence: 3,
                        request_text: "GET /closed HTTP/1.1\r\n\r\n".to_string(),
                        ..ReplayTabState::default()
                    },
                ],
            },
            ..WorkspaceStateSnapshot::default()
        };
        let incoming = WorkspaceStateSnapshot {
            replay: ReplayWorkspaceState {
                active_tab_id: Some("active".to_string()),
                tab_sequence: 3,
                tabs: vec![ReplayTabState {
                    id: "active".to_string(),
                    sequence: 1,
                    request_text: "GET /active-edited HTTP/1.1\r\n\r\n".to_string(),
                    ..ReplayTabState::default()
                }],
            },
            ..WorkspaceStateSnapshot::default()
        };

        let merged = super::merge_workspace_keepalive_snapshot(
            current,
            incoming,
            super::WorkspaceKeepaliveMetadata {
                replay_tabs_complete: false,
                replay_tab_ids: Some(vec!["active".to_string(), "inactive".to_string()]),
                ..super::WorkspaceKeepaliveMetadata::default()
            },
        );

        assert_eq!(merged.replay.tabs.len(), 2);
        assert!(merged.replay.tabs.iter().any(|tab| tab.id == "inactive"));
        assert!(!merged.replay.tabs.iter().any(|tab| tab.id == "closed"));
        let active = merged
            .replay
            .tabs
            .iter()
            .find(|tab| tab.id == "active")
            .expect("active tab");
        assert!(active.request_text.contains("/active-edited"));
    }

    #[test]
    fn workspace_keepalive_complete_fuzzer_payload_clears_stale_fields() {
        let stale_attack_id = Uuid::new_v4();
        let stale_source_id = Uuid::new_v4();
        let current = WorkspaceStateSnapshot {
            fuzzer: FuzzerWorkspaceState {
                source_transaction_id: Some(stale_source_id),
                target: Some(RequestTargetOverride {
                    scheme: "https".to_string(),
                    host: "old.example".to_string(),
                    port: "443".to_string(),
                }),
                target_request_authority: Some("old.example".to_string()),
                notice: "old notice".to_string(),
                request_text: "FUZZ /old HTTP/1.1\r\n\r\n".to_string(),
                payloads_text: "old-payload".to_string(),
                attack_record_id: Some(stale_attack_id),
                ..FuzzerWorkspaceState::default()
            },
            ..WorkspaceStateSnapshot::default()
        };
        let incoming = WorkspaceStateSnapshot {
            fuzzer: FuzzerWorkspaceState {
                request_text: "FUZZ /new HTTP/1.1\r\n\r\n".to_string(),
                payloads_text: String::new(),
                attack_record_id: None,
                ..FuzzerWorkspaceState::default()
            },
            ..WorkspaceStateSnapshot::default()
        };

        let merged = super::merge_workspace_keepalive_snapshot(
            current,
            incoming,
            super::WorkspaceKeepaliveMetadata {
                replay_tabs_complete: false,
                fuzzer_complete: true,
                ..super::WorkspaceKeepaliveMetadata::default()
            },
        );

        assert_eq!(
            merged.fuzzer.request_text,
            "FUZZ /new HTTP/1.1\r\n\r\n".to_string()
        );
        assert!(merged.fuzzer.payloads_text.is_empty());
        assert!(merged.fuzzer.attack_record_id.is_none());
        assert!(merged.fuzzer.source_transaction_id.is_none());
        assert!(merged.fuzzer.target.is_none());
        assert!(merged.fuzzer.target_request_authority.is_none());
        assert!(merged.fuzzer.notice.is_empty());
    }

    #[test]
    fn workspace_keepalive_partial_fuzzer_text_preserves_coupled_fields() {
        let current_source_id = Uuid::new_v4();
        let current_attack_id = Uuid::new_v4();
        let incoming_source_id = Uuid::new_v4();
        let incoming_attack_id = Uuid::new_v4();
        let current = WorkspaceStateSnapshot {
            fuzzer: FuzzerWorkspaceState {
                base_request: Some(test_editable_request("/old")),
                source_transaction_id: Some(current_source_id),
                target: Some(RequestTargetOverride {
                    scheme: "https".to_string(),
                    host: "old.example".to_string(),
                    port: "443".to_string(),
                }),
                target_request_authority: Some("old.example".to_string()),
                notice: "old notice".to_string(),
                request_text: "GET /old HTTP/1.1\r\nHost: old.example\r\n\r\n".to_string(),
                payloads_text: "old-payload".to_string(),
                attack_record_id: Some(current_attack_id),
                ..FuzzerWorkspaceState::default()
            },
            ..WorkspaceStateSnapshot::default()
        };
        let incoming = WorkspaceStateSnapshot {
            fuzzer: FuzzerWorkspaceState {
                base_request: Some(test_editable_request("/new")),
                source_transaction_id: Some(incoming_source_id),
                target: Some(RequestTargetOverride {
                    scheme: "https".to_string(),
                    host: "new.example".to_string(),
                    port: "443".to_string(),
                }),
                target_request_authority: Some("new.example".to_string()),
                notice: "new notice".to_string(),
                request_text: "GET /new HTTP/1.1\r\nHost: new.example\r\n\r\n".to_string(),
                payloads_text: "new-payload".to_string(),
                attack_record_id: Some(incoming_attack_id),
                ..FuzzerWorkspaceState::default()
            },
            ..WorkspaceStateSnapshot::default()
        };

        for fuzzer_complete in [true, false] {
            let merged = super::merge_workspace_keepalive_snapshot(
                current.clone(),
                incoming.clone(),
                super::WorkspaceKeepaliveMetadata {
                    replay_tabs_complete: false,
                    fuzzer_complete,
                    text_complete: Some(false),
                    ..super::WorkspaceKeepaliveMetadata::default()
                },
            );

            assert_eq!(
                merged.fuzzer.request_text,
                "GET /old HTTP/1.1\r\nHost: old.example\r\n\r\n".to_string()
            );
            assert_eq!(merged.fuzzer.payloads_text, "old-payload");
            assert_eq!(merged.fuzzer.source_transaction_id, Some(current_source_id));
            assert_eq!(merged.fuzzer.attack_record_id, Some(current_attack_id));
            assert_eq!(
                merged
                    .fuzzer
                    .target
                    .as_ref()
                    .map(|target| target.host.as_str()),
                Some("old.example")
            );
            assert_eq!(
                merged.fuzzer.target_request_authority.as_deref(),
                Some("old.example")
            );
            assert_eq!(merged.fuzzer.notice, "old notice");
        }
    }

    #[test]
    fn workspace_keepalive_empty_request_text_does_not_restore_stale_response() {
        let current = WorkspaceStateSnapshot {
            replay: ReplayWorkspaceState {
                active_tab_id: Some("active".to_string()),
                tab_sequence: 1,
                tabs: vec![ReplayTabState {
                    id: "active".to_string(),
                    sequence: 1,
                    base_request: Some(test_editable_request("/old")),
                    request_text: "GET /old HTTP/1.1\r\nHost: example.test\r\n\r\n".to_string(),
                    response_record: Some(crate::model::TransactionRecord::http(
                        chrono::Utc::now(),
                        "GET".to_string(),
                        "https".to_string(),
                        "example.test".to_string(),
                        "/old".to_string(),
                        Some(200),
                        1,
                        crate::model::MessageRecord::from_headers_and_body(
                            &HeaderMap::new(),
                            &[],
                            0,
                        ),
                        None,
                        Vec::new(),
                        None,
                        None,
                    )),
                    target_scheme: "https".to_string(),
                    target_host: "example.test".to_string(),
                    target_port: "443".to_string(),
                    ..ReplayTabState::default()
                }],
            },
            ..WorkspaceStateSnapshot::default()
        };
        let incoming = WorkspaceStateSnapshot {
            replay: ReplayWorkspaceState {
                active_tab_id: Some("active".to_string()),
                tab_sequence: 1,
                tabs: vec![ReplayTabState {
                    id: "active".to_string(),
                    sequence: 1,
                    base_request: Some(test_editable_request("/old")),
                    request_text: String::new(),
                    response_record: None,
                    target_scheme: "https".to_string(),
                    target_host: "example.test".to_string(),
                    target_port: "443".to_string(),
                    ..ReplayTabState::default()
                }],
            },
            ..WorkspaceStateSnapshot::default()
        };

        let merged = super::merge_workspace_keepalive_snapshot(
            current,
            incoming,
            super::WorkspaceKeepaliveMetadata::default(),
        );

        let active = merged.replay.tabs.first().expect("active tab");
        assert!(active.request_text.is_empty());
        assert!(active.response_record.is_none());
    }

    #[test]
    fn workspace_keepalive_explicit_null_response_does_not_restore_stale_response() {
        let request_text = "GET /old HTTP/1.1\r\nHost: example.test\r\n\r\n".to_string();
        let current = WorkspaceStateSnapshot {
            replay: ReplayWorkspaceState {
                active_tab_id: Some("active".to_string()),
                tab_sequence: 1,
                tabs: vec![ReplayTabState {
                    id: "active".to_string(),
                    sequence: 1,
                    base_request: Some(test_editable_request("/old")),
                    request_text: request_text.clone(),
                    response_record: Some(test_replay_response_record("/old", 200)),
                    target_scheme: "https".to_string(),
                    target_host: "example.test".to_string(),
                    target_port: "443".to_string(),
                    ..ReplayTabState::default()
                }],
            },
            ..WorkspaceStateSnapshot::default()
        };
        let incoming = WorkspaceStateSnapshot {
            replay: ReplayWorkspaceState {
                active_tab_id: Some("active".to_string()),
                tab_sequence: 1,
                tabs: vec![ReplayTabState {
                    id: "active".to_string(),
                    sequence: 1,
                    base_request: Some(test_editable_request("/old")),
                    request_text,
                    response_record: None,
                    response_record_complete: Some(true),
                    target_scheme: "https".to_string(),
                    target_host: "example.test".to_string(),
                    target_port: "443".to_string(),
                    ..ReplayTabState::default()
                }],
            },
            ..WorkspaceStateSnapshot::default()
        };

        let merged = super::merge_workspace_keepalive_snapshot(
            current,
            incoming,
            super::WorkspaceKeepaliveMetadata::default(),
        );

        let active = merged.replay.tabs.first().expect("active tab");
        assert!(active.response_record.is_none());
    }

    #[test]
    fn workspace_keepalive_skips_missing_http_tab_when_text_is_partial() {
        let current = WorkspaceStateSnapshot {
            replay: ReplayWorkspaceState {
                active_tab_id: Some("existing".to_string()),
                tab_sequence: 1,
                tabs: vec![ReplayTabState {
                    id: "existing".to_string(),
                    sequence: 1,
                    request_text: "GET /existing HTTP/1.1\r\n\r\n".to_string(),
                    target_scheme: "https".to_string(),
                    target_host: "example.test".to_string(),
                    target_port: "443".to_string(),
                    ..ReplayTabState::default()
                }],
            },
            ..WorkspaceStateSnapshot::default()
        };
        let incoming = WorkspaceStateSnapshot {
            replay: ReplayWorkspaceState {
                active_tab_id: Some("new".to_string()),
                tab_sequence: 2,
                tabs: vec![ReplayTabState {
                    id: "new".to_string(),
                    sequence: 2,
                    request_text: "GET /truncated HTTP/1.1\r\n\r\n".to_string(),
                    target_scheme: "https".to_string(),
                    target_host: "example.test".to_string(),
                    target_port: "443".to_string(),
                    ..ReplayTabState::default()
                }],
            },
            ..WorkspaceStateSnapshot::default()
        };

        let merged = super::merge_workspace_keepalive_snapshot(
            current,
            incoming,
            super::WorkspaceKeepaliveMetadata {
                text_complete: Some(false),
                ..Default::default()
            },
        );

        assert_eq!(merged.replay.tabs.len(), 1);
        assert_eq!(merged.replay.tabs[0].id, "existing");
        assert_eq!(merged.replay.active_tab_id.as_deref(), Some("existing"));
    }

    #[test]
    fn workspace_keepalive_creates_missing_http_tab_shell_when_children_are_compact() {
        let current = WorkspaceStateSnapshot {
            replay: ReplayWorkspaceState {
                active_tab_id: Some("existing".to_string()),
                tabs: vec![ReplayTabState {
                    id: "existing".to_string(),
                    sequence: 1,
                    ..ReplayTabState::default()
                }],
                ..ReplayWorkspaceState::default()
            },
            ..WorkspaceStateSnapshot::default()
        };
        let incoming = WorkspaceStateSnapshot {
            replay: ReplayWorkspaceState {
                active_tab_id: Some("new-http".to_string()),
                tab_sequence: 2,
                tabs: vec![ReplayTabState {
                    id: "new-http".to_string(),
                    sequence: 2,
                    custom_label: "Replay HTTP".to_string(),
                    base_request: Some(test_editable_request("/compact")),
                    request_text: "GET /compact HTTP/1.1\r\nHost: example.test\r\n\r\n".to_string(),
                    target_scheme: "https".to_string(),
                    target_host: "example.test".to_string(),
                    target_port: "443".to_string(),
                    response_record: None,
                    response_record_complete: Some(false),
                    history_entries: Vec::new(),
                    history_entries_complete: Some(false),
                    history_index: Some(7),
                    ..ReplayTabState::default()
                }],
            },
            ..WorkspaceStateSnapshot::default()
        };

        let merged = super::merge_workspace_keepalive_snapshot(
            current,
            incoming,
            super::WorkspaceKeepaliveMetadata::default(),
        );

        assert_eq!(merged.replay.tabs.len(), 2);
        assert_eq!(merged.replay.active_tab_id.as_deref(), Some("new-http"));
        let tab = merged
            .replay
            .tabs
            .iter()
            .find(|tab| tab.id == "new-http")
            .expect("new HTTP replay tab shell should be kept");
        assert_eq!(tab.custom_label, "Replay HTTP");
        assert_eq!(tab.target_host, "example.test");
        assert_eq!(
            tab.request_text,
            "GET /compact HTTP/1.1\r\nHost: example.test\r\n\r\n"
        );
        assert!(tab.response_record.is_none());
        assert!(tab.history_entries.is_empty());
        assert!(tab.history_index.is_none());
    }

    #[test]
    fn workspace_keepalive_skips_missing_websocket_tab_when_text_is_partial() {
        let current = WorkspaceStateSnapshot::default();
        let incoming = WorkspaceStateSnapshot {
            replay: ReplayWorkspaceState {
                active_tab_id: Some("ws-new".to_string()),
                tab_sequence: 1,
                tabs: vec![ReplayTabState {
                    id: "ws-new".to_string(),
                    tab_type: "websocket".to_string(),
                    sequence: 1,
                    ws_handshake_text: "GET /partial HTTP/1.1\r\n".to_string(),
                    ws_editor_text: "partial".to_string(),
                    ws_setup_queue_complete: Some(false),
                    ws_frames_complete: Some(false),
                    ..ReplayTabState::default()
                }],
            },
            ..WorkspaceStateSnapshot::default()
        };

        let merged = super::merge_workspace_keepalive_snapshot(
            current,
            incoming,
            super::WorkspaceKeepaliveMetadata {
                ws_text_complete: Some(false),
                ..Default::default()
            },
        );

        assert!(merged.replay.tabs.is_empty());
        assert!(merged.replay.active_tab_id.is_none());
    }

    #[test]
    fn workspace_keepalive_creates_missing_websocket_tab_shell_when_arrays_are_compact() {
        let current = WorkspaceStateSnapshot {
            replay: ReplayWorkspaceState {
                active_tab_id: Some("existing".to_string()),
                tabs: vec![ReplayTabState {
                    id: "existing".to_string(),
                    sequence: 1,
                    ..ReplayTabState::default()
                }],
                ..ReplayWorkspaceState::default()
            },
            ..WorkspaceStateSnapshot::default()
        };
        let incoming = WorkspaceStateSnapshot {
            replay: ReplayWorkspaceState {
                active_tab_id: Some("ws-new".to_string()),
                tab_sequence: 2,
                tabs: vec![ReplayTabState {
                    id: "ws-new".to_string(),
                    tab_type: "websocket".to_string(),
                    custom_label: "Replay WS".to_string(),
                    sequence: 2,
                    ws_scheme: "wss".to_string(),
                    ws_host: "example.test".to_string(),
                    ws_path: "/socket".to_string(),
                    ws_handshake_text: "GET /socket HTTP/1.1\r\nHost: example.test\r\n\r\n"
                        .to_string(),
                    ws_editor_text: "hello".to_string(),
                    ws_setup_queue_complete: Some(false),
                    ws_frames: vec![test_ws_replay_frame(42, "tail")],
                    ws_frames_complete: Some(false),
                    ..ReplayTabState::default()
                }],
            },
            ..WorkspaceStateSnapshot::default()
        };

        let merged = super::merge_workspace_keepalive_snapshot(
            current,
            incoming,
            super::WorkspaceKeepaliveMetadata::default(),
        );

        assert_eq!(merged.replay.tabs.len(), 2);
        assert_eq!(merged.replay.active_tab_id.as_deref(), Some("ws-new"));
        let tab = merged
            .replay
            .tabs
            .iter()
            .find(|tab| tab.id == "ws-new")
            .expect("new websocket tab shell should be kept");
        assert_eq!(tab.tab_type, "websocket");
        assert_eq!(tab.custom_label, "Replay WS");
        assert_eq!(tab.ws_host, "example.test");
        assert_eq!(tab.ws_path, "/socket");
        assert_eq!(tab.ws_editor_text, "hello");
        assert!(tab.ws_setup_queue.is_empty());
        assert_eq!(tab.ws_frames.len(), 1);
        assert_eq!(tab.ws_frames[0].index, 42);
        assert!(tab.ws_frames_truncated);
    }

    #[test]
    fn workspace_keepalive_creates_missing_websocket_tab_when_arrays_are_complete_empty() {
        let current = WorkspaceStateSnapshot::default();
        let incoming = WorkspaceStateSnapshot {
            replay: ReplayWorkspaceState {
                active_tab_id: Some("ws-new".to_string()),
                tab_sequence: 1,
                tabs: vec![ReplayTabState {
                    id: "ws-new".to_string(),
                    tab_type: "websocket".to_string(),
                    custom_label: "Replay WS".to_string(),
                    sequence: 1,
                    ws_scheme: "wss".to_string(),
                    ws_host: "example.test".to_string(),
                    ws_path: "/socket".to_string(),
                    ws_handshake_text: "GET /socket HTTP/1.1\r\nHost: example.test\r\n\r\n"
                        .to_string(),
                    ws_editor_text: "hello".to_string(),
                    ws_setup_queue_complete: Some(true),
                    ws_frames_complete: Some(true),
                    ..ReplayTabState::default()
                }],
            },
            ..WorkspaceStateSnapshot::default()
        };

        let merged = super::merge_workspace_keepalive_snapshot(
            current,
            incoming,
            super::WorkspaceKeepaliveMetadata::default(),
        );

        assert_eq!(merged.replay.tabs.len(), 1);
        assert_eq!(merged.replay.active_tab_id.as_deref(), Some("ws-new"));
        let tab = &merged.replay.tabs[0];
        assert_eq!(tab.tab_type, "websocket");
        assert_eq!(tab.ws_host, "example.test");
        assert!(tab.ws_setup_queue.is_empty());
        assert!(tab.ws_frames.is_empty());
        assert!(!tab.ws_frames_truncated);
    }

    #[test]
    fn workspace_keepalive_skips_missing_websocket_tab_when_array_flags_are_missing() {
        let current = WorkspaceStateSnapshot::default();
        let incoming = WorkspaceStateSnapshot {
            replay: ReplayWorkspaceState {
                active_tab_id: Some("ws-new".to_string()),
                tab_sequence: 1,
                tabs: vec![ReplayTabState {
                    id: "ws-new".to_string(),
                    tab_type: "websocket".to_string(),
                    sequence: 1,
                    ws_scheme: "wss".to_string(),
                    ws_host: "example.test".to_string(),
                    ws_path: "/socket".to_string(),
                    ws_handshake_text: "GET /socket HTTP/1.1\r\nHost: example.test\r\n\r\n"
                        .to_string(),
                    ws_editor_text: "hello".to_string(),
                    ..ReplayTabState::default()
                }],
            },
            ..WorkspaceStateSnapshot::default()
        };

        let merged = super::merge_workspace_keepalive_snapshot(
            current,
            incoming,
            super::WorkspaceKeepaliveMetadata::default(),
        );

        assert!(merged.replay.tabs.is_empty());
        assert!(merged.replay.active_tab_id.is_none());
    }

    #[test]
    fn workspace_keepalive_partial_ws_text_preserves_durable_text() {
        let ws_tab_id = Uuid::new_v4().to_string();
        let durable_handshake = "GET /ws HTTP/1.1\r\n".repeat(4096);
        let durable_editor = "A".repeat(70_000);
        let current = WorkspaceStateSnapshot {
            replay: ReplayWorkspaceState {
                active_tab_id: Some(ws_tab_id.clone()),
                tab_sequence: 1,
                tabs: vec![ReplayTabState {
                    id: ws_tab_id.clone(),
                    tab_type: "websocket".to_string(),
                    sequence: 1,
                    ws_host: "ws.example".to_string(),
                    ws_path: "/ws".to_string(),
                    ws_handshake_text: durable_handshake.clone(),
                    ws_editor_text: durable_editor.clone(),
                    ws_message_type: "text".to_string(),
                    ..ReplayTabState::default()
                }],
            },
            ..WorkspaceStateSnapshot::default()
        };
        let incoming = WorkspaceStateSnapshot {
            replay: ReplayWorkspaceState {
                active_tab_id: Some(ws_tab_id.clone()),
                tab_sequence: 1,
                tabs: vec![ReplayTabState {
                    id: ws_tab_id,
                    tab_type: "websocket".to_string(),
                    sequence: 1,
                    ws_host: "ws.example".to_string(),
                    ws_path: "/ws-edited".to_string(),
                    ws_handshake_text: "GET /ws HTTP/1.1\r\n".repeat(32),
                    ws_editor_text: "A".repeat(2048),
                    ws_message_type: "binary".to_string(),
                    ..ReplayTabState::default()
                }],
            },
            ..WorkspaceStateSnapshot::default()
        };

        let merged = super::merge_workspace_keepalive_snapshot(
            current,
            incoming,
            super::WorkspaceKeepaliveMetadata {
                replay_tabs_complete: false,
                fuzzer_complete: false,
                ws_text_complete: Some(false),
                ..super::WorkspaceKeepaliveMetadata::default()
            },
        );

        let tab = merged.replay.tabs.first().expect("merged websocket tab");
        assert_eq!(tab.ws_path, "/ws-edited");
        assert_eq!(tab.ws_message_type, "binary");
        assert_eq!(tab.ws_handshake_text, durable_handshake);
        assert_eq!(tab.ws_editor_text, durable_editor);
    }

    #[test]
    fn workspace_keepalive_partial_text_preserves_durable_http_and_fuzzer_text() {
        let current_request = "POST /large HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let durable_response = test_replay_response_record("/large", 200);
        let durable_history_response = test_replay_response_record("/history", 201);
        let durable_source_id = Uuid::new_v4();
        let incoming_source_id = Uuid::new_v4();
        let current = WorkspaceStateSnapshot {
            replay: ReplayWorkspaceState {
                active_tab_id: Some("active".to_string()),
                tab_sequence: 1,
                tabs: vec![ReplayTabState {
                    id: "active".to_string(),
                    sequence: 1,
                    base_request: Some(test_editable_request("/large")),
                    source_transaction_id: Some(durable_source_id),
                    request_text: format!("{current_request}{}", "A".repeat(80_000)),
                    http_version_mode: "HTTP/2".to_string(),
                    target_scheme: "https".to_string(),
                    target_host: "example.test".to_string(),
                    target_port: "443".to_string(),
                    response_record: Some(durable_response.clone()),
                    history_entries: vec![ReplayHistoryEntryState {
                        request: Some(test_editable_request("/history")),
                        request_text: "GET /history HTTP/1.1\r\nHost: example.test\r\n\r\n"
                            .to_string(),
                        response_record: Some(durable_history_response.clone()),
                        target_scheme: "https".to_string(),
                        target_host: "example.test".to_string(),
                        target_port: "443".to_string(),
                        ..ReplayHistoryEntryState::default()
                    }],
                    history_index: Some(0),
                    ..ReplayTabState::default()
                }],
            },
            fuzzer: FuzzerWorkspaceState {
                base_request: Some(test_editable_request("/fuzz-large")),
                request_text: "FUZZ /large HTTP/1.1\r\n\r\n".repeat(2048),
                payloads_text: "payload\n".repeat(2048),
                ..FuzzerWorkspaceState::default()
            },
            ..WorkspaceStateSnapshot::default()
        };
        let durable_tab_text = current.replay.tabs[0].request_text.clone();
        let durable_fuzzer_request = current.fuzzer.request_text.clone();
        let durable_fuzzer_payloads = current.fuzzer.payloads_text.clone();
        let incoming = WorkspaceStateSnapshot {
            replay: ReplayWorkspaceState {
                active_tab_id: Some("active".to_string()),
                tab_sequence: 1,
                tabs: vec![ReplayTabState {
                    id: "active".to_string(),
                    sequence: 1,
                    base_request: Some(test_editable_request("/truncated")),
                    source_transaction_id: Some(incoming_source_id),
                    request_text: format!("{current_request}{}", "A".repeat(1024)),
                    http_version_mode: "HTTP/1.0".to_string(),
                    target_scheme: "https".to_string(),
                    target_host: "edited.example".to_string(),
                    target_port: "8443".to_string(),
                    response_record: None,
                    response_record_complete: Some(true),
                    history_entries: Vec::new(),
                    history_entries_complete: Some(true),
                    ..ReplayTabState::default()
                }],
            },
            fuzzer: FuzzerWorkspaceState {
                base_request: Some(test_editable_request("/fuzz-truncated")),
                request_text: "FUZZ /large HTTP/1.1\r\n\r\n".to_string(),
                payloads_text: "payload\n".to_string(),
                ..FuzzerWorkspaceState::default()
            },
            ..WorkspaceStateSnapshot::default()
        };

        let merged = super::merge_workspace_keepalive_snapshot(
            current,
            incoming,
            super::WorkspaceKeepaliveMetadata {
                replay_tabs_complete: false,
                fuzzer_complete: true,
                text_complete: Some(false),
                ..super::WorkspaceKeepaliveMetadata::default()
            },
        );

        let tab = merged.replay.tabs.first().expect("merged tab");
        assert_eq!(tab.target_host, "edited.example");
        assert_eq!(tab.target_port, "8443");
        assert_eq!(tab.request_text, durable_tab_text);
        assert_eq!(tab.base_request.as_ref().unwrap().path, "/large");
        assert_eq!(tab.source_transaction_id, Some(durable_source_id));
        assert_eq!(tab.http_version_mode, "HTTP/2");
        assert_eq!(
            tab.response_record.as_ref().unwrap().id,
            durable_response.id
        );
        assert_eq!(tab.history_entries.len(), 1);
        assert_eq!(
            tab.history_entries[0].response_record.as_ref().unwrap().id,
            durable_history_response.id
        );
        assert_eq!(tab.history_index, Some(0));
        assert_eq!(merged.fuzzer.request_text, durable_fuzzer_request);
        assert_eq!(merged.fuzzer.payloads_text, durable_fuzzer_payloads);
        assert_eq!(
            merged.fuzzer.base_request.as_ref().unwrap().path,
            "/fuzz-large"
        );
    }

    #[test]
    fn workspace_validation_rejects_unbounded_durable_metadata() {
        let mut snapshot = WorkspaceStateSnapshot {
            client_id: Some("x".repeat(super::MAX_WORKSPACE_CLIENT_ID_BYTES + 1)),
            ..WorkspaceStateSnapshot::default()
        };
        let error = super::validate_workspace_state(&snapshot).unwrap_err();
        assert!(error.contains("workspace client id"));

        snapshot.client_id = None;
        snapshot.fuzzer.target_request_authority =
            Some("x".repeat(crate::workspace::MAX_WORKSPACE_SERIALIZED_BYTES));
        let error = super::validate_workspace_state(&snapshot).unwrap_err();
        assert!(error.contains("serialized bytes"));
    }

    #[test]
    fn workspace_validation_rejects_invalid_fuzzer_target_request_authority() {
        let mut snapshot = WorkspaceStateSnapshot::default();
        snapshot.fuzzer.target_request_authority = Some("not a url".to_string());

        let error = super::validate_workspace_state(&snapshot).unwrap_err();

        assert!(error.contains("invalid fuzzer target request authority"));
    }

    #[test]
    fn workspace_validation_rejects_ip_request_host_fuzzer_target_override() {
        let mut snapshot = WorkspaceStateSnapshot::default();
        snapshot.fuzzer.base_request = Some(EditableRequest {
            scheme: "https".to_string(),
            host: "127.0.0.1:443".to_string(),
            method: "GET".to_string(),
            path: "/fuzz".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        });
        snapshot.fuzzer.target = Some(RequestTargetOverride {
            scheme: "https".to_string(),
            host: "127.0.0.2".to_string(),
            port: "9443".to_string(),
        });

        let error = super::validate_workspace_state(&snapshot).unwrap_err();

        assert!(error.contains("request host is an IP address"));
    }

    #[test]
    fn workspace_validation_rejects_mismatched_fuzzer_target_request_authority() {
        let mut snapshot = WorkspaceStateSnapshot::default();
        snapshot.fuzzer.base_request = Some(test_editable_request("/fuzz"));
        snapshot.fuzzer.target_request_authority = Some("https://other.example".to_string());

        let error = super::validate_workspace_state(&snapshot).unwrap_err();

        assert!(error.contains("must match fuzzer base request"));
    }

    #[tokio::test]
    async fn request_intercept_forward_body_session_id_targets_inactive_session() {
        let state = Arc::new(
            AppState::new(test_app_config("sniper-forward-request-body-session")).unwrap(),
        );
        let original = state.session().await;
        let original_id = original.id();
        let active_id = state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap()
            .id;
        let record = InterceptRecord {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            peer_addr: "127.0.0.1:12345".to_string(),
            request: test_editable_request("/queued"),
            is_websocket: false,
        };
        let record_id = record.id;
        let queue = original.intercepts.clone();
        let task = tokio::spawn({
            let queue = queue.clone();
            async move { queue.enqueue(record).await }
        });
        for _ in 0..20 {
            if queue.list().await.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(queue.list().await.len(), 1);

        let conflict = super::forward_intercept(
            State(state.clone()),
            Path(record_id.to_string()),
            Query(super::SessionWriteQuery {
                session_id: Some(active_id),
                expected_active_session_id: None,
            }),
            Json(super::InterceptForwardPayload {
                session_id: Some(original_id),
                request: test_editable_request("/conflict"),
                edited: true,
            }),
        )
        .await;
        assert_eq!(conflict.status(), StatusCode::BAD_REQUEST);
        assert_eq!(queue.list().await.len(), 1);

        let response = super::forward_intercept(
            State(state.clone()),
            Path(record_id.to_string()),
            Query(super::SessionWriteQuery {
                session_id: None,
                expected_active_session_id: None,
            }),
            Json(super::InterceptForwardPayload {
                session_id: Some(original_id),
                request: test_editable_request("/forwarded"),
                edited: true,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(queue.list().await.is_empty());
        match task.await.unwrap() {
            InterceptResolution::Forward { request, .. } => assert_eq!(request.path, "/forwarded"),
            other => panic!("expected forward resolution, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn response_intercept_forward_body_session_id_targets_inactive_session() {
        let state = Arc::new(
            AppState::new(test_app_config("sniper-forward-response-body-session")).unwrap(),
        );
        let original = state.session().await;
        let original_id = original.id();
        let active_id = state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap()
            .id;
        let record = ResponseInterceptRecord {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            scheme: "https".to_string(),
            host: "example.test".to_string(),
            method: "GET".to_string(),
            path: "/queued".to_string(),
            status: 200,
            response: test_editable_response(200),
        };
        let record_id = record.id;
        let queue = original.response_intercepts.clone();
        let task = tokio::spawn({
            let queue = queue.clone();
            async move { queue.enqueue(record).await }
        });
        for _ in 0..20 {
            if queue.list().await.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(queue.list().await.len(), 1);

        let conflict = super::forward_response_intercept(
            State(state.clone()),
            Path(record_id.to_string()),
            Query(super::SessionWriteQuery {
                session_id: Some(active_id),
                expected_active_session_id: None,
            }),
            Json(super::ResponseInterceptForwardPayload {
                session_id: Some(original_id),
                response: test_editable_response(409),
                edited: true,
            }),
        )
        .await;
        assert_eq!(conflict.status(), StatusCode::BAD_REQUEST);
        assert_eq!(queue.list().await.len(), 1);

        let response = super::forward_response_intercept(
            State(state.clone()),
            Path(record_id.to_string()),
            Query(super::SessionWriteQuery {
                session_id: None,
                expected_active_session_id: None,
            }),
            Json(super::ResponseInterceptForwardPayload {
                session_id: Some(original_id),
                response: test_editable_response(204),
                edited: true,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(queue.list().await.is_empty());
        match task.await.unwrap() {
            ResponseInterceptResolution::Forward { response, .. } => {
                assert_eq!(response.status, 204)
            }
            other => panic!("expected forward resolution, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn response_intercept_forward_allows_head_representation_content_length() {
        let state = Arc::new(
            AppState::new(test_app_config(
                "sniper-forward-response-head-content-length",
            ))
            .unwrap(),
        );
        let session = state.session().await;
        let response = EditableResponse {
            status: 200,
            headers: vec![HeaderRecord {
                name: "Content-Length".to_string(),
                value: "123".to_string(),
            }],
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
        };
        let record = ResponseInterceptRecord {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            scheme: "https".to_string(),
            host: "example.test".to_string(),
            method: "HEAD".to_string(),
            path: "/queued".to_string(),
            status: 200,
            response: response.clone(),
        };
        let record_id = record.id;
        let queue = session.response_intercepts.clone();
        let task = tokio::spawn({
            let queue = queue.clone();
            async move { queue.enqueue(record).await }
        });
        for _ in 0..20 {
            if queue.list().await.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(queue.list().await.len(), 1);

        let api_response = super::forward_response_intercept(
            State(state.clone()),
            Path(record_id.to_string()),
            Query(super::SessionWriteQuery {
                session_id: Some(session.id()),
                expected_active_session_id: None,
            }),
            Json(super::ResponseInterceptForwardPayload {
                session_id: None,
                response,
                edited: true,
            }),
        )
        .await;

        assert_eq!(api_response.status(), StatusCode::NO_CONTENT);
        match task.await.unwrap() {
            ResponseInterceptResolution::Forward { response, .. } => {
                assert_eq!(response.status, 200);
                assert_eq!(response.body, "");
                assert_eq!(response.headers[0].name, "Content-Length");
                assert_eq!(response.headers[0].value, "123");
            }
            other => panic!("expected forward resolution, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn response_intercept_forward_rejects_head_response_body() {
        let state =
            Arc::new(AppState::new(test_app_config("sniper-forward-response-head-body")).unwrap());
        let session = state.session().await;
        let response = EditableResponse {
            status: 200,
            headers: vec![HeaderRecord {
                name: "Content-Length".to_string(),
                value: "4".to_string(),
            }],
            body: "body".to_string(),
            body_encoding: BodyEncoding::Utf8,
        };
        let record = ResponseInterceptRecord {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            scheme: "https".to_string(),
            host: "example.test".to_string(),
            method: "HEAD".to_string(),
            path: "/queued".to_string(),
            status: 200,
            response: EditableResponse {
                status: 200,
                headers: Vec::new(),
                body: String::new(),
                body_encoding: BodyEncoding::Utf8,
            },
        };
        let record_id = record.id;
        let queue = session.response_intercepts.clone();
        let task = tokio::spawn({
            let queue = queue.clone();
            async move { queue.enqueue(record).await }
        });
        for _ in 0..20 {
            if queue.list().await.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(queue.list().await.len(), 1);

        let api_response = super::forward_response_intercept(
            State(state.clone()),
            Path(record_id.to_string()),
            Query(super::SessionWriteQuery {
                session_id: Some(session.id()),
                expected_active_session_id: None,
            }),
            Json(super::ResponseInterceptForwardPayload {
                session_id: None,
                response,
                edited: true,
            }),
        )
        .await;

        assert_eq!(api_response.status(), StatusCode::BAD_REQUEST);
        queue.drop_response(record_id).await.unwrap();
        match task.await.unwrap() {
            ResponseInterceptResolution::Drop => {}
            other => panic!("expected drop resolution, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn request_intercept_drop_body_session_id_targets_inactive_session() {
        let state =
            Arc::new(AppState::new(test_app_config("sniper-drop-request-body-session")).unwrap());
        let original = state.session().await;
        let original_id = original.id();
        state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();
        let record = InterceptRecord {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            peer_addr: "127.0.0.1:12345".to_string(),
            request: test_editable_request("/queued"),
            is_websocket: false,
        };
        let record_id = record.id;
        let queue = original.intercepts.clone();
        let task = tokio::spawn({
            let queue = queue.clone();
            async move { queue.enqueue(record).await }
        });
        for _ in 0..20 {
            if queue.list().await.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(queue.list().await.len(), 1);

        let response = super::drop_intercept(
            State(state.clone()),
            Path(record_id.to_string()),
            Query(super::SessionWriteQuery {
                session_id: None,
                expected_active_session_id: None,
            }),
            Some(Json(super::SessionActionPayload {
                session_id: Some(original_id),
            })),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(queue.list().await.is_empty());
        assert!(matches!(task.await.unwrap(), InterceptResolution::Drop(_)));
    }

    #[tokio::test]
    async fn response_intercept_drop_body_session_id_targets_inactive_session() {
        let state =
            Arc::new(AppState::new(test_app_config("sniper-drop-response-body-session")).unwrap());
        let original = state.session().await;
        let original_id = original.id();
        state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();
        let record = ResponseInterceptRecord {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            scheme: "https".to_string(),
            host: "example.test".to_string(),
            method: "GET".to_string(),
            path: "/queued".to_string(),
            status: 200,
            response: test_editable_response(200),
        };
        let record_id = record.id;
        let queue = original.response_intercepts.clone();
        let task = tokio::spawn({
            let queue = queue.clone();
            async move { queue.enqueue(record).await }
        });
        for _ in 0..20 {
            if queue.list().await.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(queue.list().await.len(), 1);

        let response = super::drop_response_intercept(
            State(state.clone()),
            Path(record_id.to_string()),
            Query(super::SessionWriteQuery {
                session_id: None,
                expected_active_session_id: None,
            }),
            Some(Json(super::SessionActionPayload {
                session_id: Some(original_id),
            })),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(queue.list().await.is_empty());
        assert!(matches!(
            task.await.unwrap(),
            ResponseInterceptResolution::Drop
        ));
    }

    #[tokio::test]
    async fn request_forward_all_body_session_id_targets_inactive_session() {
        let state = Arc::new(
            AppState::new(test_app_config("sniper-forward-all-request-body-session")).unwrap(),
        );
        let original = state.session().await;
        let original_id = original.id();
        state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();
        let queue = original.intercepts.clone();
        let task = tokio::spawn({
            let queue = queue.clone();
            async move {
                queue
                    .enqueue(InterceptRecord {
                        id: Uuid::new_v4(),
                        started_at: Utc::now(),
                        peer_addr: "127.0.0.1:12345".to_string(),
                        request: test_editable_request("/queued"),
                        is_websocket: false,
                    })
                    .await
            }
        });
        for _ in 0..20 {
            if queue.list().await.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let response = super::forward_all_intercepts(
            State(state.clone()),
            Query(super::SessionWriteQuery {
                session_id: None,
                expected_active_session_id: None,
            }),
            Some(Json(super::SessionActionPayload {
                session_id: Some(original_id),
            })),
        )
        .await;
        let payload = response_body_json(response).await;
        assert_eq!(payload["forwarded"], 1);
        assert!(queue.list().await.is_empty());
        assert!(matches!(
            task.await.unwrap(),
            InterceptResolution::Forward { .. }
        ));
    }

    #[tokio::test]
    async fn response_forward_all_body_session_id_targets_inactive_session() {
        let state = Arc::new(
            AppState::new(test_app_config("sniper-forward-all-response-body-session")).unwrap(),
        );
        let original = state.session().await;
        let original_id = original.id();
        state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();
        let queue = original.response_intercepts.clone();
        let task = tokio::spawn({
            let queue = queue.clone();
            async move {
                queue
                    .enqueue(ResponseInterceptRecord {
                        id: Uuid::new_v4(),
                        started_at: Utc::now(),
                        scheme: "https".to_string(),
                        host: "example.test".to_string(),
                        method: "GET".to_string(),
                        path: "/queued".to_string(),
                        status: 200,
                        response: test_editable_response(200),
                    })
                    .await
            }
        });
        for _ in 0..20 {
            if queue.list().await.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let response = super::forward_all_response_intercepts(
            State(state.clone()),
            Query(super::SessionWriteQuery {
                session_id: None,
                expected_active_session_id: None,
            }),
            Some(Json(super::SessionActionPayload {
                session_id: Some(original_id),
            })),
        )
        .await;
        let payload = response_body_json(response).await;
        assert_eq!(payload["forwarded"], 1);
        assert!(queue.list().await.is_empty());
        assert!(matches!(
            task.await.unwrap(),
            ResponseInterceptResolution::Forward { .. }
        ));
    }

    #[tokio::test]
    async fn session_write_queries_reject_stale_expected_active_session() {
        let state =
            Arc::new(AppState::new(test_app_config("sniper-stale-session-write-query")).unwrap());
        let original = state.session().await;
        let original_id = original.id();
        let record = test_replay_response_record("/annotated", 200);
        let record_id = record.id;
        original.store.insert(record).await;
        state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();
        let stale_query = super::SessionWriteQuery {
            session_id: Some(original_id),
            expected_active_session_id: Some(original_id),
        };

        let event_response =
            super::clear_event_log(State(state.clone()), Query(stale_query.clone())).await;
        assert_eq!(event_response.status(), StatusCode::CONFLICT);

        let findings_response =
            super::clear_findings(State(state.clone()), Query(stale_query.clone())).await;
        assert_eq!(findings_response.status(), StatusCode::CONFLICT);

        let mut scanner_config = original.scanner.get_config().await;
        scanner_config.enabled = false;
        let scanner_response = super::update_scanner_config(
            State(state.clone()),
            Query(stale_query.clone()),
            Json(super::ScannerConfigPayload::from(scanner_config)),
        )
        .await;
        assert_eq!(scanner_response.status(), StatusCode::CONFLICT);
        assert!(original.scanner.get_config().await.enabled);

        let match_rule = MatchReplaceRule {
            id: Uuid::new_v4(),
            enabled: true,
            description: "stale".to_string(),
            scope: MatchReplaceScope::Request,
            target: MatchReplaceTarget::Path,
            search: "/old".to_string(),
            replace: "/new".to_string(),
            regex: false,
            case_sensitive: true,
        };
        let match_response = super::update_match_replace_rules(
            State(state.clone()),
            Query(stale_query.clone()),
            Json(MatchReplaceRulesPayload {
                session_id: None,
                rules: vec![match_rule],
            }),
        )
        .await;
        assert_eq!(match_response.status(), StatusCode::CONFLICT);
        assert!(original.match_replace.snapshot().await.is_empty());

        let annotation_response = super::update_transaction_annotations(
            State(state.clone()),
            Path(record_id.to_string()),
            Query(super::TransactionWriteQuery {
                session_id: Some(original_id),
                expected_active_session_id: Some(original_id),
            }),
            Json(super::AnnotationsPayload {
                session_id: None,
                color_tag: Some(Some("blue".to_string())),
                user_note: None,
                client_id: None,
                client_version: None,
            }),
        )
        .await;
        assert_eq!(annotation_response.status(), StatusCode::CONFLICT);
        assert!(original
            .store
            .get(record_id)
            .await
            .unwrap()
            .color_tag
            .is_none());

        let request_forward_response = super::forward_intercept(
            State(state.clone()),
            Path(Uuid::new_v4().to_string()),
            Query(stale_query.clone()),
            Json(super::InterceptForwardPayload {
                session_id: None,
                request: test_editable_request("/stale"),
                edited: true,
            }),
        )
        .await;
        assert_eq!(request_forward_response.status(), StatusCode::CONFLICT);

        let request_drop_response = super::drop_intercept(
            State(state.clone()),
            Path(Uuid::new_v4().to_string()),
            Query(stale_query.clone()),
            None,
        )
        .await;
        assert_eq!(request_drop_response.status(), StatusCode::CONFLICT);

        let request_forward_all_response =
            super::forward_all_intercepts(State(state.clone()), Query(stale_query.clone()), None)
                .await;
        assert_eq!(request_forward_all_response.status(), StatusCode::CONFLICT);

        let response_forward_response = super::forward_response_intercept(
            State(state.clone()),
            Path(Uuid::new_v4().to_string()),
            Query(stale_query.clone()),
            Json(super::ResponseInterceptForwardPayload {
                session_id: None,
                response: test_editable_response(200),
                edited: true,
            }),
        )
        .await;
        assert_eq!(response_forward_response.status(), StatusCode::CONFLICT);

        let response_drop_response = super::drop_response_intercept(
            State(state.clone()),
            Path(Uuid::new_v4().to_string()),
            Query(stale_query.clone()),
            None,
        )
        .await;
        assert_eq!(response_drop_response.status(), StatusCode::CONFLICT);

        let response_forward_all_response = super::forward_all_response_intercepts(
            State(state.clone()),
            Query(stale_query.clone()),
            None,
        )
        .await;
        assert_eq!(response_forward_all_response.status(), StatusCode::CONFLICT);

        let rule_response = super::delete_intercept_rule(
            State(state.clone()),
            Path(Uuid::new_v4().to_string()),
            Query(stale_query.clone()),
        )
        .await;
        assert_eq!(rule_response.status(), StatusCode::CONFLICT);

        let intercept_rule = InterceptRule {
            id: Uuid::new_v4(),
            enabled: true,
            scope: InterceptScope::Both,
            host_pattern: "stale.example".to_string(),
            path_pattern: "/api".to_string(),
            method_filter: vec!["GET".to_string()],
        };
        let upsert_response = super::upsert_intercept_rule(
            State(state.clone()),
            Query(stale_query.clone()),
            Json(super::InterceptRulePayload::from(intercept_rule)),
        )
        .await;
        assert_eq!(upsert_response.status(), StatusCode::CONFLICT);
        assert!(original.intercept_rules.list().await.is_empty());

        let oast_response =
            super::clear_oast_callbacks(State(state.clone()), Query(stale_query)).await;
        assert_eq!(oast_response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn request_forward_all_returns_json_count() {
        let state =
            Arc::new(AppState::new(test_app_config("sniper-forward-all-requests")).unwrap());
        let session = state.session().await;
        let queue = session.intercepts.clone();
        let first = InterceptRecord {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            peer_addr: "127.0.0.1:12345".to_string(),
            request: test_editable_request("/one"),
            is_websocket: false,
        };
        let second = InterceptRecord {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            peer_addr: "127.0.0.1:12346".to_string(),
            request: test_editable_request("/two"),
            is_websocket: false,
        };
        let first_task = tokio::spawn({
            let queue = queue.clone();
            async move { queue.enqueue(first).await }
        });
        let second_task = tokio::spawn({
            let queue = queue.clone();
            async move { queue.enqueue(second).await }
        });
        for _ in 0..20 {
            if session.intercepts.list().await.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(session.intercepts.list().await.len(), 2);

        let response = super::forward_all_intercepts(
            State(state.clone()),
            Query(super::SessionWriteQuery {
                session_id: None,
                expected_active_session_id: None,
            }),
            None,
        )
        .await;
        let payload = response_body_json(response).await;

        assert_eq!(payload["ok"], true);
        assert_eq!(payload["action"], "forward-all");
        assert_eq!(payload["forwarded"], 2);
        assert!(session.intercepts.list().await.is_empty());
        assert!(matches!(
            first_task.await.unwrap(),
            InterceptResolution::Forward { .. }
        ));
        assert!(matches!(
            second_task.await.unwrap(),
            InterceptResolution::Forward { .. }
        ));
    }

    #[tokio::test]
    async fn response_forward_all_returns_json_count() {
        let state =
            Arc::new(AppState::new(test_app_config("sniper-forward-all-responses")).unwrap());
        let session = state.session().await;
        let queue = session.response_intercepts.clone();
        let first = ResponseInterceptRecord {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            scheme: "https".to_string(),
            host: "example.test".to_string(),
            method: "GET".to_string(),
            path: "/one".to_string(),
            status: 200,
            response: test_editable_response(200),
        };
        let second = ResponseInterceptRecord {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            scheme: "https".to_string(),
            host: "example.test".to_string(),
            method: "GET".to_string(),
            path: "/two".to_string(),
            status: 204,
            response: test_editable_response(204),
        };
        let first_task = tokio::spawn({
            let queue = queue.clone();
            async move { queue.enqueue(first).await }
        });
        let second_task = tokio::spawn({
            let queue = queue.clone();
            async move { queue.enqueue(second).await }
        });
        for _ in 0..20 {
            if session.response_intercepts.list().await.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(session.response_intercepts.list().await.len(), 2);

        let response = super::forward_all_response_intercepts(
            State(state.clone()),
            Query(super::SessionWriteQuery {
                session_id: None,
                expected_active_session_id: None,
            }),
            None,
        )
        .await;
        let payload = response_body_json(response).await;

        assert_eq!(payload["ok"], true);
        assert_eq!(payload["action"], "forward-all");
        assert_eq!(payload["forwarded"], 2);
        assert!(session.response_intercepts.list().await.is_empty());
        assert!(matches!(
            first_task.await.unwrap(),
            ResponseInterceptResolution::Forward { .. }
        ));
        assert!(matches!(
            second_task.await.unwrap(),
            ResponseInterceptResolution::Forward { .. }
        ));
    }

    #[test]
    fn workspace_validation_rejects_oversized_replay_text_state() {
        let mut snapshot = WorkspaceStateSnapshot::default();
        snapshot.replay.tabs.push(ReplayTabState {
            id: "large-tab".to_string(),
            sequence: 1,
            request_text: "x".repeat(super::MAX_WORKSPACE_TEXT_FIELD_BYTES + 1),
            ..ReplayTabState::default()
        });

        let error = super::validate_workspace_state(&snapshot).unwrap_err();
        assert!(error.contains("replay tab request text"));
    }

    #[test]
    fn workspace_validation_rejects_oversized_replay_history_state() {
        let mut snapshot = WorkspaceStateSnapshot::default();
        snapshot.replay.tabs.push(ReplayTabState {
            id: "history-tab".to_string(),
            sequence: 1,
            history_entries: vec![
                ReplayHistoryEntryState::default();
                super::MAX_WORKSPACE_REPLAY_HISTORY_ENTRIES_PER_TAB + 1
            ],
            ..ReplayTabState::default()
        });

        let error = super::validate_workspace_state(&snapshot).unwrap_err();
        assert!(error.contains("too many history entries"));
    }

    #[test]
    fn workspace_validation_rejects_oversized_fuzzer_payload_text_state() {
        let mut snapshot = WorkspaceStateSnapshot {
            fuzzer: FuzzerWorkspaceState {
                payloads_text: "x\n".repeat(super::MAX_WORKSPACE_FUZZER_PAYLOAD_LINES + 1),
                ..FuzzerWorkspaceState::default()
            },
            ..WorkspaceStateSnapshot::default()
        };

        let error = super::validate_workspace_state(&snapshot).unwrap_err();
        assert!(error.contains("fuzzer payload text"));

        snapshot.fuzzer.payloads_text =
            "x".repeat(super::MAX_WORKSPACE_FUZZER_PAYLOAD_TEXT_BYTES + 1);
        let error = super::validate_workspace_state(&snapshot).unwrap_err();
        assert!(error.contains("fuzzer payload text"));
    }

    #[test]
    fn workspace_validation_allows_empty_replay_drafts() {
        let mut snapshot = WorkspaceStateSnapshot::default();
        snapshot.replay.tabs.push(ReplayTabState {
            id: "draft".to_string(),
            sequence: 1,
            base_request: Some(EditableRequest {
                scheme: "https".to_string(),
                host: String::new(),
                method: "GET".to_string(),
                path: "/".to_string(),
                headers: Vec::new(),
                body: String::new(),
                body_encoding: BodyEncoding::Utf8,
                preview_truncated: false,
            }),
            target_scheme: "https".to_string(),
            target_host: String::new(),
            target_port: "443".to_string(),
            ..ReplayTabState::default()
        });

        assert!(super::validate_workspace_state(&snapshot).is_ok());
    }

    #[test]
    fn workspace_validation_rejects_invalid_websocket_tab_fields() {
        let mut snapshot = WorkspaceStateSnapshot::default();
        snapshot.replay.tabs.push(ReplayTabState {
            id: Uuid::new_v4().to_string(),
            tab_type: "websocket".to_string(),
            sequence: 1,
            ws_scheme: "wss".to_string(),
            ws_host: String::new(),
            ws_port: serde_json::json!(443),
            ws_path: "/".to_string(),
            ..ReplayTabState::default()
        });
        assert!(super::validate_workspace_state(&snapshot).is_ok());

        snapshot.replay.tabs[0].ws_scheme = "https".to_string();
        assert!(super::validate_workspace_state(&snapshot).is_err());

        snapshot.replay.tabs[0].ws_scheme = "wss".to_string();
        snapshot.replay.tabs[0].ws_host = "example.test".to_string();
        snapshot.replay.tabs[0].ws_port = serde_json::json!("notaport");
        assert!(super::validate_workspace_state(&snapshot).is_err());

        snapshot.replay.tabs[0].ws_port = serde_json::json!(443);
        snapshot.replay.tabs[0].ws_headers = vec![serde_json::json!({
            "name": "Authorization",
            "value": "Bearer abc\nInjected: yes"
        })];
        assert!(super::validate_workspace_state(&snapshot).is_err());

        snapshot.replay.tabs[0].ws_headers.clear();
        snapshot.replay.tabs[0].ws_setup_queue = vec![serde_json::json!({
            "kind": "ping",
            "body": "not base64",
            "body_encoded": true
        })];
        assert!(super::validate_workspace_state(&snapshot).is_err());

        snapshot.replay.tabs[0].ws_setup_queue.clear();
        snapshot.replay.tabs[0].ws_setup_notice = "Auto-send setup disabled.".to_string();
        assert!(super::validate_workspace_state(&snapshot).is_ok());
    }

    #[test]
    fn workspace_validation_rejects_non_uuid_websocket_replay_tab_id() {
        let mut snapshot = WorkspaceStateSnapshot::default();
        snapshot.replay.tabs.push(ReplayTabState {
            id: "ws-draft".to_string(),
            tab_type: "websocket".to_string(),
            sequence: 1,
            ws_scheme: "wss".to_string(),
            ws_host: "example.test".to_string(),
            ws_port: serde_json::json!(443),
            ws_path: "/".to_string(),
            ..ReplayTabState::default()
        });

        let error = super::validate_workspace_state(&snapshot).unwrap_err();
        assert!(error.contains("id must be a UUID"));
    }

    #[test]
    fn workspace_validation_rejects_websocket_state_on_non_websocket_tabs() {
        fn assert_rejects(tab: ReplayTabState) {
            let mut snapshot = WorkspaceStateSnapshot::default();
            snapshot.replay.tabs.push(tab);
            let error = super::validate_workspace_state(&snapshot).unwrap_err();
            assert!(error.contains("must not include websocket state"));
        }

        assert_rejects(ReplayTabState {
            id: "http-draft".to_string(),
            sequence: 1,
            ws_setup_notice: "websocket only".to_string(),
            ..ReplayTabState::default()
        });
        assert_rejects(ReplayTabState {
            id: "http-draft".to_string(),
            sequence: 1,
            ws_selected_frame_index: Some(0),
            ..ReplayTabState::default()
        });
        assert_rejects(ReplayTabState {
            id: "http-draft".to_string(),
            sequence: 1,
            ws_frame_window_start: Some(0),
            ..ReplayTabState::default()
        });
    }

    #[test]
    fn workspace_validation_rejects_http_state_on_websocket_tabs() {
        fn assert_rejects(tab: ReplayTabState) {
            let mut snapshot = WorkspaceStateSnapshot::default();
            snapshot.replay.tabs.push(tab);
            let error = super::validate_workspace_state(&snapshot).unwrap_err();
            assert!(error.contains("must not include HTTP replay state"));
        }

        assert_rejects(ReplayTabState {
            id: Uuid::new_v4().to_string(),
            tab_type: "websocket".to_string(),
            sequence: 1,
            request_text: "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n".to_string(),
            ..ReplayTabState::default()
        });
        assert_rejects(ReplayTabState {
            id: Uuid::new_v4().to_string(),
            tab_type: "websocket".to_string(),
            sequence: 1,
            base_request: Some(test_editable_request("/")),
            ..ReplayTabState::default()
        });
        assert_rejects(ReplayTabState {
            id: Uuid::new_v4().to_string(),
            tab_type: "websocket".to_string(),
            sequence: 1,
            history_entries: vec![ReplayHistoryEntryState {
                request_text: "GET /history HTTP/1.1\r\n\r\n".to_string(),
                ..ReplayHistoryEntryState::default()
            }],
            ..ReplayTabState::default()
        });
    }

    #[test]
    fn workspace_validation_rejects_oversized_websocket_headers() {
        let mut snapshot = WorkspaceStateSnapshot::default();
        snapshot.replay.tabs.push(ReplayTabState {
            id: Uuid::new_v4().to_string(),
            tab_type: "websocket".to_string(),
            sequence: 1,
            ws_headers: (0..=super::MAX_WORKSPACE_WS_HEADERS)
                .map(|index| {
                    serde_json::json!({
                        "name": format!("X-Test-{index}"),
                        "value": "ok"
                    })
                })
                .collect(),
            ..ReplayTabState::default()
        });

        let error = super::validate_workspace_state(&snapshot).unwrap_err();
        assert!(error.contains("too many headers"));

        snapshot.replay.tabs[0].ws_headers = vec![serde_json::json!({
            "name": "X-Large",
            "value": "x".repeat(super::MAX_WORKSPACE_WS_HEADER_BYTES)
        })];
        let error = super::validate_workspace_state(&snapshot).unwrap_err();
        assert!(error.contains("WebSocket header cannot exceed"));
    }

    #[test]
    fn workspace_validation_checks_websocket_replay_frames() {
        let mut snapshot = WorkspaceStateSnapshot::default();
        let frame = WsReplayFrame {
            index: 0,
            captured_at: Utc::now().to_rfc3339(),
            direction: WebSocketFrameDirection::ClientToServer,
            kind: WebSocketFrameKind::Text,
            body: "hello".to_string(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 5,
            preview_truncated: false,
        };
        snapshot.replay.tabs.push(ReplayTabState {
            id: Uuid::new_v4().to_string(),
            tab_type: "websocket".to_string(),
            sequence: 1,
            ws_scheme: "wss".to_string(),
            ws_host: "example.test".to_string(),
            ws_port: serde_json::json!(443),
            ws_path: "/".to_string(),
            ws_frames: vec![frame.clone()],
            ..ReplayTabState::default()
        });
        assert!(super::validate_workspace_state(&snapshot).is_ok());

        snapshot.replay.tabs[0].ws_frames[0].body =
            "x".repeat(super::MAX_WORKSPACE_WS_FRAME_BODY_BYTES + 1);
        snapshot.replay.tabs[0].ws_frames[0].body_size =
            snapshot.replay.tabs[0].ws_frames[0].body.len();
        assert!(super::validate_workspace_state(&snapshot).is_err());

        snapshot.replay.tabs[0].ws_frames[0].body = "hello".to_string();
        snapshot.replay.tabs[0].ws_frames[0].body_size = 10;
        snapshot.replay.tabs[0].ws_frames[0].preview_truncated = false;
        assert!(super::validate_workspace_state(&snapshot).is_err());

        snapshot.replay.tabs[0].ws_frames[0].preview_truncated = true;
        assert!(super::validate_workspace_state(&snapshot).is_ok());

        snapshot.replay.tabs[0].ws_frames[0].captured_at = "not-a-timestamp".to_string();
        assert!(super::validate_workspace_state(&snapshot).is_err());

        let mut oversized_workspace = WorkspaceStateSnapshot::default();
        oversized_workspace.replay.tabs = (0..3)
            .map(|tab_index| ReplayTabState {
                id: Uuid::new_v4().to_string(),
                tab_type: "websocket".to_string(),
                sequence: tab_index + 1,
                ws_frames: vec![frame.clone(); super::MAX_WORKSPACE_WS_FRAMES],
                ..ReplayTabState::default()
            })
            .collect();
        assert!(super::validate_workspace_state(&oversized_workspace).is_err());
    }

    #[test]
    fn workspace_validation_rejects_inconsistent_replay_tabs() {
        let mut snapshot = WorkspaceStateSnapshot::default();
        snapshot.replay.active_tab_id = Some("missing".to_string());
        snapshot.replay.tabs.push(ReplayTabState {
            id: "tab-a".to_string(),
            sequence: 1,
            history_index: Some(0),
            ..ReplayTabState::default()
        });
        assert!(super::validate_workspace_state(&snapshot).is_err());

        snapshot.replay.active_tab_id = Some("tab-a".to_string());
        assert!(super::validate_workspace_state(&snapshot).is_err());

        snapshot.replay.tabs[0].history_index = None;
        snapshot.replay.tabs.push(ReplayTabState {
            id: "tab-a".to_string(),
            sequence: 2,
            ..ReplayTabState::default()
        });
        assert!(super::validate_workspace_state(&snapshot).is_err());
    }

    #[test]
    fn workspace_validation_rejects_unusable_replay_tab_sequence() {
        let mut snapshot = WorkspaceStateSnapshot::default();
        snapshot.replay.tab_sequence = usize::MAX;
        let error = super::validate_workspace_state(&snapshot).unwrap_err();
        assert!(error.contains("replay tab sequence is too large"));

        let mut snapshot = WorkspaceStateSnapshot::default();
        snapshot.replay.tabs.push(ReplayTabState {
            id: "tab-a".to_string(),
            sequence: usize::MAX,
            ..ReplayTabState::default()
        });
        let error = super::validate_workspace_state(&snapshot).unwrap_err();
        assert!(error.contains("replay tab tab-a sequence is too large"));
    }

    #[tokio::test]
    async fn target_site_map_counts_notes_once_per_record() {
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
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
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };

        let session = state.session().await;
        let mut record = TransactionRecord::http(
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
        );
        record.user_note = Some("manual note".to_string());
        session.store.insert(record).await;

        let site_map: Vec<crate::target::TargetHostNode> = response_json(
            get_target_site_map(
                State(state),
                Query(super::TargetSiteMapQuery { session_id: None }),
            )
            .await,
        )
        .await;
        assert_eq!(site_map.len(), 1);
        assert_eq!(site_map[0].paths.len(), 1);
        assert_eq!(site_map[0].paths[0].note_count, 2);
    }

    #[tokio::test]
    async fn runtime_update_waits_for_session_operation_lock() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-runtime-op-lock-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let operation_lock = state.session_operation_lock(session.id()).await;
        let operation_guard = operation_lock.lock().await;

        let blocked = tokio::time::timeout(
            Duration::from_millis(30),
            super::update_runtime_settings(
                State(state.clone()),
                Json(RuntimeSettingsUpdate {
                    session_id: Some(session.id()),
                    intercept_enabled: Some(true),
                    ..RuntimeSettingsUpdate::default()
                }),
            ),
        )
        .await;
        assert!(blocked.is_err());

        drop(operation_guard);
        let runtime: RuntimeSettingsSnapshot = response_json(
            super::update_runtime_settings(
                State(state.clone()),
                Json(RuntimeSettingsUpdate {
                    session_id: Some(session.id()),
                    intercept_enabled: Some(true),
                    ..RuntimeSettingsUpdate::default()
                }),
            )
            .await,
        )
        .await;
        assert!(runtime.intercept_enabled);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn implicit_runtime_update_finishes_before_delayed_activation_after_lock_wait() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-runtime-active-race-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let original = state.session().await;
        let operation_lock = state.session_operation_lock(original.id()).await;
        let operation_guard = operation_lock.lock().await;

        let mut update_future = Box::pin(super::update_runtime_settings(
            State(state.clone()),
            Json(RuntimeSettingsUpdate {
                session_id: None,
                intercept_enabled: Some(true),
                ..RuntimeSettingsUpdate::default()
            }),
        ));

        let blocked = tokio::time::timeout(Duration::from_millis(30), &mut update_future).await;
        assert!(blocked.is_err());
        drop(operation_guard);

        let runtime: RuntimeSettingsSnapshot = response_json(update_future.await).await;
        assert!(runtime.intercept_enabled);
        assert!(original.runtime.snapshot().await.intercept_enabled);

        let next = state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();
        assert_ne!(next.id, original.id());
        assert_eq!(state.sessions.active_session_id(), next.id);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn runtime_update_rejects_stale_expected_active_session() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-runtime-expected-active-race-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let original = state.session().await;
        let original_id = original.id();
        state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();

        let response = super::update_runtime_settings(
            State(state.clone()),
            Json(RuntimeSettingsUpdate {
                session_id: Some(original_id),
                expected_active_session_id: Some(original_id),
                intercept_enabled: Some(true),
                ..RuntimeSettingsUpdate::default()
            }),
        )
        .await;
        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        assert!(!original.runtime.snapshot().await.intercept_enabled);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn explicit_inactive_runtime_update_rechecks_proxy_work_after_lock_wait() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-runtime-proxy-work-race-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let original = state.session().await;
        state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();
        let inactive_id = original.id();
        let operation_lock = state.session_operation_lock(inactive_id).await;
        let operation_guard = operation_lock.lock().await;

        let mut update_future = Box::pin(super::update_runtime_settings(
            State(state.clone()),
            Json(RuntimeSettingsUpdate {
                session_id: Some(inactive_id),
                intercept_enabled: Some(true),
                ..RuntimeSettingsUpdate::default()
            }),
        ));

        let blocked = tokio::time::timeout(Duration::from_millis(30), &mut update_future).await;
        assert!(blocked.is_err());
        let active_proxy_owner = crate::proxy::remember_active_proxy_session_owner(
            inactive_id,
            crate::proxy::PROXY_WORK_STREAMED_RESPONSE,
        );
        drop(operation_guard);

        let response = update_future.await;
        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        assert!(!original.runtime.snapshot().await.intercept_enabled);

        drop(active_proxy_owner);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn session_proxy_operation_rechecks_proxy_work_after_lock_wait() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-proxy-operation-race-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let original = state.session().await;
        let original_id = original.id();
        state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();
        let operation_lock = state.session_operation_lock(original_id).await;
        let operation_guard = operation_lock.lock().await;

        let mut proxy_future = Box::pin(super::begin_session_proxy_operation(
            &state, &original, None, None,
        ));
        let blocked = tokio::time::timeout(Duration::from_millis(30), &mut proxy_future).await;
        assert!(blocked.is_err());
        let active_proxy_owner = crate::proxy::remember_active_proxy_session_owner(
            original_id,
            crate::proxy::PROXY_WORK_STREAMED_RESPONSE,
        );
        drop(operation_guard);

        match proxy_future.await {
            Ok(owner) => {
                drop(owner);
                panic!("proxy operation should reject inactive sessions with active proxy work");
            }
            Err(response) => assert_eq!(response.status(), super::StatusCode::CONFLICT),
        }

        drop(active_proxy_owner);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn session_proxy_operation_rechecks_expected_active_after_lock_wait() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-proxy-operation-expected-active-race-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let original = state.session().await;
        let original_id = original.id();
        let operation_lock = state.session_operation_lock(original_id).await;
        let operation_guard = operation_lock.lock().await;

        let mut proxy_future = Box::pin(super::begin_session_proxy_operation(
            &state,
            &original,
            Some(original_id),
            None,
        ));
        let blocked = tokio::time::timeout(Duration::from_millis(30), &mut proxy_future).await;
        assert!(blocked.is_err());

        let next = state
            .sessions
            .create_session(Some("new active".to_string()))
            .unwrap();
        state.sessions.activate_session(next.id).unwrap();
        drop(operation_guard);

        match proxy_future.await {
            Ok(owner) => {
                drop(owner);
                panic!("proxy operation should reject stale expected-active sessions");
            }
            Err(response) => {
                assert_eq!(response.status(), super::StatusCode::CONFLICT);
                let body = response_body_json(response).await;
                assert_eq!(
                    body.get("error").and_then(serde_json::Value::as_str),
                    Some("active session changed")
                );
            }
        }

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn session_proxy_operation_rechecks_workspace_revision_after_lock_wait() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-proxy-operation-workspace-revision-race-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let session_id = session.id();
        let expected_revision = session.workspace.snapshot().await.revision;
        let operation_lock = state.session_operation_lock(session_id).await;
        let operation_guard = operation_lock.lock().await;

        let mut proxy_future = Box::pin(super::begin_session_proxy_operation(
            &state,
            &session,
            None,
            Some(expected_revision),
        ));
        let blocked = tokio::time::timeout(Duration::from_millis(30), &mut proxy_future).await;
        assert!(blocked.is_err());

        session
            .workspace
            .replace_snapshot(WorkspaceStateSnapshot::default())
            .await;
        let current_revision = session.workspace.snapshot().await.revision;
        assert!(current_revision > expected_revision);
        drop(operation_guard);

        match proxy_future.await {
            Ok(owner) => {
                drop(owner);
                panic!("proxy operation should reject stale workspace revisions after waiting");
            }
            Err(response) => {
                assert_eq!(response.status(), super::StatusCode::CONFLICT);
                let body = response_body_json(response).await;
                assert_eq!(
                    body.get("revision"),
                    Some(&serde_json::json!(current_revision))
                );
            }
        }

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn session_proxy_operation_rejects_deleted_session_as_not_found() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-proxy-operation-deleted-session-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let original = state.session().await;
        let original_id = original.id();
        state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();
        let operation_lock = state.session_operation_lock(original_id).await;
        let operation_guard = operation_lock.lock().await;

        let mut delete_future = Box::pin(state.delete_session(original_id));
        let blocked_delete =
            tokio::time::timeout(Duration::from_millis(30), &mut delete_future).await;
        assert!(blocked_delete.is_err());

        let mut proxy_future = Box::pin(super::begin_session_proxy_operation(
            &state, &original, None, None,
        ));
        let blocked_proxy =
            tokio::time::timeout(Duration::from_millis(30), &mut proxy_future).await;
        assert!(blocked_proxy.is_err());

        drop(operation_guard);
        delete_future.await.unwrap();
        match proxy_future.await {
            Ok(owner) => {
                drop(owner);
                panic!("proxy operation should reject deleted sessions");
            }
            Err(response) => assert_eq!(response.status(), super::StatusCode::NOT_FOUND),
        }

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn oast_clear_waits_for_session_operation_lock() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-oast-clear-op-lock-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let callback_id = Uuid::new_v4();
        session
            .oast
            .push(OastCallback {
                id: callback_id,
                received_at: Utc::now(),
                protocol: "dns".to_string(),
                remote_addr: "127.0.0.1".to_string(),
                raw_data: "callback".to_string(),
                correlation_id: "correlation".to_string(),
            })
            .await;
        let operation_lock = state.session_operation_lock(session.id()).await;
        let operation_guard = operation_lock.lock().await;

        let blocked = tokio::time::timeout(
            Duration::from_millis(30),
            super::clear_oast_callbacks(
                State(state.clone()),
                Query(super::SessionWriteQuery {
                    session_id: Some(session.id()),
                    expected_active_session_id: None,
                }),
            ),
        )
        .await;
        assert!(blocked.is_err());
        assert!(session.oast.get(callback_id).await.is_some());

        drop(operation_guard);
        let response = super::clear_oast_callbacks(
            State(state.clone()),
            Query(super::SessionWriteQuery {
                session_id: Some(session.id()),
                expected_active_session_id: None,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(session.oast.list(None).await.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn startup_settings_rebind_event_follows_active_session_after_lock_wait() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-startup-rebind-event-session-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let original = state.session().await;
        let reserved_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let desired_port = reserved_listener.local_addr().unwrap().port();
        drop(reserved_listener);

        let rebind_guard = state.proxy_rebind_lock.lock().await;
        let mut update_future = Box::pin(super::update_startup_settings(
            State(state.clone()),
            Json(StartupSettingsUpdate {
                expected_active_session_id: None,
                proxy_bind_host: Some("127.0.0.1".to_string()),
                proxy_port: Some(desired_port),
            }),
        ));

        let blocked = tokio::time::timeout(Duration::from_millis(30), &mut update_future).await;
        assert!(blocked.is_err());

        let next = state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();
        assert_eq!(state.sessions.active_session_id(), next.id);
        drop(rebind_guard);

        let view = response_body_json(update_future.await).await;
        assert_eq!(view["proxy_port"].as_u64(), Some(u64::from(desired_port)));
        assert_eq!(view["rebound"].as_bool(), Some(true));

        let original_events = original.event_log.list(Some(10)).await;
        assert!(!original_events
            .iter()
            .any(|entry| entry.title == "Proxy listener rebound"));
        let active = state.session().await;
        assert_eq!(active.id(), next.id);
        assert!(active
            .event_log
            .list(Some(10))
            .await
            .iter()
            .any(|entry| entry.title == "Proxy listener rebound"));

        state.abort_proxy_task().await;
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn startup_settings_rejects_stale_expected_active_session_after_lock_wait() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-startup-expected-active-race-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let original = state.session().await;
        let original_id = original.id();
        let reserved_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let desired_port = reserved_listener.local_addr().unwrap().port();
        drop(reserved_listener);

        let rebind_guard = state.proxy_rebind_lock.lock().await;
        let mut update_future = Box::pin(super::update_startup_settings(
            State(state.clone()),
            Json(StartupSettingsUpdate {
                expected_active_session_id: Some(original_id),
                proxy_bind_host: Some("127.0.0.1".to_string()),
                proxy_port: Some(desired_port),
            }),
        ));

        let blocked = tokio::time::timeout(Duration::from_millis(30), &mut update_future).await;
        assert!(blocked.is_err());
        state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();
        drop(rebind_guard);

        let response = update_future.await;
        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        assert_ne!(state.startup.snapshot().await.proxy_port, desired_port);
        assert!(!original
            .event_log
            .list(Some(10))
            .await
            .iter()
            .any(|entry| entry.title == "Proxy listener rebound"));

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn runtime_event_oast_and_site_map_can_use_pinned_inactive_session() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-pinned-runtime-event-oast-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let active = state.session().await;
        let inactive_metadata = state
            .sessions
            .create_session(Some("Inactive".to_string()))
            .unwrap();
        let inactive = state.sessions.load_context(inactive_metadata.id).unwrap();

        active
            .event_log
            .push(EventLevel::Info, "active", "Active event", "active")
            .await;
        inactive
            .event_log
            .push(EventLevel::Info, "inactive", "Inactive event", "inactive")
            .await;
        let message = MessageRecord {
            headers: vec![HeaderRecord {
                name: "host".to_string(),
                value: "inactive.test".to_string(),
            }],
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };
        inactive
            .store
            .insert(TransactionRecord::http(
                Utc::now(),
                "GET".to_string(),
                "https".to_string(),
                "inactive.test".to_string(),
                "/pinned".to_string(),
                Some(204),
                1,
                message.clone(),
                Some(message),
                Vec::new(),
                None,
                None,
            ))
            .await;
        let callback_id = Uuid::new_v4();
        inactive
            .oast
            .push(OastCallback {
                id: callback_id,
                received_at: Utc::now(),
                protocol: "dns".to_string(),
                remote_addr: "127.0.0.1".to_string(),
                raw_data: "inactive callback".to_string(),
                correlation_id: "inactive-correlation".to_string(),
            })
            .await;
        inactive.persist().await.unwrap();

        let runtime: RuntimeSettingsSnapshot = response_json(
            super::update_runtime_settings(
                State(state.clone()),
                Json(RuntimeSettingsUpdate {
                    session_id: Some(inactive.id()),
                    oast_enabled: Some(true),
                    oast_server_url: Some("https://inactive-oast.test".to_string()),
                    oast_provider: Some(OastProvider::Boast),
                    ..RuntimeSettingsUpdate::default()
                }),
            )
            .await,
        )
        .await;
        assert!(runtime.oast_enabled);
        assert_eq!(runtime.oast_provider, OastProvider::Boast);

        let active_proxy_owner = crate::proxy::remember_active_proxy_session_owner(
            inactive.id(),
            crate::proxy::PROXY_WORK_STREAMED_RESPONSE,
        );

        let runtime_read: RuntimeSettingsSnapshot = response_json(
            super::get_runtime_settings(
                State(state.clone()),
                Query(super::RuntimeQuery {
                    session_id: Some(inactive.id()),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(runtime_read.oast_provider, OastProvider::Boast);

        let workspace_read: WorkspaceStateSnapshot = response_json(
            super::get_workspace_state(
                State(state.clone()),
                Query(super::WorkspaceStateQuery {
                    session_id: Some(inactive.id()),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(workspace_read.session_id, Some(inactive.id()));

        let inactive_events: Vec<crate::event_log::EventLogEntry> = response_json(
            super::list_event_log(
                State(state.clone()),
                Query(super::EventLogQuery {
                    session_id: Some(inactive.id()),
                    limit: Some(10),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(inactive_events.len(), 2);
        assert!(inactive_events
            .iter()
            .any(|entry| entry.title == "Runtime settings updated"));
        assert!(inactive_events
            .iter()
            .any(|entry| entry.title == "Inactive event"));

        let site_map: Vec<crate::target::TargetHostNode> = response_json(
            get_target_site_map(
                State(state.clone()),
                Query(super::TargetSiteMapQuery {
                    session_id: Some(inactive.id()),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(site_map.len(), 1);
        assert_eq!(site_map[0].host, "inactive.test");

        let callbacks: Vec<serde_json::Value> = response_json(
            super::list_oast_callbacks(
                State(state.clone()),
                Query(super::OastQuery {
                    session_id: Some(inactive.id()),
                    limit: None,
                }),
            )
            .await,
        )
        .await;
        assert_eq!(callbacks.len(), 1);
        let callback_id_text = callback_id.to_string();
        assert_eq!(callbacks[0]["id"].as_str(), Some(callback_id_text.as_str()));

        let callback: serde_json::Value = response_json(
            super::get_oast_callback(
                State(state.clone()),
                Path(callback_id_text.clone()),
                Query(super::OastQuery {
                    session_id: Some(inactive.id()),
                    limit: None,
                }),
            )
            .await,
        )
        .await;
        assert_eq!(callback["id"].as_str(), Some(callback_id_text.as_str()));

        let oast_status: serde_json::Value = response_json(
            super::oast_status(
                State(state.clone()),
                Query(super::OastQuery {
                    session_id: Some(inactive.id()),
                    limit: None,
                }),
            )
            .await,
        )
        .await;
        assert_eq!(oast_status["provider"], "boast");

        let payload_response = super::generate_oast_payload(
            State(state.clone()),
            Query(super::OastQuery {
                session_id: Some(inactive.id()),
                limit: None,
            }),
        )
        .await;
        assert_eq!(payload_response.status(), StatusCode::OK);

        let events_response = super::events(
            State(state.clone()),
            Query(super::EventsQuery {
                session_id: Some(inactive.id()),
            }),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(events_response.status(), StatusCode::OK);
        let mut events_body = events_response.into_body();
        let maybe_event =
            tokio::time::timeout(Duration::from_millis(150), events_body.frame()).await;
        if let Ok(Some(Ok(frame))) = maybe_event {
            if let Ok(bytes) = frame.into_data() {
                let text = String::from_utf8_lossy(&bytes);
                assert!(
                    !text.contains("session_changed"),
                    "explicit inactive session event stream must not emit session_changed: {text}"
                );
            }
        }

        let missing_events_response = super::events(
            State(state.clone()),
            Query(super::EventsQuery {
                session_id: Some(Uuid::new_v4()),
            }),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(missing_events_response.status(), StatusCode::NOT_FOUND);

        let blocked_clear_response = super::clear_event_log(
            State(state.clone()),
            Query(super::SessionWriteQuery {
                session_id: Some(inactive.id()),
                expected_active_session_id: None,
            }),
        )
        .await;
        assert_eq!(blocked_clear_response.status(), StatusCode::CONFLICT);
        let blocked_clear_body = response_body_json(blocked_clear_response).await;
        assert_eq!(
            blocked_clear_body
                .get("error")
                .and_then(serde_json::Value::as_str),
            Some("session has active proxy work")
        );
        let expected_inactive_id = inactive.id().to_string();
        assert_eq!(
            blocked_clear_body
                .get("session_id")
                .and_then(serde_json::Value::as_str),
            Some(expected_inactive_id.as_str())
        );

        drop(active_proxy_owner);

        let clear_response = super::clear_event_log(
            State(state.clone()),
            Query(super::SessionWriteQuery {
                session_id: Some(inactive.id()),
                expected_active_session_id: None,
            }),
        )
        .await;
        assert_eq!(clear_response.status(), StatusCode::NO_CONTENT);

        let inactive_events_after_clear: Vec<crate::event_log::EventLogEntry> = response_json(
            super::list_event_log(
                State(state.clone()),
                Query(super::EventLogQuery {
                    session_id: Some(inactive.id()),
                    limit: Some(10),
                }),
            )
            .await,
        )
        .await;
        assert!(inactive_events_after_clear.is_empty());
        assert_eq!(active.event_log.list(Some(10)).await.len(), 1);

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[tokio::test]
    async fn update_runtime_settings_rejects_oast_server_url_with_path() {
        let config = test_app_config("sniper-oast-payload-url-path");
        let data_dir = config.data_dir.clone();
        let state = Arc::new(AppState::new(config).unwrap());

        let response = super::update_runtime_settings(
            State(state.clone()),
            Json(RuntimeSettingsUpdate {
                oast_enabled: Some(true),
                oast_server_url: Some("https://oast.example.test/api".to_string()),
                oast_provider: Some(OastProvider::Boast),
                ..RuntimeSettingsUpdate::default()
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body should be readable");
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("OAST server URL"));
        assert!(!state.session().await.runtime.snapshot().await.oast_enabled);

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[tokio::test]
    async fn scanner_rules_and_match_replace_can_use_pinned_inactive_session() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-pinned-scanner-rules-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let active = state.session().await;
        let inactive_metadata = state
            .sessions
            .create_session(Some("Inactive".to_string()))
            .unwrap();
        let inactive = state.sessions.load_context(inactive_metadata.id).unwrap();
        let inactive_id = inactive.id();

        let active_finding = ScannerFinding {
            id: Uuid::new_v4(),
            record_id: Uuid::new_v4(),
            found_at: Utc::now(),
            rule_id: String::new(),
            severity: Severity::Info,
            category: "active".to_string(),
            title: "Active finding".to_string(),
            detail: String::new(),
            evidence: String::new(),
            host: "active.test".to_string(),
            path: "/".to_string(),
            location: None,
        };
        let inactive_finding = ScannerFinding {
            id: Uuid::new_v4(),
            record_id: Uuid::new_v4(),
            found_at: Utc::now(),
            rule_id: String::new(),
            severity: Severity::High,
            category: "inactive".to_string(),
            title: "Inactive finding".to_string(),
            detail: String::new(),
            evidence: String::new(),
            host: "inactive.test".to_string(),
            path: "/finding".to_string(),
            location: None,
        };
        active.scanner.replace_all(vec![active_finding]).await;
        inactive
            .scanner
            .replace_all(vec![inactive_finding.clone()])
            .await;
        inactive.persist().await.unwrap();

        let match_rule = MatchReplaceRule {
            id: Uuid::new_v4(),
            enabled: true,
            description: "inactive only".to_string(),
            scope: MatchReplaceScope::Request,
            target: MatchReplaceTarget::Path,
            search: "/old".to_string(),
            replace: "/new".to_string(),
            regex: false,
            case_sensitive: true,
        };
        let response = super::update_match_replace_rules(
            State(state.clone()),
            Query(super::SessionWriteQuery {
                session_id: Some(inactive_id),
                expected_active_session_id: None,
            }),
            Json(MatchReplaceRulesPayload {
                session_id: None,
                rules: vec![match_rule.clone()],
            }),
        )
        .await;
        assert!(response.status().is_success());

        let intercept_rule = InterceptRule {
            id: Uuid::new_v4(),
            enabled: true,
            scope: InterceptScope::Both,
            host_pattern: "inactive.test".to_string(),
            path_pattern: "/api".to_string(),
            method_filter: vec!["GET".to_string()],
        };
        let response = super::upsert_intercept_rule(
            State(state.clone()),
            Query(super::SessionWriteQuery {
                session_id: Some(inactive_id),
                expected_active_session_id: None,
            }),
            Json(super::InterceptRulePayload::from(intercept_rule.clone())),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let mut scanner_config = inactive.scanner.get_config().await;
        scanner_config.enabled = false;
        let response = super::update_scanner_config(
            State(state.clone()),
            Query(super::SessionWriteQuery {
                session_id: Some(inactive_id),
                expected_active_session_id: None,
            }),
            Json(super::ScannerConfigPayload::from(scanner_config.clone())),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let active_proxy_owner = crate::proxy::remember_active_proxy_session_owner(
            inactive_id,
            crate::proxy::PROXY_WORK_STREAMED_RESPONSE,
        );

        let inactive_config: ScannerConfig = response_json(
            super::get_scanner_config(
                State(state.clone()),
                Query(super::SessionScopedQuery {
                    session_id: Some(inactive_id),
                }),
            )
            .await,
        )
        .await;
        assert!(!inactive_config.enabled);

        let inactive_rules: Vec<MatchReplaceRule> = response_json(
            super::list_match_replace_rules(
                State(state.clone()),
                Query(super::SessionScopedQuery {
                    session_id: Some(inactive_id),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(inactive_rules.len(), 1);
        assert_eq!(inactive_rules[0].id, match_rule.id);
        assert!(active.match_replace.snapshot().await.is_empty());

        let inactive_intercept_rules: Vec<InterceptRule> = response_json(
            super::list_intercept_rules(
                State(state.clone()),
                Query(super::SessionScopedQuery {
                    session_id: Some(inactive_id),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(inactive_intercept_rules.len(), 1);
        assert_eq!(inactive_intercept_rules[0].id, intercept_rule.id);
        assert!(active.intercept_rules.list().await.is_empty());

        let inactive_findings: Vec<FindingSummary> = response_json(
            super::list_findings(
                State(state.clone()),
                Query(super::FindingsQuery {
                    session_id: Some(inactive_id),
                    limit: Some(10),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(inactive_findings.len(), 1);
        assert_eq!(inactive_findings[0].id, inactive_finding.id);

        let inactive_findings_count = response_json::<serde_json::Value>(
            super::count_findings(
                State(state.clone()),
                Query(super::SessionScopedQuery {
                    session_id: Some(inactive_id),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(inactive_findings_count["count"], 1);

        let finding: ScannerFinding = response_json(
            super::get_finding(
                State(state.clone()),
                Path(inactive_finding.id.to_string()),
                Query(super::SessionScopedQuery {
                    session_id: Some(inactive_id),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(finding.id, inactive_finding.id);

        drop(active_proxy_owner);

        let reloaded = state.sessions.load_context(inactive_id).unwrap();
        assert!(!reloaded.scanner.get_config().await.enabled);
        assert!(active.scanner.get_config().await.enabled);

        let response = super::clear_findings(
            State(state.clone()),
            Query(super::SessionWriteQuery {
                session_id: Some(inactive_id),
                expected_active_session_id: None,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let reloaded_after_clear = state.sessions.load_context(inactive_id).unwrap();
        assert!(reloaded_after_clear.scanner.list(Some(10)).await.is_empty());
        assert_eq!(active.scanner.list(Some(10)).await.len(), 1);

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[tokio::test]
    async fn rule_write_body_session_id_targets_inactive_session_and_rejects_conflicts() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-body-session-rule-write-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let active = state.session().await;
        let active_id = active.id();
        let inactive_metadata = state
            .sessions
            .create_session(Some("Inactive".to_string()))
            .unwrap();
        let inactive = state.sessions.load_context(inactive_metadata.id).unwrap();
        let inactive_id = inactive.id();

        let match_rule = MatchReplaceRule {
            id: Uuid::new_v4(),
            enabled: true,
            description: "body pinned inactive".to_string(),
            scope: MatchReplaceScope::Request,
            target: MatchReplaceTarget::Path,
            search: "/before".to_string(),
            replace: "/after".to_string(),
            regex: false,
            case_sensitive: true,
        };
        let response = super::update_match_replace_rules(
            State(state.clone()),
            Query(super::SessionWriteQuery {
                session_id: None,
                expected_active_session_id: None,
            }),
            Json(MatchReplaceRulesPayload {
                session_id: Some(inactive_id),
                rules: vec![match_rule.clone()],
            }),
        )
        .await;
        assert!(response.status().is_success());
        assert!(active.match_replace.snapshot().await.is_empty());
        let inactive_rules: Vec<MatchReplaceRule> = response_json(
            super::list_match_replace_rules(
                State(state.clone()),
                Query(super::SessionScopedQuery {
                    session_id: Some(inactive_id),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(inactive_rules[0].id, match_rule.id);

        let conflict_response = super::update_match_replace_rules(
            State(state.clone()),
            Query(super::SessionWriteQuery {
                session_id: Some(active_id),
                expected_active_session_id: None,
            }),
            Json(MatchReplaceRulesPayload {
                session_id: Some(inactive_id),
                rules: Vec::new(),
            }),
        )
        .await;
        assert_eq!(conflict_response.status(), StatusCode::BAD_REQUEST);
        let inactive_rules_after_conflict: Vec<MatchReplaceRule> = response_json(
            super::list_match_replace_rules(
                State(state.clone()),
                Query(super::SessionScopedQuery {
                    session_id: Some(inactive_id),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(inactive_rules_after_conflict.len(), 1);

        let intercept_rule = InterceptRule {
            id: Uuid::new_v4(),
            enabled: true,
            scope: InterceptScope::Both,
            host_pattern: "inactive.example".to_string(),
            path_pattern: "/ws".to_string(),
            method_filter: vec!["GET".to_string()],
        };
        let response = super::upsert_intercept_rule(
            State(state.clone()),
            Query(super::SessionWriteQuery {
                session_id: None,
                expected_active_session_id: None,
            }),
            Json(super::InterceptRulePayload {
                session_id: Some(inactive_id),
                rule: intercept_rule.clone(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(active.intercept_rules.list().await.is_empty());
        let inactive_intercept_rules: Vec<InterceptRule> = response_json(
            super::list_intercept_rules(
                State(state.clone()),
                Query(super::SessionScopedQuery {
                    session_id: Some(inactive_id),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(inactive_intercept_rules[0].id, intercept_rule.id);

        let conflict_response = super::upsert_intercept_rule(
            State(state.clone()),
            Query(super::SessionWriteQuery {
                session_id: Some(active_id),
                expected_active_session_id: None,
            }),
            Json(super::InterceptRulePayload {
                session_id: Some(inactive_id),
                rule: intercept_rule,
            }),
        )
        .await;
        assert_eq!(conflict_response.status(), StatusCode::BAD_REQUEST);
        assert!(active.intercept_rules.list().await.is_empty());
        let inactive_intercept_rules_after_conflict: Vec<InterceptRule> = response_json(
            super::list_intercept_rules(
                State(state.clone()),
                Query(super::SessionScopedQuery {
                    session_id: Some(inactive_id),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(inactive_intercept_rules_after_conflict.len(), 1);

        let mut scanner_config = inactive.scanner.get_config().await;
        scanner_config.enabled = false;
        let response = super::update_scanner_config(
            State(state.clone()),
            Query(super::SessionWriteQuery {
                session_id: None,
                expected_active_session_id: None,
            }),
            Json(super::ScannerConfigPayload {
                session_id: Some(inactive_id),
                config: scanner_config.clone(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(active.scanner.get_config().await.enabled);
        let inactive_scanner_config: ScannerConfig = response_json(
            super::get_scanner_config(
                State(state.clone()),
                Query(super::SessionScopedQuery {
                    session_id: Some(inactive_id),
                }),
            )
            .await,
        )
        .await;
        assert!(!inactive_scanner_config.enabled);

        let conflict_response = super::update_scanner_config(
            State(state.clone()),
            Query(super::SessionWriteQuery {
                session_id: Some(active_id),
                expected_active_session_id: None,
            }),
            Json(super::ScannerConfigPayload {
                session_id: Some(inactive_id),
                config: scanner_config,
            }),
        )
        .await;
        assert_eq!(conflict_response.status(), StatusCode::BAD_REQUEST);
        assert!(active.scanner.get_config().await.enabled);
        let inactive_scanner_config_after_conflict: ScannerConfig = response_json(
            super::get_scanner_config(
                State(state.clone()),
                Query(super::SessionScopedQuery {
                    session_id: Some(inactive_id),
                }),
            )
            .await,
        )
        .await;
        assert!(!inactive_scanner_config_after_conflict.enabled);

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[tokio::test]
    async fn annotation_update_persists_via_journal_without_registry_metadata_rewrite() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-annotation-registry-bypass-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let message = MessageRecord {
            headers: vec![HeaderRecord {
                name: "host".to_string(),
                value: "example.test".to_string(),
            }],
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };
        let record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "example.test".to_string(),
            "/annotate".to_string(),
            Some(200),
            1,
            message.clone(),
            Some(message),
            Vec::new(),
            None,
            None,
        );
        let id = record.id;
        session.store.insert(record).await;

        let storage_dir = session.storage_dir().to_path_buf();
        let registry_path = storage_dir
            .parent()
            .expect("session dir should have registry parent")
            .join("registry.json");
        std::fs::remove_file(&registry_path).unwrap();
        std::fs::create_dir(&registry_path).unwrap();

        let response = super::update_transaction_annotations(
            State(state.clone()),
            Path(id.to_string()),
            Query(super::TransactionWriteQuery {
                session_id: None,
                expected_active_session_id: None,
            }),
            Json(super::AnnotationsPayload {
                session_id: None,
                color_tag: Some(Some("blue".to_string())),
                user_note: Some(Some("durable snapshot".to_string())),
                client_id: None,
                client_version: None,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::OK);
        let live = session.store.get(id).await.unwrap();
        assert_eq!(live.color_tag.as_deref(), Some("blue"));
        assert_eq!(live.user_note.as_deref(), Some("durable snapshot"));

        let reloaded = state.sessions.load_context(session.id()).unwrap();
        let durable = reloaded.store.get(id).await.unwrap();
        assert_eq!(durable.color_tag.as_deref(), Some("blue"));
        assert_eq!(durable.user_note.as_deref(), Some("durable snapshot"));

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn workspace_update_persists_without_registry_metadata_rewrite() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-workspace-registry-bypass-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let mut snapshot = session.workspace.snapshot().await;
        snapshot.session_id = Some(session.id());
        snapshot.client_id = Some("test-ui".to_string());
        snapshot.client_version = 1;
        snapshot.replay = ReplayWorkspaceState {
            active_tab_id: Some("committed-workspace-tab".to_string()),
            tabs: vec![ReplayTabState {
                id: "committed-workspace-tab".to_string(),
                sequence: 1,
                ..ReplayTabState::default()
            }],
            ..ReplayWorkspaceState::default()
        };

        let registry_path = session
            .storage_dir()
            .parent()
            .expect("session dir should have registry parent")
            .join("registry.json");
        std::fs::remove_file(&registry_path).unwrap();
        std::fs::create_dir(&registry_path).unwrap();

        let response = super::update_workspace_state(State(state.clone()), Json(snapshot)).await;

        assert_eq!(response.status(), super::StatusCode::OK);
        let live = session.workspace.snapshot().await;
        assert_eq!(
            live.replay.active_tab_id.as_deref(),
            Some("committed-workspace-tab")
        );

        let reloaded = state.sessions.load_context(session.id()).unwrap();
        let durable = reloaded.workspace.snapshot().await;
        assert_eq!(
            durable.replay.active_tab_id.as_deref(),
            Some("committed-workspace-tab")
        );

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn inactive_workspace_read_does_not_create_transaction_journal() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-workspace-read-no-journal-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let inactive = state
            .sessions
            .create_session(Some("Inactive".to_string()))
            .unwrap();
        let journal_path = data_dir
            .join("sessions")
            .join(inactive.id.to_string())
            .join("transactions.journal");
        assert!(!journal_path.exists());

        let snapshot: WorkspaceStateSnapshot = response_json(
            super::get_workspace_state(
                State(state.clone()),
                Query(super::WorkspaceStateQuery {
                    session_id: Some(inactive.id),
                }),
            )
            .await,
        )
        .await;

        assert_eq!(snapshot.session_id, Some(inactive.id));
        assert!(!journal_path.exists());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn workspace_update_rejects_snapshot_for_unknown_session() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-workspace-session-guard-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let active_session = state.session().await;

        let mut snapshot = WorkspaceStateSnapshot {
            session_id: Some(Uuid::new_v4()),
            client_id: Some("test-ui".to_string()),
            client_version: 1,
            ..WorkspaceStateSnapshot::default()
        };
        snapshot.replay.active_tab_id = Some("unknown-session-tab".to_string());

        let response = super::update_workspace_state(State(state.clone()), Json(snapshot)).await;

        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        let active = active_session.workspace.snapshot().await;
        assert!(active.replay.active_tab_id.is_none());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn workspace_update_rejects_snapshot_without_session_id() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-workspace-missing-session-guard-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let active_session = state.session().await;

        let mut snapshot = WorkspaceStateSnapshot {
            client_id: Some("legacy-ui".to_string()),
            client_version: 1,
            ..WorkspaceStateSnapshot::default()
        };
        snapshot.replay.active_tab_id = Some("legacy-tab".to_string());
        snapshot.replay.tabs.push(ReplayTabState {
            id: "legacy-tab".to_string(),
            sequence: 1,
            ..ReplayTabState::default()
        });

        let response = super::update_workspace_state(State(state.clone()), Json(snapshot)).await;

        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        let active = active_session.workspace.snapshot().await;
        assert!(active.replay.active_tab_id.is_none());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn workspace_update_migrates_legacy_fuzzer_attack_record_to_id_only() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-workspace-fuzzer-id-only-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let attack = FuzzerAttackRecord {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            completed_at: Utc::now(),
            status: FuzzerAttackStatus::Completed,
            template: EditableRequest {
                scheme: "https".to_string(),
                host: "fuzzer.example".to_string(),
                method: "GET".to_string(),
                path: "/".to_string(),
                headers: Vec::new(),
                body: String::new(),
                body_encoding: BodyEncoding::Utf8,
                preview_truncated: false,
            },
            payload_count: 1,
            marker_count: 0,
            results: Vec::new(),
            notes: Vec::new(),
        };
        let attack_id = attack.id;
        let snapshot = WorkspaceStateSnapshot {
            session_id: Some(session.id()),
            client_id: Some("test-ui".to_string()),
            client_version: 1,
            fuzzer: FuzzerWorkspaceState {
                attack_record: Some(attack),
                ..FuzzerWorkspaceState::default()
            },
            ..WorkspaceStateSnapshot::default()
        };

        let response = super::update_workspace_state(State(state.clone()), Json(snapshot)).await;

        assert_eq!(response.status(), super::StatusCode::OK);
        let saved: WorkspaceStateSnapshot = response_json(response).await;
        assert_eq!(saved.fuzzer.attack_record_id, Some(attack_id));
        assert!(saved.fuzzer.attack_record.is_none());
        let durable = session.workspace.snapshot().await;
        assert_eq!(durable.fuzzer.attack_record_id, Some(attack_id));
        assert!(durable.fuzzer.attack_record.is_none());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn workspace_update_saves_snapshot_for_inactive_session_id() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-workspace-inactive-save-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let inactive = state.session().await;
        state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();

        let mut snapshot = WorkspaceStateSnapshot {
            session_id: Some(inactive.id()),
            client_id: Some("test-ui".to_string()),
            client_version: 1,
            ..WorkspaceStateSnapshot::default()
        };
        snapshot.replay.active_tab_id = Some("inactive-tab".to_string());
        snapshot.replay.tabs.push(ReplayTabState {
            id: "inactive-tab".to_string(),
            sequence: 1,
            ..ReplayTabState::default()
        });

        let response = super::update_workspace_state(State(state.clone()), Json(snapshot)).await;

        assert_eq!(response.status(), super::StatusCode::OK);
        let active = state.session().await;
        assert!(active
            .workspace
            .snapshot()
            .await
            .replay
            .active_tab_id
            .is_none());
        let reloaded = state.sessions.load_context(inactive.id()).unwrap();
        assert_eq!(
            reloaded
                .workspace
                .snapshot()
                .await
                .replay
                .active_tab_id
                .as_deref(),
            Some("inactive-tab")
        );

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn workspace_update_rejects_stale_implicit_active_session_guard() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-workspace-active-guard-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let original = state.session().await;
        let original_id = original.id();
        let active = state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();

        let mut snapshot = WorkspaceStateSnapshot {
            session_id: Some(original_id),
            expected_active_session_id: Some(original_id),
            client_id: Some("sniper-cli".to_string()),
            client_version: 1,
            ..WorkspaceStateSnapshot::default()
        };
        snapshot.replay.active_tab_id = Some("stale-tab".to_string());
        snapshot.replay.tabs.push(ReplayTabState {
            id: "stale-tab".to_string(),
            sequence: 1,
            ..ReplayTabState::default()
        });

        let response = super::update_workspace_state(State(state.clone()), Json(snapshot)).await;

        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        let body = response_body_json(response).await;
        assert_eq!(
            body.get("error").and_then(serde_json::Value::as_str),
            Some("active session changed")
        );
        let active_id = active.id.to_string();
        assert_eq!(
            body.get("session_id").and_then(serde_json::Value::as_str),
            Some(active_id.as_str())
        );
        assert!(original.workspace.snapshot().await.replay.tabs.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn workspace_update_rejects_expected_active_target_mismatch() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-workspace-active-target-mismatch-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let active = state.session().await;
        let active_id = active.id();
        let inactive = state
            .sessions
            .create_session(Some("inactive".to_string()))
            .unwrap();

        let mut snapshot = WorkspaceStateSnapshot {
            session_id: Some(inactive.id),
            expected_active_session_id: Some(active_id),
            client_id: Some("sniper-cli".to_string()),
            client_version: 1,
            ..WorkspaceStateSnapshot::default()
        };
        snapshot.replay.active_tab_id = Some("mismatched-tab".to_string());
        snapshot.replay.tabs.push(ReplayTabState {
            id: "mismatched-tab".to_string(),
            sequence: 1,
            ..ReplayTabState::default()
        });

        let response = super::update_workspace_state(State(state.clone()), Json(snapshot)).await;

        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        let body = response_body_json(response).await;
        assert_eq!(
            body.get("error").and_then(serde_json::Value::as_str),
            Some("active session changed")
        );
        assert!(state
            .sessions
            .load_context(inactive.id)
            .unwrap()
            .workspace
            .snapshot()
            .await
            .replay
            .tabs
            .is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn workspace_keepalive_rejects_stale_implicit_active_session_guard() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-workspace-keepalive-active-guard-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let original = state.session().await;
        let original_id = original.id();
        let active = state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();

        let mut snapshot = WorkspaceStateSnapshot {
            session_id: Some(original_id),
            expected_active_session_id: Some(original_id),
            client_id: Some("sniper-cli".to_string()),
            client_version: 1,
            ..WorkspaceStateSnapshot::default()
        };
        snapshot.replay.active_tab_id = Some("stale-keepalive-tab".to_string());
        snapshot.replay.tabs.push(ReplayTabState {
            id: "stale-keepalive-tab".to_string(),
            sequence: 1,
            ..ReplayTabState::default()
        });

        let response = super::update_workspace_state_keepalive(
            State(state.clone()),
            Json(super::WorkspaceKeepaliveUpdate {
                snapshot,
                keepalive: super::WorkspaceKeepaliveMetadata::default(),
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        let body = response_body_json(response).await;
        assert_eq!(
            body.get("error").and_then(serde_json::Value::as_str),
            Some("active session changed")
        );
        let active_id = active.id.to_string();
        assert_eq!(
            body.get("session_id").and_then(serde_json::Value::as_str),
            Some(active_id.as_str())
        );
        assert!(original.workspace.snapshot().await.replay.tabs.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn workspace_update_rejects_inactive_session_with_pending_active_proxy_work() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-workspace-active-proxy-guard-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let inactive = state.session().await;
        state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();

        let pending_generation = crate::proxy::remember_pending_persist_context_for_test(&inactive);
        let active_proxy_owner = crate::proxy::remember_active_proxy_session_owner(
            inactive.id(),
            crate::proxy::PROXY_WORK_STREAMED_RESPONSE,
        );

        let read_response = super::get_workspace_state(
            State(state.clone()),
            Query(super::WorkspaceStateQuery {
                session_id: Some(inactive.id()),
            }),
        )
        .await;
        assert_eq!(read_response.status(), super::StatusCode::OK);

        let mut snapshot = WorkspaceStateSnapshot {
            session_id: Some(inactive.id()),
            client_id: Some("test-ui".to_string()),
            client_version: 1,
            ..WorkspaceStateSnapshot::default()
        };
        snapshot.replay.active_tab_id = Some("blocked-inactive-tab".to_string());
        snapshot.replay.tabs.push(ReplayTabState {
            id: "blocked-inactive-tab".to_string(),
            sequence: 1,
            ..ReplayTabState::default()
        });

        let response = super::update_workspace_state(State(state.clone()), Json(snapshot)).await;

        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        assert!(inactive
            .workspace
            .snapshot()
            .await
            .replay
            .active_tab_id
            .is_none());

        drop(active_proxy_owner);
        assert!(crate::proxy::forget_pending_persist_context_for_test(
            inactive.id(),
            pending_generation
        ));

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn replay_send_rejects_payload_for_unknown_session_before_sending() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-replay-send-session-guard-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;

        let response = super::send_replay(
            State(state.clone()),
            Json(super::ReplaySendPayload {
                session_id: Some(Uuid::new_v4()),
                expected_active_session_id: None,
                expected_workspace_revision: None,
                request: EditableRequest {
                    scheme: "https".to_string(),
                    host: "example.test".to_string(),
                    method: "GET".to_string(),
                    path: "/".to_string(),
                    headers: Vec::new(),
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                target: None,
                source_transaction_id: None,
                http_version: None,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::NOT_FOUND);
        assert!(session.store.snapshot(Some(10)).await.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn replay_send_rejects_missing_session_before_sending() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-replay-send-missing-session-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;

        let response = super::send_replay(
            State(state.clone()),
            Json(super::ReplaySendPayload {
                session_id: None,
                expected_active_session_id: None,
                expected_workspace_revision: None,
                request: EditableRequest {
                    scheme: "https".to_string(),
                    host: "example.test".to_string(),
                    method: "GET".to_string(),
                    path: "/".to_string(),
                    headers: Vec::new(),
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                target: None,
                source_transaction_id: None,
                http_version: None,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        assert!(session.store.snapshot(Some(10)).await.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn replay_send_rejects_stale_implicit_active_session_guard() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-replay-send-active-guard-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let original = state.session().await;
        let original_id = original.id();
        let active = state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();

        let response = super::send_replay(
            State(state.clone()),
            Json(super::ReplaySendPayload {
                session_id: Some(original_id),
                expected_active_session_id: Some(original_id),
                expected_workspace_revision: None,
                request: EditableRequest {
                    scheme: "https".to_string(),
                    host: "example.test".to_string(),
                    method: "GET".to_string(),
                    path: "/".to_string(),
                    headers: Vec::new(),
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                target: None,
                source_transaction_id: None,
                http_version: None,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        let body = response_body_json(response).await;
        assert_eq!(
            body.get("error").and_then(serde_json::Value::as_str),
            Some("active session changed")
        );
        let active_id = active.id.to_string();
        assert_eq!(
            body.get("session_id").and_then(serde_json::Value::as_str),
            Some(active_id.as_str())
        );
        assert!(original.store.snapshot(Some(10)).await.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn replay_send_rejects_expected_active_target_mismatch() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-replay-send-active-target-mismatch-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let active_id = state.session().await.id();
        let inactive = state
            .sessions
            .create_session(Some("inactive".to_string()))
            .unwrap();

        let response = super::send_replay(
            State(state.clone()),
            Json(super::ReplaySendPayload {
                session_id: Some(inactive.id),
                expected_active_session_id: Some(active_id),
                expected_workspace_revision: None,
                request: EditableRequest {
                    scheme: "https".to_string(),
                    host: "example.test".to_string(),
                    method: "GET".to_string(),
                    path: "/".to_string(),
                    headers: Vec::new(),
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                target: None,
                source_transaction_id: None,
                http_version: None,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        let body = response_body_json(response).await;
        assert_eq!(
            body.get("error").and_then(serde_json::Value::as_str),
            Some("active session changed")
        );
        assert!(state
            .sessions
            .load_context(inactive.id)
            .unwrap()
            .store
            .snapshot(Some(10))
            .await
            .is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn replay_send_validation_errors_use_json_error_body() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-replay-send-json-error-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;

        let response = super::send_replay(
            State(state.clone()),
            Json(super::ReplaySendPayload {
                session_id: Some(session.id()),
                expected_active_session_id: None,
                expected_workspace_revision: None,
                request: EditableRequest {
                    scheme: "https".to_string(),
                    host: "example.test".to_string(),
                    method: "GET".to_string(),
                    path: "/".to_string(),
                    headers: Vec::new(),
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                target: None,
                source_transaction_id: None,
                http_version: Some("HTTP/3".to_string()),
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::BAD_REQUEST);
        let body = response_body_json(response).await;
        assert_eq!(body.get("record"), Some(&serde_json::Value::Null));
        assert!(body
            .get("error")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .contains("unsupported replay http_version"));
        assert!(session.store.snapshot(Some(10)).await.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn replay_send_rejects_ip_request_host_target_override_before_sending() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-replay-send-ip-target-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;

        let response = super::send_replay(
            State(state.clone()),
            Json(super::ReplaySendPayload {
                session_id: Some(session.id()),
                expected_active_session_id: None,
                expected_workspace_revision: None,
                request: EditableRequest {
                    scheme: "https".to_string(),
                    host: "127.0.0.1".to_string(),
                    method: "GET".to_string(),
                    path: "/".to_string(),
                    headers: Vec::new(),
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                target: Some(RequestTargetOverride {
                    scheme: "http".to_string(),
                    host: String::new(),
                    port: String::new(),
                }),
                source_transaction_id: None,
                http_version: None,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::BAD_REQUEST);
        let body = response_body_json(response).await;
        assert!(body
            .get("error")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .contains("request host is an IP address"));
        assert!(session.store.snapshot(Some(10)).await.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn replay_send_rejects_preview_truncated_request_before_sending() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-replay-send-truncated-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;

        let response = super::send_replay(
            State(state.clone()),
            Json(super::ReplaySendPayload {
                session_id: Some(session.id()),
                expected_active_session_id: None,
                expected_workspace_revision: None,
                request: EditableRequest {
                    scheme: "https".to_string(),
                    host: "example.test".to_string(),
                    method: "POST".to_string(),
                    path: "/".to_string(),
                    headers: Vec::new(),
                    body: "partial".to_string(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: true,
                },
                target: None,
                source_transaction_id: None,
                http_version: None,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::BAD_REQUEST);
        let body = response_body_json(response).await;
        assert!(body
            .get("error")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .contains("preview is truncated"));
        assert!(session.store.snapshot(Some(10)).await.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn replay_send_rejects_stale_workspace_revision_before_sending() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-replay-send-workspace-revision-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let session_id = session.id();
        let stale_revision = session.workspace.snapshot().await.revision;
        session
            .workspace
            .replace_snapshot(WorkspaceStateSnapshot::default())
            .await;
        let current_revision = session.workspace.snapshot().await.revision;
        assert!(current_revision > stale_revision);

        let response = super::send_replay(
            State(state.clone()),
            Json(super::ReplaySendPayload {
                session_id: Some(session_id),
                expected_active_session_id: None,
                expected_workspace_revision: Some(stale_revision),
                request: EditableRequest {
                    scheme: "https".to_string(),
                    host: "example.test".to_string(),
                    method: "GET".to_string(),
                    path: "/".to_string(),
                    headers: Vec::new(),
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                target: None,
                source_transaction_id: None,
                http_version: None,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        let body = response_body_json(response).await;
        assert_eq!(
            body.get("revision"),
            Some(&serde_json::json!(current_revision))
        );
        let session_id_string = session_id.to_string();
        assert_eq!(
            body.get("session_id").and_then(serde_json::Value::as_str),
            Some(session_id_string.as_str())
        );
        assert!(session.store.snapshot(Some(10)).await.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn replay_send_releases_session_operation_lock_while_upstream_is_pending() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-replay-send-lock-release-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let session_id = session.id();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer).await.unwrap();
            let _ = accepted_tx.send(());
            let _ = release_rx.await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        });

        let response_task = tokio::spawn(super::send_replay(
            State(state.clone()),
            Json(super::ReplaySendPayload {
                session_id: Some(session_id),
                expected_active_session_id: None,
                expected_workspace_revision: None,
                request: EditableRequest {
                    scheme: "http".to_string(),
                    host: addr.to_string(),
                    method: "GET".to_string(),
                    path: "/".to_string(),
                    headers: Vec::new(),
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                target: None,
                source_transaction_id: None,
                http_version: None,
            }),
        ));

        tokio::time::timeout(Duration::from_secs(2), accepted_rx)
            .await
            .expect("replay should reach the upstream server")
            .expect("upstream accept marker should be sent");
        assert!(crate::proxy::session_has_active_proxy_work(session_id));

        let operation_lock = state.session_operation_lock(session_id).await;
        let operation_guard =
            tokio::time::timeout(Duration::from_millis(200), operation_lock.lock())
                .await
                .expect(
                    "replay must not hold the session operation lock while waiting on upstream",
                );
        drop(operation_guard);

        let _ = release_tx.send(());
        let response = response_task.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn replay_send_rejects_unknown_session_before_validating_payload() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-replay-invalid-session-guard-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());

        let response = super::send_replay(
            State(state),
            Json(super::ReplaySendPayload {
                session_id: Some(Uuid::new_v4()),
                expected_active_session_id: None,
                expected_workspace_revision: None,
                request: EditableRequest {
                    scheme: "ftp".to_string(),
                    host: String::new(),
                    method: "CONNECT".to_string(),
                    path: String::new(),
                    headers: Vec::new(),
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                target: None,
                source_transaction_id: None,
                http_version: Some("HTTP/3".to_string()),
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::NOT_FOUND);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn fuzzer_run_rejects_payload_for_unknown_session_before_attack() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-fuzzer-session-guard-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;

        let response = super::run_fuzzer_attack(
            State(state.clone()),
            Json(crate::fuzzer::FuzzerAttackPayload {
                session_id: Some(Uuid::new_v4()),
                expected_active_session_id: None,
                expected_workspace_revision: None,
                template: EditableRequest {
                    scheme: "https".to_string(),
                    host: "example.test".to_string(),
                    method: "GET".to_string(),
                    path: "/$payload$".to_string(),
                    headers: Vec::new(),
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                payloads: vec!["one".to_string()],
                source_transaction_id: None,
                http_version: None,
                target: None,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::NOT_FOUND);
        assert!(session.fuzzer.list(Some(10)).await.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn fuzzer_run_rejects_missing_session_before_attack() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-fuzzer-missing-session-guard-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;

        let response = super::run_fuzzer_attack(
            State(state.clone()),
            Json(crate::fuzzer::FuzzerAttackPayload {
                session_id: None,
                expected_active_session_id: None,
                expected_workspace_revision: None,
                template: EditableRequest {
                    scheme: "https".to_string(),
                    host: "example.test".to_string(),
                    method: "GET".to_string(),
                    path: "/$payload$".to_string(),
                    headers: Vec::new(),
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                payloads: vec!["one".to_string()],
                source_transaction_id: None,
                http_version: None,
                target: None,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        assert!(session.fuzzer.list(Some(10)).await.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn fuzzer_run_rejects_expanded_ip_host_target_override_before_attack() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-fuzzer-expanded-ip-target-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;

        let response = super::run_fuzzer_attack(
            State(state.clone()),
            Json(crate::fuzzer::FuzzerAttackPayload {
                session_id: Some(session.id()),
                expected_active_session_id: None,
                expected_workspace_revision: None,
                template: EditableRequest {
                    scheme: "https".to_string(),
                    host: "$payload$".to_string(),
                    method: "GET".to_string(),
                    path: "/".to_string(),
                    headers: Vec::new(),
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                payloads: vec!["127.0.0.1".to_string()],
                source_transaction_id: None,
                http_version: None,
                target: Some(RequestTargetOverride {
                    scheme: "https".to_string(),
                    host: "example.test".to_string(),
                    port: "443".to_string(),
                }),
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::BAD_REQUEST);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("request host is an IP address"));
        assert!(session.fuzzer.list(Some(10)).await.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn fuzzer_run_rejects_stale_implicit_active_session_guard() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-fuzzer-active-guard-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let original = state.session().await;
        let original_id = original.id();
        let active = state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();

        let response = super::run_fuzzer_attack(
            State(state.clone()),
            Json(crate::fuzzer::FuzzerAttackPayload {
                session_id: Some(original_id),
                expected_active_session_id: Some(original_id),
                expected_workspace_revision: None,
                template: EditableRequest {
                    scheme: "https".to_string(),
                    host: "example.test".to_string(),
                    method: "GET".to_string(),
                    path: "/$payload$".to_string(),
                    headers: Vec::new(),
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                payloads: vec!["one".to_string()],
                source_transaction_id: None,
                http_version: None,
                target: None,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        let body = response_body_json(response).await;
        assert_eq!(
            body.get("error").and_then(serde_json::Value::as_str),
            Some("active session changed")
        );
        let active_id = active.id.to_string();
        assert_eq!(
            body.get("session_id").and_then(serde_json::Value::as_str),
            Some(active_id.as_str())
        );
        assert!(original.fuzzer.list(Some(10)).await.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn fuzzer_run_rejects_stale_workspace_revision_before_attack() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-fuzzer-workspace-revision-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let session_id = session.id();
        let stale_revision = session.workspace.snapshot().await.revision;
        session
            .workspace
            .replace_snapshot(WorkspaceStateSnapshot::default())
            .await;
        let current_revision = session.workspace.snapshot().await.revision;
        assert!(current_revision > stale_revision);

        let response = super::run_fuzzer_attack(
            State(state.clone()),
            Json(crate::fuzzer::FuzzerAttackPayload {
                session_id: Some(session_id),
                expected_active_session_id: None,
                expected_workspace_revision: Some(stale_revision),
                template: EditableRequest {
                    scheme: "https".to_string(),
                    host: "example.test".to_string(),
                    method: "GET".to_string(),
                    path: "/$payload$".to_string(),
                    headers: Vec::new(),
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                payloads: vec!["one".to_string()],
                source_transaction_id: None,
                http_version: None,
                target: None,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        let body = response_body_json(response).await;
        assert_eq!(
            body.get("revision"),
            Some(&serde_json::json!(current_revision))
        );
        assert!(session.fuzzer.list(Some(10)).await.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn fuzzer_run_rejects_expected_active_target_mismatch() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-fuzzer-active-target-mismatch-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let active_id = state.session().await.id();
        let inactive = state
            .sessions
            .create_session(Some("inactive".to_string()))
            .unwrap();

        let response = super::run_fuzzer_attack(
            State(state.clone()),
            Json(crate::fuzzer::FuzzerAttackPayload {
                session_id: Some(inactive.id),
                expected_active_session_id: Some(active_id),
                expected_workspace_revision: None,
                template: EditableRequest {
                    scheme: "https".to_string(),
                    host: "example.test".to_string(),
                    method: "GET".to_string(),
                    path: "/$payload$".to_string(),
                    headers: Vec::new(),
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                payloads: vec!["one".to_string()],
                source_transaction_id: None,
                http_version: None,
                target: None,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        let body = response_body_json(response).await;
        assert_eq!(
            body.get("error").and_then(serde_json::Value::as_str),
            Some("active session changed")
        );
        assert!(state
            .sessions
            .load_context(inactive.id)
            .unwrap()
            .fuzzer
            .list(Some(10))
            .await
            .is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn fuzzer_run_rejects_unknown_session_before_validating_payload() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-fuzzer-invalid-session-guard-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());

        let response = super::run_fuzzer_attack(
            State(state),
            Json(crate::fuzzer::FuzzerAttackPayload {
                session_id: Some(Uuid::new_v4()),
                expected_active_session_id: None,
                expected_workspace_revision: None,
                template: EditableRequest {
                    scheme: "ftp".to_string(),
                    host: String::new(),
                    method: "CONNECT".to_string(),
                    path: String::new(),
                    headers: Vec::new(),
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                payloads: Vec::new(),
                source_transaction_id: None,
                http_version: Some("HTTP/3".to_string()),
                target: None,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::NOT_FOUND);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn fuzzer_run_rejects_payload_expansion_that_invalidates_request() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-fuzzer-expanded-request-validation-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;

        let response = super::run_fuzzer_attack(
            State(state.clone()),
            Json(crate::fuzzer::FuzzerAttackPayload {
                session_id: Some(session.id()),
                expected_active_session_id: None,
                expected_workspace_revision: None,
                template: EditableRequest {
                    scheme: "https".to_string(),
                    host: "example.test".to_string(),
                    method: "POST".to_string(),
                    path: "/$payload$".to_string(),
                    headers: Vec::new(),
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                payloads: vec!["bad path".to_string()],
                source_transaction_id: None,
                http_version: None,
                target: None,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::BAD_REQUEST);
        assert!(session.fuzzer.list(Some(10)).await.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn fuzzer_run_accepts_base64_template_that_is_valid_after_expansion() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-fuzzer-expanded-base64-template-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        });

        let response = super::run_fuzzer_attack(
            State(state.clone()),
            Json(crate::fuzzer::FuzzerAttackPayload {
                session_id: Some(session.id()),
                expected_active_session_id: None,
                expected_workspace_revision: None,
                template: EditableRequest {
                    scheme: "http".to_string(),
                    host: addr.to_string(),
                    method: "POST".to_string(),
                    path: "/".to_string(),
                    headers: Vec::new(),
                    body: "AA$payload$".to_string(),
                    body_encoding: BodyEncoding::Base64,
                    preview_truncated: false,
                },
                payloads: vec!["EC".to_string()],
                source_transaction_id: None,
                http_version: None,
                target: None,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::OK);
        let attack: crate::fuzzer::FuzzerAttackRecord = response_json(response).await;
        assert!(matches!(
            attack.status,
            crate::fuzzer::FuzzerAttackStatus::Completed
        ));
        assert_eq!(attack.results.len(), 1);
        assert_eq!(attack.results[0].status, Some(200));

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn fuzzer_run_rejects_preview_truncated_template_before_attack() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-fuzzer-truncated-template-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;

        let response = super::run_fuzzer_attack(
            State(state.clone()),
            Json(crate::fuzzer::FuzzerAttackPayload {
                session_id: Some(session.id()),
                expected_active_session_id: None,
                expected_workspace_revision: None,
                template: EditableRequest {
                    scheme: "https".to_string(),
                    host: "example.test".to_string(),
                    method: "POST".to_string(),
                    path: "/$payload$".to_string(),
                    headers: Vec::new(),
                    body: "partial".to_string(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: true,
                },
                payloads: vec!["one".to_string()],
                source_transaction_id: None,
                http_version: None,
                target: None,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::BAD_REQUEST);
        assert!(session.fuzzer.list(Some(10)).await.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn every_history_column_sort_key_is_accepted() {
        // The UI offers a sort for each column and the store implements each one,
        // but requests pass through this validator first — a key missing here is a
        // 400 that looks like the column is broken, which is how the Edited column
        // shipped the first time.
        for key in [
            "index",
            "host",
            "method",
            "path",
            "status",
            "length",
            "mime",
            "notes",
            "tls",
            "edited",
            "started_at",
        ] {
            assert!(
                super::validate_transaction_sort_key(Some(key)).is_ok(),
                "sort key {key} must be accepted"
            );
        }
        assert!(super::validate_transaction_sort_key(Some("nonsense")).is_err());
    }

    #[test]
    fn session_operation_conflicts_include_proxy_lifecycle_guards() {
        let response = super::session_operation_error_response(anyhow::anyhow!(
            "cannot delete a session while proxy activity is still running"
        ));
        assert_eq!(response.status(), super::StatusCode::CONFLICT);

        let response = super::session_operation_error_response(anyhow::anyhow!(
            "cannot delete a session while capture persistence is pending"
        ));
        assert_eq!(response.status(), super::StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn ws_replay_disconnect_returns_not_found_for_unknown_connection() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-ws-replay-disconnect-missing-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;

        let response = super::ws_replay_disconnect(
            State(state),
            Json(super::WsReplayDisconnectPayload {
                session_id: Some(session.id()),
                expected_active_session_id: None,
                expected_workspace_revision: None,
                id: Uuid::new_v4(),
                remove: false,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::NOT_FOUND);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn ws_replay_remove_returns_not_found_for_unknown_connection() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-ws-replay-remove-missing-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;

        let response = super::ws_replay_disconnect(
            State(state),
            Json(super::WsReplayDisconnectPayload {
                session_id: Some(session.id()),
                expected_active_session_id: None,
                expected_workspace_revision: None,
                id: Uuid::new_v4(),
                remove: true,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::NOT_FOUND);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn ws_replay_remove_waits_for_session_operation_lock() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-ws-replay-remove-lock-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let session_id = session.id();
        let connection_id = Uuid::new_v4();
        state
            .ws_replay
            .remember_disconnected_connection_for_test(connection_id, session_id)
            .await;
        let operation_lock = state.session_operation_lock(session_id).await;
        let operation_guard = operation_lock.lock_owned().await;

        let response_task = tokio::spawn(super::ws_replay_disconnect(
            State(state.clone()),
            Json(super::WsReplayDisconnectPayload {
                session_id: Some(session_id),
                expected_active_session_id: None,
                expected_workspace_revision: None,
                id: connection_id,
                remove: true,
            }),
        ));

        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            !response_task.is_finished(),
            "ws replay remove should wait for the session operation lock"
        );
        drop(operation_guard);

        let response = response_task.await.unwrap();
        assert_eq!(response.status(), super::StatusCode::OK);
        assert!(state.ws_replay.snapshot(connection_id).await.is_none());
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn ws_replay_snapshot_waits_for_session_operation_lock() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-ws-replay-snapshot-lock-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let session_id = session.id();
        let connection_id = Uuid::new_v4();
        state
            .ws_replay
            .remember_disconnected_connection_for_test(connection_id, session_id)
            .await;
        let operation_lock = state.session_operation_lock(session_id).await;
        let operation_guard = operation_lock.lock_owned().await;

        let response_task = tokio::spawn(super::ws_replay_snapshot(
            State(state.clone()),
            Path(connection_id.to_string()),
            Query(super::WsFramesSinceQuery {
                since: 0,
                session_id: Some(session_id),
            }),
        ));

        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            !response_task.is_finished(),
            "ws replay snapshot should wait for the session operation lock"
        );
        drop(operation_guard);

        let response = response_task.await.unwrap();
        assert_eq!(response.status(), super::StatusCode::OK);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn ws_replay_frames_waits_for_session_operation_lock() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-ws-replay-frames-lock-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let session_id = session.id();
        let connection_id = Uuid::new_v4();
        state
            .ws_replay
            .remember_disconnected_connection_for_test(connection_id, session_id)
            .await;
        let operation_lock = state.session_operation_lock(session_id).await;
        let operation_guard = operation_lock.lock_owned().await;

        let response_task = tokio::spawn(super::ws_replay_frames(
            State(state.clone()),
            Path(connection_id.to_string()),
            Query(super::WsFramesSinceQuery {
                since: 0,
                session_id: Some(session_id),
            }),
        ));

        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            !response_task.is_finished(),
            "ws replay frames should wait for the session operation lock"
        );
        drop(operation_guard);

        let response = response_task.await.unwrap();
        assert_eq!(response.status(), super::StatusCode::OK);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn ws_replay_remove_rechecks_proxy_work_after_lock_wait() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-ws-replay-remove-proxy-work-race-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let original = state.session().await;
        let original_id = original.id();
        state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();
        let connection_id = Uuid::new_v4();
        state
            .ws_replay
            .remember_disconnected_connection_for_test(connection_id, original_id)
            .await;
        let operation_lock = state.session_operation_lock(original_id).await;
        let operation_guard = operation_lock.lock_owned().await;

        let response_task = tokio::spawn(super::ws_replay_disconnect(
            State(state.clone()),
            Json(super::WsReplayDisconnectPayload {
                session_id: Some(original_id),
                expected_active_session_id: None,
                expected_workspace_revision: None,
                id: connection_id,
                remove: true,
            }),
        ));

        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            !response_task.is_finished(),
            "ws replay remove should wait before rechecking active proxy work"
        );
        let active_proxy_owner = crate::proxy::remember_active_proxy_session_owner(
            original_id,
            crate::proxy::PROXY_WORK_STREAMED_RESPONSE,
        );
        drop(operation_guard);

        let response = response_task.await.unwrap();
        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        assert!(state.ws_replay.snapshot(connection_id).await.is_some());

        drop(active_proxy_owner);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn ws_replay_remove_rechecks_workspace_revision_after_lock_wait() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-ws-replay-remove-workspace-revision-race-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let session_id = session.id();
        let expected_revision = session.workspace.snapshot().await.revision;
        let connection_id = Uuid::new_v4();
        state
            .ws_replay
            .remember_disconnected_connection_for_test(connection_id, session_id)
            .await;
        let operation_lock = state.session_operation_lock(session_id).await;
        let operation_guard = operation_lock.lock_owned().await;

        let response_task = tokio::spawn(super::ws_replay_disconnect(
            State(state.clone()),
            Json(super::WsReplayDisconnectPayload {
                session_id: Some(session_id),
                expected_active_session_id: None,
                expected_workspace_revision: Some(expected_revision),
                id: connection_id,
                remove: true,
            }),
        ));

        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            !response_task.is_finished(),
            "ws replay remove should wait before rechecking workspace revision"
        );
        session
            .workspace
            .replace_snapshot(WorkspaceStateSnapshot::default())
            .await;
        let current_revision = session.workspace.snapshot().await.revision;
        assert!(current_revision > expected_revision);
        drop(operation_guard);

        let response = response_task.await.unwrap();
        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        let body = response_body_json(response).await;
        assert_eq!(
            body.get("revision"),
            Some(&serde_json::json!(current_revision))
        );
        assert!(state.ws_replay.snapshot(connection_id).await.is_some());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn ws_replay_send_rechecks_proxy_work_after_lock_wait() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-ws-replay-send-proxy-work-race-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let original = state.session().await;
        let original_id = original.id();
        state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();
        let connection_id = Uuid::new_v4();
        state
            .ws_replay
            .remember_disconnected_connection_for_test(connection_id, original_id)
            .await;
        let operation_lock = state.session_operation_lock(original_id).await;
        let operation_guard = operation_lock.lock_owned().await;

        let response_task = tokio::spawn(super::ws_replay_send(
            State(state.clone()),
            Json(super::WsReplaySendPayload {
                session_id: Some(original_id),
                expected_active_session_id: None,
                expected_workspace_revision: None,
                id: connection_id,
                body: "hello".to_string(),
                binary: false,
                kind: None,
            }),
        ));

        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            !response_task.is_finished(),
            "ws replay send should wait before rechecking active proxy work"
        );
        let active_proxy_owner = crate::proxy::remember_active_proxy_session_owner(
            original_id,
            crate::proxy::PROXY_WORK_STREAMED_RESPONSE,
        );
        drop(operation_guard);

        let response = response_task.await.unwrap();
        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        assert!(state.ws_replay.snapshot(connection_id).await.is_some());

        drop(active_proxy_owner);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn ws_replay_connect_rechecks_workspace_revision_after_lock_wait() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-ws-replay-connect-workspace-revision-race-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let session_id = session.id();
        let expected_revision = session.workspace.snapshot().await.revision;
        let connection_id = Uuid::new_v4();
        let operation_lock = state.session_operation_lock(session_id).await;
        let operation_guard = operation_lock.lock_owned().await;

        let response_task = tokio::spawn(super::ws_replay_connect(
            State(state.clone()),
            Json(super::WsReplayConnectPayload {
                session_id: Some(session_id),
                expected_active_session_id: None,
                expected_workspace_revision: Some(expected_revision),
                id: connection_id,
                scheme: "wss".to_string(),
                host: "example.test".to_string(),
                port: 443,
                path: "/socket".to_string(),
                headers: Vec::new(),
            }),
        ));

        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            !response_task.is_finished(),
            "ws replay connect should wait before rechecking workspace revision"
        );
        session
            .workspace
            .replace_snapshot(WorkspaceStateSnapshot::default())
            .await;
        let current_revision = session.workspace.snapshot().await.revision;
        assert!(current_revision > expected_revision);
        drop(operation_guard);

        let response = response_task.await.unwrap();
        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        let body = response_body_json(response).await;
        assert_eq!(
            body.get("revision"),
            Some(&serde_json::json!(current_revision))
        );
        assert!(state.ws_replay.snapshot(connection_id).await.is_none());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn ws_replay_connect_rechecks_proxy_work_after_lock_wait() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-ws-replay-connect-proxy-work-race-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let original = state.session().await;
        let original_id = original.id();
        state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();
        let connection_id = Uuid::new_v4();
        let operation_lock = state.session_operation_lock(original_id).await;
        let operation_guard = operation_lock.lock_owned().await;

        let response_task = tokio::spawn(super::ws_replay_connect(
            State(state.clone()),
            Json(super::WsReplayConnectPayload {
                session_id: Some(original_id),
                expected_active_session_id: None,
                expected_workspace_revision: None,
                id: connection_id,
                scheme: "wss".to_string(),
                host: "example.test".to_string(),
                port: 443,
                path: "/socket".to_string(),
                headers: Vec::new(),
            }),
        ));

        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            !response_task.is_finished(),
            "ws replay connect should wait before rechecking active proxy work"
        );
        let active_proxy_owner = crate::proxy::remember_active_proxy_session_owner(
            original_id,
            crate::proxy::PROXY_WORK_STREAMED_RESPONSE,
        );
        drop(operation_guard);

        let response = response_task.await.unwrap();
        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        assert!(state.ws_replay.snapshot(connection_id).await.is_none());

        drop(active_proxy_owner);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn ws_replay_actions_reject_stale_expected_active_session() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-ws-replay-expected-active-race-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let original = state.session().await;
        let original_id = original.id();
        state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();

        let connect_id = Uuid::new_v4();
        let response = super::ws_replay_connect(
            State(state.clone()),
            Json(super::WsReplayConnectPayload {
                session_id: Some(original_id),
                expected_active_session_id: Some(original_id),
                expected_workspace_revision: None,
                id: connect_id,
                scheme: "wss".to_string(),
                host: "example.test".to_string(),
                port: 443,
                path: "/socket".to_string(),
                headers: Vec::new(),
            }),
        )
        .await;
        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        assert!(state.ws_replay.snapshot(connect_id).await.is_none());

        let send_id = Uuid::new_v4();
        state
            .ws_replay
            .remember_disconnected_connection_for_test(send_id, original_id)
            .await;
        let response = super::ws_replay_send(
            State(state.clone()),
            Json(super::WsReplaySendPayload {
                session_id: Some(original_id),
                expected_active_session_id: Some(original_id),
                expected_workspace_revision: None,
                id: send_id,
                body: "hello".to_string(),
                binary: false,
                kind: None,
            }),
        )
        .await;
        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        assert!(state.ws_replay.snapshot(send_id).await.is_some());

        let remove_id = Uuid::new_v4();
        state
            .ws_replay
            .remember_disconnected_connection_for_test(remove_id, original_id)
            .await;
        let response = super::ws_replay_disconnect(
            State(state.clone()),
            Json(super::WsReplayDisconnectPayload {
                session_id: Some(original_id),
                expected_active_session_id: Some(original_id),
                expected_workspace_revision: None,
                id: remove_id,
                remove: true,
            }),
        )
        .await;
        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        assert!(state.ws_replay.snapshot(remove_id).await.is_some());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn ws_replay_actions_reject_stale_workspace_revision() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-ws-replay-workspace-revision-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let session_id = session.id();
        let stale_revision = session.workspace.snapshot().await.revision;
        session
            .workspace
            .replace_snapshot(WorkspaceStateSnapshot::default())
            .await;
        let current_revision = session.workspace.snapshot().await.revision;
        assert!(current_revision > stale_revision);

        let connect_id = Uuid::new_v4();
        let response = super::ws_replay_connect(
            State(state.clone()),
            Json(super::WsReplayConnectPayload {
                session_id: Some(session_id),
                expected_active_session_id: None,
                expected_workspace_revision: Some(stale_revision),
                id: connect_id,
                scheme: "wss".to_string(),
                host: "example.test".to_string(),
                port: 443,
                path: "/socket".to_string(),
                headers: Vec::new(),
            }),
        )
        .await;
        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        assert!(state.ws_replay.snapshot(connect_id).await.is_none());

        let send_id = Uuid::new_v4();
        state
            .ws_replay
            .remember_disconnected_connection_for_test(send_id, session_id)
            .await;
        let response = super::ws_replay_send(
            State(state.clone()),
            Json(super::WsReplaySendPayload {
                session_id: Some(session_id),
                expected_active_session_id: None,
                expected_workspace_revision: Some(stale_revision),
                id: send_id,
                body: "hello".to_string(),
                binary: false,
                kind: None,
            }),
        )
        .await;
        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        assert!(state.ws_replay.snapshot(send_id).await.is_some());

        let disconnect_id = Uuid::new_v4();
        state
            .ws_replay
            .remember_disconnected_connection_for_test(disconnect_id, session_id)
            .await;
        let response = super::ws_replay_disconnect(
            State(state.clone()),
            Json(super::WsReplayDisconnectPayload {
                session_id: Some(session_id),
                expected_active_session_id: None,
                expected_workspace_revision: Some(stale_revision),
                id: disconnect_id,
                remove: false,
            }),
        )
        .await;
        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        assert!(state.ws_replay.snapshot(disconnect_id).await.is_some());

        let remove_id = Uuid::new_v4();
        state
            .ws_replay
            .remember_disconnected_connection_for_test(remove_id, session_id)
            .await;
        let response = super::ws_replay_disconnect(
            State(state.clone()),
            Json(super::WsReplayDisconnectPayload {
                session_id: Some(session_id),
                expected_active_session_id: None,
                expected_workspace_revision: Some(stale_revision),
                id: remove_id,
                remove: true,
            }),
        )
        .await;
        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        assert!(state.ws_replay.snapshot(remove_id).await.is_some());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn ws_replay_connect_rejects_unknown_session() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-ws-replay-connect-unknown-session-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());

        let response = super::ws_replay_connect(
            State(state),
            Json(super::WsReplayConnectPayload {
                session_id: Some(Uuid::new_v4()),
                expected_active_session_id: None,
                expected_workspace_revision: None,
                id: Uuid::new_v4(),
                scheme: "wss".to_string(),
                host: "example.test".to_string(),
                port: 443,
                path: "/socket".to_string(),
                headers: Vec::new(),
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::NOT_FOUND);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn ws_replay_connect_rejects_oversized_handshake_payloads() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-ws-replay-connect-caps-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let mut cases = Vec::new();

        cases.push(super::WsReplayConnectPayload {
            session_id: Some(session.id()),
            expected_active_session_id: None,
            expected_workspace_revision: None,
            id: Uuid::new_v4(),
            scheme: "wss".to_string(),
            host: "h".repeat(super::MAX_WS_REPLAY_HOST_BYTES + 1),
            port: 443,
            path: "/socket".to_string(),
            headers: Vec::new(),
        });
        cases.push(super::WsReplayConnectPayload {
            session_id: Some(session.id()),
            expected_active_session_id: None,
            expected_workspace_revision: None,
            id: Uuid::new_v4(),
            scheme: "wss".to_string(),
            host: "example.test".to_string(),
            port: 443,
            path: format!("/{}", "p".repeat(super::MAX_WS_REPLAY_PATH_BYTES + 1)),
            headers: Vec::new(),
        });
        cases.push(super::WsReplayConnectPayload {
            session_id: Some(session.id()),
            expected_active_session_id: None,
            expected_workspace_revision: None,
            id: Uuid::new_v4(),
            scheme: "wss".to_string(),
            host: "example.test".to_string(),
            port: 443,
            path: "/socket".to_string(),
            headers: (0..=super::MAX_WORKSPACE_WS_HEADERS)
                .map(|index| HeaderRecord {
                    name: format!("x-test-{index}"),
                    value: "ok".to_string(),
                })
                .collect(),
        });
        cases.push(super::WsReplayConnectPayload {
            session_id: Some(session.id()),
            expected_active_session_id: None,
            expected_workspace_revision: None,
            id: Uuid::new_v4(),
            scheme: "wss".to_string(),
            host: "example.test".to_string(),
            port: 443,
            path: "/socket".to_string(),
            headers: vec![HeaderRecord {
                name: "x-large".to_string(),
                value: "x".repeat(super::MAX_WORKSPACE_WS_HEADER_BYTES + 1),
            }],
        });
        cases.push(super::WsReplayConnectPayload {
            session_id: Some(session.id()),
            expected_active_session_id: None,
            expected_workspace_revision: None,
            id: Uuid::new_v4(),
            scheme: "wss".to_string(),
            host: "example.test".to_string(),
            port: 443,
            path: "/socket".to_string(),
            headers: (0..5)
                .map(|index| HeaderRecord {
                    name: format!("x-total-{index}"),
                    value: "x".repeat(60 * 1024),
                })
                .collect(),
        });

        for payload in cases {
            let connection_id = payload.id;
            let response = super::ws_replay_connect(State(state.clone()), Json(payload)).await;
            assert_eq!(response.status(), super::StatusCode::BAD_REQUEST);
            assert!(state.ws_replay.snapshot(connection_id).await.is_none());
        }

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn ws_replay_remove_rejects_unknown_session() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-ws-replay-remove-unknown-session-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());

        let response = super::ws_replay_disconnect(
            State(state),
            Json(super::WsReplayDisconnectPayload {
                session_id: Some(Uuid::new_v4()),
                expected_active_session_id: None,
                expected_workspace_revision: None,
                id: Uuid::new_v4(),
                remove: true,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::NOT_FOUND);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn transaction_read_paths_can_use_pinned_inactive_session() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-transaction-pinned-session-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let original = state.session().await;
        let original_id = original.id();
        let message = MessageRecord {
            headers: vec![HeaderRecord {
                name: "host".to_string(),
                value: "inactive.example".to_string(),
            }],
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };
        let record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "inactive.example".to_string(),
            "/pinned".to_string(),
            Some(200),
            1,
            message.clone(),
            Some(message),
            Vec::new(),
            None,
            None,
        );
        let record_id = record.id;
        original.store.insert(record).await;
        state.persist_session_context(&original).await.unwrap();
        let active_id = state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap()
            .id;

        let active_response = super::get_transaction(
            State(state.clone()),
            Path(record_id.to_string()),
            Query(super::TransactionGetQuery { session_id: None }),
        )
        .await;
        assert_eq!(active_response.status(), super::StatusCode::NOT_FOUND);

        let active_list_response = super::list_transactions(
            State(state.clone()),
            Query(super::TransactionQuery::default()),
        )
        .await;
        let active_list: Vec<crate::model::TransactionSummary> =
            response_json(active_list_response).await;
        assert!(active_list.is_empty());

        {
            let _active_proxy_owner = crate::proxy::remember_active_proxy_session_owner(
                original_id,
                crate::proxy::PROXY_WORK_STREAMED_RESPONSE,
            );

            let pinned_response = super::get_transaction(
                State(state.clone()),
                Path(record_id.to_string()),
                Query(super::TransactionGetQuery {
                    session_id: Some(original_id),
                }),
            )
            .await;
            assert_eq!(pinned_response.status(), super::StatusCode::OK);

            let pinned_list_response = super::list_transactions(
                State(state.clone()),
                Query(super::TransactionQuery {
                    session_id: Some(original_id),
                    ..super::TransactionQuery::default()
                }),
            )
            .await;
            let pinned_list: Vec<crate::model::TransactionSummary> =
                response_json(pinned_list_response).await;
            assert_eq!(pinned_list.len(), 1);
            assert_eq!(pinned_list[0].id, record_id);

            let pinned_page_response = super::list_transactions_page(
                State(state.clone()),
                Query(super::TransactionQuery {
                    session_id: Some(original_id),
                    ..super::TransactionQuery::default()
                }),
            )
            .await;
            let pinned_page: super::TransactionPageResponse =
                response_json(pinned_page_response).await;
            assert_eq!(pinned_page.items.len(), 1);
            assert_eq!(pinned_page.items[0].id, record_id);
        }

        let active_annotation_response = super::update_transaction_annotations(
            State(state.clone()),
            Path(record_id.to_string()),
            Query(super::TransactionWriteQuery {
                session_id: None,
                expected_active_session_id: None,
            }),
            Json(super::AnnotationsPayload {
                session_id: None,
                color_tag: Some(Some("red".to_string())),
                user_note: None,
                client_id: None,
                client_version: None,
            }),
        )
        .await;
        assert_eq!(
            active_annotation_response.status(),
            super::StatusCode::NOT_FOUND
        );

        let pinned_annotation_response = super::update_transaction_annotations(
            State(state.clone()),
            Path(record_id.to_string()),
            Query(super::TransactionWriteQuery {
                session_id: None,
                expected_active_session_id: None,
            }),
            Json(super::AnnotationsPayload {
                session_id: Some(original_id),
                color_tag: Some(Some("blue".to_string())),
                user_note: Some(Some("inactive note".to_string())),
                client_id: None,
                client_version: None,
            }),
        )
        .await;
        assert_eq!(pinned_annotation_response.status(), super::StatusCode::OK);
        let annotated_session = state.sessions.load_context(original_id).unwrap();
        let annotated = annotated_session.store.get(record_id).await.unwrap();
        assert_eq!(annotated.color_tag.as_deref(), Some("blue"));
        assert_eq!(annotated.user_note.as_deref(), Some("inactive note"));

        let conflicting_annotation_response = super::update_transaction_annotations(
            State(state.clone()),
            Path(record_id.to_string()),
            Query(super::TransactionWriteQuery {
                session_id: Some(active_id),
                expected_active_session_id: None,
            }),
            Json(super::AnnotationsPayload {
                session_id: Some(original_id),
                color_tag: Some(Some("green".to_string())),
                user_note: None,
                client_id: None,
                client_version: None,
            }),
        )
        .await;
        assert_eq!(
            conflicting_annotation_response.status(),
            super::StatusCode::BAD_REQUEST
        );
        let annotated_after_conflict = annotated_session.store.get(record_id).await.unwrap();
        assert_eq!(annotated_after_conflict.color_tag.as_deref(), Some("blue"));

        let pinned_page_response = super::list_transactions_page(
            State(state.clone()),
            Query(super::TransactionQuery {
                session_id: Some(original_id),
                ..super::TransactionQuery::default()
            }),
        )
        .await;
        let pinned_page: super::TransactionPageResponse = response_json(pinned_page_response).await;
        assert_eq!(pinned_page.items.len(), 1);
        assert_eq!(pinned_page.items[0].id, record_id);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn fuzzer_and_websocket_read_paths_can_use_pinned_inactive_session() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-fuzzer-websocket-pinned-session-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let original = state.session().await;
        let original_id = original.id();
        let template = EditableRequest {
            scheme: "https".to_string(),
            host: "inactive.example".to_string(),
            method: "GET".to_string(),
            path: "/fuzz".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let attack = FuzzerAttackRecord {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            completed_at: Utc::now(),
            status: FuzzerAttackStatus::Completed,
            template,
            payload_count: 1,
            marker_count: 0,
            results: Vec::new(),
            notes: vec!["inactive attack".to_string()],
        };
        let attack_id = attack.id;
        original.fuzzer.insert(attack).await;
        let message = MessageRecord {
            headers: vec![HeaderRecord {
                name: "host".to_string(),
                value: "inactive.example".to_string(),
            }],
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };
        let websocket = WebSocketSessionRecord {
            id: Uuid::new_v4(),
            sequence: 0,
            started_at: Utc::now(),
            closed_at: Some(Utc::now()),
            duration_ms: Some(1),
            scheme: "wss".to_string(),
            host: "inactive.example".to_string(),
            path: "/socket".to_string(),
            status: Some(101),
            request: message.clone(),
            response: Some(message),
            frames: Vec::new(),
            notes: vec!["inactive websocket".to_string()],
        };
        let websocket_id = websocket.id;
        original.websockets.open(websocket).await;
        state.persist_session_context(&original).await.unwrap();
        state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();

        let active_fuzzer_response = super::get_fuzzer_attack(
            State(state.clone()),
            Path(attack_id.to_string()),
            Query(super::FuzzerQuery {
                session_id: None,
                limit: None,
            }),
        )
        .await;
        assert_eq!(
            active_fuzzer_response.status(),
            super::StatusCode::NOT_FOUND
        );
        let active_proxy_owner = crate::proxy::remember_active_proxy_session_owner(
            original_id,
            crate::proxy::PROXY_WORK_STREAMED_RESPONSE,
        );

        let pinned_fuzzer_response = super::get_fuzzer_attack(
            State(state.clone()),
            Path(attack_id.to_string()),
            Query(super::FuzzerQuery {
                session_id: Some(original_id),
                limit: None,
            }),
        )
        .await;
        assert_eq!(pinned_fuzzer_response.status(), super::StatusCode::OK);
        let pinned_fuzzer_list = super::list_fuzzer_attacks(
            State(state.clone()),
            Query(super::FuzzerQuery {
                session_id: Some(original_id),
                limit: None,
            }),
        )
        .await;
        let pinned_fuzzer_summaries: Vec<crate::fuzzer::FuzzerAttackSummary> =
            response_json(pinned_fuzzer_list).await;
        assert_eq!(pinned_fuzzer_summaries.len(), 1);
        assert_eq!(pinned_fuzzer_summaries[0].id, attack_id);

        let active_websocket_response = super::get_websocket(
            State(state.clone()),
            Path(websocket_id.to_string()),
            Query(super::WebSocketQuery {
                session_id: None,
                limit: None,
                offset: None,
                frame_limit: None,
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(
            active_websocket_response.status(),
            super::StatusCode::NOT_FOUND
        );
        let pinned_websocket_response = super::get_websocket(
            State(state.clone()),
            Path(websocket_id.to_string()),
            Query(super::WebSocketQuery {
                session_id: Some(original_id),
                limit: None,
                offset: None,
                frame_limit: None,
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(pinned_websocket_response.status(), super::StatusCode::OK);
        let pinned_websocket_list = super::list_websockets_page(
            State(state),
            Query(super::WebSocketQuery {
                session_id: Some(original_id),
                limit: None,
                offset: None,
                frame_limit: None,
                ..Default::default()
            }),
        )
        .await;
        let pinned_websocket_page: super::WebSocketPageResponse =
            response_json(pinned_websocket_list).await;
        assert_eq!(pinned_websocket_page.items.len(), 1);
        assert_eq!(pinned_websocket_page.items[0].id, websocket_id);
        drop(active_proxy_owner);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn websocket_detail_frame_limit_returns_tail_frames_without_changing_summary_count() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-websocket-frame-limit-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let websocket = WebSocketSessionRecord {
            id: Uuid::new_v4(),
            sequence: 0,
            started_at: Utc::now(),
            closed_at: Some(Utc::now()),
            duration_ms: Some(1),
            scheme: "wss".to_string(),
            host: "example.test".to_string(),
            path: "/socket".to_string(),
            status: Some(101),
            request: MessageRecord::from_headers_and_body(&HeaderMap::new(), &[], 1024),
            response: None,
            frames: (0..1002)
                .map(|index| WebSocketFrameRecord {
                    index,
                    captured_at: Utc::now(),
                    direction: WebSocketFrameDirection::ServerToClient,
                    kind: WebSocketFrameKind::Text,
                    body_preview: format!("frame-{index}"),
                    body_encoding: BodyEncoding::Utf8,
                    body_size: 0,
                    preview_truncated: false,
                })
                .collect(),
            notes: Vec::new(),
        };
        let websocket_id = websocket.id;
        session.websockets.open(websocket).await;

        let detail_response = super::get_websocket(
            State(state.clone()),
            Path(websocket_id.to_string()),
            Query(super::WebSocketQuery {
                session_id: Some(session.id()),
                limit: None,
                offset: None,
                frame_limit: Some(2),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(detail_response.status(), super::StatusCode::OK);
        let detail: WebSocketSessionRecord = response_json(detail_response).await;
        assert_eq!(
            detail
                .frames
                .iter()
                .map(|frame| frame.index)
                .collect::<Vec<_>>(),
            vec![1000, 1001]
        );

        let older_detail_response = super::get_websocket(
            State(state.clone()),
            Path(websocket_id.to_string()),
            Query(super::WebSocketQuery {
                session_id: Some(session.id()),
                frame_limit: Some(3),
                before_index: Some(1000),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(older_detail_response.status(), super::StatusCode::OK);
        let older_detail: WebSocketSessionRecord = response_json(older_detail_response).await;
        assert_eq!(
            older_detail
                .frames
                .iter()
                .map(|frame| frame.index)
                .collect::<Vec<_>>(),
            vec![997, 998, 999]
        );

        let exhausted_older_detail_response = super::get_websocket(
            State(state.clone()),
            Path(websocket_id.to_string()),
            Query(super::WebSocketQuery {
                session_id: Some(session.id()),
                frame_limit: Some(3),
                before_index: Some(0),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(
            exhausted_older_detail_response.status(),
            super::StatusCode::OK
        );
        let exhausted_older_detail: WebSocketSessionRecord =
            response_json(exhausted_older_detail_response).await;
        assert!(exhausted_older_detail.frames.is_empty());

        let empty_detail_response = super::get_websocket(
            State(state.clone()),
            Path(websocket_id.to_string()),
            Query(super::WebSocketQuery {
                session_id: Some(session.id()),
                limit: None,
                offset: None,
                frame_limit: Some(0),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(empty_detail_response.status(), super::StatusCode::OK);
        let empty_detail: WebSocketSessionRecord = response_json(empty_detail_response).await;
        assert!(empty_detail.frames.is_empty());

        let default_detail_response = super::get_websocket(
            State(state.clone()),
            Path(websocket_id.to_string()),
            Query(super::WebSocketQuery {
                session_id: Some(session.id()),
                limit: None,
                offset: None,
                frame_limit: None,
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(default_detail_response.status(), super::StatusCode::OK);
        let default_detail: WebSocketSessionRecord = response_json(default_detail_response).await;
        assert_eq!(default_detail.frames.len(), 1000);
        assert_eq!(default_detail.frames[0].index, 2);
        assert_eq!(default_detail.frames[999].index, 1001);

        let oversized_detail_response = super::get_websocket(
            State(state.clone()),
            Path(websocket_id.to_string()),
            Query(super::WebSocketQuery {
                session_id: Some(session.id()),
                limit: None,
                offset: None,
                frame_limit: Some(50_000),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(oversized_detail_response.status(), super::StatusCode::OK);
        let oversized_detail: WebSocketSessionRecord =
            response_json(oversized_detail_response).await;
        assert_eq!(oversized_detail.frames.len(), 1000);
        assert_eq!(oversized_detail.frames[0].index, 2);

        let legacy_list_response = super::list_websockets(
            State(state.clone()),
            Query(super::WebSocketQuery {
                session_id: Some(session.id()),
                limit: Some(10),
                offset: None,
                frame_limit: None,
                ..Default::default()
            }),
        )
        .await;
        let legacy_list: Vec<WebSocketSessionSummary> = response_json(legacy_list_response).await;
        assert_eq!(legacy_list[0].frame_count, 1002);
        assert_eq!(legacy_list[0].retained_frame_count, 1002);
        assert_eq!(legacy_list[0].last_frame_index, Some(1001));

        let list_response = super::list_websockets_page(
            State(state),
            Query(super::WebSocketQuery {
                session_id: Some(session.id()),
                limit: Some(10),
                offset: None,
                frame_limit: None,
                ..Default::default()
            }),
        )
        .await;
        let page: super::WebSocketPageResponse = response_json(list_response).await;
        assert_eq!(page.items[0].frame_count, 1002);
        assert_eq!(page.items[0].retained_frame_count, 1002);
        assert_eq!(page.items[0].last_frame_index, Some(1001));

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn websocket_page_without_explicit_limit_uses_store_default_limit() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-websocket-page-default-limit-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 600,
            max_transaction_entries: 600,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let message = MessageRecord::from_headers_and_body(&HeaderMap::new(), &[], 1024);
        for index in 0..501 {
            session
                .websockets
                .open(WebSocketSessionRecord {
                    id: Uuid::new_v4(),
                    sequence: 0,
                    started_at: Utc::now(),
                    closed_at: Some(Utc::now()),
                    duration_ms: Some(1),
                    scheme: "wss".to_string(),
                    host: format!("ws-{index}.example.test"),
                    path: "/socket".to_string(),
                    status: Some(101),
                    request: message.clone(),
                    response: Some(message.clone()),
                    frames: Vec::new(),
                    notes: Vec::new(),
                })
                .await;
        }

        let response = super::list_websockets_page(
            State(state),
            Query(super::WebSocketQuery {
                session_id: Some(session.id()),
                limit: None,
                offset: None,
                frame_limit: None,
                ..Default::default()
            }),
        )
        .await;
        let page: super::WebSocketPageResponse = response_json(response).await;

        assert_eq!(page.items.len(), 501);
        assert_eq!(page.limit, 600);
        assert_eq!(page.filtered_total, Some(501));
        assert!(!page.has_more);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn websocket_events_stream_emits_summary_update() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-websocket-events-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let events_response = super::events(
            State(state),
            Query(super::EventsQuery {
                session_id: Some(session.id()),
            }),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(events_response.status(), super::StatusCode::OK);
        let mut events_body = events_response.into_body();

        let websocket = WebSocketSessionRecord {
            id: Uuid::new_v4(),
            sequence: 0,
            started_at: Utc::now(),
            closed_at: None,
            duration_ms: None,
            scheme: "wss".to_string(),
            host: "events.example".to_string(),
            path: "/socket".to_string(),
            status: Some(101),
            request: MessageRecord::from_headers_and_body(&HeaderMap::new(), &[], 1024),
            response: None,
            frames: Vec::new(),
            notes: Vec::new(),
        };
        let websocket_id = websocket.id;
        session.websockets.open(websocket).await;

        let mut text = String::new();
        for _ in 0..8 {
            let frame = tokio::time::timeout(Duration::from_secs(1), events_body.frame())
                .await
                .expect("websocket event stream should yield a frame")
                .expect("websocket event stream should remain open")
                .expect("websocket event frame should be ok");
            if let Ok(bytes) = frame.into_data() {
                text.push_str(&String::from_utf8_lossy(&bytes));
            }
            if text.contains("event: websocket") && text.contains(&websocket_id.to_string()) {
                break;
            }
        }

        assert!(
            text.contains("event: websocket"),
            "event stream should include websocket summary event: {text}"
        );
        assert!(
            text.contains(&websocket_id.to_string()),
            "websocket event should include summary id {websocket_id}: {text}"
        );

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn explicit_active_events_stream_emits_session_changed() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-active-events-session-changed-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let active = state.session().await;
        let events_response = super::events(
            State(state.clone()),
            Query(super::EventsQuery {
                session_id: Some(active.id()),
            }),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(events_response.status(), super::StatusCode::OK);
        let mut events_body = events_response.into_body();

        state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();

        let mut text = String::new();
        for _ in 0..8 {
            let frame = tokio::time::timeout(Duration::from_secs(1), events_body.frame())
                .await
                .expect("active event stream should yield a frame")
                .expect("active event stream should remain open")
                .expect("active event frame should be ok");
            if let Ok(bytes) = frame.into_data() {
                text.push_str(&String::from_utf8_lossy(&bytes));
            }
            if text.contains("event: session_changed") {
                break;
            }
        }

        assert!(
            text.contains("event: session_changed"),
            "active explicit event stream should include session_changed: {text}"
        );

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn pinned_transaction_read_reports_corrupt_registered_session_as_server_error() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-corrupt-pinned-session-read-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let original_id = state
            .sessions
            .create_session(Some("corrupt inactive".to_string()))
            .unwrap()
            .id;

        let storage_dir = state.sessions.session_storage_path(original_id).unwrap();
        std::fs::remove_dir_all(&storage_dir).unwrap();
        std::fs::write(&storage_dir, b"not a directory").unwrap();

        let response = super::get_transaction(
            State(state.clone()),
            Path(uuid::Uuid::new_v4().to_string()),
            Query(super::TransactionGetQuery {
                session_id: Some(original_id),
            }),
        )
        .await;
        assert_eq!(response.status(), super::StatusCode::INTERNAL_SERVER_ERROR);

        let _ = std::fs::remove_file(storage_dir);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn workspace_update_reports_corrupt_registered_session_as_server_error() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-corrupt-pinned-workspace-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let original_id = state
            .sessions
            .create_session(Some("corrupt inactive".to_string()))
            .unwrap()
            .id;

        let storage_dir = state.sessions.session_storage_path(original_id).unwrap();
        std::fs::remove_dir_all(&storage_dir).unwrap();
        std::fs::write(&storage_dir, b"not a directory").unwrap();

        let response = super::update_workspace_state(
            State(state.clone()),
            Json(WorkspaceStateSnapshot {
                session_id: Some(original_id),
                ..WorkspaceStateSnapshot::default()
            }),
        )
        .await;
        assert_eq!(response.status(), super::StatusCode::INTERNAL_SERVER_ERROR);

        let _ = std::fs::remove_file(storage_dir);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn workspace_update_returns_conflict_before_validating_stale_payload() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-workspace-stale-invalid-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let mut current = WorkspaceStateSnapshot::default();
        current.replay.active_tab_id = Some("current".to_string());
        current.replay.tabs.push(ReplayTabState {
            id: "current".to_string(),
            sequence: 1,
            ..ReplayTabState::default()
        });
        let current = session.workspace.replace_snapshot(current).await;
        assert_eq!(current.revision, 1);

        let mut stale = WorkspaceStateSnapshot {
            session_id: Some(session.id()),
            ..WorkspaceStateSnapshot::default()
        };
        stale.replay.tabs.push(ReplayTabState {
            id: "bad-stale".to_string(),
            sequence: 1,
            base_request: Some(EditableRequest {
                scheme: "ftp".to_string(),
                host: "bad host".to_string(),
                method: "GET".to_string(),
                path: "/".to_string(),
                headers: Vec::new(),
                body: String::new(),
                body_encoding: BodyEncoding::Utf8,
                preview_truncated: false,
            }),
            ..ReplayTabState::default()
        });

        let response = super::update_workspace_state(State(state), Json(stale)).await;

        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn scanner_config_update_rolls_back_when_persist_fails() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-scanner-config-rollback-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let mut next_config = session.scanner.get_config().await;
        assert!(next_config.enabled);
        next_config.enabled = false;

        let storage_dir = session.storage_dir().to_path_buf();
        std::fs::remove_dir_all(&storage_dir).unwrap();
        std::fs::write(&storage_dir, b"not a directory").unwrap();

        let response = super::update_scanner_config(
            State(state),
            Query(super::SessionWriteQuery {
                session_id: None,
                expected_active_session_id: None,
            }),
            Json(super::ScannerConfigPayload::from(next_config)),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::INTERNAL_SERVER_ERROR);
        assert!(session.scanner.get_config().await.enabled);

        let _ = std::fs::remove_file(storage_dir);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn scanner_config_update_rewrites_durable_snapshot_after_registry_metadata_failure() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-scanner-config-registry-rollback-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let mut next_config = session.scanner.get_config().await;
        assert!(next_config.enabled);
        next_config.enabled = false;

        let registry_path = session
            .storage_dir()
            .parent()
            .expect("session dir should have registry parent")
            .join("registry.json");
        std::fs::remove_file(&registry_path).unwrap();
        std::fs::create_dir(&registry_path).unwrap();

        let response = super::update_scanner_config(
            State(state.clone()),
            Query(super::SessionWriteQuery {
                session_id: None,
                expected_active_session_id: None,
            }),
            Json(super::ScannerConfigPayload::from(next_config)),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::INTERNAL_SERVER_ERROR);
        assert!(session.scanner.get_config().await.enabled);

        let reloaded = state.sessions.load_context(session.id()).unwrap();
        assert!(reloaded.scanner.get_config().await.enabled);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn sequence_upsert_rejects_missing_session_before_saving() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-sequence-missing-session-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "Missing session".to_string(),
            steps: Vec::new(),
        };

        let response = super::upsert_sequence(
            State(state),
            Json(super::SequenceUpsertPayload {
                session_id: None,
                expected_active_session_id: None,
                definition,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        assert!(session.sequence.list_definitions().await.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn sequence_upsert_rejects_stale_expected_active_session() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-sequence-upsert-stale-active-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let original = state.session().await;
        let original_id = original.id();
        state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();
        let definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "Stale active".to_string(),
            steps: Vec::new(),
        };

        let response = super::upsert_sequence(
            State(state),
            Json(super::SequenceUpsertPayload {
                session_id: Some(original_id),
                expected_active_session_id: Some(original_id),
                definition,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        assert!(original.sequence.list_definitions().await.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn sequence_delete_rejects_stale_expected_active_session() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-sequence-delete-stale-active-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let original = state.session().await;
        let original_id = original.id();
        let definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "Stale delete".to_string(),
            steps: Vec::new(),
        };
        original
            .sequence
            .upsert_definition(definition.clone())
            .await;
        state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();

        let response = super::delete_sequence(
            State(state),
            Path(definition.id.to_string()),
            Query(super::SequenceSessionQuery {
                session_id: Some(original_id),
                expected_active_session_id: Some(original_id),
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        assert!(original
            .sequence
            .get_definition(definition.id)
            .await
            .is_some());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn sequence_upsert_rechecks_proxy_work_after_lock_wait() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-sequence-upsert-proxy-work-race-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let original = state.session().await;
        let original_id = original.id();
        state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();
        let definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "Race upsert".to_string(),
            steps: Vec::new(),
        };
        let operation_lock = state.session_operation_lock(original_id).await;
        let operation_guard = operation_lock.lock().await;

        let mut upsert_future = Box::pin(super::upsert_sequence(
            State(state.clone()),
            Json(super::SequenceUpsertPayload {
                session_id: Some(original_id),
                expected_active_session_id: None,
                definition,
            }),
        ));
        let blocked = tokio::time::timeout(Duration::from_millis(30), &mut upsert_future).await;
        assert!(blocked.is_err());
        let active_proxy_owner = crate::proxy::remember_active_proxy_session_owner(
            original_id,
            crate::proxy::PROXY_WORK_STREAMED_RESPONSE,
        );
        drop(operation_guard);

        let response = upsert_future.await;
        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        assert!(original.sequence.list_definitions().await.is_empty());

        drop(active_proxy_owner);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn sequence_delete_rechecks_proxy_work_after_lock_wait() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-sequence-delete-proxy-work-race-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let original = state.session().await;
        let original_id = original.id();
        let definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "Race delete".to_string(),
            steps: Vec::new(),
        };
        original
            .sequence
            .upsert_definition(definition.clone())
            .await;
        state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();
        let operation_lock = state.session_operation_lock(original_id).await;
        let operation_guard = operation_lock.lock().await;

        let mut delete_future = Box::pin(super::delete_sequence(
            State(state.clone()),
            Path(definition.id.to_string()),
            Query(super::SequenceSessionQuery {
                session_id: Some(original_id),
                expected_active_session_id: None,
            }),
        ));
        let blocked = tokio::time::timeout(Duration::from_millis(30), &mut delete_future).await;
        assert!(blocked.is_err());
        let active_proxy_owner = crate::proxy::remember_active_proxy_session_owner(
            original_id,
            crate::proxy::PROXY_WORK_STREAMED_RESPONSE,
        );
        drop(operation_guard);

        let response = delete_future.await;
        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        assert!(original
            .sequence
            .get_definition(definition.id)
            .await
            .is_some());

        drop(active_proxy_owner);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn sequence_run_rejects_unknown_session_before_running() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-sequence-unknown-session-run-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "Unknown session run".to_string(),
            steps: Vec::new(),
        };
        session.sequence.upsert_definition(definition.clone()).await;

        let response = super::run_sequence(
            State(state),
            Path(definition.id.to_string()),
            Json(super::SequenceRunPayload {
                session_id: Some(Uuid::new_v4()),
                expected_active_session_id: None,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::NOT_FOUND);
        assert!(session.sequence.list_runs(None).await.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn sequence_run_rejects_stale_implicit_active_session_guard() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-sequence-run-active-guard-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let original = state.session().await;
        let original_id = original.id();
        let definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "Stale active sequence run".to_string(),
            steps: Vec::new(),
        };
        original
            .sequence
            .upsert_definition(definition.clone())
            .await;
        let active = state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();

        let response = super::run_sequence(
            State(state.clone()),
            Path(definition.id.to_string()),
            Json(super::SequenceRunPayload {
                session_id: Some(original_id),
                expected_active_session_id: Some(original_id),
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        let body = response_body_json(response).await;
        assert_eq!(
            body.get("error").and_then(serde_json::Value::as_str),
            Some("active session changed")
        );
        let active_id = active.id.to_string();
        assert_eq!(
            body.get("session_id").and_then(serde_json::Value::as_str),
            Some(active_id.as_str())
        );
        assert!(original.sequence.list_runs(None).await.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn sequence_run_rechecks_proxy_work_after_lock_wait() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-sequence-run-proxy-work-race-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let original = state.session().await;
        let original_id = original.id();
        let definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "Race run".to_string(),
            steps: Vec::new(),
        };
        original
            .sequence
            .upsert_definition(definition.clone())
            .await;
        state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();
        let operation_lock = state.session_operation_lock(original_id).await;
        let operation_guard = operation_lock.lock().await;

        let mut run_future = Box::pin(super::run_sequence(
            State(state.clone()),
            Path(definition.id.to_string()),
            Json(super::SequenceRunPayload {
                session_id: Some(original_id),
                expected_active_session_id: None,
            }),
        ));
        let blocked = tokio::time::timeout(Duration::from_millis(30), &mut run_future).await;
        assert!(blocked.is_err());
        let active_proxy_owner = crate::proxy::remember_active_proxy_session_owner(
            original_id,
            crate::proxy::PROXY_WORK_STREAMED_RESPONSE,
        );
        drop(operation_guard);

        let response = run_future.await;
        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        assert!(original.sequence.list_runs(None).await.is_empty());

        drop(active_proxy_owner);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn sequence_run_releases_session_operation_lock_while_upstream_is_pending() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-sequence-run-lock-release-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let session_id = session.id();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer).await.unwrap();
            let _ = accepted_tx.send(());
            let _ = release_rx.await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        });

        let definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "Lock release".to_string(),
            steps: vec![SequenceStep {
                id: uuid::Uuid::new_v4(),
                label: "Slow upstream".to_string(),
                request: EditableRequest {
                    scheme: "http".to_string(),
                    host: addr.to_string(),
                    method: "GET".to_string(),
                    path: "/".to_string(),
                    headers: Vec::new(),
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                source_transaction_id: None,
                http_version: None,
                target: None,
                request_text: None,
                request_parse_error: None,
                extractions: Vec::new(),
            }],
        };
        session.sequence.upsert_definition(definition.clone()).await;

        let response_task = tokio::spawn(super::run_sequence(
            State(state.clone()),
            Path(definition.id.to_string()),
            Json(super::SequenceRunPayload {
                session_id: Some(session_id),
                expected_active_session_id: None,
            }),
        ));

        tokio::time::timeout(Duration::from_secs(2), accepted_rx)
            .await
            .expect("sequence should reach the upstream server")
            .expect("upstream accept marker should be sent");
        assert!(crate::proxy::session_has_active_proxy_work(session_id));

        let operation_lock = state.session_operation_lock(session_id).await;
        let operation_guard =
            tokio::time::timeout(Duration::from_millis(200), operation_lock.lock())
                .await
                .expect(
                    "sequence must not hold the session operation lock while waiting on upstream",
                );
        drop(operation_guard);

        let _ = release_tx.send(());
        let response = response_task.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn sequence_reads_and_writes_use_pinned_inactive_session() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-sequence-pinned-inactive-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let inactive = state.session().await;
        let inactive_id = inactive.id();
        let inactive_definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "Inactive sequence".to_string(),
            steps: Vec::new(),
        };
        inactive
            .sequence
            .upsert_definition(inactive_definition.clone())
            .await;
        state.persist_session_context(&inactive).await.unwrap();
        state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();

        let active_response = super::get_sequence(
            State(state.clone()),
            Path(inactive_definition.id.to_string()),
            Query(super::SequenceSessionQuery {
                session_id: None,
                expected_active_session_id: None,
            }),
        )
        .await;
        assert_eq!(active_response.status(), super::StatusCode::NOT_FOUND);

        let active_proxy_owner = crate::proxy::remember_active_proxy_session_owner(
            inactive_id,
            crate::proxy::PROXY_WORK_STREAMED_RESPONSE,
        );

        let pinned_response = super::get_sequence(
            State(state.clone()),
            Path(inactive_definition.id.to_string()),
            Query(super::SequenceSessionQuery {
                session_id: Some(inactive_id),
                expected_active_session_id: None,
            }),
        )
        .await;
        assert_eq!(pinned_response.status(), super::StatusCode::OK);

        let pinned_definitions: Vec<SequenceDefinition> = response_json(
            super::list_sequences(
                State(state.clone()),
                Query(super::SequenceSessionQuery {
                    session_id: Some(inactive_id),
                    expected_active_session_id: None,
                }),
            )
            .await,
        )
        .await;
        assert_eq!(pinned_definitions.len(), 1);
        assert_eq!(pinned_definitions[0].id, inactive_definition.id);

        let pinned_runs: Vec<crate::sequence::SequenceRunRecord> = response_json(
            super::list_sequence_runs(
                State(state.clone()),
                Query(super::SequenceQuery {
                    session_id: Some(inactive_id),
                    limit: None,
                }),
            )
            .await,
        )
        .await;
        assert!(pinned_runs.is_empty());

        drop(active_proxy_owner);

        let active_definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "Must not save to active".to_string(),
            steps: Vec::new(),
        };
        let response = super::upsert_sequence(
            State(state.clone()),
            Json(super::SequenceUpsertPayload {
                session_id: Some(inactive_id),
                expected_active_session_id: None,
                definition: active_definition.clone(),
            }),
        )
        .await;
        assert_eq!(response.status(), super::StatusCode::NO_CONTENT);

        let active = state.session().await;
        assert!(active.sequence.list_definitions().await.is_empty());
        let reloaded = state.sessions.load_context(inactive_id).unwrap();
        assert!(reloaded
            .sequence
            .get_definition(active_definition.id)
            .await
            .is_some());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn sequence_upsert_rolls_back_when_persist_fails() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-sequence-upsert-rollback-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "Rollback sequence".to_string(),
            steps: Vec::new(),
        };

        let storage_dir = session.storage_dir().to_path_buf();
        std::fs::remove_dir_all(&storage_dir).unwrap();
        std::fs::write(&storage_dir, b"not a directory").unwrap();

        let response = super::upsert_sequence(
            State(state),
            Json(super::SequenceUpsertPayload {
                session_id: Some(session.id()),
                expected_active_session_id: None,
                definition,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::INTERNAL_SERVER_ERROR);
        assert!(session.sequence.list_definitions().await.is_empty());

        let _ = std::fs::remove_file(storage_dir);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn sequence_run_returns_500_when_session_snapshot_persist_fails() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-sequence-run-rollback-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "Rollback sequence run".to_string(),
            steps: vec![SequenceStep {
                id: uuid::Uuid::new_v4(),
                label: "closed local port".to_string(),
                request: EditableRequest {
                    scheme: "http".to_string(),
                    host: "127.0.0.1:9".to_string(),
                    method: "GET".to_string(),
                    path: "/".to_string(),
                    headers: vec![HeaderRecord {
                        name: "Host".to_string(),
                        value: "127.0.0.1:9".to_string(),
                    }],
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                source_transaction_id: None,
                http_version: None,
                target: Some(RequestTargetOverride {
                    scheme: "http".to_string(),
                    host: "127.0.0.1".to_string(),
                    port: "9".to_string(),
                }),
                request_text: None,
                request_parse_error: None,
                extractions: Vec::new(),
            }],
        };
        session.sequence.upsert_definition(definition.clone()).await;

        let storage_dir = session.storage_dir().to_path_buf();
        std::fs::remove_dir_all(&storage_dir).unwrap();
        std::fs::write(&storage_dir, b"not a directory").unwrap();

        let response = super::run_sequence(
            State(state),
            Path(definition.id.to_string()),
            Json(super::SequenceRunPayload {
                session_id: Some(session.id()),
                expected_active_session_id: None,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::INTERNAL_SERVER_ERROR);
        assert!(session.sequence.list_runs(None).await.is_empty());

        let _ = std::fs::remove_file(storage_dir);
        let _ = std::fs::remove_dir_all(data_dir);
    }
}
