use std::{
    collections::HashMap,
    convert::Infallible,
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, LazyLock, Mutex,
    },
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use axum::body::Body;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bytes::{Bytes, BytesMut};
use chrono::Utc;
use futures_util::{
    future::{AbortHandle, Abortable},
    SinkExt, StreamExt,
};
use http::{
    header::{
        HeaderMap, HeaderName, HeaderValue, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HOST,
        SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_EXTENSIONS, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_PROTOCOL,
        SEC_WEBSOCKET_VERSION, TRANSFER_ENCODING, UPGRADE,
    },
    request::Parts,
    uri::Authority,
    Method, Request, Response, StatusCode, Uri, Version,
};
use http_body_util::BodyExt;
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as AutoBuilder,
};
use reqwest::{redirect::Policy, Client};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::{
    connect_async_tls_with_config,
    tungstenite::{
        client::IntoClientRequest,
        handshake::derive_accept_key,
        protocol::{Message as WebSocketMessage, Role},
        Error as TungsteniteError,
    },
    MaybeTlsStream, WebSocketStream,
};
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    event_log::EventLevel,
    intercept::{
        InterceptRecord, InterceptResolution, ResponseInterceptRecord, ResponseInterceptResolution,
    },
    model::{
        BodyEncoding, EditableRequest, EditableResponse, HeaderRecord, MessageRecord,
        RequestTargetOverride, TransactionRecord, WebSocketFrameDirection, WebSocketFrameKind,
        WebSocketFrameRecord, WebSocketSessionRecord,
    },
    runtime_state::{self, RuntimeStateSnapshot},
    session::SessionContext,
    special_host,
    state::AppState,
};

const REPLAY_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const REPLAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const WEBSOCKET_CAPTURE_PREVIEW_BYTES: usize = 64 * 1024;

type ProxyClient = Client;
type UpstreamWebSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
const MAX_PROXY_REQUEST_BODY_BYTES: usize = 64 * 1024 * 1024;
const MAX_PROXY_BUFFERED_RESPONSE_BODY_BYTES: usize = 64 * 1024 * 1024;

struct UpstreamResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

struct ExecutedExchange {
    record: TransactionRecord,
    response: std::result::Result<UpstreamResponse, UpstreamError>,
}

struct StreamedRecordContext {
    state: Arc<AppState>,
    session: Arc<SessionContext>,
    _session_owner: ActiveProxySessionGuard,
    persist_generation: u64,
    record_id: Option<Uuid>,
    started_at: chrono::DateTime<Utc>,
    started: Instant,
    method: String,
    scheme: String,
    host: String,
    path: String,
    status: StatusCode,
    request_capture: MessageRecord,
    response_headers: HeaderMap,
    notes: Vec<String>,
    original_request_capture: Option<MessageRecord>,
    request_version: Option<Version>,
    response_version: Version,
    max_preview: usize,
}

struct UpstreamError {
    status: StatusCode,
    message: String,
}

fn with_record_http_versions(
    mut record: TransactionRecord,
    request_version: Option<Version>,
    response_version: Option<Version>,
) -> TransactionRecord {
    if let Some(version) = request_version {
        record = record.with_request_http_version(version);
    }
    if let Some(version) = response_version {
        record = record.with_response_http_version(version);
    }
    record
}

pub async fn run_proxy_listener(state: Arc<AppState>) -> Result<TcpListener> {
    let listener = bind_proxy_listener(state.config.proxy_addr)
        .await
        .with_context(|| {
            format!(
                "failed to bind proxy listener to {}",
                state.config.proxy_addr
            )
        })?;

    info!(proxy_addr = %listener.local_addr()?, "proxy listener ready");
    Ok(listener)
}

pub async fn run_proxy(state: Arc<AppState>) -> Result<()> {
    let listener = run_proxy_listener(state.clone()).await?;
    serve_proxy(listener, state).await
}

/// Bind a TCP listener with `SO_REUSEADDR` so that recently-closed sockets
/// on the same port don't block us.
pub async fn bind_proxy_listener(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = if addr.is_ipv6() {
        tokio::net::TcpSocket::new_v6()?
    } else {
        tokio::net::TcpSocket::new_v4()?
    };
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    socket.listen(1024)
}

/// Try to rebind the proxy listener to a new address at runtime.
/// On success: aborts old proxy task, spawns new one, updates active_proxy_addr.
/// On failure: attempts to restore the old listener; returns the error message.
pub async fn rebind_proxy(
    state: Arc<AppState>,
    new_addr: std::net::SocketAddr,
) -> std::result::Result<(), String> {
    let _rebind_guard = state.proxy_rebind_lock.lock().await;
    rebind_proxy_locked(Arc::clone(&state), new_addr).await
}

/// Rebind the proxy listener while the caller already holds `proxy_rebind_lock`.
pub async fn rebind_proxy_locked(
    state: Arc<AppState>,
    new_addr: std::net::SocketAddr,
) -> std::result::Result<(), String> {
    let current = state.get_active_proxy_addr().await;
    if current == new_addr {
        if !state.is_proxy_online() {
            return restart_proxy_listener_on_current_addr(Arc::clone(&state), new_addr).await;
        }
        return Ok(());
    }

    close_live_websocket_relays(
        state.as_ref(),
        "Proxy listener rebind closed the live WebSocket relay.",
    )
    .await
    .map_err(|error| error.to_string())?;

    // Always stop the old listener first.  When the host changes on the same
    // port (e.g. 127.0.0.1:8080 → 0.0.0.0:8080) the old socket would block
    // the new bind because 0.0.0.0 encompasses 127.0.0.1.
    // `abort_proxy_task` awaits the task so the TcpListener is fully dropped.
    state.abort_proxy_task().await;
    state.set_proxy_online(false);
    persist_proxy_runtime_state(&state, current, false, "after stopping proxy for rebind").await;

    // Bind the new address with SO_REUSEADDR.
    // Retry a few times because macOS may not release the port instantly
    // after the old TcpListener is dropped.
    let bind_result = {
        let mut last_err = None;
        let mut listener = None;
        for attempt in 0..10 {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            match bind_proxy_listener(new_addr).await {
                Ok(l) => {
                    listener = Some(l);
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }
        listener.ok_or_else(|| last_err.unwrap())
    };
    let listener = match bind_result {
        Ok(l) => l,
        Err(bind_err) => {
            // New bind failed — try to restore the old listener
            warn!(
                old = %current,
                new = %new_addr,
                %bind_err,
                "rebind failed, attempting to restore old listener"
            );
            match bind_proxy_listener(current).await {
                Ok(restored) => {
                    let restored_addr = restored.local_addr().unwrap_or(current);
                    state.set_active_proxy_addr(restored_addr).await;
                    let proxy_generation = state.mark_proxy_listener_online();
                    persist_proxy_runtime_state(
                        &state,
                        restored_addr,
                        true,
                        "after restoring proxy listener",
                    )
                    .await;
                    let proxy_state = state.clone();
                    let offline_state = state.clone();
                    let handle = tokio::spawn(async move {
                        if let Err(error) = serve_proxy(restored, proxy_state).await {
                            tracing::error!(?error, "restored proxy task stopped");
                            mark_proxy_offline_after_task_exit(
                                &offline_state,
                                restored_addr,
                                proxy_generation,
                                "after restored proxy task stopped",
                            )
                            .await;
                        }
                    });
                    state.set_proxy_task(handle).await;
                }
                Err(restore_err) => {
                    tracing::error!(
                        %restore_err,
                        "failed to restore old proxy listener — proxy is offline"
                    );
                    persist_proxy_runtime_state(
                        &state,
                        current,
                        false,
                        "after failed proxy restore",
                    )
                    .await;
                }
            }
            return Err(format!("Could not bind to {} ({})", new_addr, bind_err));
        }
    };

    drain_proxy_connections(Duration::from_millis(200)).await;

    let bound_addr = listener
        .local_addr()
        .map_err(|e| format!("failed to read bound address: {e}"))?;

    // Update active address
    state.set_active_proxy_addr(bound_addr).await;
    let proxy_generation = state.mark_proxy_listener_online();
    persist_proxy_runtime_state(&state, bound_addr, true, "after proxy rebind").await;

    info!(old = %current, new = %bound_addr, "proxy listener rebound");

    // Spawn new proxy task
    let proxy_state = state.clone();
    let offline_state = state.clone();
    let handle = tokio::spawn(async move {
        if let Err(error) = serve_proxy(listener, proxy_state).await {
            tracing::error!(?error, "rebound proxy task stopped");
            mark_proxy_offline_after_task_exit(
                &offline_state,
                bound_addr,
                proxy_generation,
                "after rebound proxy task stopped",
            )
            .await;
        }
    });
    state.set_proxy_task(handle).await;

    Ok(())
}

async fn restart_proxy_listener_on_current_addr(
    state: Arc<AppState>,
    addr: SocketAddr,
) -> std::result::Result<(), String> {
    let listener = bind_proxy_listener(addr)
        .await
        .map_err(|error| format!("Could not bind to {addr} ({error})"))?;
    let bound_addr = listener
        .local_addr()
        .map_err(|error| format!("failed to read bound address: {error}"))?;
    state.set_active_proxy_addr(bound_addr).await;
    let proxy_generation = state.mark_proxy_listener_online();
    persist_proxy_runtime_state(
        &state,
        bound_addr,
        true,
        "after restarting offline proxy listener",
    )
    .await;

    info!(addr = %bound_addr, "offline proxy listener restarted");
    let proxy_state = state.clone();
    let offline_state = state.clone();
    let handle = tokio::spawn(async move {
        if let Err(error) = serve_proxy(listener, proxy_state).await {
            tracing::error!(?error, "restarted proxy task stopped");
            mark_proxy_offline_after_task_exit(
                &offline_state,
                bound_addr,
                proxy_generation,
                "after restarted proxy task stopped",
            )
            .await;
        }
    });
    state.set_proxy_task(handle).await;

    Ok(())
}

async fn persist_proxy_runtime_state(
    state: &Arc<AppState>,
    proxy_addr: SocketAddr,
    proxy_online: bool,
    context: &'static str,
) {
    let ui_addr = state.get_active_ui_addr().await;
    if let Err(error) = runtime_state::persist_runtime_state(
        &state.config.data_dir,
        &RuntimeStateSnapshot::with_proxy_status_and_instance(
            proxy_addr,
            ui_addr,
            proxy_online,
            state.runtime_instance_id,
        ),
    ) {
        warn!(?error, context, "failed to persist runtime state");
    }
}

pub async fn mark_proxy_offline_after_task_exit(
    state: &Arc<AppState>,
    expected_addr: SocketAddr,
    expected_generation: u64,
    context: &'static str,
) {
    let proxy_addr = state.get_active_proxy_addr().await;
    if proxy_addr != expected_addr {
        return;
    }
    if !state.mark_proxy_listener_offline_if_current(expected_generation) {
        return;
    }
    persist_proxy_runtime_state(state, proxy_addr, false, context).await;
}

pub async fn serve_proxy(listener: TcpListener, state: Arc<AppState>) -> Result<()> {
    loop {
        let (stream, peer_addr) = listener.accept().await.context("proxy accept failed")?;
        let io = TokioIo::new(stream);
        let state = state.clone();

        let connection_id = Uuid::new_v4();
        let (abort, registration) = AbortHandle::new_pair();
        remember_proxy_connection(connection_id, abort);
        tokio::spawn(async move {
            let service =
                service_fn(move |request| handle_request(request, state.clone(), peer_addr));

            let connection = http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(io, service)
                .with_upgrades();
            if let Ok(Err(error)) = Abortable::new(connection, registration).await {
                warn!(%peer_addr, ?error, "proxy connection failed");
            }
            forget_proxy_connection(connection_id);
        });
    }
}

pub async fn send_replay_request(
    state: Arc<AppState>,
    request: EditableRequest,
    target: Option<RequestTargetOverride>,
    source_transaction_id: Option<Uuid>,
    http_version: Option<String>,
) -> Result<TransactionRecord> {
    let session = state.session().await;
    send_replay_request_for_session(
        state,
        session,
        request,
        target,
        source_transaction_id,
        http_version,
    )
    .await
}

pub async fn send_replay_request_for_session(
    state: Arc<AppState>,
    session: Arc<SessionContext>,
    request: EditableRequest,
    target: Option<RequestTargetOverride>,
    source_transaction_id: Option<Uuid>,
    http_version: Option<String>,
) -> Result<TransactionRecord> {
    try_send_replay_request_for_session(
        state,
        session,
        request,
        target,
        source_transaction_id,
        http_version,
    )
    .await
    .map_err(ReplaySendError::into_error)
}

#[derive(Debug)]
pub struct ReplaySendError {
    message: String,
    record: Option<TransactionRecord>,
}

impl ReplaySendError {
    fn without_record(error: anyhow::Error) -> Self {
        Self {
            message: error.to_string(),
            record: None,
        }
    }

    fn with_record(message: String, record: TransactionRecord) -> Self {
        Self {
            message,
            record: Some(record),
        }
    }

    pub fn record(&self) -> Option<&TransactionRecord> {
        self.record.as_ref()
    }

    pub fn into_error(self) -> anyhow::Error {
        anyhow!(self.message)
    }
}

impl std::fmt::Display for ReplaySendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ReplaySendError {}

pub async fn try_send_replay_request_for_session(
    state: Arc<AppState>,
    session: Arc<SessionContext>,
    request: EditableRequest,
    target: Option<RequestTargetOverride>,
    source_transaction_id: Option<Uuid>,
    http_version: Option<String>,
) -> std::result::Result<TransactionRecord, ReplaySendError> {
    request
        .try_body_bytes()
        .context("request body is not valid base64")
        .map_err(ReplaySendError::without_record)?;
    if is_websocket_upgrade_editable(&request) {
        return Err(ReplaySendError::without_record(anyhow!(
            "Replay currently supports HTTP/HTTPS requests only, not WebSocket upgrades",
        )));
    }

    validate_reusable_request_source(session.as_ref(), &request, source_transaction_id)
        .await
        .map_err(ReplaySendError::without_record)?;

    let started_at = Utc::now();
    let started = Instant::now();
    let (request, mut notes, original_request_capture) =
        apply_request_match_replace(session.as_ref(), request, state.config.body_preview_bytes)
            .await;
    let request = build_replay_exchange_request(&request, target.as_ref())
        .map_err(ReplaySendError::without_record)?;
    let upstream_insecure = session.runtime.upstream_insecure().await;
    let requested_http_version = parse_replay_http_version(http_version.as_deref())
        .map_err(ReplaySendError::without_record)?;
    let client = build_replay_client(
        upstream_insecure,
        &request,
        target.as_ref(),
        requested_http_version,
    )
    .await
    .map_err(ReplaySendError::without_record)?;
    let outbound_uri_authority = build_replay_outbound_uri_authority(&request, target.as_ref())
        .map_err(ReplaySendError::without_record)?;
    notes.push("Sent from Replay.".to_string());
    let exchange = execute_http_exchange(
        state.clone(),
        session.clone(),
        &client,
        request,
        started_at,
        started,
        notes,
        true,
        original_request_capture,
        requested_http_version.or(Some(Version::HTTP_11)),
        requested_http_version,
        outbound_uri_authority.as_deref(),
    )
    .await;

    let mut record = exchange.record.clone();
    if requested_http_version == Some(Version::HTTP_2)
        && record.response_http_version() != Some("HTTP/2")
    {
        let message = format!(
            "requested HTTP/2 but upstream negotiated {}",
            record.response_http_version().unwrap_or("unknown")
        );
        record.notes.push(message.clone());
        store_record_and_scan(&state, &session, record.clone()).await;
        return Err(ReplaySendError::with_record(message, record));
    }

    if let Err(error) = &exchange.response {
        let message = if requested_http_version == Some(Version::HTTP_2)
            && !error.message.contains("HTTP/2")
        {
            format!("HTTP/2 replay failed: {}", error.message)
        } else {
            error.message.clone()
        };
        if message != error.message {
            record.notes.push(message.clone());
        }
        store_record_and_scan(&state, &session, record.clone()).await;
        return Err(ReplaySendError::with_record(message, record));
    }

    session
        .event_log
        .push(
            EventLevel::Info,
            "replay",
            "Request sent",
            format!("{} {}{}", record.method, record.host, record.path),
        )
        .await;
    store_record_and_scan(&state, &session, record.clone()).await;
    Ok(record)
}

fn build_client(upstream_insecure: bool) -> ProxyClient {
    Client::builder()
        .redirect(Policy::none())
        .danger_accept_invalid_certs(upstream_insecure)
        .http1_only()
        .build()
        .expect("failed to build upstream HTTP client")
}

fn parse_replay_http_version(value: Option<&str>) -> Result<Option<Version>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    match value {
        "HTTP/1.0" | "1.0" => Ok(Some(Version::HTTP_10)),
        "HTTP/1.1" | "1.1" => Ok(Some(Version::HTTP_11)),
        "HTTP/2" | "HTTP/2.0" | "2" | "2.0" => Ok(Some(Version::HTTP_2)),
        other => Err(anyhow!("unsupported replay http_version: {other}")),
    }
}

async fn build_replay_client(
    upstream_insecure: bool,
    request: &EditableRequest,
    target: Option<&RequestTargetOverride>,
    http_version: Option<Version>,
) -> Result<ProxyClient> {
    let mut builder = Client::builder()
        .redirect(Policy::none())
        .danger_accept_invalid_certs(upstream_insecure)
        .timeout(REPLAY_REQUEST_TIMEOUT)
        .connect_timeout(REPLAY_CONNECT_TIMEOUT);

    // Force HTTP version if specified
    match http_version {
        Some(Version::HTTP_10 | Version::HTTP_11) => {
            builder = builder.http1_only();
        }
        Some(Version::HTTP_2) => {
            builder = builder.http2_prior_knowledge();
        }
        Some(_) | None => {
            // Auto-negotiate (default)
        }
    }

    if let Some(target) = target {
        let request_scheme = request.scheme.trim();
        let target_scheme = target.scheme.trim();
        let effective_scheme = if target_scheme.is_empty() {
            request_scheme
        } else {
            target_scheme
        };
        let request_authority = parse_request_authority(&request.host, request_scheme)?;
        let target_host = target.host.trim();
        let target_authority = if target_host.is_empty() {
            None
        } else {
            Some(parse_replay_target_authority(
                target_host,
                effective_scheme,
            )?)
        };
        let changes_target = target_authority.is_some()
            || !target.port.trim().is_empty()
            || !target_scheme.is_empty();
        if changes_target {
            let target_port = replay_target_port(
                target.port.trim(),
                effective_scheme,
                target_authority
                    .as_ref()
                    .and_then(|authority| authority.port)
                    .or(request_authority.port),
            )?;
            let request_port = request_authority
                .port
                .unwrap_or(default_port_for_scheme(request_scheme)?);
            let dial_host = target_authority
                .as_ref()
                .map(|authority| authority.host.as_str())
                .unwrap_or(request_authority.host.as_str());
            if effective_scheme.eq_ignore_ascii_case(request_scheme)
                && dial_host.eq_ignore_ascii_case(&request_authority.host)
                && target_port == request_port
            {
                return builder
                    .build()
                    .context("failed to build replay HTTP client");
            }
            if request_authority.host.parse::<IpAddr>().is_ok() {
                bail!(
                    "Replay target override is not supported when the request host is an IP address"
                );
            }
            if target_authority.is_some() || !target.port.trim().is_empty() {
                let resolved_addrs = resolve_target_host(dial_host, target_port).await?;
                builder = builder.resolve_to_addrs(&request_authority.host, &resolved_addrs);
            }
        }
    }

    builder
        .build()
        .context("failed to build replay HTTP client")
}

fn build_replay_exchange_request(
    request: &EditableRequest,
    target: Option<&RequestTargetOverride>,
) -> Result<EditableRequest> {
    crate::api::validate_runnable_editable_request(request).map_err(anyhow::Error::msg)?;
    validate_replay_header_records(&request.headers)?;
    let Some(target) = target else {
        return Ok(request.clone());
    };

    let target_host = target.host.trim();
    let target_port = target.port.trim();
    let target_scheme = target.scheme.trim();
    if target_host.is_empty() && target_port.is_empty() && target_scheme.is_empty() {
        return Ok(request.clone());
    }

    let mut rewritten = request.clone();
    if !target_scheme.is_empty() {
        rewritten.scheme = target_scheme.to_ascii_lowercase();
    }

    let request_authority = parse_request_authority(&request.host, &rewritten.scheme)?;
    let target_authority = if target_host.is_empty() {
        None
    } else {
        Some(parse_replay_target_authority(
            target_host,
            &rewritten.scheme,
        )?)
    };
    replay_target_port(
        target_port,
        &rewritten.scheme,
        target_authority
            .as_ref()
            .and_then(|authority| authority.port)
            .or(request_authority.port),
    )?;
    crate::api::validate_runnable_editable_request(&rewritten).map_err(anyhow::Error::msg)?;
    Ok(rewritten)
}

fn validate_replay_header_records(headers: &[HeaderRecord]) -> Result<()> {
    for header in headers {
        HeaderName::from_bytes(header.name.as_bytes())
            .map_err(|_| anyhow!("invalid request header name: {}", header.name))?;
        HeaderValue::from_str(&header.value)
            .map_err(|_| anyhow!("invalid request header value for {}", header.name))?;
    }
    Ok(())
}

fn build_replay_outbound_uri_authority(
    request: &EditableRequest,
    target: Option<&RequestTargetOverride>,
) -> Result<Option<String>> {
    let Some(target) = target else {
        return Ok(None);
    };
    if target.host.trim().is_empty() && target.port.trim().is_empty() {
        return Ok(None);
    }
    let request_authority = parse_request_authority(&request.host, &request.scheme)?;
    let target_authority = if target.host.trim().is_empty() {
        None
    } else {
        Some(parse_replay_target_authority(
            target.host.trim(),
            &request.scheme,
        )?)
    };
    let target_port = replay_target_port(
        target.port.trim(),
        &request.scheme,
        target_authority
            .as_ref()
            .and_then(|authority| authority.port)
            .or(request_authority.port),
    )?;
    let request_port = request_authority
        .port
        .unwrap_or(default_port_for_scheme(&request.scheme)?);
    let dial_host = target_authority
        .as_ref()
        .map(|authority| authority.host.as_str())
        .unwrap_or(request_authority.host.as_str());
    if dial_host.eq_ignore_ascii_case(&request_authority.host) && target_port == request_port {
        return Ok(None);
    }
    Ok(Some(build_authority_without_port(&request_authority.host)))
}

fn parse_request_authority(authority: &str, scheme: &str) -> Result<ParsedAuthority> {
    let parsed = url::Url::parse(&format!("{scheme}://{authority}"))
        .with_context(|| format!("failed to parse request authority {authority}"))?;
    let host = parsed
        .host_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow!("request is missing a valid authority"))?;
    Ok(ParsedAuthority {
        host,
        port: parsed.port(),
    })
}

fn parse_replay_target_authority(authority: &str, scheme: &str) -> Result<ParsedAuthority> {
    let authority = authority.trim();
    let normalized = if authority.contains(':')
        && !authority.starts_with('[')
        && authority.parse::<IpAddr>().is_ok()
    {
        format!("[{authority}]")
    } else {
        authority.to_string()
    };
    parse_request_authority(&normalized, scheme)
}

fn replay_target_port(target_port: &str, scheme: &str, request_port: Option<u16>) -> Result<u16> {
    if target_port.is_empty() {
        return Ok(request_port.unwrap_or(default_port_for_scheme(scheme)?));
    }

    let port = target_port
        .parse::<u16>()
        .with_context(|| format!("invalid replay target port: {target_port}"))?;
    if port == 0 {
        anyhow::bail!("invalid replay target port: {target_port}");
    }
    Ok(port)
}

fn default_port_for_scheme(scheme: &str) -> Result<u16> {
    match scheme.to_ascii_lowercase().as_str() {
        "https" => Ok(443),
        "http" => Ok(80),
        other => Err(anyhow!("unsupported request scheme for replay: {other}")),
    }
}

fn build_authority_without_port(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') && !host.ends_with(']') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

async fn resolve_target_host(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    let addrs: Vec<SocketAddr> = tokio::time::timeout(
        REPLAY_CONNECT_TIMEOUT,
        tokio::net::lookup_host((host, port)),
    )
    .await
    .with_context(|| format!("timed out resolving replay target host {host}:{port}"))?
    .with_context(|| format!("failed to resolve replay target host {host}:{port}"))?
    .collect();

    if addrs.is_empty() {
        Err(anyhow!(
            "replay target host {host}:{port} resolved to no addresses"
        ))
    } else {
        Ok(addrs)
    }
}

struct ParsedAuthority {
    host: String,
    port: Option<u16>,
}

async fn handle_request(
    request: Request<Incoming>,
    state: Arc<AppState>,
    peer_addr: SocketAddr,
) -> Result<Response<Body>, Infallible> {
    let (session, _session_owner) = state.session_with_proxy_owner().await;
    let response = if request.method() == Method::CONNECT {
        handle_connect(request, state, session, peer_addr).await
    } else {
        handle_http(request, state, session, peer_addr).await
    };

    Ok(response)
}

async fn handle_connect(
    request: Request<Incoming>,
    state: Arc<AppState>,
    session: Arc<SessionContext>,
    peer_addr: SocketAddr,
) -> Response<Body> {
    let started_at = Utc::now();
    let started = Instant::now();
    let request_http_version = request.version();
    let target = match connect_target(request.uri()) {
        Ok(target) => target,
        Err(error) => {
            warn!(%peer_addr, ?error, "invalid CONNECT target");
            return record_connect_rejection(
                &state,
                &session,
                request.uri(),
                request.headers(),
                started_at,
                started,
                StatusCode::BAD_REQUEST,
                error.to_string(),
                request_http_version,
            )
            .await;
        }
    };
    if let Err(error) = validate_connect_host_header(request.headers(), &target) {
        warn!(%peer_addr, ?error, target = %target, "invalid CONNECT Host header");
        return record_connect_rejection(
            &state,
            &session,
            request.uri(),
            request.headers(),
            started_at,
            started,
            StatusCode::BAD_REQUEST,
            error.to_string(),
            request_http_version,
        )
        .await;
    }
    let request_capture = MessageRecord::from_headers_and_body(
        request.headers(),
        &[],
        state.config.body_preview_bytes,
    );
    let upgrade = hyper::upgrade::on(request);

    if special_host::is_special_host(&target) {
        let state = state.clone();
        let session = session.clone();
        spawn_tracked_proxy_task(session.id(), async move {
            if let Err(error) = serve_special_host_tls(
                upgrade,
                state,
                session,
                target.clone(),
                request_capture,
                started_at,
                started,
                request_http_version,
            )
            .await
            {
                warn!(?error, "special host TLS handler failed");
            }
        });
    } else if session.runtime.is_passthrough(&target).await {
        let upstream_stream = match tokio::net::TcpStream::connect(&target).await {
            Ok(stream) => stream,
            Err(error) => {
                warn!(
                    %peer_addr,
                    ?error,
                    target = %target,
                    "passthrough tunnel upstream connect failed before CONNECT response"
                );
                let record = with_record_http_versions(
                    TransactionRecord::tunnel(
                        started_at,
                        target.clone(),
                        Some(StatusCode::BAD_GATEWAY.as_u16()),
                        started.elapsed().as_millis() as u64,
                        request_capture,
                        vec![format!(
                            "Passthrough tunnel failed to connect to upstream: {error}"
                        )],
                    ),
                    Some(request_http_version),
                    Some(Version::HTTP_11),
                );
                let insert_outcome = insert_transaction_quiet(
                    &session,
                    record,
                    "passthrough tunnel connect failure",
                )
                .await;
                persist_transaction_insert_outcome(&state, &session, insert_outcome).await;
                return text_response(
                    StatusCode::BAD_GATEWAY,
                    "passthrough tunnel upstream connect failed",
                );
            }
        };
        let state = state.clone();
        let session = session.clone();
        let target = target.clone();
        spawn_tracked_proxy_task(session.id(), async move {
            if let Err(error) = serve_passthrough_tunnel(
                upgrade,
                upstream_stream,
                state.clone(),
                session.clone(),
                target.clone(),
                request_capture,
                started_at,
                started,
                request_http_version,
            )
            .await
            {
                warn!(%peer_addr, ?error, target = %target, "passthrough tunnel failed");
            }
        });
    } else {
        let failure_state = state.clone();
        let failure_session = session.clone();
        let failure_target = target.clone();
        let failure_capture = request_capture.clone();
        let failure_started_at = started_at;
        let failure_started = started;
        let failure_request_http_version = request_http_version;

        spawn_tracked_proxy_task(session.id(), async move {
            if let Err(error) = serve_https_mitm(
                upgrade,
                state.clone(),
                session.clone(),
                target,
                request_capture,
                started_at,
                started,
                peer_addr,
                request_http_version,
            )
            .await
            {
                warn!(%peer_addr, ?error, target = %failure_target, "HTTPS MITM handler failed");
                record_connect_post_ok_tunnel_failure(
                    &failure_state,
                    &failure_session,
                    failure_target,
                    failure_capture,
                    failure_started_at,
                    failure_started,
                    format!("HTTPS MITM failed: {error}"),
                    failure_request_http_version,
                )
                .await;
            }
        });
    }

    Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap_or_else(|_| {
            text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to build CONNECT response",
            )
        })
}

async fn handle_http(
    request: Request<Incoming>,
    state: Arc<AppState>,
    session: Arc<SessionContext>,
    peer_addr: SocketAddr,
) -> Response<Body> {
    handle_forwardable_request(request, state, session, peer_addr, "http", None, false).await
}

async fn handle_forwardable_request(
    mut request: Request<Incoming>,
    state: Arc<AppState>,
    session: Arc<SessionContext>,
    peer_addr: SocketAddr,
    default_scheme: &str,
    authority_override: Option<String>,
    secure_special_host: bool,
) -> Response<Body> {
    let started_at = Utc::now();
    let started = Instant::now();
    let is_websocket = is_websocket_upgrade_headers(request.headers());
    if is_websocket {
        if let Some(message) =
            websocket_upgrade_validation_error(request.method(), request.headers())
        {
            return record_http_rejection(
                &state,
                &session,
                RejectedRequestIdentity::from_request(
                    request.method(),
                    request.uri(),
                    request.headers(),
                    default_scheme,
                    authority_override.as_deref(),
                ),
                request.headers(),
                &[],
                Some(request.version()),
                started_at,
                started,
                StatusCode::BAD_REQUEST,
                message.to_string(),
                "invalid websocket upgrade",
            )
            .await;
        }
    }
    let on_upgrade = is_websocket.then(|| hyper::upgrade::on(&mut request));
    let (parts, body) = request.into_parts();
    if let Err(error) = validate_forwardable_host_headers(&parts.uri, &parts.headers) {
        return record_http_rejection(
            &state,
            &session,
            RejectedRequestIdentity::from_request(
                &parts.method,
                &parts.uri,
                &parts.headers,
                default_scheme,
                authority_override.as_deref(),
            ),
            &parts.headers,
            &[],
            Some(parts.version),
            started_at,
            started,
            StatusCode::BAD_REQUEST,
            error.to_string(),
            "invalid Host header",
        )
        .await;
    }
    let absolute_uri = match resolve_absolute_uri(
        &parts.uri,
        &parts.headers,
        default_scheme,
        authority_override.as_deref(),
    ) {
        Ok(uri) => uri,
        Err(error) => {
            return record_http_rejection(
                &state,
                &session,
                RejectedRequestIdentity::from_request(
                    &parts.method,
                    &parts.uri,
                    &parts.headers,
                    default_scheme,
                    authority_override.as_deref(),
                ),
                &parts.headers,
                &[],
                Some(parts.version),
                started_at,
                started,
                StatusCode::BAD_REQUEST,
                error.to_string(),
                "invalid proxy request uri",
            )
            .await
        }
    };
    let proxy_addr = state.get_active_proxy_addr().await;
    if request_targets_own_listener(&absolute_uri, proxy_addr) {
        return record_http_rejection(
            &state,
            &session,
            RejectedRequestIdentity::from_absolute_uri(&parts.method, &absolute_uri),
            &parts.headers,
            &[],
            Some(parts.version),
            started_at,
            started,
            StatusCode::LOOP_DETECTED,
            format!(
                "Request targets Sniper's own proxy listener ({proxy_addr}); refusing to forward to avoid a proxy loop. Point the client at a real destination, or open http://sniper for the certificate portal."
            ),
            "proxy loop guard",
        )
        .await;
    }

    if let Err(message) = validate_supported_transfer_encoding(&parts.headers) {
        return record_http_rejection(
            &state,
            &session,
            RejectedRequestIdentity::from_absolute_uri(&parts.method, &absolute_uri),
            &parts.headers,
            &[],
            Some(parts.version),
            started_at,
            started,
            StatusCode::BAD_REQUEST,
            message,
            "unsupported request transfer encoding",
        )
        .await;
    }
    let request_bytes = match collect_body(body).await {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!(%peer_addr, ?error, "failed to read request body");
            let status = error.status();
            return record_http_rejection(
                &state,
                &session,
                RejectedRequestIdentity::from_absolute_uri(&parts.method, &absolute_uri),
                &parts.headers,
                &[],
                Some(parts.version),
                started_at,
                started,
                status,
                error.to_string(),
                "proxy request body rejected",
            )
            .await;
        }
    };

    if let Some(on_upgrade) = on_upgrade {
        return forward_websocket_request(
            parts,
            request_bytes,
            absolute_uri,
            on_upgrade,
            state,
            session,
            peer_addr,
            started_at,
            started,
            secure_special_host,
        )
        .await;
    }

    forward_http_request(
        parts,
        request_bytes,
        absolute_uri,
        state,
        session,
        peer_addr,
        started_at,
        started,
        secure_special_host,
    )
    .await
}

#[derive(Debug)]
enum BodyCollectionError {
    TooLarge { limit: usize },
    Read(String),
}

impl BodyCollectionError {
    fn status(&self) -> StatusCode {
        match self {
            Self::TooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Read(_) => StatusCode::BAD_REQUEST,
        }
    }
}

impl std::fmt::Display for BodyCollectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { limit } => {
                write!(f, "request body exceeds {} bytes", limit)
            }
            Self::Read(error) => write!(f, "body collection failed: {error}"),
        }
    }
}

async fn collect_body(mut body: Incoming) -> std::result::Result<Bytes, BodyCollectionError> {
    let mut bytes = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| BodyCollectionError::Read(error.to_string()))?;
        if let Ok(data) = frame.into_data() {
            let new_len =
                bytes
                    .len()
                    .checked_add(data.len())
                    .ok_or(BodyCollectionError::TooLarge {
                        limit: MAX_PROXY_REQUEST_BODY_BYTES,
                    })?;
            if new_len > MAX_PROXY_REQUEST_BODY_BYTES {
                return Err(BodyCollectionError::TooLarge {
                    limit: MAX_PROXY_REQUEST_BODY_BYTES,
                });
            }
            bytes.extend_from_slice(&data);
        }
    }
    Ok(bytes.freeze())
}

/// Local IP addresses across every interface on this host. Used to recognize a
/// request that points back at the proxy's own listener when it is bound to a
/// wildcard address (0.0.0.0 / ::), where the listener answers on any local IP.
#[cfg(unix)]
fn local_interface_ips() -> Vec<IpAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    let mut addrs = Vec::new();
    // SAFETY: getifaddrs allocates a linked list we walk read-only and free via
    // freeifaddrs; every pointer is null-checked before dereference.
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return addrs;
        }
        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_addr.is_null() {
                match (*ifa.ifa_addr).sa_family as i32 {
                    libc::AF_INET => {
                        let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                        // s_addr is in network byte order; to_ne_bytes yields the
                        // in-memory octets [a, b, c, d] regardless of host endianness.
                        addrs.push(IpAddr::V4(Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes())));
                    }
                    libc::AF_INET6 => {
                        let sin6 = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                        addrs.push(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)));
                    }
                    _ => {}
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    addrs
}

#[cfg(not(unix))]
fn local_interface_ips() -> Vec<IpAddr> {
    // ponytail: non-unix falls back to loopback/bound-ip detection only; add
    // platform enumeration here if Sniper ever ships on a non-unix target.
    Vec::new()
}

fn host_belongs_to_this_machine(host: &str, bound_ip: IpAddr) -> bool {
    let host = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host);
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let Ok(ip) = host.parse::<IpAddr>() else {
        // A non-IP hostname (other than localhost) is not resolved here; the
        // realistic self-target cases are IP literals or localhost.
        return false;
    };
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }
    if bound_ip.is_unspecified() {
        local_interface_ips().iter().any(|local| *local == ip)
    } else {
        ip == bound_ip
    }
}

/// True when `uri` resolves back to the proxy's own listener, which would make
/// the proxy forward the request to itself and spin in a tight loop until the
/// process exhausts sockets. Port must match the listener; only then is the
/// (potentially costly) host check performed.
fn request_targets_own_listener(uri: &Uri, proxy_addr: SocketAddr) -> bool {
    let Some(authority) = uri.authority() else {
        return false;
    };
    let port = match authority.port_u16() {
        Some(port) => port,
        None => match uri.scheme_str().and_then(|scheme| default_port_for_scheme(scheme).ok()) {
            Some(port) => port,
            None => return false,
        },
    };
    if port != proxy_addr.port() {
        return false;
    }
    host_belongs_to_this_machine(authority.host(), proxy_addr.ip())
}

fn resolve_absolute_uri(
    uri: &Uri,
    headers: &HeaderMap,
    default_scheme: &str,
    authority_override: Option<&str>,
) -> Result<Uri> {
    if uri.scheme().is_some() && uri.authority().is_some() {
        validate_authority_for_client_input(
            uri.authority()
                .context("absolute-form request URI is missing authority")?,
            "absolute-form request authority",
        )?;
        if let Some(authority_override) = authority_override {
            validate_absolute_uri_matches_authority_override(
                uri,
                default_scheme,
                authority_override,
            )?;
        }
        return Ok(uri.clone());
    }

    let authority = if let Some(authority) = authority_override {
        let authority = parse_client_authority(authority, "CONNECT tunnel authority")?;
        validate_origin_form_host_matches_authority_override(headers, default_scheme, &authority)?;
        authority.to_string()
    } else {
        let host_header = headers
            .get(HOST)
            .context("missing Host header for origin-form request")?
            .to_str()
            .context("invalid Host header")?;
        parse_client_authority(host_header, "Host header")?.to_string()
    };
    let path = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    if path == "*" {
        bail!("star-form request targets are not supported by proxy forwarding");
    }

    Uri::builder()
        .scheme(default_scheme)
        .authority(authority)
        .path_and_query(path)
        .build()
        .map_err(|error| anyhow!("failed to build absolute URI: {error}"))
}

fn validate_forwardable_host_headers(uri: &Uri, headers: &HeaderMap) -> Result<()> {
    let mut host_headers = headers.get_all(HOST).iter();
    let host_header = host_headers.next();
    if host_headers.next().is_some() {
        bail!("multiple Host headers are not supported");
    }

    if uri.scheme().is_none() || uri.authority().is_none() {
        return Ok(());
    }
    let Some(host_header) = host_header else {
        return Ok(());
    };

    let host_header = host_header.to_str().context("invalid Host header")?;
    let header_authority = parse_client_authority(host_header, "Host header")?;
    let uri_authority = uri
        .authority()
        .context("absolute-form request URI is missing authority")?;
    validate_authority_for_client_input(uri_authority, "absolute-form request authority")?;
    let scheme = uri.scheme_str().unwrap_or("http");
    let uri_port = uri_authority
        .port_u16()
        .unwrap_or(default_port_for_scheme(scheme)?);
    let header_port = header_authority
        .port_u16()
        .unwrap_or(default_port_for_scheme(scheme)?);
    if !authority_hosts_equivalent(uri_authority.host(), header_authority.host())
        || uri_port != header_port
    {
        bail!("absolute-form request authority does not match Host header: {host_header}");
    }
    Ok(())
}

fn validate_origin_form_host_matches_authority_override(
    headers: &HeaderMap,
    default_scheme: &str,
    override_authority: &Authority,
) -> Result<()> {
    let mut host_headers = headers.get_all(HOST).iter();
    let Some(host_header) = host_headers.next() else {
        return Ok(());
    };
    if host_headers.next().is_some() {
        bail!("multiple Host headers are not supported");
    }

    let host_header = host_header.to_str().context("invalid Host header")?;
    let header_authority = parse_client_authority(host_header, "Host header")?;
    let header_port = header_authority
        .port_u16()
        .unwrap_or(default_port_for_scheme(default_scheme)?);
    let override_port = override_authority
        .port_u16()
        .ok_or_else(|| anyhow!("CONNECT tunnel authority must include a port"))?;
    if !authority_hosts_equivalent(override_authority.host(), header_authority.host())
        || override_port != header_port
    {
        bail!("origin-form Host header does not match CONNECT tunnel authority: {host_header}");
    }

    Ok(())
}

fn validate_absolute_uri_matches_authority_override(
    uri: &Uri,
    default_scheme: &str,
    authority_override: &str,
) -> Result<()> {
    let uri_authority = uri
        .authority()
        .context("absolute-form request URI is missing authority")?;
    validate_authority_for_client_input(uri_authority, "absolute-form request authority")?;
    let override_authority =
        parse_client_authority(authority_override, "CONNECT tunnel authority")?;
    let scheme = uri.scheme_str().unwrap_or(default_scheme);
    if !scheme.eq_ignore_ascii_case(default_scheme) {
        bail!("absolute-form request scheme does not match CONNECT tunnel scheme: {scheme}");
    }
    let uri_port = uri_authority
        .port_u16()
        .unwrap_or(default_port_for_scheme(scheme)?);
    let override_port = override_authority
        .port_u16()
        .ok_or_else(|| anyhow!("CONNECT tunnel authority must include a port"))?;
    if !authority_hosts_equivalent(uri_authority.host(), override_authority.host())
        || uri_port != override_port
    {
        bail!(
            "absolute-form request authority does not match CONNECT tunnel authority: {}",
            uri_authority
        );
    }
    Ok(())
}

fn parse_client_authority(authority: &str, label: &str) -> Result<Authority> {
    let authority: Authority = authority
        .parse()
        .with_context(|| format!("invalid {label}: {authority}"))?;
    validate_authority_for_client_input(&authority, label)?;
    Ok(authority)
}

fn validate_authority_for_client_input(authority: &Authority, label: &str) -> Result<()> {
    if authority.as_str().contains('@') {
        bail!("{label} must not include URI userinfo");
    }
    let host = authority.host();
    if host.is_empty() || host == "[]" {
        bail!("{label} must include a host");
    }
    if authority_has_invalid_explicit_port(authority) {
        bail!("{label} includes an invalid port: {authority}");
    }
    if authority.port().is_some() && authority.port_u16().is_none() {
        bail!("{label} includes an invalid port: {authority}");
    }
    Ok(())
}

fn authority_has_invalid_explicit_port(authority: &Authority) -> bool {
    if authority.port_u16().is_some() {
        return false;
    }
    let raw = authority.as_str();
    if raw.ends_with(']') {
        return false;
    }
    let Some((host_part, port_part)) = raw.rsplit_once(':') else {
        return false;
    };
    if port_part.is_empty() {
        return true;
    }
    if host_part.starts_with('[') || !host_part.contains(':') {
        return true;
    }
    false
}

fn authority_hosts_equivalent(left: &str, right: &str) -> bool {
    let left = left
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(left);
    let right = right
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(right);
    left.eq_ignore_ascii_case(right)
}

fn connect_target(uri: &Uri) -> Result<String> {
    if uri.scheme().is_some() {
        return Err(anyhow!(
            "CONNECT request target must be authority-form host:port"
        ));
    }
    let target = uri
        .authority()
        .map(|authority| authority.as_str())
        .unwrap_or_else(|| uri.path().trim());
    if target.is_empty() {
        return Err(anyhow!("CONNECT request is missing authority"));
    }
    let authority = parse_client_authority(target, "CONNECT target authority")?;
    authority
        .port_u16()
        .ok_or_else(|| anyhow!("CONNECT target authority must include a port: {target}"))?;
    Ok(authority.to_string())
}

fn validate_connect_host_header(headers: &HeaderMap, target: &str) -> Result<()> {
    let mut host_headers = headers.get_all(HOST).iter();
    let Some(host_header) = host_headers.next() else {
        return Ok(());
    };
    if host_headers.next().is_some() {
        bail!("multiple Host headers are not supported for CONNECT");
    }

    let host_header = host_header
        .to_str()
        .context("invalid CONNECT Host header")?;
    let header_authority = parse_client_authority(host_header, "CONNECT Host header")?;
    let target_authority = parse_client_authority(target, "CONNECT target authority")?;
    let target_port = target_authority
        .port_u16()
        .ok_or_else(|| anyhow!("CONNECT target authority must include a port: {target}"))?;
    let header_port = header_authority.port_u16().unwrap_or(target_port);

    if !authority_hosts_equivalent(header_authority.host(), target_authority.host())
        || header_port != target_port
    {
        bail!("CONNECT Host header does not match CONNECT target authority");
    }
    Ok(())
}

fn rebuild_response(
    headers: HeaderMap,
    status: StatusCode,
    body: Bytes,
    request_method: &str,
) -> Response<Body> {
    let mut sanitized = headers;
    let upstream_content_length = sanitized.get(CONTENT_LENGTH).cloned();
    strip_hop_by_hop_headers(&mut sanitized);
    sanitized.remove(CONTENT_LENGTH);
    if response_must_not_include_content_length(status) {
        sanitized.remove(CONTENT_LENGTH);
    } else if request_method.eq_ignore_ascii_case("HEAD") || status == StatusCode::NOT_MODIFIED {
        if let Some(value) = upstream_content_length {
            sanitized.insert(CONTENT_LENGTH, value);
        }
    } else if let Ok(value) = HeaderValue::from_str(&body.len().to_string()) {
        sanitized.insert(CONTENT_LENGTH, value);
    }

    let wire_body = if response_must_not_include_body(status, request_method) {
        Bytes::new()
    } else {
        body
    };

    let mut response = Response::new(Body::from(wire_body));
    *response.status_mut() = status;
    *response.headers_mut() = sanitized;
    response
}

fn rebuild_streaming_response(
    headers: HeaderMap,
    status: StatusCode,
    body: Body,
    request_method: &str,
) -> Response<Body> {
    let mut sanitized = headers;
    let upstream_content_length = sanitized.get(CONTENT_LENGTH).cloned();
    strip_hop_by_hop_headers(&mut sanitized);
    if response_must_not_include_content_length(status) {
        sanitized.remove(CONTENT_LENGTH);
    } else if request_method.eq_ignore_ascii_case("HEAD") || status == StatusCode::NOT_MODIFIED {
        sanitized.remove(CONTENT_LENGTH);
        if let Some(value) = upstream_content_length {
            sanitized.insert(CONTENT_LENGTH, value);
        }
    } else {
        sanitized.remove(CONTENT_LENGTH);
    }

    let wire_body = if response_must_not_include_body(status, request_method) {
        Body::empty()
    } else {
        body
    };

    let mut response = Response::new(wire_body);
    *response.status_mut() = status;
    *response.headers_mut() = sanitized;
    response
}

fn response_must_not_include_content_length(status: StatusCode) -> bool {
    status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::RESET_CONTENT
}

fn response_must_not_include_body(status: StatusCode, request_method: &str) -> bool {
    request_method.eq_ignore_ascii_case("HEAD")
        || status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::RESET_CONTENT
        || status == StatusCode::NOT_MODIFIED
}

fn response_allows_synthesized_content_length(status: StatusCode) -> bool {
    !response_must_not_include_content_length(status) && status != StatusCode::NOT_MODIFIED
}

fn strip_hop_by_hop_headers(headers: &mut HeaderMap) {
    let connection_tokens = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| {
            value
                .split(',')
                .map(|token| token.trim().to_ascii_lowercase())
                .filter(|token| !token.is_empty())
        })
        .collect::<Vec<_>>();

    for header in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(header);
    }

    for token in connection_tokens {
        if let Ok(name) = HeaderName::from_bytes(token.as_bytes()) {
            headers.remove(name);
        }
    }
}

fn validate_supported_transfer_encoding(headers: &HeaderMap) -> std::result::Result<(), String> {
    let codings = transfer_encoding_tokens(headers)?;
    if codings.is_empty() || (codings.len() == 1 && codings[0].eq_ignore_ascii_case("chunked")) {
        return Ok(());
    }
    Err(format!(
        "unsupported Transfer-Encoding chain: {}",
        codings.join(", ")
    ))
}

fn transfer_encoding_tokens(headers: &HeaderMap) -> std::result::Result<Vec<String>, String> {
    let mut codings = Vec::new();
    for value in headers.get_all(TRANSFER_ENCODING) {
        let value = value
            .to_str()
            .map_err(|_| "invalid Transfer-Encoding header".to_string())?;
        codings.extend(
            value
                .split(',')
                .map(|coding| coding.trim().to_ascii_lowercase())
                .filter(|coding| !coding.is_empty()),
        );
    }
    Ok(codings)
}

fn text_response(status: StatusCode, message: impl Into<String>) -> Response<Body> {
    text_response_for_method(status, message, "GET")
}

fn text_response_for_method(
    status: StatusCode,
    message: impl Into<String>,
    request_method: &str,
) -> Response<Body> {
    let message = message.into();
    let len = message.len();
    let body = local_response_wire_body(status, request_method, message.into_bytes());
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    if response_allows_synthesized_content_length(status) {
        if let Ok(value) = HeaderValue::from_str(&len.to_string()) {
            response.headers_mut().insert(CONTENT_LENGTH, value);
        }
    }
    response
}

struct RejectedRequestIdentity {
    method: String,
    scheme: String,
    host: String,
    path: String,
}

impl RejectedRequestIdentity {
    fn from_request(
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        default_scheme: &str,
        authority_override: Option<&str>,
    ) -> Self {
        let scheme = uri.scheme_str().unwrap_or(default_scheme).to_string();
        let host = authority_override
            .map(str::to_string)
            .or_else(|| uri.authority().map(|authority| authority.to_string()))
            .or_else(|| {
                headers
                    .get(HOST)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| "<unknown>".to_string());
        let path = uri
            .path_and_query()
            .map(|value| value.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        Self {
            method: method.to_string(),
            scheme,
            host,
            path,
        }
    }

    fn from_absolute_uri(method: &Method, uri: &Uri) -> Self {
        Self {
            method: method.to_string(),
            scheme: uri.scheme_str().unwrap_or("http").to_string(),
            host: uri
                .authority()
                .map(|authority| authority.to_string())
                .unwrap_or_else(|| "<unknown>".to_string()),
            path: uri
                .path_and_query()
                .map(|value| value.as_str().to_string())
                .unwrap_or_else(|| "/".to_string()),
        }
    }
}

async fn record_http_rejection(
    state: &Arc<AppState>,
    session: &Arc<SessionContext>,
    identity: RejectedRequestIdentity,
    request_headers: &HeaderMap,
    request_body: &[u8],
    request_http_version: Option<Version>,
    started_at: chrono::DateTime<Utc>,
    started: Instant,
    status: StatusCode,
    message: String,
    context: &'static str,
) -> Response<Body> {
    let request_capture = MessageRecord::from_headers_and_body(
        request_headers,
        request_body,
        state.config.body_preview_bytes,
    );
    let (response, response_capture) =
        synthetic_error_response_for_method(status, &message, state, &identity.method);
    let record = with_record_http_versions(
        TransactionRecord::http(
            started_at,
            identity.method,
            identity.scheme,
            identity.host,
            normalize_request_path(&identity.path),
            Some(status.as_u16()),
            started.elapsed().as_millis() as u64,
            request_capture,
            Some(response_capture),
            vec![format!("Proxy rejected request: {message}")],
            None,
            None,
        ),
        request_http_version,
        Some(Version::HTTP_11),
    );
    let insert_outcome = insert_transaction_quiet(session, record, context).await;
    persist_transaction_insert_outcome(state, session, insert_outcome).await;
    response
}

async fn record_connect_rejection(
    state: &Arc<AppState>,
    session: &Arc<SessionContext>,
    uri: &Uri,
    request_headers: &HeaderMap,
    started_at: chrono::DateTime<Utc>,
    started: Instant,
    status: StatusCode,
    message: String,
    request_http_version: Version,
) -> Response<Body> {
    let target = uri
        .authority()
        .map(|authority| authority.to_string())
        .unwrap_or_else(|| uri.path().trim().to_string())
        .if_empty_then("<unknown>");
    let request_capture =
        MessageRecord::from_headers_and_body(request_headers, &[], state.config.body_preview_bytes);
    let (response, response_capture) = synthetic_error_response(status, &message, state);
    let record = with_record_http_versions(
        TransactionRecord::tunnel(
            started_at,
            target,
            Some(status.as_u16()),
            started.elapsed().as_millis() as u64,
            request_capture,
            vec![format!("Proxy rejected CONNECT: {message}")],
        )
        .with_response(response_capture),
        Some(request_http_version),
        Some(Version::HTTP_11),
    );
    let insert_outcome = insert_transaction_quiet(session, record, "invalid connect target").await;
    persist_transaction_insert_outcome(state, session, insert_outcome).await;
    response
}

async fn record_connect_post_ok_tunnel_failure(
    state: &Arc<AppState>,
    session: &Arc<SessionContext>,
    target: String,
    request_capture: MessageRecord,
    started_at: chrono::DateTime<Utc>,
    started: Instant,
    note: String,
    request_http_version: Version,
) {
    let note = format!("{note}; CONNECT 200 had already been sent to the client");
    let record = with_record_http_versions(
        TransactionRecord::tunnel(
            started_at,
            target,
            Some(StatusCode::OK.as_u16()),
            started.elapsed().as_millis() as u64,
            request_capture,
            vec![note],
        ),
        Some(request_http_version),
        Some(Version::HTTP_11),
    );
    let insert_outcome =
        insert_transaction_quiet(session, record, "connect post-ok tunnel failure").await;
    persist_transaction_insert_outcome(state, session, insert_outcome).await;
}

trait EmptyStringExt {
    fn if_empty_then(self, fallback: &str) -> String;
}

impl EmptyStringExt for String {
    fn if_empty_then(self, fallback: &str) -> String {
        if self.is_empty() {
            fallback.to_string()
        } else {
            self
        }
    }
}

fn local_response_wire_body(status: StatusCode, request_method: &str, body: Vec<u8>) -> Vec<u8> {
    if response_must_not_include_body(status, request_method) {
        Vec::new()
    } else {
        body
    }
}

fn build_local_response(status: StatusCode, headers: HeaderMap, body: Vec<u8>) -> Response<Body> {
    build_local_response_for_method(status, headers, body, "GET")
}

fn build_local_response_for_method(
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
    request_method: &str,
) -> Response<Body> {
    let body = local_response_wire_body(status, request_method, body);
    let len = body.len();
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    if response_allows_synthesized_content_length(status)
        && !response_must_not_include_body(status, request_method)
    {
        if let Ok(value) = HeaderValue::from_str(&len.to_string()) {
            response.headers_mut().insert(CONTENT_LENGTH, value);
        }
    } else if response_must_not_include_content_length(status) {
        response.headers_mut().remove(CONTENT_LENGTH);
    }
    response
}

async fn serve_special_host_tls(
    upgrade: hyper::upgrade::OnUpgrade,
    state: Arc<AppState>,
    session: Arc<SessionContext>,
    connect_target: String,
    connect_capture: MessageRecord,
    started_at: chrono::DateTime<Utc>,
    started: Instant,
    request_http_version: Version,
) -> Result<()> {
    let upgraded = match upgrade.await {
        Ok(upgraded) => upgraded,
        Err(error) => {
            let message = format!("CONNECT upgrade failed for special host: {error}");
            record_connect_post_ok_tunnel_failure(
                &state,
                &session,
                connect_target.clone(),
                connect_capture,
                started_at,
                started,
                message.clone(),
                request_http_version,
            )
            .await;
            return Err(anyhow!(message));
        }
    };
    let upgraded = TokioIo::new(upgraded);
    let acceptor: TlsAcceptor = match state.certificates.tls_acceptor() {
        Ok(acceptor) => acceptor,
        Err(error) => {
            let message = format!("failed to build special host TLS certificate: {error}");
            record_connect_post_ok_tunnel_failure(
                &state,
                &session,
                connect_target.clone(),
                connect_capture,
                started_at,
                started,
                message.clone(),
                request_http_version,
            )
            .await;
            return Err(anyhow!(message));
        }
    };
    let tls_stream = match acceptor.accept(upgraded).await {
        Ok(tls_stream) => tls_stream,
        Err(error) => {
            let message = format!("TLS handshake failed for special host: {error}");
            record_connect_post_ok_tunnel_failure(
                &state,
                &session,
                connect_target.clone(),
                connect_capture,
                started_at,
                started,
                message.clone(),
                request_http_version,
            )
            .await;
            return Err(anyhow!(message));
        }
    };

    let request_authority = special_host_record_authority(&connect_target);
    let record = with_record_http_versions(
        TransactionRecord::tunnel(
            started_at,
            connect_target,
            Some(StatusCode::OK.as_u16()),
            started.elapsed().as_millis() as u64,
            connect_capture,
            vec![
                "CONNECT tunnel terminated locally for the Sniper certificate portal.".to_string(),
            ],
        ),
        Some(request_http_version),
        Some(Version::HTTP_11),
    );
    let insert_outcome = insert_transaction_quiet(&session, record, "special-host tunnel").await;
    persist_transaction_insert_outcome(&state, &session, insert_outcome).await;

    let io = TokioIo::new(tls_stream);
    let special_host_authority = request_authority.clone();
    let service = service_fn(move |request| {
        handle_special_host_request(
            request,
            state.clone(),
            session.clone(),
            special_host_authority.clone(),
        )
    });
    let mut builder = AutoBuilder::new(TokioExecutor::new());
    builder
        .http1()
        .preserve_header_case(true)
        .title_case_headers(true);
    if let Err(error) = builder.serve_connection(io, service).await {
        warn!(
            ?error,
            "special host HTTP serving failed after CONNECT was recorded"
        );
    }
    Ok(())
}

fn special_host_record_authority(connect_target: &str) -> String {
    match connect_target.parse::<Authority>() {
        Ok(authority) if authority.port_u16() == Some(443) => authority.host().to_string(),
        _ => connect_target.to_string(),
    }
}

async fn serve_passthrough_tunnel(
    upgrade: hyper::upgrade::OnUpgrade,
    mut upstream_stream: tokio::net::TcpStream,
    state: Arc<AppState>,
    session: Arc<SessionContext>,
    target: String,
    request_capture: MessageRecord,
    started_at: chrono::DateTime<chrono::Utc>,
    started: Instant,
    request_http_version: Version,
) -> Result<()> {
    let upgraded = match upgrade.await {
        Ok(upgraded) => upgraded,
        Err(error) => {
            let message = format!("CONNECT upgrade failed for passthrough tunnel: {error}");
            record_connect_post_ok_tunnel_failure(
                &state,
                &session,
                target,
                request_capture,
                started_at,
                started,
                message.clone(),
                request_http_version,
            )
            .await;
            return Err(anyhow!(message));
        }
    };
    let mut client_stream = TokioIo::new(upgraded);

    let record = with_record_http_versions(
        TransactionRecord::tunnel(
            started_at,
            target,
            Some(StatusCode::OK.as_u16()),
            0,
            request_capture,
            vec!["SSL passthrough tunnel established.".to_string()],
        ),
        Some(request_http_version),
        Some(Version::HTTP_11),
    );
    let record_id = record.id;
    let insert_outcome = insert_transaction_quiet(&session, record, "passthrough tunnel").await;
    persist_transaction_insert_outcome(&state, &session, insert_outcome).await;

    let result = tokio::io::copy_bidirectional(&mut client_stream, &mut upstream_stream).await;

    let notes = match &result {
        Ok((client_to_server, server_to_client)) => {
            vec![format!(
                "SSL passthrough: {client_to_server} bytes sent, {server_to_client} bytes received"
            )]
        }
        Err(error) => {
            vec![format!(
                "SSL passthrough tunnel error after CONNECT 200 was sent: {error}"
            )]
        }
    };

    let _ = update_transaction_record_quiet(
        &state,
        &session,
        record_id,
        "passthrough tunnel completion",
        |record| {
            record.duration_ms = started.elapsed().as_millis() as u64;
            record.notes = notes.clone();
        },
    )
    .await;

    result.context("passthrough tunnel relay failed")?;
    Ok(())
}

async fn serve_https_mitm(
    upgrade: hyper::upgrade::OnUpgrade,
    state: Arc<AppState>,
    session: Arc<SessionContext>,
    target: String,
    connect_capture: MessageRecord,
    started_at: chrono::DateTime<Utc>,
    started: Instant,
    peer_addr: SocketAddr,
    request_http_version: Version,
) -> Result<()> {
    let authority: Authority = target
        .parse()
        .with_context(|| format!("invalid CONNECT target authority: {target}"))?;
    let upgraded = upgrade
        .await
        .context("CONNECT upgrade failed for HTTPS MITM")?;
    let upgraded = TokioIo::new(upgraded);
    let acceptor = state
        .certificates
        .tls_acceptor_for_host(authority.host())
        .with_context(|| format!("failed to build MITM certificate for {}", authority.host()))?;
    let tls_stream = acceptor
        .accept(upgraded)
        .await
        .with_context(|| format!("TLS handshake failed for {}", authority.host()))?;

    let record = with_record_http_versions(
        TransactionRecord::tunnel(
            started_at,
            target,
            Some(StatusCode::OK.as_u16()),
            started.elapsed().as_millis() as u64,
            connect_capture,
            vec![format!(
                "HTTPS MITM terminated locally and is forwarding upstream traffic for {}.",
                authority.host()
            )],
        ),
        Some(request_http_version),
        Some(Version::HTTP_11),
    );
    let insert_outcome = insert_transaction_quiet(&session, record, "https mitm tunnel").await;
    persist_transaction_insert_outcome(&state, &session, insert_outcome).await;

    let io = TokioIo::new(tls_stream);
    let connect_authority = authority.to_string();
    let log_authority = connect_authority.clone();
    let service = service_fn(move |request| {
        handle_https_mitm_request(
            request,
            state.clone(),
            session.clone(),
            peer_addr,
            connect_authority.clone(),
        )
    });
    let mut builder = AutoBuilder::new(TokioExecutor::new());
    builder
        .http1()
        .preserve_header_case(true)
        .title_case_headers(true);
    if let Err(error) = builder
        .serve_connection_with_upgrades(io, service)
        .await
        .map_err(|error| anyhow!("HTTPS MITM HTTP serving failed: {error}"))
    {
        warn!(%peer_addr, target = %log_authority, ?error, "HTTPS MITM HTTP serving failed after CONNECT was recorded");
    }
    Ok(())
}

async fn handle_special_host_request(
    request: Request<Incoming>,
    state: Arc<AppState>,
    session: Arc<SessionContext>,
    request_authority: String,
) -> Result<Response<Body>, Infallible> {
    let started_at = Utc::now();
    let started = Instant::now();
    let (parts, body) = request.into_parts();
    let request_http_version = parts.version;
    let path = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let body_bytes = match collect_body(body).await {
        Ok(bytes) => bytes,
        Err(error) => {
            let message = error.to_string();
            let request_capture = MessageRecord::from_headers_and_body(
                &parts.headers,
                &[],
                state.config.body_preview_bytes,
            );
            let (response, response_capture) = synthetic_error_response_for_method(
                error.status(),
                &message,
                &state,
                parts.method.as_str(),
            );
            let insert_outcome = insert_transaction_quiet(
                &session,
                with_record_http_versions(
                    TransactionRecord::http(
                        started_at,
                        parts.method.to_string(),
                        "https".to_string(),
                        request_authority.clone(),
                        path,
                        Some(error.status().as_u16()),
                        started.elapsed().as_millis() as u64,
                        request_capture,
                        Some(response_capture),
                        vec![message],
                        None,
                        None,
                    ),
                    Some(request_http_version),
                    Some(Version::HTTP_11),
                ),
                "special host body collection failed",
            )
            .await;
            persist_transaction_insert_outcome(&state, &session, insert_outcome).await;
            return Ok(response);
        }
    };
    let request_capture = MessageRecord::from_headers_and_body(
        &parts.headers,
        body_bytes.as_ref(),
        state.config.body_preview_bytes,
    );
    let proxy_addr = state.get_active_proxy_addr().await;
    let response = special_host::respond(&path, &parts.method, state.as_ref(), true, proxy_addr);
    let special_host::SpecialHostResponse {
        status,
        headers,
        body,
        notes,
    } = response;
    let response_body = local_response_wire_body(status, parts.method.as_str(), body);
    let response_capture = MessageRecord::from_headers_and_body(
        &headers,
        response_body.as_ref(),
        state.config.body_preview_bytes,
    );

    let insert_outcome = insert_transaction_quiet(
        &session,
        with_record_http_versions(
            TransactionRecord::http(
                started_at,
                parts.method.to_string(),
                "https".to_string(),
                request_authority,
                path,
                Some(status.as_u16()),
                started.elapsed().as_millis() as u64,
                request_capture,
                Some(response_capture),
                notes,
                None,
                None,
            ),
            Some(request_http_version),
            Some(Version::HTTP_11),
        ),
        "special-host request",
    )
    .await;
    persist_transaction_insert_outcome(&state, &session, insert_outcome).await;

    Ok(build_local_response_for_method(
        status,
        headers,
        response_body,
        parts.method.as_str(),
    ))
}

async fn handle_https_mitm_request(
    request: Request<Incoming>,
    state: Arc<AppState>,
    session: Arc<SessionContext>,
    peer_addr: SocketAddr,
    connect_authority: String,
) -> Result<Response<Body>, Infallible> {
    Ok(handle_forwardable_request(
        request,
        state,
        session,
        peer_addr,
        "https",
        Some(connect_authority),
        true,
    )
    .await)
}

async fn forward_http_request(
    parts: Parts,
    request_bytes: Bytes,
    absolute_uri: Uri,
    state: Arc<AppState>,
    session: Arc<SessionContext>,
    peer_addr: SocketAddr,
    started_at: chrono::DateTime<Utc>,
    started: Instant,
    secure_special_host: bool,
) -> Response<Body> {
    let request_http_version = parts.version;
    let editable_request = editable_request_from_parts(&parts, &request_bytes, &absolute_uri);
    let intercepted_request = match maybe_intercept_request(
        session.clone(),
        peer_addr,
        editable_request,
        false,
    )
    .await
    {
        InterceptResolution::Forward(request) => request,
        InterceptResolution::Drop(request) => {
            let dropped = build_dropped_transaction(
                state.as_ref(),
                request,
                started_at,
                started,
                "Request dropped in intercept.",
                Some(request_http_version),
            );
            let insert_outcome =
                insert_transaction_quiet(&session, dropped.record, "dropped request").await;
            persist_transaction_insert_outcome(&state, &session, insert_outcome).await;
            return dropped.response;
        }
    };
    let (forwarded_request, notes, original_request_capture) = apply_request_match_replace(
        session.as_ref(),
        intercepted_request,
        state.config.body_preview_bytes,
    )
    .await;

    let client = build_client(session.runtime.upstream_insecure().await);
    if should_stream_upstream_response(session.as_ref(), &forwarded_request).await {
        return execute_streaming_http_exchange(
            state.clone(),
            session.clone(),
            &client,
            forwarded_request,
            started_at,
            started,
            notes,
            secure_special_host,
            original_request_capture,
            Some(request_http_version),
            None,
            None,
        )
        .await;
    }

    let response_method = forwarded_request.method.clone();
    let exchange = execute_http_exchange(
        state.clone(),
        session.clone(),
        &client,
        forwarded_request,
        started_at,
        started,
        notes,
        secure_special_host,
        original_request_capture,
        Some(request_http_version),
        None,
        None,
    )
    .await;
    let mut record = exchange.record.clone();
    let client_response = match exchange.response {
        Ok(response) => {
            let intercepted = maybe_intercept_response(
                session.clone(),
                &record,
                response.status,
                &response.headers,
                &response.body,
            )
            .await;
            match intercepted {
                ResponseInterceptResolution::PassThrough => {
                    // No intercept — use original raw bytes directly to avoid
                    // lossy UTF-8 conversion that corrupts gzip/br bodies.
                    rebuild_response(
                        response.headers,
                        response.status,
                        response.body,
                        &response_method,
                    )
                }
                ResponseInterceptResolution::Forward(edited) => {
                    let headers = header_map_from_records(&edited.headers);
                    let body = Bytes::from(edited.body_bytes());
                    let status = StatusCode::from_u16(edited.status)
                        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                    record.status = Some(status.as_u16());
                    record.response = Some(MessageRecord::from_headers_and_body(
                        &headers,
                        body.as_ref(),
                        state.config.body_preview_bytes,
                    ));
                    rebuild_response(headers, status, body, &response_method)
                }
                ResponseInterceptResolution::Drop => {
                    let message = "Response dropped in intercept.";
                    let (response, response_capture) = synthetic_error_response_for_method(
                        StatusCode::BAD_GATEWAY,
                        message,
                        &state,
                        &response_method,
                    );
                    record.status = Some(StatusCode::BAD_GATEWAY.as_u16());
                    record.response = Some(response_capture);
                    record = record.with_response_http_version(Version::HTTP_11);
                    record.notes.push(message.to_string());
                    response
                }
            }
        }
        Err(error) => text_response_for_method(error.status, error.message, &response_method),
    };

    store_record_and_scan(&state, &session, record).await;
    client_response
}

async fn forward_websocket_request(
    parts: Parts,
    request_bytes: Bytes,
    absolute_uri: Uri,
    on_upgrade: hyper::upgrade::OnUpgrade,
    state: Arc<AppState>,
    session: Arc<SessionContext>,
    peer_addr: SocketAddr,
    started_at: chrono::DateTime<Utc>,
    started: Instant,
    secure_special_host: bool,
) -> Response<Body> {
    let request_http_version = parts.version;
    let client_request_headers = parts.headers.clone();
    let editable_request = editable_request_from_parts(&parts, &request_bytes, &absolute_uri);
    let forwarded_request = match maybe_intercept_request(
        session.clone(),
        peer_addr,
        editable_request,
        true,
    )
    .await
    {
        InterceptResolution::Forward(request) => request,
        InterceptResolution::Drop(request) => {
            let dropped = build_dropped_transaction(
                state.as_ref(),
                request,
                started_at,
                started,
                "WebSocket upgrade dropped in intercept.",
                Some(request_http_version),
            );
            let insert_outcome =
                insert_transaction_quiet(&session, dropped.record, "dropped websocket upgrade")
                    .await;
            persist_transaction_insert_outcome(&state, &session, insert_outcome).await;
            return dropped.response;
        }
    };
    let (forwarded_request, request_notes, original_request_capture) = apply_request_match_replace(
        session.as_ref(),
        forwarded_request,
        state.config.body_preview_bytes,
    )
    .await;

    if !is_websocket_upgrade_editable(&forwarded_request) {
        let response_method = forwarded_request.method.clone();
        let client = build_client(session.runtime.upstream_insecure().await);
        let exchange = execute_http_exchange(
            state.clone(),
            session.clone(),
            &client,
            forwarded_request,
            started_at,
            started,
            merge_notes(
                request_notes,
                vec!["Request left intercept without websocket upgrade headers.".to_string()],
            ),
            secure_special_host,
            original_request_capture,
            Some(request_http_version),
            None,
            None,
        )
        .await;
        let record = exchange.record.clone();
        store_record_and_scan(&state, &session, record).await;
        return match exchange.response {
            Ok(response) => rebuild_response(
                response.headers,
                response.status,
                response.body,
                &response_method,
            ),
            Err(error) => text_response_for_method(error.status, error.message, &response_method),
        };
    }

    let request_headers = header_map_from_records(&forwarded_request.headers);
    let request_capture = MessageRecord::from_headers_and_body(
        &request_headers,
        &forwarded_request.body_bytes(),
        state.config.body_preview_bytes,
    );
    if let Some(message) =
        websocket_upgrade_validation_error_for_editable(&forwarded_request, &request_headers)
    {
        let (client_response, response_capture) = synthetic_error_response_for_method(
            StatusCode::BAD_REQUEST,
            message,
            &state,
            &forwarded_request.method,
        );
        let record = with_record_http_versions(
            TransactionRecord::http(
                started_at,
                forwarded_request.method.clone(),
                forwarded_request.scheme.clone(),
                forwarded_request.host.clone(),
                normalize_request_path(&forwarded_request.path),
                Some(StatusCode::BAD_REQUEST.as_u16()),
                started.elapsed().as_millis() as u64,
                request_capture,
                Some(response_capture),
                merge_notes(
                    request_notes,
                    vec![format!("Invalid WebSocket handshake: {message}")],
                ),
                original_request_capture,
                None,
            ),
            Some(request_http_version),
            Some(Version::HTTP_11),
        );
        let insert_outcome =
            insert_transaction_quiet(&session, record, "invalid edited websocket upgrade").await;
        persist_transaction_insert_outcome(&state, &session, insert_outcome).await;
        return client_response;
    }

    if special_host::is_special_host(&forwarded_request.host) {
        let response_method = forwarded_request.method.clone();
        let exchange = execute_http_exchange(
            state.clone(),
            session.clone(),
            &build_client(session.runtime.upstream_insecure().await),
            forwarded_request,
            started_at,
            started,
            merge_notes(
                request_notes,
                vec![
                    "WebSocket upgrades are not supported on the Sniper bootstrap host."
                        .to_string(),
                ],
            ),
            secure_special_host,
            original_request_capture,
            Some(request_http_version),
            None,
            None,
        )
        .await;
        let record = exchange.record.clone();
        let insert_outcome =
            insert_transaction_quiet(&session, record, "special-host websocket request").await;
        persist_transaction_insert_outcome(&state, &session, insert_outcome).await;
        return match exchange.response {
            Ok(response) => rebuild_response(
                response.headers,
                response.status,
                response.body,
                &response_method,
            ),
            Err(error) => text_response_for_method(error.status, error.message, &response_method),
        };
    }

    let response = match connect_upstream_websocket(
        &forwarded_request,
        session.runtime.upstream_insecure().await,
    )
    .await
    {
        Ok(response) => response,
        Err(UpstreamWebSocketConnectError::Http {
            status,
            headers,
            body,
        }) => {
            let response_capture = MessageRecord::from_headers_and_body(
                &headers,
                body.as_ref(),
                state.config.body_preview_bytes,
            );
            let record = with_record_http_versions(
                TransactionRecord::http(
                    started_at,
                    forwarded_request.method.clone(),
                    forwarded_request.scheme.clone(),
                    forwarded_request.host.clone(),
                    normalize_request_path(&forwarded_request.path),
                    Some(status.as_u16()),
                    started.elapsed().as_millis() as u64,
                    request_capture,
                    Some(response_capture),
                    merge_notes(
                        request_notes,
                        vec![format!(
                            "Upstream WebSocket handshake returned HTTP {status}"
                        )],
                    ),
                    original_request_capture,
                    None,
                ),
                Some(request_http_version),
                Some(Version::HTTP_11),
            );
            let insert_outcome =
                insert_transaction_quiet(&session, record, "websocket upstream http response")
                    .await;
            persist_transaction_insert_outcome(&state, &session, insert_outcome).await;
            return rebuild_response(headers, status, body, &forwarded_request.method);
        }
        Err(UpstreamWebSocketConnectError::Other(error)) => {
            let message = format!("WebSocket connect failed: {error}");
            let (client_response, response_capture) = synthetic_error_response_for_method(
                StatusCode::BAD_GATEWAY,
                &message,
                &state,
                &forwarded_request.method,
            );
            let record = with_record_http_versions(
                TransactionRecord::http(
                    started_at,
                    forwarded_request.method.clone(),
                    forwarded_request.scheme.clone(),
                    forwarded_request.host.clone(),
                    normalize_request_path(&forwarded_request.path),
                    Some(StatusCode::BAD_GATEWAY.as_u16()),
                    started.elapsed().as_millis() as u64,
                    request_capture,
                    Some(response_capture),
                    merge_notes(request_notes, vec![message]),
                    original_request_capture,
                    None,
                ),
                Some(request_http_version),
                Some(Version::HTTP_11),
            );
            let insert_outcome =
                insert_transaction_quiet(&session, record, "websocket connect failure").await;
            persist_transaction_insert_outcome(&state, &session, insert_outcome).await;
            return client_response;
        }
    };

    let response_headers = match build_websocket_client_response_headers(
        &client_request_headers,
        response.upstream_headers.clone(),
    ) {
        Ok(headers) => headers,
        Err(error) => {
            let message = format!("Invalid WebSocket handshake: {error}");
            let (client_response, response_capture) = synthetic_error_response_for_method(
                StatusCode::BAD_REQUEST,
                &message,
                &state,
                &forwarded_request.method,
            );
            let record = with_record_http_versions(
                TransactionRecord::http(
                    started_at,
                    forwarded_request.method.clone(),
                    forwarded_request.scheme.clone(),
                    forwarded_request.host.clone(),
                    normalize_request_path(&forwarded_request.path),
                    Some(StatusCode::BAD_REQUEST.as_u16()),
                    started.elapsed().as_millis() as u64,
                    request_capture,
                    Some(response_capture),
                    merge_notes(request_notes, vec![message]),
                    original_request_capture,
                    None,
                ),
                Some(request_http_version),
                Some(Version::HTTP_11),
            );
            let insert_outcome =
                insert_transaction_quiet(&session, record, "invalid websocket handshake").await;
            persist_transaction_insert_outcome(&state, &session, insert_outcome).await;
            return client_response;
        }
    };
    let original_response_capture = MessageRecord::from_headers_and_body(
        &response_headers,
        &[],
        state.config.body_preview_bytes,
    );
    let applied_response = session
        .match_replace
        .apply_response(response_headers, Bytes::new())
        .await;
    let original_response_capture =
        (!applied_response.notes.is_empty()).then_some(original_response_capture);
    if !applied_response.notes.is_empty() {
        session
            .event_log
            .push(
                EventLevel::Info,
                "match_replace",
                "Rules applied",
                applied_response.notes.join(" | "),
            )
            .await;
    }
    if let Some(error) = websocket_response_validation_error(
        &client_request_headers,
        &response.upstream_headers,
        &applied_response.headers,
    ) {
        let message = format!("Invalid WebSocket handshake response: {error}");
        let (client_response, response_capture) = synthetic_error_response_for_method(
            StatusCode::BAD_REQUEST,
            &message,
            &state,
            &forwarded_request.method,
        );
        let record = with_record_http_versions(
            TransactionRecord::http(
                started_at,
                forwarded_request.method.clone(),
                forwarded_request.scheme.clone(),
                forwarded_request.host.clone(),
                normalize_request_path(&forwarded_request.path),
                Some(StatusCode::BAD_REQUEST.as_u16()),
                started.elapsed().as_millis() as u64,
                request_capture,
                Some(response_capture),
                merge_notes(
                    merge_notes(request_notes, applied_response.notes),
                    vec![message],
                ),
                original_request_capture,
                original_response_capture,
            ),
            Some(request_http_version),
            Some(Version::HTTP_11),
        );
        let insert_outcome =
            insert_transaction_quiet(&session, record, "invalid websocket response").await;
        persist_transaction_insert_outcome(&state, &session, insert_outcome).await;
        return client_response;
    }

    let response_capture = MessageRecord::from_headers_and_body(
        &applied_response.headers,
        &[],
        state.config.body_preview_bytes,
    );
    let request_path = normalize_request_path(&forwarded_request.path);
    let capture_enabled = session.runtime.websocket_capture_enabled().await;
    let http_record = with_record_http_versions(
        TransactionRecord::http(
            started_at,
            forwarded_request.method.clone(),
            forwarded_request.scheme.clone(),
            forwarded_request.host.clone(),
            request_path.clone(),
            Some(StatusCode::SWITCHING_PROTOCOLS.as_u16()),
            started.elapsed().as_millis() as u64,
            request_capture.clone(),
            Some(response_capture.clone()),
            merge_notes(
                merge_notes(request_notes, applied_response.notes),
                vec![websocket_upgrade_transaction_note(capture_enabled).to_string()],
            ),
            original_request_capture,
            original_response_capture,
        ),
        Some(request_http_version),
        Some(Version::HTTP_11),
    );
    let insert_outcome =
        insert_transaction_quiet(&session, http_record, "websocket upgrade transaction").await;
    persist_transaction_insert_outcome(&state, &session, insert_outcome).await;
    session
        .event_log
        .push(
            EventLevel::Info,
            "websocket",
            "Session opened",
            format!("{}{}", forwarded_request.host, request_path),
        )
        .await;

    let mut captured_websocket_id = capture_enabled.then(Uuid::new_v4);

    if let Some(id) = captured_websocket_id {
        if let Err(error) = session
            .open_websocket_capture(WebSocketSessionRecord {
                id,
                sequence: 0,
                started_at,
                closed_at: None,
                duration_ms: None,
                scheme: forwarded_request.scheme.clone(),
                host: forwarded_request.host.clone(),
                path: request_path.clone(),
                status: Some(StatusCode::SWITCHING_PROTOCOLS.as_u16()),
                request: request_capture,
                response: Some(response_capture),
                frames: Vec::new(),
                notes: vec!["Live relay established.".to_string()],
            })
            .await
        {
            warn!(
                ?error,
                websocket_id = %id,
                "failed to journal captured WebSocket open"
            );
            captured_websocket_id = None;
        }
    }
    persist_session_state_quiet(&session).await;

    let relay_id = Uuid::new_v4();
    let (relay_abort, relay_registration) = AbortHandle::new_pair();
    remember_live_websocket_relay(
        relay_id,
        captured_websocket_id,
        &session,
        started,
        relay_abort,
    );

    spawn_tracked_proxy_task(session.id(), async move {
        let relay = relay_websocket_session(
            on_upgrade,
            response.websocket,
            state.clone(),
            session.clone(),
            captured_websocket_id,
            started,
        );
        match Abortable::new(relay, relay_registration).await {
            Ok(Err(error)) => {
                warn!(
                    %peer_addr,
                    host = %forwarded_request.host,
                    path = %request_path,
                    ?error,
                    "websocket relay failed"
                );
                if let Some(id) = captured_websocket_id {
                    let close_note = Some(format!("Relay error: {error}"));
                    match session
                        .close_websocket_capture(
                            id,
                            Utc::now(),
                            started.elapsed().as_millis() as u64,
                            close_note.clone(),
                        )
                        .await
                    {
                        Ok(true) => {}
                        Ok(false) => {
                            warn!(
                                websocket_id = %id,
                                "captured WebSocket was missing before relay error close"
                            );
                        }
                        Err(close_error) => {
                            warn!(
                                ?close_error,
                                websocket_id = %id,
                                "failed to journal relay error close for captured WebSocket"
                            );
                            session
                                .websockets
                                .close(
                                    id,
                                    Utc::now(),
                                    started.elapsed().as_millis() as u64,
                                    close_note,
                                )
                                .await;
                            persist_session_state_quiet(&session).await;
                        }
                    }
                }
            }
            Err(_aborted) => {
                close_aborted_live_websocket_relay(
                    &state,
                    &session,
                    relay_id,
                    captured_websocket_id,
                    started,
                    "Proxy shutdown closed the live WebSocket relay.",
                )
                .await;
            }
            Ok(Ok(())) => {}
        }
        forget_live_websocket_relay_unless_close_pending(relay_id);
    });

    build_local_response(
        StatusCode::SWITCHING_PROTOCOLS,
        applied_response.headers,
        Vec::new(),
    )
}

async fn maybe_intercept_request(
    session: Arc<SessionContext>,
    peer_addr: SocketAddr,
    request: EditableRequest,
    is_websocket: bool,
) -> InterceptResolution {
    if !session.runtime.intercept_enabled().await {
        return InterceptResolution::Forward(request);
    }

    if special_host::is_special_host(&request.host) {
        return InterceptResolution::Forward(request);
    }
    if session.runtime.intercept_scope_only().await
        && !session.runtime.is_in_scope(&request.host).await
    {
        return InterceptResolution::Forward(request);
    }

    if !session.intercept_rules.matches_any(&request).await {
        return InterceptResolution::Forward(request);
    }

    session
        .event_log
        .push(
            EventLevel::Info,
            "intercept",
            "Request queued",
            format!(
                "{} {}{} from {}",
                request.method, request.host, request.path, peer_addr
            ),
        )
        .await;

    let resolution = session
        .intercepts
        .enqueue(InterceptRecord {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            peer_addr: peer_addr.to_string(),
            request,
            is_websocket,
        })
        .await;
    persist_session_state_quiet(&session).await;
    resolution
}

async fn maybe_intercept_response(
    session: Arc<SessionContext>,
    record: &TransactionRecord,
    status: StatusCode,
    headers: &HeaderMap,
    body: &Bytes,
) -> ResponseInterceptResolution {
    if !session.runtime.intercept_enabled().await {
        return ResponseInterceptResolution::PassThrough;
    }

    if special_host::is_special_host(&record.host) {
        return ResponseInterceptResolution::PassThrough;
    }
    if session.runtime.intercept_scope_only().await
        && !session.runtime.is_in_scope(&record.host).await
    {
        return ResponseInterceptResolution::PassThrough;
    }

    let editable_request = record.editable_request();
    if !session
        .intercept_rules
        .matches_any_response(&editable_request)
        .await
    {
        return ResponseInterceptResolution::PassThrough;
    }

    session
        .event_log
        .push(
            EventLevel::Info,
            "intercept",
            "Response queued",
            format!(
                "{} {} {}{} → {}",
                record.method,
                status.as_u16(),
                record.host,
                record.path,
                record.id
            ),
        )
        .await;

    let editable = EditableResponse::from_status_headers_body(status.as_u16(), headers, body);
    let resolution = session
        .response_intercepts
        .enqueue(ResponseInterceptRecord {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            scheme: record.scheme.clone(),
            host: record.host.clone(),
            method: record.method.clone(),
            path: record.path.clone(),
            status: status.as_u16(),
            response: editable.clone(),
        })
        .await;
    persist_session_state_quiet(&session).await;
    resolution
}

async fn store_record_and_scan(
    state: &Arc<AppState>,
    session: &Arc<SessionContext>,
    record: TransactionRecord,
) {
    let insert_outcome =
        insert_transaction_quiet(session, record.clone(), "captured transaction").await;
    scan_record_for_session(session, record);
    persist_transaction_insert_outcome(state, session, insert_outcome).await;
}

fn scan_record_for_session(session: &Arc<SessionContext>, record: TransactionRecord) {
    let scanner = session.scanner.clone();
    let scan_generation = scanner.clear_generation();
    let scan_session = Arc::clone(session);
    spawn_tracked_proxy_task(session.id(), async move {
        let config = scanner.get_config().await;
        let findings = crate::scanner::scan_transaction(&record, &config);
        let mut accepted_findings = false;
        for finding in findings {
            accepted_findings |= scanner.push_if_generation(finding, scan_generation).await;
        }
        // Findings live in state.json, so persisting them no longer drags the
        // transactions along. Doing this as a full snapshot rewrote the whole
        // session document every PERSIST_DEBOUNCE while browsing — 11 rewrites
        // per 20 seconds on a real 1.35 GB session.
        if accepted_findings {
            persist_session_state_quiet(&scan_session).await;
        }
    });
}

async fn insert_transaction_quiet(
    session: &Arc<SessionContext>,
    record: TransactionRecord,
    _context: &'static str,
) -> crate::store::TransactionInsertOutcome {
    session.store.insert(record).await
}

async fn update_transaction_record_quiet(
    state: &Arc<AppState>,
    session: &Arc<SessionContext>,
    record_id: Uuid,
    context: &'static str,
    update: impl Fn(&mut TransactionRecord),
) -> bool {
    match session
        .store
        .update_record_durable(record_id, |record| update(record))
        .await
    {
        Ok(Some(_)) => {
            // `update_record_durable` already appended and fsynced this change to
            // the journal, so the snapshot rewrite is not what makes it durable —
            // it only compacts the journal. Doing it unconditionally here meant
            // every streamed response rewrote the whole session document.
            if transaction_journal_compaction_due(session) {
                persist_session_quiet(state, session).await;
            }
            true
        }
        Ok(None) => false,
        Err(error) => {
            warn!(
                ?error,
                context,
                "failed to append durable transaction update journal entry; falling back to immediate snapshot persistence"
            );
            if session
                .store
                .update_record(record_id, |record| update(record))
                .await
                .is_some()
            {
                persist_session_immediate_quiet(state, session).await;
                true
            } else {
                false
            }
        }
    }
}

async fn persist_transaction_insert_outcome(
    state: &Arc<AppState>,
    session: &Arc<SessionContext>,
    outcome: crate::store::TransactionInsertOutcome,
) {
    if outcome.immediate_snapshot_required() {
        persist_session_immediate_quiet(state, session).await;
    } else if transaction_journal_compaction_due(session) {
        persist_session_quiet(state, session).await;
    }
}

/// How much transaction journal (active file plus checkpoint) may pile up before a
/// full session snapshot is rewritten to compact it.
///
/// 64 MiB replays in roughly 80 ms at the measured 0.8 GB/s JSON parse rate, and
/// is about 5,000 records at the average record size of a real session. Raising it
/// makes the expensive snapshot rewrites rarer, at the cost of a slower load and a
/// longer window of non-journaled state (event log entries) to lose in a crash.
const TRANSACTION_JOURNAL_COMPACT_BYTES: u64 = 64 * 1024 * 1024;

/// Persists only the small components, to state.json. For changes that are not a
/// captured transaction — an intercept enqueue, a websocket open, a scanner
/// finding — rewriting the transactions along with them is wasted work.
async fn persist_session_state_quiet(session: &SessionContext) {
    if let Err(error) = session.persist_state_only().await {
        warn!(
            ?error,
            session_id = %session.id(),
            "failed to persist session state"
        );
    }
}

/// The journal is only emptied by a full snapshot rewrite, so that rewrite has to
/// be driven by how much the journal has accumulated. Every other trigger made it
/// fire on essentially every request.
fn transaction_journal_compaction_due(session: &SessionContext) -> bool {
    session.transaction_journal_replay_bytes() >= TRANSACTION_JOURNAL_COMPACT_BYTES
}

async fn should_stream_upstream_response(
    session: &SessionContext,
    request: &EditableRequest,
) -> bool {
    if special_host::is_special_host(&request.host) {
        return false;
    }
    if session.match_replace.has_enabled_response_rules().await {
        return false;
    }
    if should_buffer_for_response_intercept(session, request).await {
        return false;
    }
    true
}

async fn should_buffer_for_response_intercept(
    session: &SessionContext,
    request: &EditableRequest,
) -> bool {
    if !session.runtime.intercept_enabled().await {
        return false;
    }
    if session.runtime.intercept_scope_only().await
        && !session.runtime.is_in_scope(&request.host).await
    {
        return false;
    }
    session.intercept_rules.matches_any_response(request).await
}

async fn execute_streaming_http_exchange(
    state: Arc<AppState>,
    session: Arc<SessionContext>,
    client: &ProxyClient,
    request: EditableRequest,
    started_at: chrono::DateTime<Utc>,
    started: Instant,
    mut notes: Vec<String>,
    _secure_special_host: bool,
    original_request_capture: Option<MessageRecord>,
    request_http_version: Option<Version>,
    requested_http_version: Option<Version>,
    outbound_uri_authority: Option<&str>,
) -> Response<Body> {
    let request_headers = header_map_from_records(&request.headers);
    let request_body = request.body_bytes();
    let request_capture = MessageRecord::from_headers_and_body(
        &request_headers,
        request_body.as_ref(),
        state.config.body_preview_bytes,
    );
    let path = normalize_request_path(&request.path);
    let method = match Method::from_bytes(request.method.as_bytes()) {
        Ok(method) => method,
        Err(error) => {
            let message = format!("Invalid HTTP method: {error}");
            notes.push(message.clone());
            let (response, response_capture) =
                synthetic_error_response(StatusCode::BAD_REQUEST, &message, &state);
            let record = with_record_http_versions(
                TransactionRecord::http(
                    started_at,
                    request.method,
                    request.scheme,
                    request.host,
                    path,
                    Some(StatusCode::BAD_REQUEST.as_u16()),
                    started.elapsed().as_millis() as u64,
                    request_capture,
                    Some(response_capture),
                    notes,
                    original_request_capture,
                    None,
                ),
                request_http_version,
                Some(Version::HTTP_11),
            );
            store_record_and_scan(&state, &session, record).await;
            return response;
        }
    };

    let absolute_uri = match build_uri_from_request(&request, outbound_uri_authority) {
        Ok(uri) => uri,
        Err(error) => {
            let message = error.to_string();
            notes.push(message.clone());
            let (response, response_capture) = synthetic_error_response_for_method(
                StatusCode::BAD_REQUEST,
                &message,
                &state,
                method.as_str(),
            );
            let record = with_record_http_versions(
                TransactionRecord::http(
                    started_at,
                    method.to_string(),
                    request.scheme,
                    request.host,
                    path,
                    Some(StatusCode::BAD_REQUEST.as_u16()),
                    started.elapsed().as_millis() as u64,
                    request_capture,
                    Some(response_capture),
                    notes,
                    original_request_capture,
                    None,
                ),
                request_http_version,
                Some(Version::HTTP_11),
            );
            store_record_and_scan(&state, &session, record).await;
            return response;
        }
    };

    let host_override =
        replay_host_override(&request_headers, outbound_uri_authority, &request.host);
    let mut outbound_headers = request_headers.clone();
    strip_hop_by_hop_headers(&mut outbound_headers);
    outbound_headers.remove(HOST);
    outbound_headers.remove(CONTENT_LENGTH);

    let mut request_builder = client
        .request(method.clone(), absolute_uri.to_string())
        .headers(outbound_headers)
        .body(request_body.clone());
    if let Some(version) = requested_http_version {
        request_builder = request_builder.version(version);
    }
    if let Some(host_override) = host_override {
        request_builder = request_builder.header(HOST, host_override);
    }

    match request_builder.send().await {
        Ok(response) => {
            let status = response.status();
            let response_version = response.version();
            let response_headers = response.headers().clone();
            let method_text = method.to_string();
            if let Err(error) = validate_supported_transfer_encoding(&response_headers) {
                let message = format!("Unsupported upstream response transfer encoding: {error}");
                notes.push(message.clone());
                session
                    .event_log
                    .push(
                        EventLevel::Warn,
                        "proxy",
                        "Unsupported upstream response transfer encoding",
                        message.clone(),
                    )
                    .await;
                let (response, response_capture) = synthetic_error_response_for_method(
                    StatusCode::BAD_GATEWAY,
                    &message,
                    &state,
                    method.as_str(),
                );
                let record = with_record_http_versions(
                    TransactionRecord::http(
                        started_at,
                        method.to_string(),
                        request.scheme,
                        request.host,
                        path,
                        Some(StatusCode::BAD_GATEWAY.as_u16()),
                        started.elapsed().as_millis() as u64,
                        request_capture,
                        Some(response_capture),
                        notes,
                        original_request_capture,
                        None,
                    ),
                    request_http_version,
                    Some(Version::HTTP_11),
                );
                store_record_and_scan(&state, &session, record).await;
                return response;
            }
            let persist_generation = remember_persist_context(&session);
            let context = StreamedRecordContext {
                state: state.clone(),
                session: session.clone(),
                _session_owner: remember_active_proxy_session_owner(session.id()),
                persist_generation,
                record_id: None,
                started_at,
                started,
                method: method_text.clone(),
                scheme: request.scheme,
                host: request.host,
                path,
                status,
                request_capture,
                response_headers: response_headers.clone(),
                notes,
                original_request_capture,
                request_version: request_http_version,
                response_version,
                max_preview: state.config.body_preview_bytes,
            };

            if response_must_not_include_body(status, &method_text) {
                context.store(Vec::new(), 0).await;
                return rebuild_streaming_response(
                    response_headers,
                    status,
                    Body::empty(),
                    &method_text,
                );
            }

            let mut context = context;
            context.insert_provisional_record().await;
            let body = stream_upstream_response_body(response, context);
            rebuild_streaming_response(response_headers, status, body, &method_text)
        }
        Err(error) => {
            let message = format!("Upstream request failed: {error}");
            notes.push(message.clone());
            session
                .event_log
                .push(
                    EventLevel::Warn,
                    "proxy",
                    "Upstream request failed",
                    message.clone(),
                )
                .await;
            let (response, response_capture) = synthetic_error_response_for_method(
                StatusCode::BAD_GATEWAY,
                &message,
                &state,
                method.as_str(),
            );
            let record = with_record_http_versions(
                TransactionRecord::http(
                    started_at,
                    method.to_string(),
                    request.scheme,
                    request.host,
                    path,
                    Some(StatusCode::BAD_GATEWAY.as_u16()),
                    started.elapsed().as_millis() as u64,
                    request_capture,
                    Some(response_capture),
                    notes,
                    original_request_capture,
                    None,
                ),
                request_http_version,
                Some(Version::HTTP_11),
            );
            store_record_and_scan(&state, &session, record).await;
            response
        }
    }
}

fn stream_upstream_response_body(
    response: reqwest::Response,
    context: StreamedRecordContext,
) -> Body {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<std::result::Result<Bytes, std::io::Error>>(8);
    let pump_id = Uuid::new_v4();
    let session_id = context.session.id();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
    remember_streamed_response_pump(pump_id, session_id, shutdown_tx);
    tokio::spawn(async move {
        let mut upstream = response.bytes_stream();
        let mut preview = Vec::new();
        let mut body_size = 0usize;
        let mut context = context;
        let mut notes = std::mem::take(&mut context.notes);

        loop {
            tokio::select! {
                _ = tx.closed() => {
                    notes.push(
                        "Client disconnected before streamed response completed.".to_string(),
                    );
                    break;
                }
                _ = &mut shutdown_rx => {
                    notes.push(
                        "Shutdown finalized streamed response capture before upstream EOF.".to_string(),
                    );
                    break;
                }
                chunk = upstream.next() => {
                    match chunk {
                        Some(Ok(bytes)) => {
                            body_size = body_size.saturating_add(bytes.len());
                            append_body_preview(&mut preview, bytes.as_ref(), context.max_preview);
                            if tx.send(Ok(bytes)).await.is_err() {
                                notes.push(
                                    "Client disconnected before streamed response completed.".to_string(),
                                );
                                break;
                            }
                        }
                        Some(Err(error)) => {
                            let message = format!("Failed to read upstream response body: {error}");
                            notes.push(message.clone());
                            let _ = tx.send(Err(std::io::Error::other(message))).await;
                            break;
                        }
                        None => break,
                    }
                }
            }
        }

        context.store_with_notes(preview, body_size, notes).await;
        forget_streamed_response_pump(pump_id);
    });

    Body::from_stream(async_stream::stream! {
        while let Some(chunk) = rx.recv().await {
            yield chunk;
        }
    })
}

fn append_body_preview(preview: &mut Vec<u8>, chunk: &[u8], max_preview: usize) {
    let remaining = max_preview.saturating_sub(preview.len());
    if remaining == 0 {
        return;
    }
    preview.extend_from_slice(&chunk[..remaining.min(chunk.len())]);
}

async fn read_response_body_limited(response: reqwest::Response, limit: usize) -> Result<Bytes> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        bail!("upstream response body exceeds {limit} bytes");
    }
    let mut stream = response.bytes_stream();
    let mut body = BytesMut::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("failed to read upstream response body chunk")?;
        if body.len().saturating_add(chunk.len()) > limit {
            bail!("upstream response body exceeds {limit} bytes");
        }
        body.extend_from_slice(chunk.as_ref());
    }
    Ok(body.freeze())
}

fn apply_streamed_record_update(stored: &mut TransactionRecord, record: &TransactionRecord) {
    stored.status = record.status;
    stored.duration_ms = record.duration_ms;
    stored.response = record.response.clone();
    stored.notes = record.notes.clone();
    stored.original_response = record.original_response.clone();
    stored.http_version = record.http_version.clone();
    stored.response_http_version = record.response_http_version.clone();
}

impl StreamedRecordContext {
    async fn insert_provisional_record(&mut self) {
        if self.record_id.is_some() {
            return;
        }
        let mut notes = self.notes.clone();
        notes.push("Streaming response capture is still in progress.".to_string());
        let record = self.build_record(Vec::new(), 0, notes);
        self.record_id = Some(record.id);
        let insert_outcome =
            insert_transaction_quiet(&self.session, record, "streaming response started").await;
        persist_transaction_insert_outcome(&self.state, &self.session, insert_outcome).await;
    }

    async fn store(self, preview: Vec<u8>, body_size: usize) {
        let notes = self.notes.clone();
        self.store_with_notes(preview, body_size, notes).await;
    }

    async fn store_with_notes(self, preview: Vec<u8>, body_size: usize, notes: Vec<String>) {
        let record = self.build_record(preview, body_size, notes);
        if let Some(record_id) = self.record_id {
            if update_transaction_record_quiet(
                &self.state,
                &self.session,
                record_id,
                "streaming response completion",
                |stored| apply_streamed_record_update(stored, &record),
            )
            .await
            {
                let mut scan_record = record;
                scan_record.id = record_id;
                scan_record_for_session(&self.session, scan_record);
                forget_persist_context_if_clean(self.session.id(), self.persist_generation);
                return;
            }
        }
        store_record_and_scan(&self.state, &self.session, record).await;
        forget_persist_context_if_clean(self.session.id(), self.persist_generation);
    }

    fn build_record(
        &self,
        preview: Vec<u8>,
        body_size: usize,
        notes: Vec<String>,
    ) -> TransactionRecord {
        let mut response_capture = MessageRecord::from_headers_and_body(
            &self.response_headers,
            preview.as_ref(),
            self.max_preview,
        );
        response_capture.body_size = body_size;
        if body_size > preview.len() {
            response_capture.preview_truncated = true;
            if response_capture.content_decoded {
                response_capture.decoded_body_size = None;
                response_capture.content_decoded = false;
            }
        }
        with_record_http_versions(
            TransactionRecord::http(
                self.started_at,
                self.method.clone(),
                self.scheme.clone(),
                self.host.clone(),
                self.path.clone(),
                Some(self.status.as_u16()),
                self.started.elapsed().as_millis() as u64,
                self.request_capture.clone(),
                Some(response_capture),
                notes,
                self.original_request_capture.clone(),
                None,
            ),
            self.request_version,
            Some(self.response_version),
        )
    }
}

async fn execute_http_exchange(
    state: Arc<AppState>,
    session: Arc<SessionContext>,
    client: &ProxyClient,
    request: EditableRequest,
    started_at: chrono::DateTime<Utc>,
    started: Instant,
    mut notes: Vec<String>,
    secure_special_host: bool,
    original_request_capture: Option<MessageRecord>,
    request_http_version: Option<Version>,
    requested_http_version: Option<Version>,
    outbound_uri_authority: Option<&str>,
) -> ExecutedExchange {
    let request_headers = header_map_from_records(&request.headers);
    let request_body = request.body_bytes();
    let request_capture = MessageRecord::from_headers_and_body(
        &request_headers,
        request_body.as_ref(),
        state.config.body_preview_bytes,
    );
    let path = normalize_request_path(&request.path);
    let method = match Method::from_bytes(request.method.as_bytes()) {
        Ok(method) => method,
        Err(error) => {
            let message = format!("Invalid HTTP method: {error}");
            notes.push(message.clone());
            let (_response, response_capture) =
                synthetic_error_response(StatusCode::BAD_REQUEST, &message, &state);
            return ExecutedExchange {
                record: with_record_http_versions(
                    TransactionRecord::http(
                        started_at,
                        request.method,
                        request.scheme,
                        request.host,
                        path,
                        Some(StatusCode::BAD_REQUEST.as_u16()),
                        started.elapsed().as_millis() as u64,
                        request_capture,
                        Some(response_capture),
                        notes,
                        None,
                        None,
                    ),
                    request_http_version,
                    Some(Version::HTTP_11),
                ),
                response: Err(UpstreamError {
                    status: StatusCode::BAD_REQUEST,
                    message,
                }),
            };
        }
    };

    if special_host::is_special_host(&request.host) {
        let proxy_addr = state.get_active_proxy_addr().await;
        let response = special_host::respond(
            &path,
            &method,
            state.as_ref(),
            secure_special_host || request.scheme.eq_ignore_ascii_case("https"),
            proxy_addr,
        );
        let response_body =
            local_response_wire_body(response.status, method.as_str(), response.body);
        let response_capture = MessageRecord::from_headers_and_body(
            &response.headers,
            response_body.as_ref(),
            state.config.body_preview_bytes,
        );
        notes.extend(response.notes.clone());
        return ExecutedExchange {
            record: with_record_http_versions(
                TransactionRecord::http(
                    started_at,
                    method.to_string(),
                    request.scheme,
                    request.host,
                    path,
                    Some(response.status.as_u16()),
                    started.elapsed().as_millis() as u64,
                    request_capture,
                    Some(response_capture),
                    notes,
                    original_request_capture,
                    None,
                ),
                request_http_version,
                Some(Version::HTTP_11),
            ),
            response: Ok(UpstreamResponse {
                status: response.status,
                headers: response.headers,
                body: Bytes::from(response_body),
            }),
        };
    }

    let absolute_uri = match build_uri_from_request(&request, outbound_uri_authority) {
        Ok(uri) => uri,
        Err(error) => {
            let message = error.to_string();
            notes.push(message.clone());
            let (_response, response_capture) = synthetic_error_response_for_method(
                StatusCode::BAD_REQUEST,
                &message,
                &state,
                method.as_str(),
            );
            return ExecutedExchange {
                record: with_record_http_versions(
                    TransactionRecord::http(
                        started_at,
                        method.to_string(),
                        request.scheme,
                        request.host,
                        path,
                        Some(StatusCode::BAD_REQUEST.as_u16()),
                        started.elapsed().as_millis() as u64,
                        request_capture,
                        Some(response_capture),
                        notes,
                        original_request_capture,
                        None,
                    ),
                    request_http_version,
                    Some(Version::HTTP_11),
                ),
                response: Err(UpstreamError {
                    status: StatusCode::BAD_REQUEST,
                    message,
                }),
            };
        }
    };

    let host_override =
        replay_host_override(&request_headers, outbound_uri_authority, &request.host);
    let mut outbound_headers = request_headers.clone();
    strip_hop_by_hop_headers(&mut outbound_headers);
    outbound_headers.remove(HOST);
    outbound_headers.remove(CONTENT_LENGTH);

    let mut request_builder = client
        .request(method.clone(), absolute_uri.to_string())
        .headers(outbound_headers)
        .body(request_body.clone());
    if let Some(version) = requested_http_version {
        request_builder = request_builder.version(version);
    }
    if let Some(host_override) = host_override {
        request_builder = request_builder.header(HOST, host_override);
    }

    match request_builder.send().await {
        Ok(response) => {
            let status = response.status();
            let resp_version = response.version();
            let response_headers = response.headers().clone();
            if let Err(error) = validate_supported_transfer_encoding(&response_headers) {
                let message = format!("Unsupported upstream response transfer encoding: {error}");
                notes.push(message.clone());
                session
                    .event_log
                    .push(
                        EventLevel::Warn,
                        "proxy",
                        "Unsupported upstream response transfer encoding",
                        message.clone(),
                    )
                    .await;
                let (_response, response_capture) = synthetic_error_response_for_method(
                    StatusCode::BAD_GATEWAY,
                    &message,
                    &state,
                    method.as_str(),
                );
                return ExecutedExchange {
                    record: with_record_http_versions(
                        TransactionRecord::http(
                            started_at,
                            method.to_string(),
                            request.scheme,
                            request.host,
                            path,
                            Some(StatusCode::BAD_GATEWAY.as_u16()),
                            started.elapsed().as_millis() as u64,
                            request_capture,
                            Some(response_capture),
                            notes,
                            original_request_capture,
                            None,
                        ),
                        request_http_version,
                        Some(Version::HTTP_11),
                    ),
                    response: Err(UpstreamError {
                        status: StatusCode::BAD_GATEWAY,
                        message,
                    }),
                };
            }
            match read_response_body_limited(response, MAX_PROXY_BUFFERED_RESPONSE_BODY_BYTES).await
            {
                Ok(response_bytes) => {
                    let original_response_capture = {
                        let pre = MessageRecord::from_headers_and_body(
                            &response_headers,
                            response_bytes.as_ref(),
                            state.config.body_preview_bytes,
                        );
                        Some(pre)
                    };
                    let applied_response = session
                        .match_replace
                        .apply_response(response_headers, response_bytes)
                        .await;
                    let original_response_capture = if applied_response.notes.is_empty() {
                        None
                    } else {
                        original_response_capture
                    };
                    if !applied_response.notes.is_empty() {
                        session
                            .event_log
                            .push(
                                EventLevel::Info,
                                "match_replace",
                                "Rules applied",
                                applied_response.notes.join(" | "),
                            )
                            .await;
                    }
                    notes.extend(applied_response.notes.clone());
                    let response_capture = MessageRecord::from_headers_and_body(
                        &applied_response.headers,
                        applied_response.body.as_ref(),
                        state.config.body_preview_bytes,
                    );
                    ExecutedExchange {
                        record: with_record_http_versions(
                            TransactionRecord::http(
                                started_at,
                                method.to_string(),
                                request.scheme,
                                request.host,
                                path,
                                Some(status.as_u16()),
                                started.elapsed().as_millis() as u64,
                                request_capture,
                                Some(response_capture),
                                notes,
                                original_request_capture,
                                original_response_capture,
                            ),
                            request_http_version,
                            Some(resp_version),
                        ),
                        response: Ok(UpstreamResponse {
                            status,
                            headers: applied_response.headers,
                            body: applied_response.body,
                        }),
                    }
                }
                Err(error) => {
                    let message = format!("Failed to read upstream response body: {error}");
                    notes.push(message.clone());
                    session
                        .event_log
                        .push(
                            EventLevel::Warn,
                            "proxy",
                            "Response read failed",
                            message.clone(),
                        )
                        .await;
                    let (_response, response_capture) = synthetic_error_response_for_method(
                        StatusCode::BAD_GATEWAY,
                        &message,
                        &state,
                        method.as_str(),
                    );
                    ExecutedExchange {
                        record: with_record_http_versions(
                            TransactionRecord::http(
                                started_at,
                                method.to_string(),
                                request.scheme,
                                request.host,
                                path,
                                Some(StatusCode::BAD_GATEWAY.as_u16()),
                                started.elapsed().as_millis() as u64,
                                request_capture,
                                Some(response_capture),
                                notes,
                                original_request_capture,
                                None,
                            ),
                            request_http_version,
                            Some(Version::HTTP_11),
                        ),
                        response: Err(UpstreamError {
                            status: StatusCode::BAD_GATEWAY,
                            message,
                        }),
                    }
                }
            }
        }
        Err(error) => {
            let message = format!("Upstream request failed: {error}");
            notes.push(message.clone());
            session
                .event_log
                .push(
                    EventLevel::Warn,
                    "proxy",
                    "Upstream request failed",
                    message.clone(),
                )
                .await;
            let (_response, response_capture) = synthetic_error_response_for_method(
                StatusCode::BAD_GATEWAY,
                &message,
                &state,
                method.as_str(),
            );
            ExecutedExchange {
                record: with_record_http_versions(
                    TransactionRecord::http(
                        started_at,
                        method.to_string(),
                        request.scheme,
                        request.host,
                        path,
                        Some(StatusCode::BAD_GATEWAY.as_u16()),
                        started.elapsed().as_millis() as u64,
                        request_capture,
                        Some(response_capture),
                        notes,
                        original_request_capture,
                        None,
                    ),
                    request_http_version,
                    Some(Version::HTTP_11),
                ),
                response: Err(UpstreamError {
                    status: StatusCode::BAD_GATEWAY,
                    message,
                }),
            }
        }
    }
}

async fn apply_request_match_replace(
    session: &SessionContext,
    request: EditableRequest,
    preview_bytes: usize,
) -> (EditableRequest, Vec<String>, Option<MessageRecord>) {
    let original_headers = header_map_from_records(&request.headers);
    let original_body = request.body_bytes();
    let applied_request = session.match_replace.apply_request(request).await;
    if !applied_request.notes.is_empty() {
        session
            .event_log
            .push(
                EventLevel::Info,
                "match_replace",
                "Rules applied",
                applied_request.notes.join(" | "),
            )
            .await;
    }
    let original_capture = if applied_request.notes.is_empty() {
        None
    } else {
        Some(MessageRecord::from_headers_and_body(
            &original_headers,
            original_body.as_ref(),
            preview_bytes,
        ))
    };
    (
        applied_request.request,
        applied_request.notes,
        original_capture,
    )
}

async fn validate_reusable_request_source(
    session: &SessionContext,
    request: &EditableRequest,
    source_transaction_id: Option<Uuid>,
) -> Result<()> {
    let Some(source_transaction_id) = source_transaction_id else {
        return Ok(());
    };
    let source_record = session
        .store
        .get(source_transaction_id)
        .await
        .ok_or_else(|| anyhow!("The captured request is no longer available in HTTP history."))?;
    if source_record.request.preview_truncated {
        let request_body = request.body_bytes();
        let Some(source_body_size) = reusable_source_full_body_size(&source_record.request) else {
            return Err(anyhow!(
                "The captured request body was truncated at the preview cap. Increase the preview cap and capture it again, or paste the full body manually before sending."
            ));
        };
        if request.preview_truncated
            || request_body == source_record.request.body_bytes()
            || request_body.len() < source_body_size
        {
            return Err(anyhow!(
                "The captured request body was truncated at the preview cap. Increase the preview cap and capture it again, or paste the full body manually before sending."
            ));
        }
    }
    Ok(())
}

fn reusable_source_full_body_size(request: &MessageRecord) -> Option<usize> {
    if request.content_decoded {
        request.decoded_body_size
    } else {
        Some(request.body_size)
    }
}

fn merge_notes(mut left: Vec<String>, mut right: Vec<String>) -> Vec<String> {
    left.append(&mut right);
    left
}

fn editable_request_from_parts(
    parts: &Parts,
    request_bytes: &Bytes,
    absolute_uri: &Uri,
) -> EditableRequest {
    let scheme = absolute_uri.scheme_str().unwrap_or("http").to_string();
    let host = absolute_uri
        .authority()
        .map(|authority| authority.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let path = absolute_uri
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    let plain_chunked_transfer = transfer_encoding_tokens(&parts.headers)
        .map(|codings| codings.len() == 1 && codings[0].eq_ignore_ascii_case("chunked"))
        .unwrap_or(false);
    let mut headers: Vec<HeaderRecord> = parts
        .headers
        .iter()
        .filter(|(name, _)| {
            !plain_chunked_transfer
                || (!name
                    .as_str()
                    .eq_ignore_ascii_case(TRANSFER_ENCODING.as_str())
                    && !name.as_str().eq_ignore_ascii_case(CONTENT_LENGTH.as_str()))
        })
        .map(|(name, value)| HeaderRecord {
            name: name.as_str().to_string(),
            value: String::from_utf8_lossy(value.as_bytes()).into_owned(),
        })
        .collect();
    if !headers
        .iter()
        .any(|header| header.name.eq_ignore_ascii_case("host"))
        && !host.is_empty()
    {
        headers.insert(
            0,
            HeaderRecord {
                name: "host".to_string(),
                value: host.clone(),
            },
        );
    }
    if plain_chunked_transfer {
        headers.push(HeaderRecord {
            name: CONTENT_LENGTH.as_str().to_string(),
            value: request_bytes.len().to_string(),
        });
    }

    let body_encoding = if is_raw_request_body_utf8(request_bytes.as_ref()) {
        BodyEncoding::Utf8
    } else {
        BodyEncoding::Base64
    };
    let body = match &body_encoding {
        BodyEncoding::Utf8 => String::from_utf8_lossy(request_bytes.as_ref()).into_owned(),
        BodyEncoding::Base64 => STANDARD.encode(request_bytes.as_ref()),
    };

    EditableRequest {
        scheme,
        host,
        method: parts.method.to_string(),
        path,
        headers,
        body,
        body_encoding,
        preview_truncated: false,
    }
}

fn is_raw_request_body_utf8(body: &[u8]) -> bool {
    std::str::from_utf8(body).is_ok() && !body.contains(&0)
}

fn header_map_from_records(headers: &[HeaderRecord]) -> HeaderMap {
    // Used to reconstruct outbound REQUEST headers (Replay, intercept-forward,
    // upstream proxy, etc.). Per RFC 7230 §3.2.2 and RFC 6265 §5.4, browsers
    // MUST send a single `Cookie:` header with `; ` separated pairs. Some
    // upstream servers reject requests with multiple `Cookie:` headers (502
    // upstream connect failure observed on hyper/h1 frame parsing). Consolidate
    // all Cookie values into one header to match real browser behaviour.
    //
    // Note: this function is REQUEST-side only. `Set-Cookie` (response) must
    // never be merged — those use the dedicated response path.
    let mut map = HeaderMap::new();
    let mut cookies: Vec<String> = Vec::new();
    for header in headers {
        let Ok(name) = HeaderName::from_bytes(header.name.as_bytes()) else {
            continue;
        };
        if name == COOKIE {
            let trimmed = header.value.trim();
            if !trimmed.is_empty() {
                cookies.push(trimmed.to_string());
            }
            continue;
        }
        if let Ok(value) = HeaderValue::from_str(&header.value) {
            map.append(name, value);
        }
    }
    if !cookies.is_empty() {
        if let Ok(value) = HeaderValue::from_str(&cookies.join("; ")) {
            map.insert(COOKIE, value);
        }
    }
    map
}

fn build_uri_from_request(
    request: &EditableRequest,
    authority_override: Option<&str>,
) -> Result<Uri> {
    let path = normalize_request_path(&request.path);
    if path == "*" {
        bail!("star-form request targets are not supported by replay send");
    }
    Uri::builder()
        .scheme(request.scheme.as_str())
        .authority(authority_override.unwrap_or(request.host.as_str()))
        .path_and_query(path)
        .build()
        .map_err(|error| anyhow!("failed to build upstream URI: {error}"))
}

fn replay_host_override(
    request_headers: &HeaderMap,
    outbound_uri_authority: Option<&str>,
    request_host: &str,
) -> Option<HeaderValue> {
    request_headers.get(HOST).cloned().or_else(|| {
        outbound_uri_authority
            .is_some()
            .then(|| HeaderValue::from_str(request_host).ok())
            .flatten()
    })
}

fn normalize_request_path(path: &str) -> String {
    if path.trim().is_empty() {
        "/".to_string()
    } else if path == "*" {
        "*".to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

fn synthetic_error_response(
    status: StatusCode,
    message: &str,
    state: &Arc<AppState>,
) -> (Response<Body>, MessageRecord) {
    synthetic_error_response_for_method(status, message, state, "GET")
}

fn synthetic_error_response_for_method(
    status: StatusCode,
    message: &str,
    state: &Arc<AppState>,
    request_method: &str,
) -> (Response<Body>, MessageRecord) {
    let response = text_response_for_method(status, message, request_method);
    let capture_body =
        local_response_wire_body(status, request_method, message.as_bytes().to_vec());
    let capture = MessageRecord::from_headers_and_body(
        response.headers(),
        capture_body.as_ref(),
        state.config.body_preview_bytes,
    );
    (response, capture)
}

struct DroppedExchange {
    record: TransactionRecord,
    response: Response<Body>,
}

fn build_dropped_transaction(
    state: &AppState,
    request: EditableRequest,
    started_at: chrono::DateTime<Utc>,
    started: Instant,
    note: &str,
    request_http_version: Option<Version>,
) -> DroppedExchange {
    let request_headers = header_map_from_records(&request.headers);
    let request_capture = MessageRecord::from_headers_and_body(
        &request_headers,
        &request.body_bytes(),
        state.config.body_preview_bytes,
    );
    let request_method = request.method.clone();
    let response = text_response_for_method(StatusCode::FORBIDDEN, note, &request_method);
    let capture_body = local_response_wire_body(
        StatusCode::FORBIDDEN,
        &request_method,
        note.as_bytes().to_vec(),
    );
    let response_capture = MessageRecord::from_headers_and_body(
        response.headers(),
        capture_body.as_ref(),
        state.config.body_preview_bytes,
    );
    DroppedExchange {
        record: with_record_http_versions(
            TransactionRecord::http(
                started_at,
                request.method,
                request.scheme,
                request.host,
                normalize_request_path(&request.path),
                Some(StatusCode::FORBIDDEN.as_u16()),
                started.elapsed().as_millis() as u64,
                request_capture,
                Some(response_capture),
                vec![note.to_string()],
                None,
                None,
            ),
            request_http_version,
            Some(Version::HTTP_11),
        ),
        response,
    }
}

fn is_websocket_upgrade_headers(headers: &HeaderMap) -> bool {
    header_values_contain_token(headers, UPGRADE, "websocket")
        && header_values_contain_token(headers, CONNECTION, "upgrade")
}

fn websocket_upgrade_validation_error(
    method: &Method,
    headers: &HeaderMap,
) -> Option<&'static str> {
    if method != Method::GET {
        return Some("WebSocket upgrade requests must use GET");
    }
    if headers.contains_key(TRANSFER_ENCODING) {
        return Some("WebSocket upgrade requests must not include a request body");
    }
    if headers.get_all(CONTENT_LENGTH).iter().any(|value| {
        value
            .to_str()
            .map(|value| value.trim() != "0")
            .unwrap_or(true)
    }) {
        return Some("WebSocket upgrade requests must not include a request body");
    }

    let key = match single_header_value(headers, SEC_WEBSOCKET_KEY) {
        Some(key) => key,
        None => return Some("missing or invalid Sec-WebSocket-Key"),
    };
    let decoded_key = match STANDARD.decode(key.as_bytes()) {
        Ok(decoded_key) => decoded_key,
        Err(_) => return Some("invalid Sec-WebSocket-Key"),
    };
    if decoded_key.len() != 16 {
        return Some("invalid Sec-WebSocket-Key");
    }

    let version = single_header_value(headers, SEC_WEBSOCKET_VERSION).map(str::trim);
    if version != Some("13") {
        return Some("unsupported Sec-WebSocket-Version");
    }

    None
}

fn single_header_value(headers: &HeaderMap, name: HeaderName) -> Option<&str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(first)
}

fn websocket_upgrade_validation_error_for_editable(
    request: &EditableRequest,
    headers: &HeaderMap,
) -> Option<&'static str> {
    if !request.method.eq_ignore_ascii_case("GET") {
        return Some("WebSocket upgrade requests must use GET");
    }
    if !request.body_bytes().is_empty() {
        return Some("WebSocket upgrade requests must not include a request body");
    }
    websocket_upgrade_validation_error(&Method::GET, headers)
}

fn header_values_contain_token(headers: &HeaderMap, name: HeaderName, token: &str) -> bool {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(token))
        })
}

fn is_websocket_upgrade_editable(request: &EditableRequest) -> bool {
    let headers = header_map_from_records(&request.headers);
    is_websocket_upgrade_headers(&headers)
}

fn websocket_upgrade_transaction_note(capture_enabled: bool) -> &'static str {
    if capture_enabled {
        "WebSocket upgrade proxied and mirrored into WebSockets history."
    } else {
        "WebSocket upgrade proxied; WebSocket capture is disabled."
    }
}

struct ConnectedWebSocket {
    websocket: UpstreamWebSocket,
    upstream_headers: HeaderMap,
}

enum UpstreamWebSocketConnectError {
    Http {
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
    },
    Other(anyhow::Error),
}

async fn connect_upstream_websocket(
    request: &EditableRequest,
    upstream_insecure: bool,
) -> std::result::Result<ConnectedWebSocket, UpstreamWebSocketConnectError> {
    let url = websocket_url(request).map_err(UpstreamWebSocketConnectError::Other)?;
    let mut upstream_request = url
        .into_client_request()
        .map_err(|error| UpstreamWebSocketConnectError::Other(anyhow!(error)))?;
    {
        let forwarded_headers = websocket_forward_headers_from_records(&request.headers);
        let headers = upstream_request.headers_mut();
        for (name, value) in forwarded_headers.iter() {
            if name == HOST {
                headers.insert(HOST, value.clone());
            } else {
                headers.append(name.clone(), value.clone());
            }
        }
    }

    let (websocket, response) = match connect_async_tls_with_config(
        upstream_request,
        None,
        false,
        crate::ws_tls::insecure_connector(upstream_insecure),
    )
    .await
    {
        Ok(response) => response,
        Err(TungsteniteError::Http(response)) => {
            let status = response.status();
            let headers = response.headers().clone();
            let body = Bytes::from(response.into_body().unwrap_or_default());
            return Err(UpstreamWebSocketConnectError::Http {
                status,
                headers,
                body,
            });
        }
        Err(error) => {
            return Err(UpstreamWebSocketConnectError::Other(
                anyhow!(error).context("upstream WebSocket handshake failed"),
            ));
        }
    };

    Ok(ConnectedWebSocket {
        websocket,
        upstream_headers: response.headers().clone(),
    })
}

pub(crate) fn websocket_forward_headers_from_records(records: &[HeaderRecord]) -> HeaderMap {
    let mut headers = header_map_from_records(records);
    strip_hop_by_hop_headers(&mut headers);
    let remove = headers
        .keys()
        .filter(|name| !should_forward_websocket_header(name.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    for name in remove {
        headers.remove(name);
    }
    headers
}

fn should_forward_websocket_header(name: &str) -> bool {
    !matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "upgrade"
            | "proxy-connection"
            | "content-length"
            | "sec-websocket-key"
            | "sec-websocket-version"
            | "sec-websocket-extensions"
            | "sec-websocket-accept"
    )
}

fn websocket_url(request: &EditableRequest) -> Result<String> {
    let scheme = match request.scheme.as_str() {
        "http" => "ws",
        "https" => "wss",
        "ws" => "ws",
        "wss" => "wss",
        other => return Err(anyhow!("unsupported WebSocket scheme: {other}")),
    };

    Ok(format!(
        "{scheme}://{}{}",
        request.host,
        normalize_request_path(&request.path)
    ))
}

fn build_websocket_client_response_headers(
    request_headers: &HeaderMap,
    upstream_headers: HeaderMap,
) -> Result<HeaderMap> {
    let websocket_key = single_header_value(request_headers, SEC_WEBSOCKET_KEY)
        .context("missing or invalid Sec-WebSocket-Key")?;
    let mut headers = upstream_headers;
    strip_hop_by_hop_headers(&mut headers);
    if headers.contains_key(SEC_WEBSOCKET_PROTOCOL) {
        let protocol = single_header_value(&headers, SEC_WEBSOCKET_PROTOCOL)
            .context("invalid upstream Sec-WebSocket-Protocol")?
            .trim();
        if protocol.is_empty() {
            anyhow::bail!("invalid upstream Sec-WebSocket-Protocol");
        }
    }
    headers.remove(SEC_WEBSOCKET_ACCEPT);
    headers.remove(SEC_WEBSOCKET_EXTENSIONS);
    headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
    headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
    headers.insert(
        SEC_WEBSOCKET_ACCEPT,
        HeaderValue::from_str(&derive_accept_key(websocket_key.as_bytes()))
            .context("failed to derive Sec-WebSocket-Accept")?,
    );

    if let Some(protocol) = headers.get(SEC_WEBSOCKET_PROTOCOL).cloned() {
        headers.insert(SEC_WEBSOCKET_PROTOCOL, protocol);
    }
    Ok(headers)
}

fn websocket_response_validation_error(
    request_headers: &HeaderMap,
    upstream_headers: &HeaderMap,
    response_headers: &HeaderMap,
) -> Option<&'static str> {
    if !is_websocket_upgrade_headers(response_headers) {
        return Some("missing WebSocket upgrade response headers");
    }

    let request_key = match single_header_value(request_headers, SEC_WEBSOCKET_KEY) {
        Some(value) => value,
        None => return Some("missing request Sec-WebSocket-Key"),
    };
    let expected_accept = derive_accept_key(request_key.as_bytes());
    let response_accept =
        single_header_value(response_headers, SEC_WEBSOCKET_ACCEPT).map(str::trim);
    if response_accept != Some(expected_accept.as_str()) {
        return Some("invalid Sec-WebSocket-Accept");
    }
    if response_headers.contains_key(SEC_WEBSOCKET_EXTENSIONS) {
        return Some("WebSocket extensions must not be negotiated by match/replace");
    }
    let response_protocol = if response_headers.contains_key(SEC_WEBSOCKET_PROTOCOL) {
        match single_header_value(response_headers, SEC_WEBSOCKET_PROTOCOL).map(str::trim) {
            Some(protocol) if !protocol.is_empty() => Some(protocol),
            _ => return Some("invalid Sec-WebSocket-Protocol"),
        }
    } else {
        None
    };
    let upstream_protocol = if upstream_headers.contains_key(SEC_WEBSOCKET_PROTOCOL) {
        match single_header_value(upstream_headers, SEC_WEBSOCKET_PROTOCOL).map(str::trim) {
            Some(protocol) if !protocol.is_empty() => Some(protocol),
            _ => return Some("invalid upstream Sec-WebSocket-Protocol"),
        }
    } else {
        None
    };
    if let Some(protocol) = response_protocol {
        let offered = request_headers
            .get_all(SEC_WEBSOCKET_PROTOCOL)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .map(str::trim)
            .any(|offered| !offered.is_empty() && offered == protocol);
        if !offered {
            return Some("Sec-WebSocket-Protocol was not offered by the client");
        }
    }
    if response_protocol != upstream_protocol {
        return Some("Sec-WebSocket-Protocol changed after upstream negotiation");
    }

    None
}

static LAST_PERSIST: Mutex<Option<Instant>> = Mutex::new(None);
static PERSIST_IN_FLIGHT: AtomicBool = AtomicBool::new(false);
static PERSIST_DIRTY_SESSIONS: LazyLock<Mutex<HashMap<Uuid, u64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static PERSIST_TRAILING_SESSIONS: LazyLock<Mutex<HashMap<Uuid, u64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static PERSIST_PENDING_CONTEXTS: LazyLock<Mutex<HashMap<Uuid, Arc<SessionContext>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static PERSIST_CONTEXT_GENERATIONS: LazyLock<Mutex<HashMap<Uuid, u64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NEXT_PERSIST_CONTEXT_GENERATION: AtomicU64 = AtomicU64::new(1);
static LIVE_WEBSOCKET_RELAYS: LazyLock<Mutex<HashMap<Uuid, LiveWebSocketRelay>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static ACTIVE_STREAMED_RESPONSE_PUMPS: LazyLock<Mutex<HashMap<Uuid, StreamedResponsePump>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static ACTIVE_PROXY_CONNECTIONS: LazyLock<Mutex<HashMap<Uuid, AbortHandle>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static ACTIVE_PROXY_SESSION_OWNERS: LazyLock<Mutex<HashMap<Uuid, usize>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
const PERSIST_DEBOUNCE: Duration = Duration::from_secs(2);
const PENDING_PERSIST_FLUSH_PROXY_WAIT: Duration = Duration::from_secs(1);
const PENDING_PERSIST_FLUSH_RETRY_LIMIT: usize = 3;
const PENDING_PERSIST_FLUSH_SWEEP_LIMIT: usize = 8;

#[derive(Clone)]
struct LiveWebSocketRelay {
    session: Arc<SessionContext>,
    captured_websocket_id: Option<Uuid>,
    started: Instant,
    abort: AbortHandle,
    close_persist_pending: Arc<AtomicBool>,
}

struct StreamedResponsePump {
    session_id: Uuid,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

pub(crate) struct ActiveProxySessionGuard {
    session_id: Uuid,
}

impl Drop for ActiveProxySessionGuard {
    fn drop(&mut self) {
        forget_active_proxy_session_owner(self.session_id);
    }
}

async fn persist_session_quiet(state: &Arc<AppState>, session: &Arc<SessionContext>) {
    let generation = remember_persist_context(session);

    if let Some(delay) = persist_debounce_remaining() {
        mark_persist_dirty_generation(session.id(), generation);
        schedule_delayed_persist(state, session, delay, generation);
        return;
    }

    if PERSIST_IN_FLIGHT.swap(true, Ordering::AcqRel) {
        mark_persist_dirty_generation(session.id(), generation);
        schedule_delayed_persist(state, session, PERSIST_DEBOUNCE, generation);
        return;
    }

    spawn_persist_task(Arc::clone(state), Arc::clone(session), generation);
}

async fn persist_session_immediate_quiet(state: &Arc<AppState>, session: &Arc<SessionContext>) {
    let generation = remember_persist_context(session);
    {
        let mut last = LAST_PERSIST.lock().unwrap_or_else(|e| e.into_inner());
        *last = Some(Instant::now());
    }
    if let Err(error) = state.persist_session_context(session).await {
        warn!(
            ?error,
            session_id = %session.id(),
            "failed to immediately persist session snapshot"
        );
        mark_persist_dirty_generation(session.id(), generation);
        schedule_delayed_persist(state, session, PERSIST_DEBOUNCE, generation);
        return;
    }
    forget_persist_state_if_generation(session.id(), generation);
}

fn persist_debounce_remaining() -> Option<Duration> {
    let last = LAST_PERSIST.lock().unwrap_or_else(|e| e.into_inner());
    last.and_then(|ts| PERSIST_DEBOUNCE.checked_sub(ts.elapsed()))
}

fn schedule_delayed_persist(
    state: &Arc<AppState>,
    session: &Arc<SessionContext>,
    delay: Duration,
    generation: u64,
) {
    let session_id = session.id();
    {
        let mut scheduled = PERSIST_TRAILING_SESSIONS
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if scheduled
            .get(&session_id)
            .is_some_and(|existing| *existing >= generation)
        {
            return;
        }
        scheduled.insert(session_id, generation);
    }
    let state = Arc::clone(state);
    let session = Arc::clone(session);
    tokio::spawn(async move {
        tokio::time::sleep(delay).await;
        if !clear_trailing_persist_if_generation(session_id, generation) {
            return;
        }
        if !take_persist_dirty_if_generation(session_id, generation) {
            forget_persist_context_if_clean(session_id, generation);
            return;
        }
        start_persist_or_reschedule(state, session, generation);
    });
}

fn start_persist_or_reschedule(
    state: Arc<AppState>,
    session: Arc<SessionContext>,
    generation: u64,
) {
    if let Some(delay) = persist_debounce_remaining() {
        mark_persist_dirty_generation(session.id(), generation);
        schedule_delayed_persist(&state, &session, delay, generation);
        return;
    }

    if PERSIST_IN_FLIGHT.swap(true, Ordering::AcqRel) {
        mark_persist_dirty_generation(session.id(), generation);
        schedule_delayed_persist(&state, &session, PERSIST_DEBOUNCE, generation);
        return;
    }

    spawn_persist_task(state, session, generation);
}

fn spawn_persist_task(state: Arc<AppState>, session: Arc<SessionContext>, generation: u64) {
    {
        let mut last = LAST_PERSIST.lock().unwrap_or_else(|e| e.into_inner());
        *last = Some(Instant::now());
    }

    tokio::spawn(async move {
        if let Err(error) = state.persist_session_context(&session).await {
            warn!(?error, session_id = %session.id(), "failed to persist session snapshot");
            mark_persist_dirty_generation(session.id(), generation);
        }
        PERSIST_IN_FLIGHT.store(false, Ordering::Release);
        if has_persist_dirty(session.id()) {
            let generation = current_persist_generation(session.id()).unwrap_or(generation);
            schedule_delayed_persist(&state, &session, PERSIST_DEBOUNCE, generation);
        } else {
            forget_persist_context_if_clean(session.id(), generation);
        }
    });
}

fn mark_session_persist_pending(state: &Arc<AppState>, session: &Arc<SessionContext>) {
    let generation = remember_persist_context_once_and_mark_dirty(session);
    schedule_delayed_persist(state, session, PERSIST_DEBOUNCE, generation);
}

fn remember_persist_context(session: &Arc<SessionContext>) -> u64 {
    let generation = NEXT_PERSIST_CONTEXT_GENERATION.fetch_add(1, Ordering::Relaxed);
    let mut pending = PERSIST_PENDING_CONTEXTS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    pending.insert(session.id(), Arc::clone(session));
    let mut generations = PERSIST_CONTEXT_GENERATIONS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    generations.insert(session.id(), generation);
    generation
}

fn remember_persist_context_once_and_mark_dirty(session: &Arc<SessionContext>) -> u64 {
    let session_id = session.id();
    let mut pending = PERSIST_PENDING_CONTEXTS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let mut generations = PERSIST_CONTEXT_GENERATIONS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let generation = if pending.contains_key(&session_id) {
        generations
            .get(&session_id)
            .copied()
            .unwrap_or_else(|| NEXT_PERSIST_CONTEXT_GENERATION.fetch_add(1, Ordering::Relaxed))
    } else {
        NEXT_PERSIST_CONTEXT_GENERATION.fetch_add(1, Ordering::Relaxed)
    };
    pending.insert(session_id, Arc::clone(session));
    generations.insert(session_id, generation);
    mark_persist_dirty_generation(session_id, generation);
    generation
}

#[cfg(test)]
pub(crate) fn remember_pending_persist_context_for_test(session: &Arc<SessionContext>) -> u64 {
    remember_persist_context(session)
}

fn forget_persist_context_if_generation(session_id: Uuid, generation: u64) -> bool {
    let mut pending = PERSIST_PENDING_CONTEXTS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let mut generations = PERSIST_CONTEXT_GENERATIONS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if generations.get(&session_id).copied() != Some(generation) {
        return false;
    }
    pending.remove(&session_id);
    generations.remove(&session_id);
    true
}

fn forget_persist_state_if_generation(session_id: Uuid, generation: u64) -> bool {
    if !forget_persist_context_if_generation(session_id, generation) {
        return false;
    }
    take_persist_dirty_if_generation(session_id, generation);
    clear_trailing_persist_if_generation(session_id, generation);
    true
}

fn forget_persist_context_if_clean(session_id: Uuid, generation: u64) -> bool {
    let mut pending = PERSIST_PENDING_CONTEXTS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let mut generations = PERSIST_CONTEXT_GENERATIONS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if generations.get(&session_id).copied() != Some(generation) {
        return false;
    }
    let dirty = PERSIST_DIRTY_SESSIONS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if dirty.contains_key(&session_id) {
        return false;
    }
    let trailing = PERSIST_TRAILING_SESSIONS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if trailing.contains_key(&session_id) {
        return false;
    }
    drop(trailing);
    drop(dirty);
    pending.remove(&session_id);
    generations.remove(&session_id);
    true
}

#[cfg(test)]
pub(crate) fn forget_pending_persist_context_for_test(session_id: Uuid, generation: u64) -> bool {
    forget_persist_context_if_generation(session_id, generation)
}

fn current_persist_generation(session_id: Uuid) -> Option<u64> {
    let generations = PERSIST_CONTEXT_GENERATIONS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    generations.get(&session_id).copied()
}

fn remember_live_websocket_relay(
    relay_id: Uuid,
    captured_websocket_id: Option<Uuid>,
    session: &Arc<SessionContext>,
    started: Instant,
    abort: AbortHandle,
) {
    let mut relays = LIVE_WEBSOCKET_RELAYS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    relays.insert(
        relay_id,
        LiveWebSocketRelay {
            session: Arc::clone(session),
            captured_websocket_id,
            started,
            abort,
            close_persist_pending: Arc::new(AtomicBool::new(false)),
        },
    );
}

fn forget_live_websocket_relay(relay_id: Uuid) {
    let mut relays = LIVE_WEBSOCKET_RELAYS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    relays.remove(&relay_id);
}

fn forget_live_websocket_relay_unless_close_pending(relay_id: Uuid) {
    let mut relays = LIVE_WEBSOCKET_RELAYS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if relays
        .get(&relay_id)
        .map(|relay| relay.close_persist_pending.load(Ordering::Acquire))
        .unwrap_or(false)
    {
        return;
    }
    relays.remove(&relay_id);
}

fn claim_live_websocket_relay_close_persist(relay_id: Uuid) -> bool {
    let relays = LIVE_WEBSOCKET_RELAYS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    relays
        .get(&relay_id)
        .map(|relay| {
            relay
                .close_persist_pending
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        })
        .unwrap_or(false)
}

async fn close_aborted_live_websocket_relay(
    state: &Arc<AppState>,
    session: &Arc<SessionContext>,
    relay_id: Uuid,
    captured_websocket_id: Option<Uuid>,
    started: Instant,
    note: &'static str,
) {
    let Some(websocket_id) = captured_websocket_id else {
        return;
    };
    if !claim_live_websocket_relay_close_persist(relay_id) {
        return;
    }
    if let Err(error) = session
        .close_websocket_capture(
            websocket_id,
            Utc::now(),
            started.elapsed().as_millis() as u64,
            Some(note.to_string()),
        )
        .await
    {
        warn!(
            ?error,
            websocket_id = %websocket_id,
            "failed to journal captured WebSocket abort close"
        );
    }
    persist_session_quiet(state, session).await;
    forget_live_websocket_relay(relay_id);
}

fn remember_streamed_response_pump(
    pump_id: Uuid,
    session_id: Uuid,
    shutdown: tokio::sync::oneshot::Sender<()>,
) {
    let mut pumps = ACTIVE_STREAMED_RESPONSE_PUMPS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    pumps.insert(
        pump_id,
        StreamedResponsePump {
            session_id,
            shutdown,
        },
    );
}

fn forget_streamed_response_pump(pump_id: Uuid) {
    let mut pumps = ACTIVE_STREAMED_RESPONSE_PUMPS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    pumps.remove(&pump_id);
}

fn signal_streamed_response_pumps(session_id: Uuid) -> usize {
    let pumps = {
        let mut active = ACTIVE_STREAMED_RESPONSE_PUMPS
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let pump_ids = active
            .iter()
            .filter_map(|(pump_id, pump)| (pump.session_id == session_id).then_some(*pump_id))
            .collect::<Vec<_>>();
        pump_ids
            .into_iter()
            .filter_map(|pump_id| active.remove(&pump_id))
            .collect::<Vec<_>>()
    };
    let count = pumps.len();
    for pump in pumps {
        let _ = pump.shutdown.send(());
    }
    count
}

fn remember_proxy_connection(connection_id: Uuid, abort: AbortHandle) {
    let mut connections = ACTIVE_PROXY_CONNECTIONS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    connections.insert(connection_id, abort);
}

fn forget_proxy_connection(connection_id: Uuid) {
    let mut connections = ACTIVE_PROXY_CONNECTIONS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    connections.remove(&connection_id);
}

pub(crate) fn remember_active_proxy_session_owner(session_id: Uuid) -> ActiveProxySessionGuard {
    let mut owners = ACTIVE_PROXY_SESSION_OWNERS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    *owners.entry(session_id).or_insert(0) += 1;
    ActiveProxySessionGuard { session_id }
}

fn forget_active_proxy_session_owner(session_id: Uuid) {
    let mut owners = ACTIVE_PROXY_SESSION_OWNERS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if let Some(count) = owners.get_mut(&session_id) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            owners.remove(&session_id);
        }
    }
}

pub fn session_has_active_proxy_work(session_id: Uuid) -> bool {
    let owners = ACTIVE_PROXY_SESSION_OWNERS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    owners.get(&session_id).copied().unwrap_or(0) > 0
}

fn active_proxy_work_is_empty() -> bool {
    let connections_empty = {
        let connections = ACTIVE_PROXY_CONNECTIONS
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        connections.is_empty()
    };
    if !connections_empty {
        return false;
    }
    let owners = ACTIVE_PROXY_SESSION_OWNERS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    owners.is_empty()
}

fn spawn_tracked_proxy_task<F>(session_id: Uuid, future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    let connection_id = Uuid::new_v4();
    let (abort, registration) = AbortHandle::new_pair();
    let session_owner = remember_active_proxy_session_owner(session_id);
    remember_proxy_connection(connection_id, abort);
    tokio::spawn(async move {
        let _session_owner = session_owner;
        let _ = Abortable::new(future, registration).await;
        forget_proxy_connection(connection_id);
    });
}

pub async fn drain_proxy_connections(timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        if active_proxy_work_is_empty() {
            return;
        }
        if Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let connections = {
        let connections = ACTIVE_PROXY_CONNECTIONS
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        connections.values().cloned().collect::<Vec<_>>()
    };
    for connection in connections {
        connection.abort();
    }

    let deadline = Instant::now() + timeout;
    loop {
        if active_proxy_work_is_empty() || Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

pub async fn close_live_websocket_relays(state: &AppState, note: &'static str) -> Result<()> {
    let relays = {
        let relays = LIVE_WEBSOCKET_RELAYS
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        relays
            .iter()
            .map(|(websocket_id, relay)| (*websocket_id, relay.clone()))
            .collect::<Vec<_>>()
    };

    let mut sessions_to_persist = HashMap::new();
    let mut relay_ids_by_session: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
    for (relay_id, relay) in relays {
        if !state.sessions.contains_session(relay.session.id()) {
            if pending_session_belongs_to_state(state, relay.session.as_ref()) {
                relay.abort.abort();
                forget_live_websocket_relay(relay_id);
            }
            continue;
        }
        relay.abort.abort();
        if let Some(websocket_id) = relay.captured_websocket_id {
            relay.close_persist_pending.store(true, Ordering::Release);
            if let Err(error) = relay
                .session
                .close_websocket_capture(
                    websocket_id,
                    Utc::now(),
                    relay.started.elapsed().as_millis() as u64,
                    Some(note.to_string()),
                )
                .await
            {
                warn!(
                    ?error,
                    websocket_id = %websocket_id,
                    "failed to journal captured WebSocket shutdown close"
                );
            }
            let session_id = relay.session.id();
            sessions_to_persist.insert(session_id, Arc::clone(&relay.session));
            relay_ids_by_session
                .entry(session_id)
                .or_default()
                .push(relay_id);
        } else {
            forget_live_websocket_relay(relay_id);
        }
    }

    let mut failures = Vec::new();
    for (session_id, session) in sessions_to_persist {
        let pending_generation = current_persist_generation(session_id);
        if let Some(generation) = pending_generation {
            take_persist_dirty_if_generation(session_id, generation);
        }
        if let Err(error) = state.persist_session_context(&session).await {
            if let Some(generation) = pending_generation {
                mark_persist_dirty_generation(session_id, generation);
            }
            warn!(
                ?error,
                session_id = %session_id,
                "failed to persist closed live websocket relays"
            );
            failures.push(format!("{session_id}: {error:#}"));
        } else if let Some(relay_ids) = relay_ids_by_session.remove(&session_id) {
            if let Some(generation) = pending_generation {
                if !has_persist_dirty(session_id) {
                    clear_trailing_persist_if_generation(session_id, generation);
                    forget_persist_context_if_clean(session_id, generation);
                }
            }
            for relay_id in relay_ids {
                forget_live_websocket_relay(relay_id);
            }
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        bail!(
            "failed to persist closed live websocket relays for {} session(s): {}",
            failures.len(),
            failures.join("; ")
        )
    }
}

pub fn session_has_live_websocket_relays(session_id: Uuid) -> bool {
    let relays = LIVE_WEBSOCKET_RELAYS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    relays
        .values()
        .any(|relay| relay.session.id() == session_id)
}

pub fn live_websocket_session_context(session_id: Uuid) -> Option<Arc<SessionContext>> {
    let relays = LIVE_WEBSOCKET_RELAYS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    relays
        .values()
        .find(|relay| relay.session.id() == session_id)
        .map(|relay| Arc::clone(&relay.session))
}

pub fn pending_session_context(session_id: Uuid) -> Option<Arc<SessionContext>> {
    let pending = PERSIST_PENDING_CONTEXTS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    pending.get(&session_id).cloned()
}

pub fn session_has_pending_persist(session_id: Uuid) -> bool {
    let pending = PERSIST_PENDING_CONTEXTS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if pending.contains_key(&session_id) {
        return true;
    }
    drop(pending);
    if has_persist_dirty(session_id) {
        return true;
    }
    let trailing = PERSIST_TRAILING_SESSIONS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    trailing.contains_key(&session_id)
}

pub async fn flush_pending_session_persists(state: &AppState) -> Result<()> {
    let mut failures = Vec::new();

    for _ in 0..PENDING_PERSIST_FLUSH_SWEEP_LIMIT {
        let sessions = {
            let pending = PERSIST_PENDING_CONTEXTS
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let generations = PERSIST_CONTEXT_GENERATIONS
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            pending
                .iter()
                .filter_map(|(session_id, session)| {
                    if !state.sessions.contains_session(*session_id)
                        && !pending_session_belongs_to_state(state, session.as_ref())
                    {
                        return None;
                    }
                    generations
                        .get(session_id)
                        .copied()
                        .map(|generation| (Arc::clone(session), generation))
                })
                .collect::<Vec<_>>()
        };
        if sessions.is_empty() {
            break;
        }

        for (session, generation) in sessions {
            let session_id = session.id();
            if !state.sessions.contains_session(session_id) {
                if pending_session_belongs_to_state(state, session.as_ref()) {
                    forget_persist_state_if_generation(session_id, generation);
                }
                continue;
            }
            wait_for_session_proxy_work_to_finish(session_id, PENDING_PERSIST_FLUSH_PROXY_WAIT)
                .await;
            let mut attempts = 0;
            loop {
                if current_persist_generation(session_id) != Some(generation) {
                    break;
                }
                attempts += 1;
                take_persist_dirty_if_generation(session_id, generation);
                if let Err(error) = state.persist_session_context(&session).await {
                    warn!(
                        ?error,
                        session_id = %session_id,
                        "failed to flush pending session snapshot"
                    );
                    mark_persist_dirty_generation(session_id, generation);
                    failures.push(anyhow!(
                        "failed to persist pending session {session_id}: {error}"
                    ));
                    break;
                }
                if take_persist_dirty_if_generation(session_id, generation) {
                    if attempts >= PENDING_PERSIST_FLUSH_RETRY_LIMIT {
                        mark_persist_dirty_generation(session_id, generation);
                        failures.push(anyhow!(
                            "session {session_id} changed while flushing pending capture persistence"
                        ));
                        break;
                    }
                    continue;
                }
                clear_trailing_persist_if_generation(session_id, generation);
                if forget_persist_context_if_clean(session_id, generation) {
                    break;
                }
                if current_persist_generation(session_id) != Some(generation) {
                    break;
                }
                if attempts >= PENDING_PERSIST_FLUSH_RETRY_LIMIT {
                    failures.push(anyhow!(
                        "session {session_id} still has pending capture persistence after flush"
                    ));
                    break;
                }
            }
        }
        if !failures.is_empty() || pending_persist_session_count_for_state(state) == 0 {
            break;
        }
    }
    let remaining = pending_persist_session_count_for_state(state);
    if failures.is_empty() && remaining == 0 {
        Ok(())
    } else {
        if remaining > 0 {
            failures.push(anyhow!(
                "{remaining} pending session persist(s) remained after flush"
            ));
        }
        Err(anyhow!(
            "{} pending session persist(s) failed: {}",
            failures.len(),
            failures
                .into_iter()
                .map(|error| error.to_string())
                .collect::<Vec<_>>()
                .join("; ")
        ))
    }
}

fn pending_session_belongs_to_state(state: &AppState, session: &SessionContext) -> bool {
    session
        .storage_dir()
        .parent()
        .is_some_and(|parent| parent == state.config.data_dir.join(crate::session::SESSIONS_DIR))
}

fn pending_persist_session_count_for_state(state: &AppState) -> usize {
    let pending = PERSIST_PENDING_CONTEXTS
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    pending
        .iter()
        .filter(|(session_id, session)| {
            state.sessions.contains_session(**session_id)
                || pending_session_belongs_to_state(state, session.as_ref())
        })
        .count()
}

async fn wait_for_session_proxy_work_to_finish(session_id: Uuid, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while session_has_active_proxy_work(session_id) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let signaled_stream_pumps = if session_has_active_proxy_work(session_id) {
        signal_streamed_response_pumps(session_id)
    } else {
        0
    };
    if signaled_stream_pumps > 0 {
        let deadline = Instant::now() + timeout;
        while session_has_active_proxy_work(session_id) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    if session_has_active_proxy_work(session_id) {
        warn!(
            session_id = %session_id,
            signaled_stream_pumps,
            "flushing pending session snapshot while proxy activity is still running"
        );
    }
}

fn mark_persist_dirty_generation(session_id: Uuid, generation: u64) {
    let mut dirty = PERSIST_DIRTY_SESSIONS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    dirty
        .entry(session_id)
        .and_modify(|existing| *existing = (*existing).max(generation))
        .or_insert(generation);
}

fn take_persist_dirty_if_generation(session_id: Uuid, generation: u64) -> bool {
    let mut dirty = PERSIST_DIRTY_SESSIONS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if dirty
        .get(&session_id)
        .is_none_or(|dirty_generation| *dirty_generation > generation)
    {
        return false;
    }
    dirty.remove(&session_id);
    true
}

fn has_persist_dirty(session_id: Uuid) -> bool {
    let dirty = PERSIST_DIRTY_SESSIONS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    dirty.contains_key(&session_id)
}

#[cfg(test)]
fn clear_trailing_persist(session_id: Uuid) {
    let mut scheduled = PERSIST_TRAILING_SESSIONS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    scheduled.remove(&session_id);
}

fn clear_trailing_persist_if_generation(session_id: Uuid, generation: u64) -> bool {
    let mut scheduled = PERSIST_TRAILING_SESSIONS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if scheduled.get(&session_id).copied() != Some(generation) {
        return false;
    }
    scheduled.remove(&session_id);
    true
}

async fn append_captured_websocket_frame(
    state: &Arc<AppState>,
    session: &Arc<SessionContext>,
    id: Uuid,
    frame: WebSocketFrameRecord,
) {
    match session.append_websocket_capture_frame(id, frame).await {
        Ok(true) => mark_session_persist_pending(state, session),
        Ok(false) => {}
        Err(error) => warn!(
            ?error,
            websocket_id = %id,
            "failed to journal captured WebSocket frame"
        ),
    }
}

async fn relay_websocket_session(
    on_upgrade: hyper::upgrade::OnUpgrade,
    upstream_ws: UpstreamWebSocket,
    state: Arc<AppState>,
    session: Arc<SessionContext>,
    session_id: Option<Uuid>,
    started: Instant,
) -> Result<()> {
    let upgraded = on_upgrade
        .await
        .context("client websocket upgrade did not complete")?;
    let client_ws =
        WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, None).await;

    let (mut client_sink, mut client_stream) = client_ws.split();
    let (mut upstream_sink, mut upstream_stream) = upstream_ws.split();
    let mut frame_index = 0_usize;
    let max_preview = state
        .config
        .body_preview_bytes
        .min(WEBSOCKET_CAPTURE_PREVIEW_BYTES);
    let close_note = loop {
        tokio::select! {
            message = client_stream.next() => {
                match message {
                    Some(Ok(message)) => {
                        if !should_relay_websocket_frame(&message) {
                            if let Some(id) = session_id {
                                if let Some(frame) = capture_websocket_frame(
                                    frame_index,
                                    WebSocketFrameDirection::ClientToServer,
                                    &message,
                                    max_preview,
                                ) {
                                    append_captured_websocket_frame(&state, &session, id, frame).await;
                                    frame_index += 1;
                                }
                            }
                            if let WebSocketMessage::Ping(payload) = &message {
                                let reply = WebSocketMessage::Pong(payload.clone());
                                if let Some(id) = session_id {
                                    if let Some(frame) = capture_websocket_frame(
                                        frame_index,
                                        WebSocketFrameDirection::ServerToClient,
                                        &reply,
                                        max_preview,
                                    ) {
                                        append_captured_websocket_frame(&state, &session, id, frame).await;
                                        frame_index += 1;
                                    }
                                }
                            }
                            continue;
                        }
                        let should_close = message.is_close();
                        let captured_message = message.clone();
                        if let Some(id) = session_id {
                            if let Some(frame) = capture_websocket_frame(
                                frame_index,
                                WebSocketFrameDirection::ClientToServer,
                                &captured_message,
                                max_preview,
                            ) {
                                append_captured_websocket_frame(&state, &session, id, frame).await;
                                frame_index += 1;
                            }
                        }
                        upstream_sink
                            .send(message)
                            .await
                            .context("failed to relay client websocket frame upstream")?;
                        if should_close {
                            if let Err(error) = client_sink.close().await {
                                warn!(?error, "failed to flush client websocket close reply");
                            }
                            if let Err(error) = upstream_sink.close().await {
                                warn!(?error, "failed to flush upstream websocket close");
                            }
                            break Some("Client initiated websocket close.".to_string());
                        }
                    }
                    Some(Err(error)) => {
                        break Some(format!("Client websocket stream error: {error}"));
                    }
                    None => {
                        break Some("Client websocket stream ended.".to_string());
                    }
                }
            }
            message = upstream_stream.next() => {
                match message {
                    Some(Ok(message)) => {
                        if !should_relay_websocket_frame(&message) {
                            if let Some(id) = session_id {
                                if let Some(frame) = capture_websocket_frame(
                                    frame_index,
                                    WebSocketFrameDirection::ServerToClient,
                                    &message,
                                    max_preview,
                                ) {
                                    append_captured_websocket_frame(&state, &session, id, frame).await;
                                    frame_index += 1;
                                }
                            }
                            if let WebSocketMessage::Ping(payload) = &message {
                                let reply = WebSocketMessage::Pong(payload.clone());
                                if let Some(id) = session_id {
                                    if let Some(frame) = capture_websocket_frame(
                                        frame_index,
                                        WebSocketFrameDirection::ClientToServer,
                                        &reply,
                                        max_preview,
                                    ) {
                                        append_captured_websocket_frame(&state, &session, id, frame).await;
                                        frame_index += 1;
                                    }
                                }
                            }
                            continue;
                        }
                        let should_close = message.is_close();
                        let captured_message = message.clone();
                        if let Some(id) = session_id {
                            if let Some(frame) = capture_websocket_frame(
                                frame_index,
                                WebSocketFrameDirection::ServerToClient,
                                &captured_message,
                                max_preview,
                            ) {
                                append_captured_websocket_frame(&state, &session, id, frame).await;
                                frame_index += 1;
                            }
                        }
                        client_sink
                            .send(message)
                            .await
                            .context("failed to relay upstream websocket frame to client")?;
                        if should_close {
                            if let Err(error) = upstream_sink.close().await {
                                warn!(?error, "failed to flush upstream websocket close reply");
                            }
                            if let Err(error) = client_sink.close().await {
                                warn!(?error, "failed to flush client websocket close");
                            }
                            break Some("Upstream websocket closed the connection.".to_string());
                        }
                    }
                    Some(Err(error)) => {
                        break Some(format!("Upstream websocket stream error: {error}"));
                    }
                    None => {
                        break Some("Upstream websocket stream ended.".to_string());
                    }
                }
            }
        }
    };

    if let Some(id) = session_id {
        if let Err(error) = session
            .close_websocket_capture(
                id,
                Utc::now(),
                started.elapsed().as_millis() as u64,
                close_note.clone(),
            )
            .await
        {
            warn!(
                ?error,
                websocket_id = %id,
                "failed to journal captured WebSocket close"
            );
        }
        session
            .event_log
            .push(
                EventLevel::Info,
                "websocket",
                "Session closed",
                close_note.unwrap_or_else(|| "WebSocket relay finished.".to_string()),
            )
            .await;
        persist_session_quiet(&state, &session).await;
    }

    Ok(())
}

fn should_relay_websocket_frame(message: &WebSocketMessage) -> bool {
    !message.is_ping()
}

fn capture_websocket_frame(
    index: usize,
    direction: WebSocketFrameDirection,
    message: &WebSocketMessage,
    max_preview: usize,
) -> Option<WebSocketFrameRecord> {
    let captured_at = Utc::now();
    let max_preview = max_preview.min(WEBSOCKET_CAPTURE_PREVIEW_BYTES);

    match message {
        WebSocketMessage::Text(text) => {
            let (preview, truncated) = websocket_text_preview(text, max_preview);
            Some(WebSocketFrameRecord {
                index,
                captured_at,
                direction,
                kind: WebSocketFrameKind::Text,
                body_preview: preview.to_string(),
                body_encoding: BodyEncoding::Utf8,
                body_size: text.len(),
                preview_truncated: truncated,
            })
        }
        WebSocketMessage::Binary(bytes) => Some(binary_frame_record(
            index,
            captured_at,
            direction,
            WebSocketFrameKind::Binary,
            bytes,
            max_preview,
        )),
        WebSocketMessage::Ping(bytes) => Some(binary_frame_record(
            index,
            captured_at,
            direction,
            WebSocketFrameKind::Ping,
            bytes,
            max_preview,
        )),
        WebSocketMessage::Pong(bytes) => Some(binary_frame_record(
            index,
            captured_at,
            direction,
            WebSocketFrameKind::Pong,
            bytes,
            max_preview,
        )),
        WebSocketMessage::Close(frame) => {
            let preview = frame
                .as_ref()
                .map(|frame| format!("{} {}", frame.code, frame.reason))
                .unwrap_or_else(|| "close".to_string());
            Some(WebSocketFrameRecord {
                index,
                captured_at,
                direction,
                kind: WebSocketFrameKind::Close,
                body_preview: preview,
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                preview_truncated: false,
            })
        }
        _ => None,
    }
}

fn websocket_text_preview(text: &str, max_preview: usize) -> (&str, bool) {
    if text.len() <= max_preview {
        return (text, false);
    }

    let end = text
        .char_indices()
        .map(|(idx, ch)| idx + ch.len_utf8())
        .take_while(|end| *end <= max_preview)
        .last()
        .unwrap_or(0);
    (&text[..end], true)
}

fn binary_frame_record(
    index: usize,
    captured_at: chrono::DateTime<Utc>,
    direction: WebSocketFrameDirection,
    kind: WebSocketFrameKind,
    bytes: &[u8],
    max_preview: usize,
) -> WebSocketFrameRecord {
    let preview_len = max_preview.min(bytes.len());
    WebSocketFrameRecord {
        index,
        captured_at,
        direction,
        kind,
        body_preview: STANDARD.encode(&bytes[..preview_len]),
        body_encoding: BodyEncoding::Base64,
        body_size: bytes.len(),
        preview_truncated: bytes.len() > max_preview,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{HeaderRecord, TransactionRecord};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn record(name: &str, value: &str) -> HeaderRecord {
        HeaderRecord {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    #[test]
    fn transfer_encoding_validation_allows_identity_and_plain_chunked() {
        let mut headers = HeaderMap::new();
        assert!(validate_supported_transfer_encoding(&headers).is_ok());

        headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        assert!(validate_supported_transfer_encoding(&headers).is_ok());
    }

    #[test]
    fn transfer_encoding_validation_rejects_unsupported_coding_chains() {
        let mut headers = HeaderMap::new();
        headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("gzip, chunked"));

        let error = validate_supported_transfer_encoding(&headers).unwrap_err();

        assert!(error.contains("gzip, chunked"));
    }

    fn editable_request(host: &str) -> EditableRequest {
        EditableRequest {
            scheme: "https".to_string(),
            host: host.to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: vec![record("Host", host)],
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        }
    }

    fn message_record_with_sizes(
        body_size: usize,
        decoded_body_size: Option<usize>,
        content_decoded: bool,
    ) -> MessageRecord {
        MessageRecord {
            headers: Vec::new(),
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size,
            decoded_body_size,
            preview_truncated: true,
            content_type: None,
            content_decoded,
        }
    }

    fn test_proxy_state(name: &str) -> (Arc<AppState>, std::path::PathBuf) {
        let data_dir = std::env::temp_dir().join(format!("{name}-{}", Uuid::new_v4()));
        let config = crate::config::AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 32,
            max_transaction_entries: 32,
            body_preview_bytes: 1024,
            data_dir: data_dir.clone(),
        };
        (Arc::new(AppState::new(config).unwrap()), data_dir)
    }

    fn ws_text_frame(index: usize) -> WebSocketFrameRecord {
        WebSocketFrameRecord {
            index,
            captured_at: Utc::now(),
            direction: WebSocketFrameDirection::ClientToServer,
            kind: WebSocketFrameKind::Text,
            body_preview: format!("frame-{index}"),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            preview_truncated: false,
        }
    }

    fn captured_transaction(host: &str) -> TransactionRecord {
        TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            host.to_string(),
            "/".to_string(),
            Some(200),
            5,
            MessageRecord::from_headers_and_body(&HeaderMap::new(), &[], 1024),
            Some(MessageRecord::from_headers_and_body(
                &HeaderMap::new(),
                b"ok",
                1024,
            )),
            Vec::new(),
            None,
            None,
        )
    }

    async fn response_from_raw(raw_response: &'static [u8]) -> reqwest::Response {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer).await.unwrap();
            stream.write_all(raw_response).await.unwrap();
        });
        reqwest::Client::new()
            .get(format!("http://{addr}/"))
            .send()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn read_response_body_limited_rejects_large_content_length() {
        let response = response_from_raw(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n").await;

        let error = read_response_body_limited(response, 3).await.unwrap_err();

        assert!(error.to_string().contains("exceeds 3 bytes"));
    }

    #[tokio::test]
    async fn read_response_body_limited_rejects_stream_over_limit() {
        let response = response_from_raw(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nabcd").await;

        let error = read_response_body_limited(response, 3).await.unwrap_err();

        assert!(error.to_string().contains("exceeds 3 bytes"));
    }

    #[test]
    fn reusable_source_size_uses_decoded_size_for_compressed_capture() {
        let record = message_record_with_sizes(20, Some(200), true);

        assert_eq!(reusable_source_full_body_size(&record), Some(200));
    }

    #[test]
    fn reusable_source_size_fails_closed_for_legacy_decoded_capture() {
        let record = message_record_with_sizes(20, None, true);

        assert_eq!(reusable_source_full_body_size(&record), None);
    }

    #[test]
    fn in_flight_persist_completion_does_not_consume_dirty_marker() {
        let session_id = Uuid::new_v4();
        assert!(!has_persist_dirty(session_id));

        {
            let mut dirty = PERSIST_DIRTY_SESSIONS
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            dirty.insert(session_id, 1);
        }

        assert!(has_persist_dirty(session_id));
        assert!(has_persist_dirty(session_id));
        assert!(take_persist_dirty_if_generation(session_id, 1));
        assert!(!has_persist_dirty(session_id));
    }

    #[tokio::test]
    async fn stale_persist_generation_does_not_forget_new_context() {
        let config = crate::config::AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 32,
            max_transaction_entries: 32,
            body_preview_bytes: 1024,
            data_dir: std::env::temp_dir().join(format!(
                "sniper-proxy-persist-generation-{}",
                Uuid::new_v4()
            )),
        };
        let data_dir = config.data_dir.clone();
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let session_id = session.id();

        let old_generation = remember_persist_context(&session);
        let new_generation = remember_persist_context(&session);

        assert!(!forget_persist_context_if_generation(
            session_id,
            old_generation
        ));
        assert!(pending_session_context(session_id).is_some());
        assert!(forget_persist_context_if_generation(
            session_id,
            new_generation
        ));
        assert!(pending_session_context(session_id).is_none());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn websocket_frame_pending_persist_reuses_existing_generation() {
        let config = crate::config::AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 32,
            max_transaction_entries: 32,
            body_preview_bytes: 1024,
            data_dir: std::env::temp_dir().join(format!(
                "sniper-proxy-ws-frame-persist-generation-{}",
                Uuid::new_v4()
            )),
        };
        let data_dir = config.data_dir.clone();
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let session_id = session.id();

        let generation = remember_persist_context(&session);
        mark_session_persist_pending(&state, &session);

        assert_eq!(current_persist_generation(session_id), Some(generation));
        assert!(pending_session_context(session_id).is_some());
        assert!(session_has_pending_persist(session_id));
        assert!(take_persist_dirty_if_generation(session_id, generation));
        clear_trailing_persist(session_id);
        assert!(forget_persist_context_if_generation(session_id, generation));
        assert!(pending_session_context(session_id).is_none());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn websocket_frame_pending_persist_flushes_without_close() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-proxy-ws-frame-flush-without-close-{}",
            Uuid::new_v4()
        ));
        let config = crate::config::AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 32,
            max_transaction_entries: 32,
            body_preview_bytes: 1024,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let websocket_id = Uuid::new_v4();
        session
            .websockets
            .open(WebSocketSessionRecord {
                id: websocket_id,
                sequence: 0,
                started_at: Utc::now(),
                closed_at: None,
                duration_ms: None,
                scheme: "wss".to_string(),
                host: "flush.example".to_string(),
                path: "/socket".to_string(),
                status: Some(101),
                request: MessageRecord::from_headers_and_body(&HeaderMap::new(), &[], 1024),
                response: None,
                frames: Vec::new(),
                notes: Vec::new(),
            })
            .await;
        assert!(
            session
                .websockets
                .append_frame(websocket_id, ws_text_frame(1))
                .await
        );
        mark_session_persist_pending(&state, &session);

        flush_pending_session_persists(state.as_ref())
            .await
            .unwrap();

        assert!(pending_session_context(session.id()).is_none());
        assert!(!session_has_pending_persist(session.id()));
        let reloaded = state.sessions.load_context(session.id()).unwrap();
        let durable = reloaded.websockets.get(websocket_id).await.unwrap();
        assert_eq!(durable.frames.len(), 1);
        assert_eq!(durable.frames[0].index, 1);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn journaled_capture_does_not_schedule_full_session_persist() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-proxy-journaled-capture-no-full-persist-{}",
            Uuid::new_v4()
        ));
        let config = crate::config::AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 32,
            max_transaction_entries: 32,
            body_preview_bytes: 1024,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let session_id = session.id();
        let mut scanner_config = session.scanner.get_config().await;
        scanner_config.enabled = false;
        session.scanner.update_config(scanner_config).await;

        let record = captured_transaction("journaled.example");
        let record_id = record.id;
        store_record_and_scan(&state, &session, record).await;
        drain_proxy_connections(Duration::from_secs(1)).await;

        assert!(session.store.get(record_id).await.is_some());
        assert!(pending_session_context(session_id).is_none());
        assert!(!session_has_pending_persist(session_id));

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn journal_fallback_capture_is_persisted_before_returning() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-proxy-journal-fallback-immediate-persist-{}",
            Uuid::new_v4()
        ));
        let config = crate::config::AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 32,
            max_transaction_entries: 32,
            body_preview_bytes: 1024,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let inactive_metadata = state
            .sessions
            .create_session(Some("read-only inactive".to_string()))
            .unwrap();
        let session = state
            .read_session_context_for_id(inactive_metadata.id)
            .await
            .unwrap();
        let mut scanner_config = session.scanner.get_config().await;
        scanner_config.enabled = false;
        session.scanner.update_config(scanner_config).await;

        let record = captured_transaction("journal-fallback.example");
        let record_id = record.id;
        store_record_and_scan(&state, &session, record).await;

        assert!(pending_session_context(session.id()).is_none());
        assert!(!session_has_pending_persist(session.id()));
        let reloaded = state.sessions.load_context(session.id()).unwrap();
        assert!(reloaded.store.get(record_id).await.is_some());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn retention_eviction_neither_rewrites_the_snapshot_nor_resurrects_on_reload() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-proxy-journaled-capture-retention-{}",
            Uuid::new_v4()
        ));
        let config = crate::config::AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 2,
            max_transaction_entries: 2,
            body_preview_bytes: 1024,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let session_id = session.id();
        let mut scanner_config = session.scanner.get_config().await;
        scanner_config.enabled = false;
        session.scanner.update_config(scanner_config).await;

        let first = captured_transaction("oldest.example");
        let first_id = first.id;
        let second = captured_transaction("middle.example");
        let second_id = second.id;
        let third = captured_transaction("newest.example");
        let third_id = third.id;

        store_record_and_scan(&state, &session, first).await;
        store_record_and_scan(&state, &session, second).await;
        drain_proxy_connections(Duration::from_secs(1)).await;
        assert!(!session_has_pending_persist(session_id));

        store_record_and_scan(&state, &session, third).await;
        drain_proxy_connections(Duration::from_secs(1)).await;

        // The third insert evicts the oldest record. That eviction must NOT
        // schedule a full snapshot rewrite: at the retention cap every insert
        // evicts, so treating it as a trigger rewrote the entire session document
        // (1.35 GB on a real session) every PERSIST_DEBOUNCE. The journal stays
        // uncompacted until it reaches TRANSACTION_JOURNAL_COMPACT_BYTES.
        assert!(!session_has_pending_persist(session_id));
        let storage_dir = state.session_storage_path(session_id).unwrap();
        let journal_len = std::fs::metadata(storage_dir.join("transactions.journal"))
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        assert!(
            journal_len > 0,
            "a retention eviction must not compact the journal"
        );

        // Safety of the above: journal replay applies the same retention cap, so
        // the evicted record does not come back and the newest two survive.
        let reloaded = state.sessions.load_context(session_id).unwrap();
        assert!(reloaded.store.get(first_id).await.is_none());
        assert!(reloaded.store.get(second_id).await.is_some());
        assert!(reloaded.store.get(third_id).await.is_some());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn streamed_capture_store_clears_clean_pending_persist_context() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-proxy-streamed-capture-cleans-pending-{}",
            Uuid::new_v4()
        ));
        let config = crate::config::AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 32,
            max_transaction_entries: 32,
            body_preview_bytes: 1024,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let session_id = session.id();
        let mut scanner_config = session.scanner.get_config().await;
        scanner_config.enabled = false;
        session.scanner.update_config(scanner_config).await;

        let request_capture = MessageRecord::from_headers_and_body(&HeaderMap::new(), &[], 1024);
        let persist_generation = remember_persist_context(&session);
        let context = StreamedRecordContext {
            state: Arc::clone(&state),
            session: Arc::clone(&session),
            _session_owner: remember_active_proxy_session_owner(session_id),
            persist_generation,
            record_id: None,
            started_at: Utc::now(),
            started: Instant::now(),
            method: "GET".to_string(),
            scheme: "https".to_string(),
            host: "streamed.example".to_string(),
            path: "/stream".to_string(),
            status: StatusCode::OK,
            request_capture,
            response_headers: HeaderMap::new(),
            notes: Vec::new(),
            original_request_capture: None,
            request_version: Some(Version::HTTP_11),
            response_version: Version::HTTP_11,
            max_preview: 1024,
        };

        context.store(b"ok".to_vec(), 2).await;
        drain_proxy_connections(Duration::from_secs(1)).await;

        assert!(pending_session_context(session_id).is_none());
        assert!(!session_has_pending_persist(session_id));
        state
            .create_session(Some("replacement".to_string()))
            .await
            .unwrap();
        state.delete_session(session_id).await.unwrap();

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn streamed_capture_provisional_record_is_updated_in_place() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-proxy-streamed-capture-updates-in-place-{}",
            Uuid::new_v4()
        ));
        let config = crate::config::AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 32,
            max_transaction_entries: 32,
            body_preview_bytes: 1024,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let session_id = session.id();
        let mut scanner_config = session.scanner.get_config().await;
        scanner_config.enabled = false;
        session.scanner.update_config(scanner_config).await;

        let request_capture = MessageRecord::from_headers_and_body(&HeaderMap::new(), &[], 1024);
        let persist_generation = remember_persist_context(&session);
        let mut context = StreamedRecordContext {
            state: Arc::clone(&state),
            session: Arc::clone(&session),
            _session_owner: remember_active_proxy_session_owner(session_id),
            persist_generation,
            record_id: None,
            started_at: Utc::now(),
            started: Instant::now(),
            method: "GET".to_string(),
            scheme: "https".to_string(),
            host: "streamed.example".to_string(),
            path: "/stream".to_string(),
            status: StatusCode::OK,
            request_capture,
            response_headers: HeaderMap::new(),
            notes: Vec::new(),
            original_request_capture: None,
            request_version: Some(Version::HTTP_11),
            response_version: Version::HTTP_11,
            max_preview: 1024,
        };

        context.insert_provisional_record().await;
        let record_id = context
            .record_id
            .expect("provisional id should be recorded");
        let provisional = session
            .store
            .get(record_id)
            .await
            .expect("provisional record should be visible");
        assert_eq!(provisional.response.as_ref().unwrap().body_size, 0);
        assert!(provisional
            .notes
            .iter()
            .any(|note| note.contains("still in progress")));

        session
            .store
            .update_annotations(record_id, None, Some(Some("keep me".to_string())))
            .await
            .expect("annotation should update");

        context
            .store_with_notes(b"complete".to_vec(), 8, vec!["done".to_string()])
            .await;

        let listed = session
            .store
            .list(&crate::store::ListFilters::default())
            .await;
        assert_eq!(listed.len(), 1);
        let final_record = session
            .store
            .get(record_id)
            .await
            .expect("final record should keep provisional id");
        assert_eq!(final_record.response.as_ref().unwrap().body_size, 8);
        assert_eq!(final_record.notes, vec!["done"]);
        assert_eq!(final_record.user_note.as_deref(), Some("keep me"));
        drain_proxy_connections(Duration::from_secs(1)).await;
        flush_pending_session_persists(state.as_ref())
            .await
            .expect("pending persist should flush");
        assert!(!session_has_pending_persist(session_id));

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn flush_pending_persist_drains_new_generation() {
        let config = crate::config::AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 32,
            max_transaction_entries: 32,
            body_preview_bytes: 1024,
            data_dir: std::env::temp_dir().join(format!(
                "sniper-proxy-flush-persist-generation-{}",
                Uuid::new_v4()
            )),
        };
        let data_dir = config.data_dir.clone();
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let session_id = session.id();
        let mutation_guard = session.mutation_guard().await;

        let old_generation = remember_persist_context(&session);
        let flush_state = Arc::clone(&state);
        let flush_task =
            tokio::spawn(async move { flush_pending_session_persists(flush_state.as_ref()).await });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert_eq!(current_persist_generation(session_id), Some(old_generation));

        let _new_generation = remember_persist_context(&session);
        mark_session_persist_pending(&state, &session);
        drop(mutation_guard);
        flush_task.await.unwrap().unwrap();

        assert_eq!(current_persist_generation(session_id), None);
        assert!(pending_session_context(session_id).is_none());
        assert!(!session_has_pending_persist(session_id));

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn flush_pending_persist_retries_same_generation_dirty_marker() {
        let config = crate::config::AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 32,
            max_transaction_entries: 32,
            body_preview_bytes: 1024,
            data_dir: std::env::temp_dir().join(format!(
                "sniper-proxy-flush-same-generation-dirty-{}",
                Uuid::new_v4()
            )),
        };
        let data_dir = config.data_dir.clone();
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let session_id = session.id();
        let mutation_guard = session.mutation_guard().await;

        let generation = remember_persist_context(&session);
        let flush_state = Arc::clone(&state);
        let flush_task =
            tokio::spawn(async move { flush_pending_session_persists(flush_state.as_ref()).await });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;

        mark_session_persist_pending(&state, &session);
        assert_eq!(current_persist_generation(session_id), Some(generation));
        drop(mutation_guard);

        flush_task.await.unwrap().unwrap();

        assert!(pending_session_context(session_id).is_none());
        assert!(!session_has_pending_persist(session_id));

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn session_pending_persist_guard_includes_dirty_and_trailing_state() {
        let session_id = Uuid::new_v4();
        assert!(!session_has_pending_persist(session_id));

        {
            let mut dirty = PERSIST_DIRTY_SESSIONS
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            dirty.insert(session_id, 1);
        }
        assert!(session_has_pending_persist(session_id));
        assert!(take_persist_dirty_if_generation(session_id, 1));

        {
            let mut trailing = PERSIST_TRAILING_SESSIONS
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            trailing.insert(session_id, 1);
        }
        assert!(session_has_pending_persist(session_id));
        clear_trailing_persist(session_id);
        assert!(!session_has_pending_persist(session_id));
    }

    #[tokio::test]
    async fn clean_forget_preserves_dirty_pending_context() {
        let config = crate::config::AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 32,
            max_transaction_entries: 32,
            body_preview_bytes: 1024,
            data_dir: std::env::temp_dir().join(format!(
                "sniper-proxy-clean-forget-dirty-{}",
                Uuid::new_v4()
            )),
        };
        let data_dir = config.data_dir.clone();
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let session_id = session.id();
        let generation = remember_persist_context(&session);

        mark_persist_dirty_generation(session_id, generation);

        assert!(!forget_persist_context_if_clean(session_id, generation));
        assert!(pending_session_context(session_id).is_some());
        assert!(session_has_pending_persist(session_id));

        assert!(take_persist_dirty_if_generation(session_id, generation));
        assert!(forget_persist_context_if_clean(session_id, generation));
        assert!(pending_session_context(session_id).is_none());
        assert!(!session_has_pending_persist(session_id));

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn shutdown_close_live_websocket_relays_persists_closed_session() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-test-live-ws-shutdown-{}", Uuid::new_v4()));
        let config = crate::config::AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let websocket_id = Uuid::new_v4();
        session
            .websockets
            .open(WebSocketSessionRecord {
                id: websocket_id,
                sequence: 0,
                started_at: Utc::now(),
                closed_at: None,
                duration_ms: None,
                scheme: "wss".to_string(),
                host: "example.test".to_string(),
                path: "/ws".to_string(),
                status: Some(StatusCode::SWITCHING_PROTOCOLS.as_u16()),
                request: MessageRecord::from_headers_and_body(&HeaderMap::new(), &[], 1024),
                response: None,
                frames: Vec::new(),
                notes: Vec::new(),
            })
            .await;
        let (abort, _registration) = AbortHandle::new_pair();
        remember_live_websocket_relay(
            websocket_id,
            Some(websocket_id),
            &session,
            Instant::now(),
            abort,
        );

        close_live_websocket_relays(
            state.as_ref(),
            "test shutdown closed the live WebSocket relay.",
        )
        .await
        .unwrap();

        let live = session.websockets.get(websocket_id).await.unwrap();
        assert!(live.closed_at.is_some());
        assert!(live.notes.iter().any(|note| note.contains("test shutdown")));

        let reloaded = state.sessions.load_context(session.id()).unwrap();
        let durable = reloaded.websockets.get(websocket_id).await.unwrap();
        assert!(durable.closed_at.is_some());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn aborted_live_websocket_relay_closes_and_persists_capture() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-test-live-ws-abort-{}", Uuid::new_v4()));
        let config = crate::config::AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let websocket_id = Uuid::new_v4();
        session
            .websockets
            .open(WebSocketSessionRecord {
                id: websocket_id,
                sequence: 0,
                started_at: Utc::now(),
                closed_at: None,
                duration_ms: None,
                scheme: "wss".to_string(),
                host: "example.test".to_string(),
                path: "/ws".to_string(),
                status: Some(StatusCode::SWITCHING_PROTOCOLS.as_u16()),
                request: MessageRecord::from_headers_and_body(&HeaderMap::new(), &[], 1024),
                response: None,
                frames: Vec::new(),
                notes: Vec::new(),
            })
            .await;
        let relay_id = Uuid::new_v4();
        let (abort, _registration) = AbortHandle::new_pair();
        remember_live_websocket_relay(
            relay_id,
            Some(websocket_id),
            &session,
            Instant::now(),
            abort,
        );

        close_aborted_live_websocket_relay(
            &state,
            &session,
            relay_id,
            Some(websocket_id),
            Instant::now(),
            "test abort closed the live WebSocket relay.",
        )
        .await;
        forget_live_websocket_relay_unless_close_pending(relay_id);
        flush_pending_session_persists(state.as_ref())
            .await
            .expect("pending websocket close persist should flush");

        let live = session.websockets.get(websocket_id).await.unwrap();
        assert!(live.closed_at.is_some());
        assert!(live.notes.iter().any(|note| note.contains("test abort")));
        assert!(!session_has_live_websocket_relays(session.id()));

        let reloaded = state.sessions.load_context(session.id()).unwrap();
        let durable = reloaded.websockets.get(websocket_id).await.unwrap();
        assert!(durable.closed_at.is_some());
        assert!(durable.notes.iter().any(|note| note.contains("test abort")));

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn close_live_websocket_relays_clears_clean_pending_persist_after_direct_save() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-close-live-ws-clears-pending-{}",
            Uuid::new_v4()
        ));
        let config = crate::config::AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let websocket_id = Uuid::new_v4();
        session
            .websockets
            .open(WebSocketSessionRecord {
                id: websocket_id,
                sequence: 0,
                started_at: Utc::now(),
                closed_at: None,
                duration_ms: None,
                scheme: "wss".to_string(),
                host: "example.test".to_string(),
                path: "/ws".to_string(),
                status: Some(StatusCode::SWITCHING_PROTOCOLS.as_u16()),
                request: MessageRecord::from_headers_and_body(&HeaderMap::new(), &[], 1024),
                response: None,
                frames: Vec::new(),
                notes: Vec::new(),
            })
            .await;
        assert!(
            session
                .websockets
                .append_frame(websocket_id, ws_text_frame(1))
                .await
        );
        mark_session_persist_pending(&state, &session);
        assert!(session_has_pending_persist(session.id()));

        let relay_id = Uuid::new_v4();
        let (abort, _registration) = AbortHandle::new_pair();
        remember_live_websocket_relay(
            relay_id,
            Some(websocket_id),
            &session,
            Instant::now(),
            abort,
        );

        close_live_websocket_relays(
            state.as_ref(),
            "test shutdown closed the live WebSocket relay.",
        )
        .await
        .unwrap();

        assert!(!session_has_live_websocket_relays(session.id()));
        assert!(!session_has_pending_persist(session.id()));
        let reloaded = state.sessions.load_context(session.id()).unwrap();
        let durable = reloaded.websockets.get(websocket_id).await.unwrap();
        assert!(durable.closed_at.is_some());
        assert_eq!(durable.frames.len(), 1);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn close_live_websocket_relays_reports_persist_failure_and_keeps_retry_state() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-close-live-ws-persist-failure-{}",
            Uuid::new_v4()
        ));
        let config = crate::config::AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let websocket_id = Uuid::new_v4();
        session
            .websockets
            .open(WebSocketSessionRecord {
                id: websocket_id,
                sequence: 0,
                started_at: Utc::now(),
                closed_at: None,
                duration_ms: None,
                scheme: "wss".to_string(),
                host: "example.test".to_string(),
                path: "/ws".to_string(),
                status: Some(StatusCode::SWITCHING_PROTOCOLS.as_u16()),
                request: MessageRecord::from_headers_and_body(&HeaderMap::new(), &[], 1024),
                response: None,
                frames: Vec::new(),
                notes: Vec::new(),
            })
            .await;
        let (abort, _registration) = AbortHandle::new_pair();
        remember_live_websocket_relay(
            websocket_id,
            Some(websocket_id),
            &session,
            Instant::now(),
            abort,
        );
        let registry_path = data_dir
            .join(crate::session::SESSIONS_DIR)
            .join("registry.json");
        std::fs::remove_file(&registry_path).unwrap();
        std::fs::create_dir(&registry_path).unwrap();

        let error = close_live_websocket_relays(
            state.as_ref(),
            "test shutdown closed the live WebSocket relay.",
        )
        .await
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("failed to persist closed live websocket relays"));
        assert!(session_has_live_websocket_relays(session.id()));
        forget_live_websocket_relay_unless_close_pending(websocket_id);
        assert!(session_has_live_websocket_relays(session.id()));

        std::fs::remove_dir_all(&registry_path).unwrap();
        close_live_websocket_relays(
            state.as_ref(),
            "test retry closed the live WebSocket relay.",
        )
        .await
        .unwrap();

        assert!(!session_has_live_websocket_relays(session.id()));
        let reloaded = state.sessions.load_context(session.id()).unwrap();
        let durable = reloaded.websockets.get(websocket_id).await.unwrap();
        assert!(durable.closed_at.is_some());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn close_live_websocket_relays_forgets_same_state_stale_session_relay() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-close-live-ws-stale-session-{}",
            Uuid::new_v4()
        ));
        let config = crate::config::AppConfig {
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
        let relay_id = Uuid::new_v4();
        let (abort, _registration) = AbortHandle::new_pair();
        remember_live_websocket_relay(
            relay_id,
            Some(Uuid::new_v4()),
            &session,
            Instant::now(),
            abort.clone(),
        );
        state
            .create_session(Some("replacement".to_string()))
            .await
            .unwrap();
        state.sessions.delete_session(session_id).unwrap();

        close_live_websocket_relays(
            state.as_ref(),
            "test shutdown closed the live WebSocket relay.",
        )
        .await
        .unwrap();

        assert!(abort.is_aborted());
        assert!(!session_has_live_websocket_relays(session_id));

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn rebind_proxy_starts_listener_when_same_address_is_offline() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-rebind-offline-same-address-{}",
            Uuid::new_v4()
        ));
        let config = crate::config::AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let desired_addr = state.get_active_proxy_addr().await;

        rebind_proxy(state.clone(), desired_addr).await.unwrap();

        let active_addr = state.get_active_proxy_addr().await;
        assert!(state.is_proxy_online());
        assert_ne!(active_addr.port(), 0);

        state.abort_proxy_task().await;
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn stale_proxy_task_exit_does_not_mark_new_listener_offline() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-stale-proxy-exit-generation-{}",
            Uuid::new_v4()
        ));
        let config = crate::config::AppConfig {
            proxy_addr: "127.0.0.1:18080".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let active_addr = "127.0.0.1:18080".parse().unwrap();
        state.set_active_proxy_addr(active_addr).await;
        let old_generation = state.mark_proxy_listener_online();
        let new_generation = state.mark_proxy_listener_online();

        mark_proxy_offline_after_task_exit(
            &state,
            active_addr,
            old_generation,
            "after stale proxy task stopped",
        )
        .await;

        assert!(state.is_proxy_online());

        mark_proxy_offline_after_task_exit(
            &state,
            active_addr,
            new_generation,
            "after current proxy task stopped",
        )
        .await;

        assert!(!state.is_proxy_online());
        let _ = std::fs::remove_dir_all(data_dir);
    }

    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[tokio::test]
    async fn rebind_proxy_keeps_existing_proxy_online_when_relay_close_persist_fails() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-rebind-live-ws-persist-failure-{}",
            Uuid::new_v4()
        ));
        let config = crate::config::AppConfig {
            proxy_addr: "127.0.0.1:18080".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let current_addr = "127.0.0.1:18080".parse().unwrap();
        state.set_active_proxy_addr(current_addr).await;
        state.set_proxy_online(true);
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = DropFlag(Arc::clone(&dropped));
        let handle = tokio::spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });
        state.set_proxy_task(handle).await;

        let session = state.session().await;
        let websocket_id = Uuid::new_v4();
        session
            .websockets
            .open(WebSocketSessionRecord {
                id: websocket_id,
                sequence: 0,
                started_at: Utc::now(),
                closed_at: None,
                duration_ms: None,
                scheme: "wss".to_string(),
                host: "example.test".to_string(),
                path: "/ws".to_string(),
                status: Some(StatusCode::SWITCHING_PROTOCOLS.as_u16()),
                request: MessageRecord::from_headers_and_body(&HeaderMap::new(), &[], 1024),
                response: None,
                frames: Vec::new(),
                notes: Vec::new(),
            })
            .await;
        let (abort, _registration) = AbortHandle::new_pair();
        remember_live_websocket_relay(
            websocket_id,
            Some(websocket_id),
            &session,
            Instant::now(),
            abort,
        );
        let registry_path = data_dir
            .join(crate::session::SESSIONS_DIR)
            .join("registry.json");
        std::fs::remove_file(&registry_path).unwrap();
        std::fs::create_dir(&registry_path).unwrap();

        let error = rebind_proxy(state.clone(), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap_err();

        assert!(error.contains("failed to persist closed live websocket relays"));
        assert!(state.is_proxy_online());
        assert_eq!(state.get_active_proxy_addr().await, current_addr);
        assert!(!dropped.load(Ordering::Acquire));
        assert!(session_has_live_websocket_relays(session.id()));

        forget_live_websocket_relay(websocket_id);
        state.abort_proxy_task().await;
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn delete_session_rejects_live_websocket_relay_until_closed() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-test-live-ws-delete-{}", Uuid::new_v4()));
        let config = crate::config::AppConfig {
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
            .create_session(Some("active".to_string()))
            .await
            .unwrap();

        let websocket_id = Uuid::new_v4();
        let (abort, _registration) = AbortHandle::new_pair();
        remember_live_websocket_relay(
            websocket_id,
            Some(websocket_id),
            &original,
            Instant::now(),
            abort,
        );

        let error = state.delete_session(original_id).await.unwrap_err();
        assert!(error.to_string().contains("live captures are active"));

        close_live_websocket_relays(
            state.as_ref(),
            "test shutdown closed the live WebSocket relay.",
        )
        .await
        .unwrap();
        state.delete_session(original_id).await.unwrap();

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn delete_session_rejects_uncaptured_live_websocket_relay_until_closed() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-uncaptured-ws-delete-{}",
            Uuid::new_v4()
        ));
        let config = crate::config::AppConfig {
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
            .create_session(Some("active".to_string()))
            .await
            .unwrap();

        let relay_id = Uuid::new_v4();
        let (abort, _registration) = AbortHandle::new_pair();
        remember_live_websocket_relay(relay_id, None, &original, Instant::now(), abort);

        let error = state.delete_session(original_id).await.unwrap_err();
        assert!(error.to_string().contains("live captures are active"));

        close_live_websocket_relays(
            state.as_ref(),
            "test shutdown closed the live WebSocket relay.",
        )
        .await
        .unwrap();
        state.delete_session(original_id).await.unwrap();

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn delete_session_rejects_active_proxy_work_until_owner_dropped() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-active-proxy-delete-{}",
            Uuid::new_v4()
        ));
        let config = crate::config::AppConfig {
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
            .create_session(Some("active".to_string()))
            .await
            .unwrap();

        let owner = remember_active_proxy_session_owner(original_id);
        let error = state.delete_session(original_id).await.unwrap_err();
        assert!(error
            .to_string()
            .contains("proxy activity is still running"));

        drop(owner);
        state.delete_session(original_id).await.unwrap();

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn proxy_editable_request_preserves_raw_compressed_body_and_headers() {
        let compressed = Bytes::from_static(&[0x1f, 0x8b, 0x08, 0x00, 0x00]);
        let request = Request::builder()
            .method("POST")
            .uri("http://example.com/upload")
            .header(HOST, "example.com")
            .header(http::header::CONTENT_ENCODING, "gzip")
            .header(CONTENT_LENGTH, compressed.len().to_string())
            .body(())
            .unwrap();
        let (parts, _) = request.into_parts();
        let absolute_uri: Uri = "http://example.com/upload".parse().unwrap();

        let editable = editable_request_from_parts(&parts, &compressed, &absolute_uri);

        assert_eq!(editable.body_encoding, BodyEncoding::Base64);
        assert_eq!(editable.body_bytes(), compressed.as_ref());
        assert!(editable.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("content-encoding") && header.value == "gzip"
        }));
        assert!(editable
            .headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("content-length")));
    }

    #[test]
    fn proxy_editable_request_canonicalizes_plain_chunked_body() {
        let body = Bytes::from_static(b"hello");
        let request = Request::builder()
            .method("POST")
            .uri("http://example.com/upload")
            .header(HOST, "example.com")
            .header(TRANSFER_ENCODING, "chunked")
            .header(CONTENT_LENGTH, "999")
            .body(())
            .unwrap();
        let (parts, _) = request.into_parts();
        let absolute_uri: Uri = "http://example.com/upload".parse().unwrap();

        let editable = editable_request_from_parts(&parts, &body, &absolute_uri);

        assert_eq!(editable.body_encoding, BodyEncoding::Utf8);
        assert_eq!(editable.body, "hello");
        assert!(!editable
            .headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("transfer-encoding")));
        let content_lengths = editable
            .headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case("content-length"))
            .collect::<Vec<_>>();
        assert_eq!(content_lengths.len(), 1);
        assert_eq!(content_lengths[0].value, "5");
    }

    #[test]
    fn connect_target_rejects_non_authority_path_before_upgrade() {
        let uri: Uri = "/".parse().unwrap();
        let error = connect_target(&uri).unwrap_err();

        assert!(error
            .to_string()
            .contains("invalid CONNECT target authority"));
    }

    #[test]
    fn connect_host_header_must_match_target_authority() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("attacker.example:443"));

        let error = validate_connect_host_header(&headers, "127.0.0.1:443").unwrap_err();

        assert!(error
            .to_string()
            .contains("does not match CONNECT target authority"));
    }

    #[test]
    fn connect_host_header_accepts_matching_ipv6_authority() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("[::1]:443"));

        validate_connect_host_header(&headers, "[::1]:443").unwrap();
    }

    #[test]
    fn own_listener_guard_detects_self_targets() {
        let wildcard: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        // Loopback and localhost on the listener port loop back into the proxy.
        assert!(request_targets_own_listener(
            &"http://127.0.0.1:8080/".parse().unwrap(),
            wildcard
        ));
        assert!(request_targets_own_listener(
            &"https://localhost:8080/".parse().unwrap(),
            wildcard
        ));
        // A different port cannot reach this listener, so it is not a loop.
        assert!(!request_targets_own_listener(
            &"http://127.0.0.1:9999/".parse().unwrap(),
            wildcard
        ));
        // An external host on the same port is a legitimate forward target.
        assert!(!request_targets_own_listener(
            &"http://example.com:8080/".parse().unwrap(),
            wildcard
        ));
        assert!(!request_targets_own_listener(
            &"http://93.184.216.34:8080/".parse().unwrap(),
            wildcard
        ));

        // Loopback-only bind: a LAN IP never reaches the listener, so no guard.
        let loopback: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert!(request_targets_own_listener(
            &"http://127.0.0.1:8080/".parse().unwrap(),
            loopback
        ));
        assert!(!request_targets_own_listener(
            &"http://93.184.216.34:8080/".parse().unwrap(),
            loopback
        ));
    }

    #[test]
    fn local_interface_ips_are_enumerable() {
        // getifaddrs should return at least the loopback interface.
        assert!(!local_interface_ips().is_empty());
    }

    #[test]
    fn connect_host_header_accepts_port_omitted() {
        // iOS/Chrome send `Host: example.com` (no port) on CONNECT; the port
        // lives in the CONNECT target authority. Inherit it instead of rejecting.
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("example.com"));

        validate_connect_host_header(&headers, "example.com:443").unwrap();
    }

    #[test]
    fn normalize_request_path_preserves_asterisk_form() {
        assert_eq!(normalize_request_path("*"), "*");
    }

    #[test]
    fn replay_uri_builder_rejects_asterisk_form_request_target() {
        let mut request = editable_request("example.com");
        request.method = "OPTIONS".to_string();
        request.path = "*".to_string();

        let error = build_uri_from_request(&request, None).unwrap_err();

        assert!(error.to_string().contains("star-form request targets"));
    }

    #[test]
    fn proxy_uri_builder_rejects_asterisk_form_request_target() {
        let uri: Uri = "*".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("example.com"));

        let error = resolve_absolute_uri(&uri, &headers, "http", None).unwrap_err();

        assert!(error.to_string().contains("star-form request targets"));
    }

    #[test]
    fn connect_target_requires_explicit_port() {
        let uri: Uri = "http://example.com".parse().unwrap();
        let error = connect_target(&uri).unwrap_err();

        assert!(error
            .to_string()
            .contains("must be authority-form host:port"));
    }

    #[test]
    fn connect_target_rejects_empty_host_authority_before_upgrade() {
        let uri: Uri = ":80".parse().unwrap();
        let error = connect_target(&uri).unwrap_err();

        assert!(error.to_string().contains("must include a host"));
    }

    #[test]
    fn client_authority_rejects_empty_and_invalid_hosts() {
        for authority in [":80", "[]:443"] {
            let error = parse_client_authority(authority, "test authority").unwrap_err();
            assert!(
                error.to_string().contains("must include a host"),
                "{authority} should be rejected as empty host"
            );
        }

        for authority in ["example.com:", "example.com:70000"] {
            assert!(
                parse_client_authority(authority, "test authority").is_err(),
                "{authority} should be rejected as invalid authority"
            );
        }
    }

    #[test]
    fn connect_target_rejects_absolute_form_with_path() {
        let uri: Uri = "http://example.com:443/ignored".parse().unwrap();
        let error = connect_target(&uri).unwrap_err();

        assert!(error
            .to_string()
            .contains("must be authority-form host:port"));
    }

    #[test]
    fn absolute_form_inside_connect_must_match_tunnel_authority() {
        let uri: Uri = "https://other.example/private".parse().unwrap();
        let headers = HeaderMap::new();
        let error =
            resolve_absolute_uri(&uri, &headers, "https", Some("origin.example:443")).unwrap_err();

        assert!(error
            .to_string()
            .contains("does not match CONNECT tunnel authority"));
    }

    #[test]
    fn absolute_form_inside_connect_accepts_default_port_match() {
        let uri: Uri = "https://origin.example/private".parse().unwrap();
        let headers = HeaderMap::new();
        let resolved =
            resolve_absolute_uri(&uri, &headers, "https", Some("origin.example:443")).unwrap();

        assert_eq!(resolved, uri);
    }

    #[test]
    fn absolute_form_inside_connect_accepts_ipv6_authority_match() {
        let uri: Uri = "https://[::1]/private".parse().unwrap();
        let headers = HeaderMap::new();
        let resolved = resolve_absolute_uri(&uri, &headers, "https", Some("[::1]:443")).unwrap();

        assert_eq!(resolved, uri);
    }

    #[test]
    fn origin_form_inside_connect_rejects_host_mismatch() {
        let uri: Uri = "/private".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("other.example"));
        let error =
            resolve_absolute_uri(&uri, &headers, "https", Some("origin.example:443")).unwrap_err();

        assert!(error
            .to_string()
            .contains("Host header does not match CONNECT tunnel authority"));
    }

    #[test]
    fn origin_form_inside_connect_accepts_matching_host_default_port() {
        let uri: Uri = "/private".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("origin.example"));
        let resolved =
            resolve_absolute_uri(&uri, &headers, "https", Some("origin.example:443")).unwrap();

        assert_eq!(resolved.to_string(), "https://origin.example:443/private");
    }

    #[test]
    fn websocket_origin_form_inside_connect_rejects_host_mismatch() {
        let uri: Uri = "/socket".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("other.example"));
        headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        headers.insert(
            SEC_WEBSOCKET_KEY,
            HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
        );
        headers.insert(SEC_WEBSOCKET_VERSION, HeaderValue::from_static("13"));

        assert!(websocket_upgrade_validation_error(&Method::GET, &headers).is_none());
        let error =
            resolve_absolute_uri(&uri, &headers, "https", Some("origin.example:443")).unwrap_err();

        assert!(error
            .to_string()
            .contains("Host header does not match CONNECT tunnel authority"));
    }

    #[test]
    fn absolute_form_inside_connect_rejects_scheme_mismatch() {
        let uri: Uri = "http://origin.example:443/private".parse().unwrap();
        let headers = HeaderMap::new();
        let error =
            resolve_absolute_uri(&uri, &headers, "https", Some("origin.example:443")).unwrap_err();

        assert!(error
            .to_string()
            .contains("scheme does not match CONNECT tunnel scheme"));
    }

    #[test]
    fn websocket_upgrade_accepts_split_connection_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
        headers.append(CONNECTION, HeaderValue::from_static("keep-alive"));
        headers.append(CONNECTION, HeaderValue::from_static("Upgrade"));

        assert!(is_websocket_upgrade_headers(&headers));
    }

    #[test]
    fn websocket_upgrade_accepts_upgrade_token_lists() {
        let mut headers = HeaderMap::new();
        headers.insert(UPGRADE, HeaderValue::from_static("h2c, websocket"));
        headers.insert(CONNECTION, HeaderValue::from_static("keep-alive, Upgrade"));

        assert!(is_websocket_upgrade_headers(&headers));
    }

    #[test]
    fn websocket_upgrade_note_reflects_capture_setting() {
        assert_eq!(
            websocket_upgrade_transaction_note(true),
            "WebSocket upgrade proxied and mirrored into WebSockets history."
        );
        assert_eq!(
            websocket_upgrade_transaction_note(false),
            "WebSocket upgrade proxied; WebSocket capture is disabled."
        );
    }

    #[test]
    fn websocket_upgrade_validation_accepts_valid_handshake() {
        let mut headers = HeaderMap::new();
        headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        headers.insert(
            SEC_WEBSOCKET_KEY,
            HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
        );
        headers.insert(SEC_WEBSOCKET_VERSION, HeaderValue::from_static("13"));

        assert_eq!(
            websocket_upgrade_validation_error(&Method::GET, &headers),
            None
        );
    }

    #[test]
    fn websocket_upgrade_validation_rejects_non_get_before_upstream_dial() {
        let mut headers = HeaderMap::new();
        headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        headers.insert(
            SEC_WEBSOCKET_KEY,
            HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
        );
        headers.insert(SEC_WEBSOCKET_VERSION, HeaderValue::from_static("13"));

        assert_eq!(
            websocket_upgrade_validation_error(&Method::POST, &headers),
            Some("WebSocket upgrade requests must use GET")
        );
    }

    #[test]
    fn websocket_upgrade_validation_rejects_missing_client_key_before_upstream_dial() {
        let mut headers = HeaderMap::new();
        headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        headers.insert(SEC_WEBSOCKET_VERSION, HeaderValue::from_static("13"));

        assert_eq!(
            websocket_upgrade_validation_error(&Method::GET, &headers),
            Some("missing or invalid Sec-WebSocket-Key")
        );
    }

    #[test]
    fn websocket_upgrade_validation_rejects_duplicate_key_or_version() {
        let mut headers = HeaderMap::new();
        headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        headers.append(
            SEC_WEBSOCKET_KEY,
            HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
        );
        headers.append(
            SEC_WEBSOCKET_KEY,
            HeaderValue::from_static("AAAAAAAAAAAAAAAAAAAAAA=="),
        );
        headers.insert(SEC_WEBSOCKET_VERSION, HeaderValue::from_static("13"));

        assert_eq!(
            websocket_upgrade_validation_error(&Method::GET, &headers),
            Some("missing or invalid Sec-WebSocket-Key")
        );

        headers.remove(SEC_WEBSOCKET_KEY);
        headers.insert(
            SEC_WEBSOCKET_KEY,
            HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
        );
        headers.append(SEC_WEBSOCKET_VERSION, HeaderValue::from_static("13"));

        assert_eq!(
            websocket_upgrade_validation_error(&Method::GET, &headers),
            Some("unsupported Sec-WebSocket-Version")
        );
    }

    #[test]
    fn websocket_upgrade_validation_rejects_body_framing_before_collecting_body() {
        let mut headers = HeaderMap::new();
        headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        headers.insert(
            SEC_WEBSOCKET_KEY,
            HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
        );
        headers.insert(SEC_WEBSOCKET_VERSION, HeaderValue::from_static("13"));
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("1"));

        assert_eq!(
            websocket_upgrade_validation_error(&Method::GET, &headers),
            Some("WebSocket upgrade requests must not include a request body")
        );

        headers.remove(CONTENT_LENGTH);
        headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        assert_eq!(
            websocket_upgrade_validation_error(&Method::GET, &headers),
            Some("WebSocket upgrade requests must not include a request body")
        );
    }

    #[test]
    fn websocket_upgrade_validation_rejects_edited_non_get_request() {
        let mut request = editable_request("upstream.example");
        request.method = "POST".to_string();
        request.headers.extend([
            record("Connection", "Upgrade"),
            record("Upgrade", "websocket"),
            record("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
            record("Sec-WebSocket-Version", "13"),
        ]);
        let headers = header_map_from_records(&request.headers);

        assert_eq!(
            websocket_upgrade_validation_error_for_editable(&request, &headers),
            Some("WebSocket upgrade requests must use GET")
        );
    }

    #[test]
    fn websocket_upgrade_validation_rejects_edited_body_without_framing_headers() {
        let mut request = editable_request("upstream.example");
        request.headers.extend([
            record("Connection", "Upgrade"),
            record("Upgrade", "websocket"),
            record("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
            record("Sec-WebSocket-Version", "13"),
        ]);
        request.body = "SHOULD_NOT_FORWARD".to_string();
        let headers = header_map_from_records(&request.headers);

        assert_eq!(
            websocket_upgrade_validation_error_for_editable(&request, &headers),
            Some("WebSocket upgrade requests must not include a request body")
        );
    }

    #[test]
    fn websocket_forwarding_preserves_host_header_override() {
        assert!(should_forward_websocket_header("Host"));
    }

    #[test]
    fn websocket_forwarding_strips_hop_by_hop_and_proxy_headers() {
        let records = vec![
            record("Host", "upstream.example"),
            record("Connection", "Upgrade, X-Hop"),
            record("Upgrade", "websocket"),
            record("X-Hop", "secret"),
            record("Proxy-Authorization", "Basic abc"),
            record("Sec-WebSocket-Key", "client-key"),
            record("X-End-To-End", "keep"),
        ];

        let headers = websocket_forward_headers_from_records(&records);

        assert_eq!(headers.get(HOST).unwrap(), "upstream.example");
        assert_eq!(headers.get("x-end-to-end").unwrap(), "keep");
        assert!(!headers.contains_key(CONNECTION));
        assert!(!headers.contains_key(UPGRADE));
        assert!(!headers.contains_key("x-hop"));
        assert!(!headers.contains_key("proxy-authorization"));
        assert!(!headers.contains_key(SEC_WEBSOCKET_KEY));
    }

    #[test]
    fn websocket_relay_only_auto_handles_ping_frames() {
        assert!(!should_relay_websocket_frame(&WebSocketMessage::Ping(
            b"ping".to_vec().into()
        )));
        assert!(should_relay_websocket_frame(&WebSocketMessage::Pong(
            b"pong".to_vec().into()
        )));
        assert!(should_relay_websocket_frame(&WebSocketMessage::Text(
            "hello".into()
        )));
        assert!(should_relay_websocket_frame(&WebSocketMessage::Close(None)));
    }

    #[test]
    fn websocket_text_preview_does_not_split_utf8_codepoint() {
        let frame = capture_websocket_frame(
            0,
            WebSocketFrameDirection::ClientToServer,
            &WebSocketMessage::Text("éx".into()),
            1,
        )
        .expect("text frame should capture");

        assert_eq!(frame.body_preview, "");
        assert!(frame.preview_truncated);

        let frame = capture_websocket_frame(
            0,
            WebSocketFrameDirection::ClientToServer,
            &WebSocketMessage::Text("éx".into()),
            2,
        )
        .expect("text frame should capture");

        assert_eq!(frame.body_preview, "é");
        assert!(frame.preview_truncated);
    }

    #[test]
    fn websocket_text_preview_is_capped_below_http_preview_limit() {
        let text = "x".repeat(WEBSOCKET_CAPTURE_PREVIEW_BYTES + 1);
        let frame = capture_websocket_frame(
            0,
            WebSocketFrameDirection::ClientToServer,
            &WebSocketMessage::Text(text.into()),
            usize::MAX,
        )
        .expect("text frame should capture");

        assert_eq!(frame.body_preview.len(), WEBSOCKET_CAPTURE_PREVIEW_BYTES);
        assert_eq!(frame.body_size, WEBSOCKET_CAPTURE_PREVIEW_BYTES + 1);
        assert!(frame.preview_truncated);
    }

    #[test]
    fn replay_exchange_rejects_invalid_header_records() {
        let mut request = editable_request("origin.example:443");
        request.headers.push(record("X-Token", "abc\ndef"));

        let error = build_replay_exchange_request(&request, None).unwrap_err();

        assert!(error
            .to_string()
            .contains("invalid request header value for X-Token"));
    }

    #[test]
    fn replay_exchange_revalidates_request_authority_after_rewrite() {
        let mut request = editable_request("origin.example:443");
        request.host = "user@127.0.0.1:8080".to_string();

        let error = build_replay_exchange_request(&request, None).unwrap_err();

        assert!(error.to_string().contains("invalid request host"));
    }

    #[test]
    fn replay_target_override_preserves_request_authority() {
        let request = editable_request("origin.example:443");
        let target = RequestTargetOverride {
            scheme: "https".to_string(),
            host: "target.example".to_string(),
            port: "9443".to_string(),
        };

        let rewritten = build_replay_exchange_request(&request, Some(&target)).unwrap();

        assert_eq!(rewritten.host, "origin.example:443");
        assert_eq!(rewritten.headers[0].value, "origin.example:443");
    }

    #[test]
    fn replay_target_override_accepts_ipv6_target_host() {
        let request = editable_request("origin.example:443");
        let target = RequestTargetOverride {
            scheme: "https".to_string(),
            host: "::1".to_string(),
            port: "9443".to_string(),
        };

        let rewritten = build_replay_exchange_request(&request, Some(&target)).unwrap();

        assert_eq!(rewritten.host, "origin.example:443");
        assert_eq!(rewritten.headers[0].value, "origin.example:443");
    }

    #[tokio::test]
    async fn replay_target_override_rejects_ip_literal_request_host() {
        let request = editable_request("127.0.0.1:443");
        let target = RequestTargetOverride {
            scheme: "https".to_string(),
            host: "127.0.0.2".to_string(),
            port: "9443".to_string(),
        };

        let error = build_replay_client(false, &request, Some(&target), None)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("request host is an IP address"));
    }

    #[tokio::test]
    async fn replay_target_override_allows_equivalent_ip_literal_request_host() {
        let request = editable_request("127.0.0.1:443");
        let target = RequestTargetOverride {
            scheme: "https".to_string(),
            host: "127.0.0.1".to_string(),
            port: "443".to_string(),
        };

        build_replay_client(false, &request, Some(&target), None)
            .await
            .expect("equivalent target override should be treated as a no-op");
    }

    #[tokio::test]
    async fn replay_target_override_rejects_bracketed_ipv6_request_host() {
        let request = editable_request("[::1]:443");
        let target = RequestTargetOverride {
            scheme: "https".to_string(),
            host: "::2".to_string(),
            port: "9443".to_string(),
        };

        let _error = build_replay_client(false, &request, Some(&target), None)
            .await
            .unwrap_err();
    }

    #[test]
    fn replay_target_override_uses_port_embedded_in_target_host() {
        let request = editable_request("origin.example:443");
        let target = RequestTargetOverride {
            scheme: "https".to_string(),
            host: "target.example:9443".to_string(),
            port: String::new(),
        };

        let rewritten = build_replay_exchange_request(&request, Some(&target)).unwrap();

        assert_eq!(rewritten.host, "origin.example:443");
        assert_eq!(rewritten.headers[0].value, "origin.example:443");
    }

    #[test]
    fn replay_outbound_uri_authority_omits_logical_port_for_target_override() {
        let request = editable_request("origin.example:8443");
        let target = RequestTargetOverride {
            scheme: "https".to_string(),
            host: "127.0.0.1".to_string(),
            port: "9443".to_string(),
        };

        let authority = build_replay_outbound_uri_authority(&request, Some(&target)).unwrap();

        assert_eq!(authority.as_deref(), Some("origin.example"));
    }

    #[test]
    fn replay_target_override_injects_original_host_when_missing() {
        let headers = HeaderMap::new();
        let host_override =
            replay_host_override(&headers, Some("origin.example"), "origin.example:8080")
                .expect("target override should synthesize original Host");

        assert_eq!(host_override, "origin.example:8080");
    }

    #[test]
    fn replay_target_override_keeps_explicit_host_header() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("signed.example:9443"));

        let host_override =
            replay_host_override(&headers, Some("origin.example"), "origin.example:8080")
                .expect("explicit Host should be preserved");

        assert_eq!(host_override, "signed.example:9443");
    }

    #[test]
    fn replay_outbound_uri_authority_ignores_equivalent_target_override() {
        let request = editable_request("origin.example:8443");
        let target = RequestTargetOverride {
            scheme: "https".to_string(),
            host: "origin.example".to_string(),
            port: "8443".to_string(),
        };

        let authority = build_replay_outbound_uri_authority(&request, Some(&target)).unwrap();

        assert_eq!(authority, None);
    }

    #[test]
    fn replay_outbound_uri_authority_brackets_ipv6_without_port() {
        let request = editable_request("[2001:db8::1]:8443");
        let target = RequestTargetOverride {
            scheme: "https".to_string(),
            host: "127.0.0.1".to_string(),
            port: "9443".to_string(),
        };

        let authority = build_replay_outbound_uri_authority(&request, Some(&target)).unwrap();

        assert_eq!(authority.as_deref(), Some("[2001:db8::1]"));
    }

    #[test]
    fn merges_multiple_cookie_headers_into_one() {
        let records = vec![
            record("cookie", "ssoLogin_pc_kr=null"),
            record("cookie", "ssoLogin_pc_en=null"),
            record("cookie", "DFPKO_JSESSIONID=abc123"),
            record("cookie", "uid=42"),
        ];
        let map = header_map_from_records(&records);
        assert_eq!(map.get_all(COOKIE).iter().count(), 1);
        let merged = map.get(COOKIE).unwrap().to_str().unwrap();
        assert_eq!(
            merged,
            "ssoLogin_pc_kr=null; ssoLogin_pc_en=null; DFPKO_JSESSIONID=abc123; uid=42"
        );
    }

    #[test]
    fn preserves_other_repeated_headers() {
        let records = vec![
            record("accept", "text/html"),
            record("accept-encoding", "gzip"),
            record("accept-encoding", "deflate"),
        ];
        let map = header_map_from_records(&records);
        assert_eq!(map.get_all("accept-encoding").iter().count(), 2);
        assert_eq!(map.get("accept").unwrap(), "text/html");
    }

    #[test]
    fn skips_empty_cookie_values() {
        let records = vec![
            record("cookie", "a=1"),
            record("cookie", "   "),
            record("cookie", ""),
            record("cookie", "b=2"),
        ];
        let map = header_map_from_records(&records);
        assert_eq!(map.get(COOKIE).unwrap(), "a=1; b=2");
    }

    #[test]
    fn handles_request_without_cookies() {
        let records = vec![record("user-agent", "test")];
        let map = header_map_from_records(&records);
        assert!(map.get(COOKIE).is_none());
        assert_eq!(map.get("user-agent").unwrap(), "test");
    }

    #[test]
    fn strip_hop_by_hop_headers_reads_all_connection_values() {
        let mut headers = HeaderMap::new();
        headers.append(CONNECTION, HeaderValue::from_static("keep-alive"));
        headers.append(CONNECTION, HeaderValue::from_static("X-Hop"));
        headers.insert("x-hop", HeaderValue::from_static("leaks"));

        strip_hop_by_hop_headers(&mut headers);

        assert!(!headers.contains_key("x-hop"));
        assert!(!headers.contains_key(CONNECTION));
    }

    #[tokio::test]
    async fn head_synthetic_error_response_has_empty_wire_and_capture_body() {
        let (state, data_dir) = test_proxy_state("sniper-head-synthetic-response");

        let (response, capture) = synthetic_error_response_for_method(
            StatusCode::BAD_REQUEST,
            "invalid host",
            &state,
            "HEAD",
        );

        assert_eq!(capture.body_size, 0);
        assert!(capture.body_preview.is_empty());
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(body.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn dropped_head_transaction_has_empty_wire_and_capture_body() {
        let (state, data_dir) = test_proxy_state("sniper-head-dropped-response");
        let request = EditableRequest {
            scheme: "http".to_string(),
            host: "example.com".to_string(),
            method: "HEAD".to_string(),
            path: "/".to_string(),
            headers: vec![record("Host", "example.com")],
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };

        let dropped = build_dropped_transaction(
            state.as_ref(),
            request,
            Utc::now(),
            Instant::now(),
            "Request dropped in intercept.",
            Some(Version::HTTP_11),
        );

        let response_capture = dropped.record.response.as_ref().unwrap();
        assert_eq!(response_capture.body_size, 0);
        assert!(response_capture.body_preview.is_empty());
        let body = dropped
            .response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        assert!(body.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn http_special_host_head_exchange_records_empty_response_body() {
        let (state, data_dir) = test_proxy_state("sniper-http-special-host-head");
        let session = state.session().await;
        let request = EditableRequest {
            scheme: "http".to_string(),
            host: "sniper".to_string(),
            method: "HEAD".to_string(),
            path: "/".to_string(),
            headers: vec![record("Host", "sniper")],
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };

        let exchange = execute_http_exchange(
            state.clone(),
            session,
            &build_client(false),
            request,
            Utc::now(),
            Instant::now(),
            Vec::new(),
            false,
            None,
            Some(Version::HTTP_11),
            None,
            None,
        )
        .await;

        assert_eq!(
            exchange
                .record
                .response
                .as_ref()
                .map(|response| response.body_size),
            Some(0)
        );
        let response = match exchange.response {
            Ok(response) => response,
            Err(error) => panic!("special-host exchange failed: {}", error.message),
        };
        assert!(response.body.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn rebuild_response_preserves_head_content_length_and_removes_wire_body() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("1234"));

        let response = rebuild_response(
            headers,
            StatusCode::OK,
            Bytes::from_static(b"hidden"),
            "HEAD",
        );

        assert_eq!(response.headers().get(CONTENT_LENGTH).unwrap(), "1234");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn rebuild_response_preserves_not_modified_content_length_and_removes_wire_body() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("55"));

        let response = rebuild_response(
            headers,
            StatusCode::NOT_MODIFIED,
            Bytes::from_static(b"not-on-the-wire"),
            "GET",
        );

        assert_eq!(response.headers().get(CONTENT_LENGTH).unwrap(), "55");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn rebuild_response_removes_reset_content_body_and_framing() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("7"));

        let response = rebuild_response(
            headers,
            StatusCode::RESET_CONTENT,
            Bytes::from_static(b"illegal"),
            "GET",
        );

        assert!(!response.headers().contains_key(CONTENT_LENGTH));
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn rebuild_streaming_response_removes_reset_content_framing() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("7"));

        let response = rebuild_streaming_response(
            headers,
            StatusCode::RESET_CONTENT,
            Body::from("illegal"),
            "GET",
        );

        assert!(!response.headers().contains_key(CONTENT_LENGTH));
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(body.is_empty());
    }

    #[test]
    fn rebuild_response_removes_content_length_from_switching_protocols() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("0"));

        let response = rebuild_response(
            headers,
            StatusCode::SWITCHING_PROTOCOLS,
            Bytes::new(),
            "GET",
        );

        assert!(!response.headers().contains_key(CONTENT_LENGTH));
    }

    #[test]
    fn websocket_extension_header_is_not_forwarded_or_reflected() {
        assert!(!should_forward_websocket_header("Sec-WebSocket-Extensions"));

        let mut request_headers = HeaderMap::new();
        request_headers.insert(
            SEC_WEBSOCKET_KEY,
            HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
        );
        let mut upstream_headers = HeaderMap::new();
        upstream_headers.insert(
            SEC_WEBSOCKET_EXTENSIONS,
            HeaderValue::from_static("permessage-deflate"),
        );

        let response_headers =
            build_websocket_client_response_headers(&request_headers, upstream_headers).unwrap();

        assert!(!response_headers.contains_key(SEC_WEBSOCKET_EXTENSIONS));
        assert!(response_headers.contains_key(SEC_WEBSOCKET_ACCEPT));
    }

    #[test]
    fn websocket_response_uses_original_client_key_for_accept() {
        let mut client_headers = HeaderMap::new();
        client_headers.insert(
            SEC_WEBSOCKET_KEY,
            HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
        );
        let mut rewritten_headers = HeaderMap::new();
        rewritten_headers.insert(
            SEC_WEBSOCKET_KEY,
            HeaderValue::from_static("AAAAAAAAAAAAAAAAAAAAAA=="),
        );

        let response_headers =
            build_websocket_client_response_headers(&client_headers, HeaderMap::new()).unwrap();

        assert_ne!(
            response_headers.get(SEC_WEBSOCKET_ACCEPT).unwrap(),
            &HeaderValue::from_str(&derive_accept_key(
                single_header_value(&rewritten_headers, SEC_WEBSOCKET_KEY)
                    .unwrap()
                    .as_bytes()
            ))
            .unwrap()
        );
        assert_eq!(
            response_headers.get(SEC_WEBSOCKET_ACCEPT).unwrap(),
            &HeaderValue::from_str(&derive_accept_key(
                single_header_value(&client_headers, SEC_WEBSOCKET_KEY)
                    .unwrap()
                    .as_bytes()
            ))
            .unwrap()
        );
    }

    #[test]
    fn websocket_response_validation_rejects_mutated_accept_header() {
        let mut request_headers = HeaderMap::new();
        request_headers.insert(
            SEC_WEBSOCKET_KEY,
            HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
        );
        let mut response_headers =
            build_websocket_client_response_headers(&request_headers, HeaderMap::new()).unwrap();
        response_headers.insert(SEC_WEBSOCKET_ACCEPT, HeaderValue::from_static("bad"));

        assert_eq!(
            websocket_response_validation_error(
                &request_headers,
                &HeaderMap::new(),
                &response_headers
            ),
            Some("invalid Sec-WebSocket-Accept")
        );
    }

    #[test]
    fn websocket_response_validation_rejects_extensions_added_after_sanitization() {
        let mut request_headers = HeaderMap::new();
        request_headers.insert(
            SEC_WEBSOCKET_KEY,
            HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
        );
        let mut response_headers =
            build_websocket_client_response_headers(&request_headers, HeaderMap::new()).unwrap();
        response_headers.insert(
            SEC_WEBSOCKET_EXTENSIONS,
            HeaderValue::from_static("permessage-deflate"),
        );

        assert_eq!(
            websocket_response_validation_error(
                &request_headers,
                &HeaderMap::new(),
                &response_headers
            ),
            Some("WebSocket extensions must not be negotiated by match/replace")
        );
    }

    #[test]
    fn websocket_response_validation_rejects_unoffered_protocol() {
        let mut request_headers = HeaderMap::new();
        request_headers.insert(
            SEC_WEBSOCKET_KEY,
            HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
        );
        request_headers.insert(
            SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static("chat, superchat"),
        );
        let mut response_headers =
            build_websocket_client_response_headers(&request_headers, HeaderMap::new()).unwrap();
        response_headers.insert(SEC_WEBSOCKET_PROTOCOL, HeaderValue::from_static("other"));

        assert_eq!(
            websocket_response_validation_error(
                &request_headers,
                &HeaderMap::new(),
                &response_headers
            ),
            Some("Sec-WebSocket-Protocol was not offered by the client")
        );

        response_headers.append(SEC_WEBSOCKET_PROTOCOL, HeaderValue::from_static("chat"));
        assert_eq!(
            websocket_response_validation_error(
                &request_headers,
                &HeaderMap::new(),
                &response_headers
            ),
            Some("invalid Sec-WebSocket-Protocol")
        );
        response_headers.remove(SEC_WEBSOCKET_PROTOCOL);
        response_headers.insert(
            SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static("superchat"),
        );
        let mut upstream_headers = HeaderMap::new();
        upstream_headers.insert(
            SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static("superchat"),
        );
        assert_eq!(
            websocket_response_validation_error(
                &request_headers,
                &upstream_headers,
                &response_headers
            ),
            None
        );
    }

    #[test]
    fn websocket_response_validation_rejects_protocol_changed_after_upstream() {
        let mut request_headers = HeaderMap::new();
        request_headers.insert(
            SEC_WEBSOCKET_KEY,
            HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
        );
        request_headers.insert(
            SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static("chat, superchat"),
        );
        let mut upstream_headers = HeaderMap::new();
        upstream_headers.insert(SEC_WEBSOCKET_PROTOCOL, HeaderValue::from_static("chat"));
        let mut response_headers =
            build_websocket_client_response_headers(&request_headers, upstream_headers.clone())
                .unwrap();
        response_headers.insert(
            SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static("superchat"),
        );

        assert_eq!(
            websocket_response_validation_error(
                &request_headers,
                &upstream_headers,
                &response_headers
            ),
            Some("Sec-WebSocket-Protocol changed after upstream negotiation")
        );

        response_headers.remove(SEC_WEBSOCKET_PROTOCOL);
        assert_eq!(
            websocket_response_validation_error(
                &request_headers,
                &upstream_headers,
                &response_headers
            ),
            Some("Sec-WebSocket-Protocol changed after upstream negotiation")
        );
    }

    #[test]
    fn cookie_header_name_is_case_insensitive() {
        let records = vec![
            record("Cookie", "a=1"),
            record("COOKIE", "b=2"),
            record("cookie", "c=3"),
        ];
        let map = header_map_from_records(&records);
        assert_eq!(map.get_all(COOKIE).iter().count(), 1);
        assert_eq!(map.get(COOKIE).unwrap(), "a=1; b=2; c=3");
    }
}
