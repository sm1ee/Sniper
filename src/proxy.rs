use std::{
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Instant,
};

use anyhow::{anyhow, Context, Result};
use axum::body::Body;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bytes::Bytes;
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use http::{
    header::{
        HeaderMap, HeaderName, HeaderValue, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HOST,
        SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_EXTENSIONS, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_PROTOCOL,
        UPGRADE,
    },
    request::Parts,
    uri::Authority,
    Method, Request, Response, StatusCode, Uri,
};
use http_body_util::BodyExt;
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use reqwest::{redirect::Policy, Client};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        client::IntoClientRequest,
        handshake::derive_accept_key,
        protocol::{Message as WebSocketMessage, Role},
    },
    MaybeTlsStream, WebSocketStream,
};
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    event_log::EventLevel,
    intercept::{InterceptRecord, InterceptResolution},
    model::{
        BodyEncoding, EditableRequest, HeaderRecord, MessageRecord, RequestTargetOverride,
        TransactionRecord, WebSocketFrameDirection, WebSocketFrameKind, WebSocketFrameRecord,
        WebSocketSessionRecord,
    },
    session::SessionContext,
    special_host,
    state::AppState,
};

type ProxyClient = Client;
type UpstreamWebSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

struct UpstreamResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

struct ExecutedExchange {
    record: TransactionRecord,
    response: std::result::Result<UpstreamResponse, UpstreamError>,
}

struct UpstreamError {
    status: StatusCode,
    message: String,
}

pub async fn run_proxy(state: Arc<AppState>) -> Result<()> {
    let listener = TcpListener::bind(state.config.proxy_addr)
        .await
        .with_context(|| {
            format!(
                "failed to bind proxy listener to {}",
                state.config.proxy_addr
            )
        })?;

    info!(proxy_addr = %listener.local_addr()?, "proxy listener ready");
    serve_proxy(listener, state).await
}

pub async fn serve_proxy(listener: TcpListener, state: Arc<AppState>) -> Result<()> {
    let client = build_client(state.config.upstream_insecure);

    loop {
        let (stream, peer_addr) = listener.accept().await.context("proxy accept failed")?;
        let io = TokioIo::new(stream);
        let state = state.clone();
        let client = client.clone();

        tokio::spawn(async move {
            let service = service_fn(move |request| {
                handle_request(request, state.clone(), client.clone(), peer_addr)
            });

            if let Err(error) = http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(io, service)
                .with_upgrades()
                .await
            {
                warn!(%peer_addr, ?error, "proxy connection failed");
            }
        });
    }
}

pub async fn send_repeater_request(
    state: Arc<AppState>,
    request: EditableRequest,
    target: Option<RequestTargetOverride>,
    source_transaction_id: Option<Uuid>,
) -> Result<TransactionRecord> {
    let session = state.session().await;
    if is_websocket_upgrade_editable(&request) {
        return Err(anyhow!(
            "Repeater currently supports HTTP/HTTPS requests only, not WebSocket upgrades"
        ));
    }

    validate_reusable_request_source(session.as_ref(), &request, source_transaction_id).await?;

    let started_at = Utc::now();
    let started = Instant::now();
    let (request, mut notes) = apply_request_match_replace(session.as_ref(), request).await;
    let request = build_repeater_exchange_request(&request, target.as_ref())?;
    let client =
        build_repeater_client(state.config.upstream_insecure, &request, target.as_ref()).await?;
    notes.push("Sent from Repeater.".to_string());
    let exchange = execute_http_exchange(
        state.clone(),
        session.clone(),
        &client,
        request,
        started_at,
        started,
        notes,
        true,
    )
    .await;

    session.store.insert(exchange.record.clone()).await;
    session
        .event_log
        .push(
            EventLevel::Info,
            "repeater",
            "Request sent",
            format!(
                "{} {}{}",
                exchange.record.method, exchange.record.host, exchange.record.path
            ),
        )
        .await;
    persist_session_quiet(&state, &session).await;
    Ok(exchange.record)
}

fn build_client(upstream_insecure: bool) -> ProxyClient {
    Client::builder()
        .redirect(Policy::none())
        .danger_accept_invalid_certs(upstream_insecure)
        .build()
        .expect("failed to build upstream HTTP client")
}

async fn build_repeater_client(
    upstream_insecure: bool,
    request: &EditableRequest,
    target: Option<&RequestTargetOverride>,
) -> Result<ProxyClient> {
    let mut builder = Client::builder()
        .redirect(Policy::none())
        .danger_accept_invalid_certs(upstream_insecure);

    if let Some(target) = target {
        let request_authority = parse_request_authority(&request.host, &request.scheme)?;
        let target_host = target.host.trim();
        if !target_host.is_empty()
            && !request_authority.host.eq_ignore_ascii_case(target_host)
            && request_authority.host.parse::<IpAddr>().is_err()
        {
            let target_port =
                repeater_target_port(target.port.trim(), &request.scheme, request_authority.port)?;
            let resolved_addrs = resolve_target_host(target_host, target_port).await?;
            builder = builder.resolve_to_addrs(&request_authority.host, &resolved_addrs);
        }
    }

    builder
        .build()
        .context("failed to build repeater HTTP client")
}

fn build_repeater_exchange_request(
    request: &EditableRequest,
    target: Option<&RequestTargetOverride>,
) -> Result<EditableRequest> {
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
    let effective_port =
        repeater_target_port(target_port, &rewritten.scheme, request_authority.port)?;
    rewritten.host = build_authority(&request_authority.host, effective_port);
    Ok(rewritten)
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

fn repeater_target_port(target_port: &str, scheme: &str, request_port: Option<u16>) -> Result<u16> {
    if target_port.is_empty() {
        return Ok(request_port.unwrap_or(default_port_for_scheme(scheme)?));
    }

    target_port
        .parse::<u16>()
        .with_context(|| format!("invalid repeater target port: {target_port}"))
}

fn default_port_for_scheme(scheme: &str) -> Result<u16> {
    match scheme.to_ascii_lowercase().as_str() {
        "https" => Ok(443),
        "http" => Ok(80),
        other => Err(anyhow!("unsupported request scheme for repeater: {other}")),
    }
}

fn build_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') && !host.ends_with(']') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

async fn resolve_target_host(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("failed to resolve repeater target host {host}:{port}"))?
        .collect();

    if addrs.is_empty() {
        Err(anyhow!(
            "repeater target host {host}:{port} resolved to no addresses"
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
    client: ProxyClient,
    peer_addr: SocketAddr,
) -> Result<Response<Body>, Infallible> {
    let session = state.session().await;
    let response = if request.method() == Method::CONNECT {
        handle_connect(request, state, session, client, peer_addr).await
    } else {
        handle_http(request, state, session, client, peer_addr).await
    };

    Ok(response)
}

async fn handle_connect(
    request: Request<Incoming>,
    state: Arc<AppState>,
    session: Arc<SessionContext>,
    client: ProxyClient,
    peer_addr: SocketAddr,
) -> Response<Body> {
    let started_at = Utc::now();
    let started = Instant::now();
    let target = match connect_target(request.uri()) {
        Ok(target) => target,
        Err(error) => {
            warn!(%peer_addr, ?error, "invalid CONNECT target");
            return text_response(StatusCode::BAD_REQUEST, error.to_string());
        }
    };
    let request_capture = MessageRecord::from_headers_and_body(
        request.headers(),
        &[],
        state.config.body_preview_bytes,
    );
    let upgrade = hyper::upgrade::on(request);

    if special_host::is_special_host(&target) {
        let state = state.clone();
        let session = session.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_special_host_tls(
                upgrade,
                state,
                session,
                request_capture,
                started_at,
                started,
            )
            .await
            {
                warn!(?error, "special host TLS handler failed");
            }
        });
    } else {
        let failure_state = state.clone();
        let failure_session = session.clone();
        let failure_target = target.clone();
        let failure_capture = request_capture.clone();
        let failure_started_at = started_at;
        let failure_started = started;

        tokio::spawn(async move {
            if let Err(error) = serve_https_mitm(
                upgrade,
                state.clone(),
                session.clone(),
                client,
                target,
                request_capture,
                started_at,
                started,
                peer_addr,
            )
            .await
            {
                warn!(%peer_addr, ?error, target = %failure_target, "HTTPS MITM handler failed");
                failure_session
                    .store
                    .insert(TransactionRecord::tunnel(
                        failure_started_at,
                        failure_target,
                        Some(StatusCode::BAD_GATEWAY.as_u16()),
                        failure_started.elapsed().as_millis() as u64,
                        failure_capture,
                        vec![format!("HTTPS MITM failed: {error}")],
                    ))
                    .await;
                persist_session_quiet(&failure_state, &failure_session).await;
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
    client: ProxyClient,
    peer_addr: SocketAddr,
) -> Response<Body> {
    handle_forwardable_request(
        request, state, session, client, peer_addr, "http", None, false,
    )
    .await
}

async fn handle_forwardable_request(
    mut request: Request<Incoming>,
    state: Arc<AppState>,
    session: Arc<SessionContext>,
    client: ProxyClient,
    peer_addr: SocketAddr,
    default_scheme: &str,
    authority_override: Option<String>,
    secure_special_host: bool,
) -> Response<Body> {
    let started_at = Utc::now();
    let started = Instant::now();
    let is_websocket = is_websocket_upgrade_headers(request.headers());
    let on_upgrade = is_websocket.then(|| hyper::upgrade::on(&mut request));
    let (parts, body) = request.into_parts();
    let absolute_uri = match resolve_absolute_uri(
        &parts.uri,
        &parts.headers,
        default_scheme,
        authority_override.as_deref(),
    ) {
        Ok(uri) => uri,
        Err(error) => return text_response(StatusCode::BAD_REQUEST, error.to_string()),
    };
    let request_bytes = match collect_body(body).await {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!(%peer_addr, ?error, "failed to read request body");
            return text_response(StatusCode::BAD_REQUEST, error);
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
        client,
        peer_addr,
        started_at,
        started,
        secure_special_host,
    )
    .await
}

async fn collect_body(body: Incoming) -> std::result::Result<Bytes, String> {
    body.collect()
        .await
        .map(|collected| collected.to_bytes())
        .map_err(|error| format!("body collection failed: {error}"))
}

fn resolve_absolute_uri(
    uri: &Uri,
    headers: &HeaderMap,
    default_scheme: &str,
    authority_override: Option<&str>,
) -> Result<Uri> {
    if uri.scheme().is_some() && uri.authority().is_some() {
        return Ok(uri.clone());
    }

    let authority = if let Some(authority) = authority_override {
        authority
    } else {
        headers
            .get(HOST)
            .context("missing Host header for origin-form request")?
            .to_str()
            .context("invalid Host header")?
    };
    let path = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");

    Uri::builder()
        .scheme(default_scheme)
        .authority(authority)
        .path_and_query(path)
        .build()
        .map_err(|error| anyhow!("failed to build absolute URI: {error}"))
}

fn connect_target(uri: &Uri) -> Result<String> {
    if let Some(authority) = uri.authority() {
        return Ok(authority.to_string());
    }

    let target = uri.path().trim();
    if target.is_empty() {
        Err(anyhow!("CONNECT request is missing authority"))
    } else {
        Ok(target.to_string())
    }
}

fn rebuild_response(headers: HeaderMap, status: StatusCode, body: Bytes) -> Response<Body> {
    let mut sanitized = headers;
    strip_hop_by_hop_headers(&mut sanitized);
    sanitized.remove(CONTENT_LENGTH);
    if let Ok(value) = HeaderValue::from_str(&body.len().to_string()) {
        sanitized.insert(CONTENT_LENGTH, value);
    }

    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    *response.headers_mut() = sanitized;
    response
}

fn strip_hop_by_hop_headers(headers: &mut HeaderMap) {
    let connection_tokens = headers
        .get(CONNECTION)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .map(|token| token.trim().to_ascii_lowercase())
                .filter(|token| !token.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

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

fn text_response(status: StatusCode, message: impl Into<String>) -> Response<Body> {
    let message = message.into();
    let mut response = Response::new(Body::from(message.clone()));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    if let Ok(value) = HeaderValue::from_str(&message.len().to_string()) {
        response.headers_mut().insert(CONTENT_LENGTH, value);
    }
    response
}

fn build_local_response(status: StatusCode, headers: HeaderMap, body: Vec<u8>) -> Response<Body> {
    let mut response = Response::new(Body::from(body.clone()));
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    if let Ok(value) = HeaderValue::from_str(&body.len().to_string()) {
        response.headers_mut().insert(CONTENT_LENGTH, value);
    }
    response
}

async fn serve_special_host_tls(
    upgrade: hyper::upgrade::OnUpgrade,
    state: Arc<AppState>,
    session: Arc<SessionContext>,
    connect_capture: MessageRecord,
    started_at: chrono::DateTime<Utc>,
    started: Instant,
) -> Result<()> {
    let upgraded = upgrade
        .await
        .context("CONNECT upgrade failed for special host")?;
    let upgraded = TokioIo::new(upgraded);
    let acceptor: TlsAcceptor = state.certificates.tls_acceptor();
    let tls_stream = acceptor
        .accept(upgraded)
        .await
        .context("TLS handshake failed for special host")?;

    session
        .store
        .insert(TransactionRecord::tunnel(
            started_at,
            "sniper:443".to_string(),
            Some(StatusCode::OK.as_u16()),
            started.elapsed().as_millis() as u64,
            connect_capture,
            vec![
                "CONNECT tunnel terminated locally for the Sniper certificate portal.".to_string(),
            ],
        ))
        .await;
    persist_session_quiet(&state, &session).await;

    let io = TokioIo::new(tls_stream);
    let service = service_fn(move |request| {
        handle_special_host_request(request, state.clone(), session.clone())
    });
    http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(io, service)
        .await
        .context("special host HTTP serving failed")
}

async fn serve_https_mitm(
    upgrade: hyper::upgrade::OnUpgrade,
    state: Arc<AppState>,
    session: Arc<SessionContext>,
    client: ProxyClient,
    target: String,
    connect_capture: MessageRecord,
    started_at: chrono::DateTime<Utc>,
    started: Instant,
    peer_addr: SocketAddr,
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

    session
        .store
        .insert(TransactionRecord::tunnel(
            started_at,
            target,
            Some(StatusCode::OK.as_u16()),
            started.elapsed().as_millis() as u64,
            connect_capture,
            vec![format!(
                "HTTPS MITM terminated locally and is forwarding upstream traffic for {}.",
                authority.host()
            )],
        ))
        .await;
    persist_session_quiet(&state, &session).await;

    let io = TokioIo::new(tls_stream);
    let connect_authority = authority.to_string();
    let service = service_fn(move |request| {
        handle_https_mitm_request(
            request,
            state.clone(),
            session.clone(),
            client.clone(),
            peer_addr,
            connect_authority.clone(),
        )
    });
    http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(io, service)
        .with_upgrades()
        .await
        .context("HTTPS MITM HTTP serving failed")
}

async fn handle_special_host_request(
    request: Request<Incoming>,
    state: Arc<AppState>,
    session: Arc<SessionContext>,
) -> Result<Response<Body>, Infallible> {
    let started_at = Utc::now();
    let started = Instant::now();
    let (parts, body) = request.into_parts();
    let body_bytes = collect_body(body).await.unwrap_or_default();
    let path = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let request_capture = MessageRecord::from_headers_and_body(
        &parts.headers,
        body_bytes.as_ref(),
        state.config.body_preview_bytes,
    );
    let response = special_host::respond(&path, &parts.method, state.as_ref(), true);
    let response_capture = MessageRecord::from_headers_and_body(
        &response.headers,
        response.body.as_ref(),
        state.config.body_preview_bytes,
    );

    session
        .store
        .insert(TransactionRecord::http(
            started_at,
            parts.method.to_string(),
            "https".to_string(),
            "sniper".to_string(),
            path,
            Some(response.status.as_u16()),
            started.elapsed().as_millis() as u64,
            request_capture,
            Some(response_capture),
            response.notes.clone(),
        ))
        .await;
    persist_session_quiet(&state, &session).await;

    Ok(build_local_response(
        response.status,
        response.headers,
        response.body,
    ))
}

async fn handle_https_mitm_request(
    request: Request<Incoming>,
    state: Arc<AppState>,
    session: Arc<SessionContext>,
    client: ProxyClient,
    peer_addr: SocketAddr,
    connect_authority: String,
) -> Result<Response<Body>, Infallible> {
    Ok(handle_forwardable_request(
        request,
        state,
        session,
        client,
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
    client: ProxyClient,
    peer_addr: SocketAddr,
    started_at: chrono::DateTime<Utc>,
    started: Instant,
    secure_special_host: bool,
) -> Response<Body> {
    let editable_request = editable_request_from_parts(&parts, &request_bytes, &absolute_uri);
    let intercepted_request = match maybe_intercept_request(
        state.clone(),
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
            );
            session.store.insert(dropped.record).await;
            persist_session_quiet(&state, &session).await;
            return dropped.response;
        }
    };
    let (forwarded_request, notes) =
        apply_request_match_replace(session.as_ref(), intercepted_request).await;

    let exchange = execute_http_exchange(
        state.clone(),
        session.clone(),
        &client,
        forwarded_request,
        started_at,
        started,
        notes,
        secure_special_host,
    )
    .await;
    let record = exchange.record.clone();
    session.store.insert(record).await;
    persist_session_quiet(&state, &session).await;

    match exchange.response {
        Ok(response) => rebuild_response(response.headers, response.status, response.body),
        Err(error) => text_response(error.status, error.message),
    }
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
    let editable_request = editable_request_from_parts(&parts, &request_bytes, &absolute_uri);
    let forwarded_request = match maybe_intercept_request(
        state.clone(),
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
            );
            session.store.insert(dropped.record).await;
            persist_session_quiet(&state, &session).await;
            return dropped.response;
        }
    };
    let (forwarded_request, request_notes) =
        apply_request_match_replace(session.as_ref(), forwarded_request).await;

    if !is_websocket_upgrade_editable(&forwarded_request) {
        let client = build_client(state.config.upstream_insecure);
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
        )
        .await;
        let record = exchange.record.clone();
        session.store.insert(record).await;
        persist_session_quiet(&state, &session).await;
        return match exchange.response {
            Ok(response) => rebuild_response(response.headers, response.status, response.body),
            Err(error) => text_response(error.status, error.message),
        };
    }

    if special_host::is_special_host(&forwarded_request.host) {
        let exchange = execute_http_exchange(
            state.clone(),
            session.clone(),
            &build_client(state.config.upstream_insecure),
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
        )
        .await;
        let record = exchange.record.clone();
        session.store.insert(record).await;
        persist_session_quiet(&state, &session).await;
        return match exchange.response {
            Ok(response) => rebuild_response(response.headers, response.status, response.body),
            Err(error) => text_response(error.status, error.message),
        };
    }

    let request_headers = header_map_from_records(&forwarded_request.headers);
    let request_capture = MessageRecord::from_headers_and_body(
        &request_headers,
        &forwarded_request.body_bytes(),
        state.config.body_preview_bytes,
    );
    let response = match connect_upstream_websocket(&forwarded_request).await {
        Ok(response) => response,
        Err(error) => {
            let record = TransactionRecord::http(
                started_at,
                forwarded_request.method.clone(),
                forwarded_request.scheme.clone(),
                forwarded_request.host.clone(),
                normalize_request_path(&forwarded_request.path),
                Some(StatusCode::BAD_GATEWAY.as_u16()),
                started.elapsed().as_millis() as u64,
                request_capture,
                None,
                vec![format!("WebSocket connect failed: {error}")],
            );
            session.store.insert(record).await;
            persist_session_quiet(&state, &session).await;
            return text_response(
                StatusCode::BAD_GATEWAY,
                format!("WebSocket connect failed: {error}"),
            );
        }
    };

    let response_headers = match build_websocket_client_response_headers(
        &request_headers,
        response.upstream_headers.clone(),
    ) {
        Ok(headers) => headers,
        Err(error) => {
            let record = TransactionRecord::http(
                started_at,
                forwarded_request.method.clone(),
                forwarded_request.scheme.clone(),
                forwarded_request.host.clone(),
                normalize_request_path(&forwarded_request.path),
                Some(StatusCode::BAD_REQUEST.as_u16()),
                started.elapsed().as_millis() as u64,
                request_capture,
                None,
                vec![format!("Invalid WebSocket handshake: {error}")],
            );
            session.store.insert(record).await;
            persist_session_quiet(&state, &session).await;
            return text_response(
                StatusCode::BAD_REQUEST,
                format!("Invalid WebSocket handshake: {error}"),
            );
        }
    };
    let applied_response = session
        .match_replace
        .apply_response(response_headers, Bytes::new())
        .await;
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

    let response_capture = MessageRecord::from_headers_and_body(
        &applied_response.headers,
        &[],
        state.config.body_preview_bytes,
    );
    let request_path = normalize_request_path(&forwarded_request.path);
    let http_record = TransactionRecord::http(
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
            request_notes,
            vec!["WebSocket upgrade proxied and mirrored into WebSockets history.".to_string()],
        ),
    );
    session.store.insert(http_record).await;
    session
        .event_log
        .push(
            EventLevel::Info,
            "websocket",
            "Session opened",
            format!("{}{}", forwarded_request.host, request_path),
        )
        .await;

    let capture_enabled = session.runtime.websocket_capture_enabled().await;
    let session_id = capture_enabled.then(Uuid::new_v4);

    if let Some(id) = session_id {
        session
            .websockets
            .open(WebSocketSessionRecord {
                id,
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
            .await;
    }
    persist_session_quiet(&state, &session).await;

    tokio::spawn(async move {
        if let Err(error) = relay_websocket_session(
            on_upgrade,
            response.websocket,
            state.clone(),
            session.clone(),
            session_id,
            started,
        )
        .await
        {
            warn!(
                %peer_addr,
                host = %forwarded_request.host,
                path = %request_path,
                ?error,
                "websocket relay failed"
            );
            if let Some(id) = session_id {
                session
                    .websockets
                    .close(
                        id,
                        Utc::now(),
                        started.elapsed().as_millis() as u64,
                        Some(format!("Relay error: {error}")),
                    )
                    .await;
                persist_session_quiet(&state, &session).await;
            }
        }
    });

    build_local_response(
        StatusCode::SWITCHING_PROTOCOLS,
        applied_response.headers,
        Vec::new(),
    )
}

async fn maybe_intercept_request(
    state: Arc<AppState>,
    session: Arc<SessionContext>,
    peer_addr: SocketAddr,
    request: EditableRequest,
    is_websocket: bool,
) -> InterceptResolution {
    if !session.runtime.intercept_enabled().await {
        return InterceptResolution::Forward(request);
    }

    if special_host::is_special_host(&request.host)
        || !session.runtime.is_in_scope(&request.host).await
    {
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
    persist_session_quiet(&state, &session).await;
    resolution
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
                record: TransactionRecord::http(
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
                ),
                response: Err(UpstreamError {
                    status: StatusCode::BAD_REQUEST,
                    message,
                }),
            };
        }
    };

    if special_host::is_special_host(&request.host) {
        let response = special_host::respond(
            &path,
            &method,
            state.as_ref(),
            secure_special_host || request.scheme.eq_ignore_ascii_case("https"),
        );
        let response_capture = MessageRecord::from_headers_and_body(
            &response.headers,
            response.body.as_ref(),
            state.config.body_preview_bytes,
        );
        notes.extend(response.notes.clone());
        return ExecutedExchange {
            record: TransactionRecord::http(
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
            ),
            response: Ok(UpstreamResponse {
                status: response.status,
                headers: response.headers,
                body: Bytes::from(response.body),
            }),
        };
    }

    let absolute_uri = match build_uri_from_request(&request) {
        Ok(uri) => uri,
        Err(error) => {
            let message = error.to_string();
            notes.push(message.clone());
            let (_response, response_capture) =
                synthetic_error_response(StatusCode::BAD_REQUEST, &message, &state);
            return ExecutedExchange {
                record: TransactionRecord::http(
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
                ),
                response: Err(UpstreamError {
                    status: StatusCode::BAD_REQUEST,
                    message,
                }),
            };
        }
    };

    let host_override = request_headers.get(HOST).cloned();
    let mut outbound_headers = request_headers.clone();
    strip_hop_by_hop_headers(&mut outbound_headers);
    outbound_headers.remove(HOST);
    outbound_headers.remove(CONTENT_LENGTH);

    let mut request_builder = client
        .request(method.clone(), absolute_uri.to_string())
        .headers(outbound_headers)
        .body(request_body.clone());
    if let Some(host_override) = host_override {
        request_builder = request_builder.header(HOST, host_override);
    }

    match request_builder.send().await {
        Ok(response) => {
            let status = response.status();
            let response_headers = response.headers().clone();
            match response.bytes().await {
                Ok(response_bytes) => {
                    let applied_response = session
                        .match_replace
                        .apply_response(response_headers, response_bytes)
                        .await;
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
                        record: TransactionRecord::http(
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
                    let (_response, response_capture) =
                        synthetic_error_response(StatusCode::BAD_GATEWAY, &message, &state);
                    ExecutedExchange {
                        record: TransactionRecord::http(
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
            let (_response, response_capture) =
                synthetic_error_response(StatusCode::BAD_GATEWAY, &message, &state);
            ExecutedExchange {
                record: TransactionRecord::http(
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
) -> (EditableRequest, Vec<String>) {
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
    (applied_request.request, applied_request.notes)
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
    if source_record.request.preview_truncated
        && request.body_bytes() == source_record.request.body_bytes()
    {
        return Err(anyhow!(
            "The captured request body was truncated at the preview cap. Increase the preview cap and capture it again, or paste the full body manually before sending."
        ));
    }
    Ok(())
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

    EditableRequest::from_headers_and_body(
        scheme,
        host,
        parts.method.to_string(),
        path,
        &parts.headers,
        request_bytes.as_ref(),
    )
}

fn header_map_from_records(headers: &[HeaderRecord]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for header in headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(header.name.as_bytes()),
            HeaderValue::from_str(&header.value),
        ) {
            map.append(name, value);
        }
    }
    map
}

fn build_uri_from_request(request: &EditableRequest) -> Result<Uri> {
    Uri::builder()
        .scheme(request.scheme.as_str())
        .authority(request.host.as_str())
        .path_and_query(normalize_request_path(&request.path))
        .build()
        .map_err(|error| anyhow!("failed to build upstream URI: {error}"))
}

fn normalize_request_path(path: &str) -> String {
    if path.trim().is_empty() {
        "/".to_string()
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
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    let capture = MessageRecord::from_headers_and_body(
        &headers,
        message.as_bytes(),
        state.config.body_preview_bytes,
    );
    (text_response(status, message), capture)
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
) -> DroppedExchange {
    let request_headers = header_map_from_records(&request.headers);
    let request_capture = MessageRecord::from_headers_and_body(
        &request_headers,
        &request.body_bytes(),
        state.config.body_preview_bytes,
    );
    let response = text_response(StatusCode::FORBIDDEN, note);
    let response_capture = MessageRecord::from_headers_and_body(
        response.headers(),
        note.as_bytes(),
        state.config.body_preview_bytes,
    );
    DroppedExchange {
        record: TransactionRecord::http(
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
        ),
        response,
    }
}

fn is_websocket_upgrade_headers(headers: &HeaderMap) -> bool {
    headers
        .get(UPGRADE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
        && headers
            .get(CONNECTION)
            .and_then(|value| value.to_str().ok())
            .map(|value| {
                value
                    .split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
            })
            .unwrap_or(false)
}

fn is_websocket_upgrade_editable(request: &EditableRequest) -> bool {
    let headers = header_map_from_records(&request.headers);
    is_websocket_upgrade_headers(&headers)
}

struct ConnectedWebSocket {
    websocket: UpstreamWebSocket,
    upstream_headers: HeaderMap,
}

async fn connect_upstream_websocket(request: &EditableRequest) -> Result<ConnectedWebSocket> {
    let mut upstream_request = websocket_url(request)?.into_client_request()?;
    {
        let headers = upstream_request.headers_mut();
        for header in &request.headers {
            if !should_forward_websocket_header(&header.name) {
                continue;
            }

            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(header.name.as_bytes()),
                HeaderValue::from_str(&header.value),
            ) {
                headers.append(name, value);
            }
        }
    }

    let (websocket, response) = connect_async(upstream_request)
        .await
        .context("upstream WebSocket handshake failed")?;

    Ok(ConnectedWebSocket {
        websocket,
        upstream_headers: response.headers().clone(),
    })
}

fn should_forward_websocket_header(name: &str) -> bool {
    !matches!(
        name.to_ascii_lowercase().as_str(),
        "host"
            | "connection"
            | "upgrade"
            | "proxy-connection"
            | "content-length"
            | "sec-websocket-key"
            | "sec-websocket-version"
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
    let websocket_key = request_headers
        .get(SEC_WEBSOCKET_KEY)
        .context("missing Sec-WebSocket-Key")?
        .to_str()
        .context("invalid Sec-WebSocket-Key")?;
    let mut headers = upstream_headers;
    strip_hop_by_hop_headers(&mut headers);
    headers.remove(SEC_WEBSOCKET_ACCEPT);
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
    if let Some(extensions) = headers.get(SEC_WEBSOCKET_EXTENSIONS).cloned() {
        headers.insert(SEC_WEBSOCKET_EXTENSIONS, extensions);
    }

    Ok(headers)
}

async fn persist_session_quiet(state: &Arc<AppState>, session: &Arc<SessionContext>) {
    if let Err(error) = state.persist_session_context(session).await {
        warn!(?error, session_id = %session.id(), "failed to persist session snapshot");
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
    let max_preview = state.config.body_preview_bytes;
    let close_note = loop {
        tokio::select! {
            message = client_stream.next() => {
                match message {
                    Some(Ok(message)) => {
                        if let Some(id) = session_id {
                            if let Some(frame) = capture_websocket_frame(
                                frame_index,
                                WebSocketFrameDirection::ClientToServer,
                                &message,
                                max_preview,
                            ) {
                                session.websockets.append_frame(id, frame).await;
                                frame_index += 1;
                            }
                        }

                        let should_close = message.is_close();
                        upstream_sink
                            .send(message)
                            .await
                            .context("failed to relay client websocket frame upstream")?;
                        if should_close {
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
                        if let Some(id) = session_id {
                            if let Some(frame) = capture_websocket_frame(
                                frame_index,
                                WebSocketFrameDirection::ServerToClient,
                                &message,
                                max_preview,
                            ) {
                                session.websockets.append_frame(id, frame).await;
                                frame_index += 1;
                            }
                        }

                        let should_close = message.is_close();
                        client_sink
                            .send(message)
                            .await
                            .context("failed to relay upstream websocket frame to client")?;
                        if should_close {
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
        session
            .websockets
            .close(
                id,
                Utc::now(),
                started.elapsed().as_millis() as u64,
                close_note.clone(),
            )
            .await;
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

fn capture_websocket_frame(
    index: usize,
    direction: WebSocketFrameDirection,
    message: &WebSocketMessage,
    max_preview: usize,
) -> Option<WebSocketFrameRecord> {
    let captured_at = Utc::now();

    match message {
        WebSocketMessage::Text(text) => {
            let bytes = text.as_bytes();
            let preview_len = max_preview.min(bytes.len());
            Some(WebSocketFrameRecord {
                index,
                captured_at,
                direction,
                kind: WebSocketFrameKind::Text,
                body_preview: String::from_utf8_lossy(&bytes[..preview_len]).into_owned(),
                body_encoding: BodyEncoding::Utf8,
                body_size: bytes.len(),
                preview_truncated: bytes.len() > max_preview,
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
