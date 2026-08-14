use std::{sync::Arc, time::Duration};

use axum::{extract::OriginalUri, routing::get, Router};
use http::HeaderMap;
use sniper::{
    config::AppConfig,
    match_replace::{MatchReplaceRule, MatchReplaceScope, MatchReplaceTarget},
    model::{
        BodyEncoding, EditableRequest, MessageRecord, RequestTargetOverride, TransactionRecord,
    },
    proxy::{send_replay_request, serve_proxy},
    runtime::RuntimeSettingsUpdate,
    state::AppState,
    store::ListFilters,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use uuid::Uuid;

#[tokio::test]
async fn proxy_applies_request_match_replace_only_once() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_app =
        Router::new().fallback(get(
            |uri: OriginalUri| async move { uri.0.path().to_string() },
        ));
    let upstream_handle = tokio::spawn(async move {
        axum::serve(upstream, upstream_app).await.unwrap();
    });

    let config = AppConfig {
        proxy_addr: "127.0.0.1:0".parse().unwrap(),
        ui_addr: "127.0.0.1:0".parse().unwrap(),
        max_entries: 100,
        max_transaction_entries: 100,
        body_preview_bytes: 4096,
        data_dir: std::env::temp_dir().join(format!(
            "sniper-test-regression-match-replace-{}",
            Uuid::new_v4()
        )),
    };
    let state = Arc::new(AppState::new(config).unwrap());
    let session = state.session().await;
    session
        .match_replace
        .replace_all(vec![MatchReplaceRule {
            id: Uuid::new_v4(),
            enabled: true,
            description: "single pass".to_string(),
            scope: MatchReplaceScope::Request,
            target: MatchReplaceTarget::Path,
            search: "a".to_string(),
            replace: "aa".to_string(),
            regex: false,
            case_sensitive: true,
        }])
        .await;

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let proxy_state = state.clone();
    let proxy_handle = tokio::spawn(async move {
        serve_proxy(proxy_listener, proxy_state).await.unwrap();
    });

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let request = format!(
        "GET http://{upstream_addr}/a HTTP/1.1\r\nHost: {upstream_addr}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).await.unwrap();
    let response = String::from_utf8_lossy(&buffer);
    assert!(response.contains("200 OK"));
    assert!(response.contains("/aa"));
    assert!(!response.contains("/aaaa"));

    tokio::time::sleep(Duration::from_millis(120)).await;

    let list = session.store.list(&ListFilters::default()).await;
    assert_eq!(list.len(), 1);
    let detail = session.store.get(list[0].id).await.unwrap();
    assert_eq!(detail.path, "/aa");
    assert_eq!(detail.notes.len(), 1);

    proxy_handle.abort();
    upstream_handle.abort();
}

#[tokio::test]
async fn proxy_records_request_and_response_http_versions_separately() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let (request_line_tx, request_line_rx) = tokio::sync::oneshot::channel();
    let upstream_handle = tokio::spawn(async move {
        let (mut socket, _) = upstream.accept().await.unwrap();
        let mut buffer = [0_u8; 2048];
        let read = socket.read(&mut buffer).await.unwrap();
        let request = String::from_utf8_lossy(&buffer[..read]);
        let first_line = request.lines().next().unwrap_or_default().to_string();
        let _ = request_line_tx.send(first_line);
        socket
            .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
    });

    let config = AppConfig {
        proxy_addr: "127.0.0.1:0".parse().unwrap(),
        ui_addr: "127.0.0.1:0".parse().unwrap(),
        max_entries: 100,
        max_transaction_entries: 100,
        body_preview_bytes: 4096,
        data_dir: std::env::temp_dir().join(format!(
            "sniper-test-regression-http-version-{}",
            Uuid::new_v4()
        )),
    };
    let state = Arc::new(AppState::new(config).unwrap());
    let session = state.session().await;
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let proxy_state = state.clone();
    let proxy_handle = tokio::spawn(async move {
        serve_proxy(proxy_listener, proxy_state).await.unwrap();
    });

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let request = format!(
        "GET http://{upstream_addr}/version HTTP/1.1\r\nHost: {upstream_addr}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).await.unwrap();
    assert!(String::from_utf8_lossy(&buffer).contains("200 OK"));
    assert_eq!(request_line_rx.await.unwrap(), "GET /version HTTP/1.1");

    tokio::time::sleep(Duration::from_millis(120)).await;
    let list = session.store.list(&ListFilters::default()).await;
    assert_eq!(list.len(), 1);
    let detail = session.store.get(list[0].id).await.unwrap();
    assert_eq!(detail.http_version.as_deref(), Some("HTTP/1.1"));
    assert_eq!(detail.response_http_version.as_deref(), Some("HTTP/1.0"));

    proxy_handle.abort();
    upstream_handle.abort();
}

#[tokio::test]
async fn replay_upstream_failure_preserves_request_match_replace_provenance() {
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_port = closed.local_addr().unwrap().port();
    drop(closed);

    let config = AppConfig {
        proxy_addr: "127.0.0.1:0".parse().unwrap(),
        ui_addr: "127.0.0.1:0".parse().unwrap(),
        max_entries: 100,
        max_transaction_entries: 100,
        body_preview_bytes: 4096,
        data_dir: std::env::temp_dir().join(format!(
            "sniper-test-regression-replay-failure-match-replace-{}",
            Uuid::new_v4()
        )),
    };
    let state = Arc::new(AppState::new(config).unwrap());
    let session = state.session().await;
    session
        .match_replace
        .replace_all(vec![MatchReplaceRule {
            id: Uuid::new_v4(),
            enabled: true,
            description: "rewrite replay path".to_string(),
            scope: MatchReplaceScope::Request,
            target: MatchReplaceTarget::Path,
            search: "before".to_string(),
            replace: "after".to_string(),
            regex: false,
            case_sensitive: true,
        }])
        .await;

    let request = EditableRequest {
        scheme: "http".to_string(),
        host: "logical.example.test".to_string(),
        method: "GET".to_string(),
        path: "/before".to_string(),
        headers: vec![sniper::model::HeaderRecord {
            name: "host".to_string(),
            value: "logical.example.test".to_string(),
        }],
        body: String::new(),
        body_encoding: BodyEncoding::Utf8,
        preview_truncated: false,
    };
    let target = RequestTargetOverride {
        scheme: "http".to_string(),
        host: "127.0.0.1".to_string(),
        port: closed_port.to_string(),
    };

    let error = send_replay_request(state, request, Some(target), None, None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("Upstream request failed"));

    let list = session.store.list(&ListFilters::default()).await;
    assert_eq!(list.len(), 1);
    let detail = session.store.get(list[0].id).await.unwrap();
    assert_eq!(detail.path, "/after");
    assert!(detail.original_request.is_some());
    assert!(detail.summary().has_match_replace);
}

#[tokio::test]
async fn replay_rejects_truncated_captured_request_reuse() {
    let config = AppConfig {
        proxy_addr: "127.0.0.1:0".parse().unwrap(),
        ui_addr: "127.0.0.1:0".parse().unwrap(),
        max_entries: 100,
        max_transaction_entries: 100,
        body_preview_bytes: 4,
        data_dir: std::env::temp_dir()
            .join(format!("sniper-test-regression-replay-{}", Uuid::new_v4())),
    };
    let state = Arc::new(AppState::new(config).unwrap());
    let session = state.session().await;

    let mut request_headers = HeaderMap::new();
    request_headers.insert("host", "example.test".parse().unwrap());
    let captured_request = MessageRecord::from_headers_and_body(&request_headers, b"abcd1234", 4);
    let source_record = TransactionRecord::http(
        chrono::Utc::now(),
        "POST".to_string(),
        "http".to_string(),
        "example.test".to_string(),
        "/upload".to_string(),
        Some(200),
        1,
        captured_request,
        None,
        Vec::new(),
        None,
        None,
    );
    session.store.insert(source_record).await;
    let source_id = session.store.list(&ListFilters::default()).await[0].id;

    let request = EditableRequest {
        scheme: "http".to_string(),
        host: "example.test".to_string(),
        method: "POST".to_string(),
        path: "/upload".to_string(),
        headers: vec![sniper::model::HeaderRecord {
            name: "host".to_string(),
            value: "example.test".to_string(),
        }],
        body: "abcd".to_string(),
        body_encoding: BodyEncoding::Utf8,
        preview_truncated: true,
    };

    let error = send_replay_request(state, request, None, Some(source_id), None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("truncated at the preview cap"));
}

#[tokio::test]
async fn replay_rejects_mutated_truncated_captured_request_reuse() {
    let config = AppConfig {
        proxy_addr: "127.0.0.1:0".parse().unwrap(),
        ui_addr: "127.0.0.1:0".parse().unwrap(),
        max_entries: 100,
        max_transaction_entries: 100,
        body_preview_bytes: 16,
        data_dir: std::env::temp_dir().join(format!(
            "sniper-test-regression-replay-mutated-truncated-{}",
            Uuid::new_v4()
        )),
    };
    let state = Arc::new(AppState::new(config).unwrap());
    let session = state.session().await;

    let mut request_headers = HeaderMap::new();
    request_headers.insert("host", "example.test".parse().unwrap());
    let mut captured_request =
        MessageRecord::from_headers_and_body(&request_headers, b"prefix-$payload$-rest", 7);
    captured_request.preview_truncated = true;
    let source_record = TransactionRecord::http(
        chrono::Utc::now(),
        "POST".to_string(),
        "http".to_string(),
        "example.test".to_string(),
        "/upload".to_string(),
        Some(200),
        1,
        captured_request,
        None,
        Vec::new(),
        None,
        None,
    );
    session.store.insert(source_record).await;
    let source_id = session.store.list(&ListFilters::default()).await[0].id;

    let request = EditableRequest {
        scheme: "http".to_string(),
        host: "example.test".to_string(),
        method: "POST".to_string(),
        path: "/upload".to_string(),
        headers: vec![sniper::model::HeaderRecord {
            name: "host".to_string(),
            value: "example.test".to_string(),
        }],
        body: "prefix-x".to_string(),
        body_encoding: BodyEncoding::Utf8,
        preview_truncated: true,
    };

    let error = send_replay_request(state, request, None, Some(source_id), None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("truncated at the preview cap"));
}

#[tokio::test]
async fn replay_rejects_short_edited_body_from_truncated_capture_even_when_flag_cleared() {
    let config = AppConfig {
        proxy_addr: "127.0.0.1:0".parse().unwrap(),
        ui_addr: "127.0.0.1:0".parse().unwrap(),
        max_entries: 100,
        max_transaction_entries: 100,
        body_preview_bytes: 16,
        data_dir: std::env::temp_dir().join(format!(
            "sniper-test-regression-replay-short-edited-truncated-{}",
            Uuid::new_v4()
        )),
    };
    let state = Arc::new(AppState::new(config).unwrap());
    let session = state.session().await;

    let mut request_headers = HeaderMap::new();
    request_headers.insert("host", "example.test".parse().unwrap());
    let mut captured_request =
        MessageRecord::from_headers_and_body(&request_headers, b"prefix-$payload$-rest", 7);
    captured_request.preview_truncated = true;
    let source_record = TransactionRecord::http(
        chrono::Utc::now(),
        "POST".to_string(),
        "http".to_string(),
        "example.test".to_string(),
        "/upload".to_string(),
        Some(200),
        1,
        captured_request,
        None,
        Vec::new(),
        None,
        None,
    );
    session.store.insert(source_record).await;
    let source_id = session.store.list(&ListFilters::default()).await[0].id;

    let request = EditableRequest {
        scheme: "http".to_string(),
        host: "example.test".to_string(),
        method: "POST".to_string(),
        path: "/upload".to_string(),
        headers: vec![sniper::model::HeaderRecord {
            name: "host".to_string(),
            value: "example.test".to_string(),
        }],
        body: "prefix-x".to_string(),
        body_encoding: BodyEncoding::Utf8,
        preview_truncated: false,
    };

    let error = send_replay_request(state, request, None, Some(source_id), None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("truncated at the preview cap"));
}

#[tokio::test]
async fn replay_preserves_custom_host_header() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_app = Router::new().fallback(get(|headers: HeaderMap| async move {
        headers
            .get("host")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string()
    }));
    let upstream_handle = tokio::spawn(async move {
        axum::serve(upstream, upstream_app).await.unwrap();
    });

    let config = AppConfig {
        proxy_addr: "127.0.0.1:0".parse().unwrap(),
        ui_addr: "127.0.0.1:0".parse().unwrap(),
        max_entries: 100,
        max_transaction_entries: 100,
        body_preview_bytes: 4096,
        data_dir: std::env::temp_dir().join(format!(
            "sniper-test-regression-replay-host-header-{}",
            Uuid::new_v4()
        )),
    };
    let state = Arc::new(AppState::new(config).unwrap());

    let custom_host = "spoofed.example.test";
    let request = EditableRequest {
        scheme: "http".to_string(),
        host: custom_host.to_string(),
        method: "GET".to_string(),
        path: "/".to_string(),
        headers: vec![sniper::model::HeaderRecord {
            name: "host".to_string(),
            value: custom_host.to_string(),
        }],
        body: String::new(),
        body_encoding: BodyEncoding::Utf8,
        preview_truncated: false,
    };

    let target = RequestTargetOverride {
        scheme: "http".to_string(),
        host: "127.0.0.1".to_string(),
        port: upstream_addr.port().to_string(),
    };

    let record = send_replay_request(state, request, Some(target), None, None)
        .await
        .unwrap();
    let response_body = record.response.as_ref().expect("response should exist");
    assert_eq!(response_body.body_preview, custom_host);

    upstream_handle.abort();
}

#[tokio::test]
async fn replay_target_override_uses_override_port_with_explicit_logical_port() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_app = Router::new().fallback(get(|headers: HeaderMap| async move {
        let host = headers
            .get("host")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        format!("upstream:{host}")
    }));
    let upstream_handle = tokio::spawn(async move {
        axum::serve(upstream, upstream_app).await.unwrap();
    });

    let trap = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let trap_addr = trap.local_addr().unwrap();
    let trap_app = Router::new().fallback(get(|| async { "trap" }));
    let trap_handle = tokio::spawn(async move {
        axum::serve(trap, trap_app).await.unwrap();
    });

    let config = AppConfig {
        proxy_addr: "127.0.0.1:0".parse().unwrap(),
        ui_addr: "127.0.0.1:0".parse().unwrap(),
        max_entries: 100,
        max_transaction_entries: 100,
        body_preview_bytes: 4096,
        data_dir: std::env::temp_dir().join(format!(
            "sniper-test-regression-replay-target-port-{}",
            Uuid::new_v4()
        )),
    };
    let state = Arc::new(AppState::new(config).unwrap());

    let logical_host = format!("logical.example.test:{}", trap_addr.port());
    let request = EditableRequest {
        scheme: "http".to_string(),
        host: logical_host.clone(),
        method: "GET".to_string(),
        path: "/".to_string(),
        headers: vec![sniper::model::HeaderRecord {
            name: "host".to_string(),
            value: logical_host.clone(),
        }],
        body: String::new(),
        body_encoding: BodyEncoding::Utf8,
        preview_truncated: false,
    };

    let target = RequestTargetOverride {
        scheme: "http".to_string(),
        host: "127.0.0.1".to_string(),
        port: upstream_addr.port().to_string(),
    };

    let record = send_replay_request(state, request, Some(target), None, None)
        .await
        .unwrap();
    let response_body = record.response.as_ref().expect("response should exist");
    assert_eq!(record.host, logical_host);
    assert_eq!(
        response_body.body_preview,
        format!("upstream:{logical_host}")
    );

    upstream_handle.abort();
    trap_handle.abort();
}

#[tokio::test]
async fn replay_traffic_is_passively_scanned() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_app = Router::new().fallback(get(|| async {
        (
            [("content-type", "text/html")],
            "<html><body>scan me</body></html>",
        )
    }));
    let upstream_handle = tokio::spawn(async move {
        axum::serve(upstream, upstream_app).await.unwrap();
    });

    let config = AppConfig {
        proxy_addr: "127.0.0.1:0".parse().unwrap(),
        ui_addr: "127.0.0.1:0".parse().unwrap(),
        max_entries: 100,
        max_transaction_entries: 100,
        body_preview_bytes: 4096,
        data_dir: std::env::temp_dir().join(format!(
            "sniper-test-regression-replay-scan-{}",
            Uuid::new_v4()
        )),
    };
    let state = Arc::new(AppState::new(config).unwrap());
    let session = state.session().await;
    let request = EditableRequest {
        scheme: "http".to_string(),
        host: upstream_addr.to_string(),
        method: "GET".to_string(),
        path: "/".to_string(),
        headers: vec![sniper::model::HeaderRecord {
            name: "host".to_string(),
            value: upstream_addr.to_string(),
        }],
        body: String::new(),
        body_encoding: BodyEncoding::Utf8,
        preview_truncated: false,
    };

    let record = send_replay_request(state, request, None, None, None)
        .await
        .unwrap();

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let findings = session.scanner.list(None).await;
            if findings.iter().any(|finding| {
                finding.record_id == record.id && finding.title.contains("Content-Security-Policy")
            }) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("replay response should be scanned");

    upstream_handle.abort();
}

#[tokio::test]
async fn intercept_forward_keeps_client_request_alive() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_app = Router::new().fallback(get(|headers: HeaderMap| async move {
        headers
            .get("host")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string()
    }));
    let upstream_handle = tokio::spawn(async move {
        axum::serve(upstream, upstream_app).await.unwrap();
    });

    let config = AppConfig {
        proxy_addr: "127.0.0.1:0".parse().unwrap(),
        ui_addr: "127.0.0.1:0".parse().unwrap(),
        max_entries: 100,
        max_transaction_entries: 100,
        body_preview_bytes: 4096,
        data_dir: std::env::temp_dir().join(format!(
            "sniper-test-regression-intercept-forward-{}",
            Uuid::new_v4()
        )),
    };
    let state = Arc::new(AppState::new(config).unwrap());
    let session = state.session().await;
    session
        .runtime
        .update(RuntimeSettingsUpdate {
            intercept_enabled: Some(true),
            websocket_capture_enabled: None,
            scope_patterns: None,
            passthrough_hosts: None,
            ..Default::default()
        })
        .await
        .unwrap();

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let proxy_state = state.clone();
    let proxy_handle = tokio::spawn(async move {
        serve_proxy(proxy_listener, proxy_state).await.unwrap();
    });

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let request = format!(
        "GET http://{upstream_addr}/ HTTP/1.1\r\nHost: {upstream_addr}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    let intercept_id = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let intercepts = session.intercepts.list().await;
            if let Some(intercept) = intercepts.first() {
                return intercept.id;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("intercept should appear in queue");

    let intercept = session
        .intercepts
        .get(intercept_id)
        .await
        .expect("intercept record should still exist");
    session
        .intercepts
        .forward(intercept_id, intercept.request, false)
        .await
        .expect("forward should resume the waiting client request");

    let mut buffer = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buffer))
        .await
        .expect("client should receive a response after forward")
        .unwrap();
    let response = String::from_utf8_lossy(&buffer);
    assert!(response.contains("200 OK"), "response was: {response}");
    assert!(response.contains(&upstream_addr.to_string()));

    proxy_handle.abort();
    upstream_handle.abort();
}
