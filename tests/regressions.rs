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
        body_preview_bytes: 4096,
        upstream_insecure: false,
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
async fn replay_rejects_truncated_captured_request_reuse() {
    let config = AppConfig {
        proxy_addr: "127.0.0.1:0".parse().unwrap(),
        ui_addr: "127.0.0.1:0".parse().unwrap(),
        max_entries: 100,
        body_preview_bytes: 4,
        upstream_insecure: false,
        data_dir: std::env::temp_dir().join(format!(
            "sniper-test-regression-replay-{}",
            Uuid::new_v4()
        )),
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

    let error = send_replay_request(state, request, None, Some(source_id))
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
        body_preview_bytes: 4096,
        upstream_insecure: false,
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

    let record = send_replay_request(state, request, Some(target), None)
        .await
        .unwrap();
    let response_body = record.response.as_ref().expect("response should exist");
    assert_eq!(response_body.body_preview, custom_host);

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
        body_preview_bytes: 4096,
        upstream_insecure: false,
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
        })
        .await;

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let proxy_state = state.clone();
    let proxy_handle = tokio::spawn(async move {
        serve_proxy(proxy_listener, proxy_state).await.unwrap();
    });

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let request = format!(
        "GET http://{upstream_addr}/ HTTP/1.1\r\nHost: intercepted.example.test\r\nConnection: close\r\n\r\n"
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
        .forward(intercept_id, intercept.request)
        .await
        .expect("forward should resume the waiting client request");

    let mut buffer = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buffer))
        .await
        .expect("client should receive a response after forward")
        .unwrap();
    let response = String::from_utf8_lossy(&buffer);
    assert!(response.contains("200 OK"), "response was: {response}");
    assert!(response.contains("intercepted.example.test"));

    proxy_handle.abort();
    upstream_handle.abort();
}
