use std::{sync::Arc, time::Duration};

use axum::{routing::get, Router};
use sniper::{
    config::AppConfig,
    intercept::{InterceptRule, InterceptScope},
    proxy::{flush_pending_session_persists, serve_proxy},
    runtime::RuntimeSettingsUpdate,
    state::AppState,
    store::ListFilters,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

#[tokio::test]
async fn proxy_captures_basic_http_exchange() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_app = Router::new().route("/hello", get(|| async { "world" }));
    let upstream_handle = tokio::spawn(async move {
        axum::serve(upstream, upstream_app).await.unwrap();
    });

    let config = AppConfig {
        proxy_addr: "127.0.0.1:0".parse().unwrap(),
        ui_addr: "127.0.0.1:0".parse().unwrap(),
        max_entries: 100,
        max_transaction_entries: 100,
        body_preview_bytes: 4096,
        data_dir: std::env::temp_dir().join(format!("sniper-test-http-{}", uuid::Uuid::new_v4())),
    };
    let state = Arc::new(AppState::new(config).unwrap());

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let proxy_state = state.clone();
    let proxy_handle = tokio::spawn(async move {
        serve_proxy(proxy_listener, proxy_state).await.unwrap();
    });

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let request = format!(
        "GET http://{upstream_addr}/hello HTTP/1.1\r\nHost: {upstream_addr}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).await.unwrap();
    let response = String::from_utf8_lossy(&buffer);
    assert!(response.contains("200 OK"));
    assert!(response.contains("world"));

    tokio::time::sleep(Duration::from_millis(120)).await;

    let session = state.session().await;
    let list = session.store.list(&ListFilters::default()).await;
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].method, "GET");
    assert!(list[0].host.contains(&upstream_addr.to_string()));

    let detail = session.store.get(list[0].id).await.unwrap();
    assert_eq!(detail.status, Some(200));
    assert!(detail
        .request
        .headers
        .iter()
        .any(|header| header.name == "host"));
    assert_eq!(detail.response.unwrap().body_preview, "world");

    proxy_handle.abort();
    upstream_handle.abort();
}

#[tokio::test]
async fn websocket_upstream_http_handshake_failure_preserves_status_and_body() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_handle = tokio::spawn(async move {
        let (mut socket, _) = upstream.accept().await.unwrap();
        let mut request = [0_u8; 1024];
        let _ = socket.read(&mut request).await.unwrap();
        socket
            .write_all(
                b"HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain\r\nX-Upstream-Reject: auth\r\nContent-Length: 12\r\nConnection: close\r\n\r\nnot allowed\n",
            )
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
            "sniper-test-websocket-http-failure-{}",
            uuid::Uuid::new_v4()
        )),
    };
    let state = Arc::new(AppState::new(config).unwrap());

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let proxy_state = state.clone();
    let proxy_handle = tokio::spawn(async move {
        serve_proxy(proxy_listener, proxy_state).await.unwrap();
    });

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let request = format!(
        "GET http://{upstream_addr}/socket HTTP/1.1\r\nHost: {upstream_addr}\r\nConnection: Upgrade, close\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).await.unwrap();
    let response = String::from_utf8_lossy(&buffer);
    assert!(
        response.contains("401 Unauthorized"),
        "unexpected websocket failure response: {response:?}"
    );
    assert!(response.contains("not allowed"));
    assert!(!response.contains("502 Bad Gateway"));

    tokio::time::sleep(Duration::from_millis(120)).await;
    let session = state.session().await;
    let list = session.store.list(&ListFilters::default()).await;
    let record = list
        .iter()
        .find(|record| record.method == "GET" && record.path == "/socket")
        .expect("websocket handshake failure should be recorded");
    assert_eq!(record.status, Some(401));
    let detail = session.store.get(record.id).await.unwrap();
    assert!(detail
        .notes
        .iter()
        .any(|note| note.contains("Upstream WebSocket handshake returned HTTP 401")));
    assert_eq!(
        detail
            .response
            .as_ref()
            .map(|response| response.body_preview.as_str()),
        Some("not allowed\n")
    );

    proxy_handle.abort();
    upstream_handle.abort();
}

#[tokio::test]
async fn proxy_streams_open_upstream_response_before_eof() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_handle = tokio::spawn(async move {
        let (mut socket, _) = upstream.accept().await.unwrap();
        let mut request = [0_u8; 1024];
        let _ = socket.read(&mut request).await.unwrap();
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 100\r\n\r\nhello",
            )
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let config = AppConfig {
        proxy_addr: "127.0.0.1:0".parse().unwrap(),
        ui_addr: "127.0.0.1:0".parse().unwrap(),
        max_entries: 100,
        max_transaction_entries: 100,
        body_preview_bytes: 4096,
        data_dir: std::env::temp_dir().join(format!(
            "sniper-test-streaming-http-{}",
            uuid::Uuid::new_v4()
        )),
    };
    let state = Arc::new(AppState::new(config).unwrap());

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let proxy_state = state.clone();
    let proxy_handle = tokio::spawn(async move {
        serve_proxy(proxy_listener, proxy_state).await.unwrap();
    });

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let request =
        format!("GET http://{upstream_addr}/stream HTTP/1.1\r\nHost: {upstream_addr}\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 128];
    tokio::time::timeout(Duration::from_millis(500), async {
        loop {
            let read = stream.read(&mut chunk).await.unwrap();
            assert!(read > 0, "proxy closed before streaming body");
            buffer.extend_from_slice(&chunk[..read]);
            if buffer.windows(5).any(|window| window == b"hello") {
                break;
            }
        }
    })
    .await
    .expect("proxy should stream response bytes before upstream EOF");

    drop(stream);
    let session = state.session().await;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let records = session.store.snapshot(Some(10)).await;
            if let Some(record) = records.iter().find(|record| record.path == "/stream") {
                if record.notes.iter().any(|note| {
                    note.contains("Client disconnected before streamed response completed")
                }) {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("streaming recorder should store a partial record after client disconnect");

    proxy_handle.abort();
    upstream_handle.abort();
}

#[tokio::test]
async fn flush_pending_persists_waits_for_streaming_body_pump_store() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_handle = tokio::spawn(async move {
        let (mut socket, _) = upstream.accept().await.unwrap();
        let mut request = [0_u8; 1024];
        let _ = socket.read(&mut request).await.unwrap();
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello")
            .await
            .unwrap();
        // Held open well past the read below: the flush has to find the body
        // still streaming, and a slow runner must not turn that into an EOF.
        tokio::time::sleep(Duration::from_secs(30)).await;
    });

    let config = AppConfig {
        proxy_addr: "127.0.0.1:0".parse().unwrap(),
        ui_addr: "127.0.0.1:0".parse().unwrap(),
        max_entries: 100,
        max_transaction_entries: 100,
        body_preview_bytes: 4096,
        data_dir: std::env::temp_dir()
            .join(format!("sniper-test-stream-flush-{}", uuid::Uuid::new_v4())),
    };
    let state = Arc::new(AppState::new(config).unwrap());

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let proxy_state = state.clone();
    let proxy_handle = tokio::spawn(async move {
        serve_proxy(proxy_listener, proxy_state).await.unwrap();
    });

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let request =
        format!("GET http://{upstream_addr}/stream HTTP/1.1\r\nHost: {upstream_addr}\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 128];
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let read = stream.read(&mut chunk).await.unwrap();
            assert!(read > 0, "proxy closed before streaming body");
            buffer.extend_from_slice(&chunk[..read]);
            if buffer.windows(5).any(|window| window == b"hello") {
                break;
            }
        }
    })
    .await
    .expect("proxy should stream response bytes before upstream EOF");
    let response_text = String::from_utf8_lossy(&buffer);
    assert!(!response_text
        .to_ascii_lowercase()
        .contains("content-length"));

    let session = state.session().await;
    flush_pending_session_persists(state.as_ref())
        .await
        .unwrap();

    let records = session.store.snapshot(Some(10)).await;
    let record = records
        .iter()
        .find(|record| record.path == "/stream")
        .expect("streaming record should be stored before flush returns");
    assert_eq!(record.status, Some(200));
    let response = record
        .response
        .as_ref()
        .expect("response should be captured");
    assert_eq!(response.body_preview, "hello");
    assert!(record
        .notes
        .iter()
        .any(|note| note.contains("Shutdown finalized streamed response capture")));

    let restored = state.sessions.load_context(session.id()).unwrap();
    let restored_records = restored.store.snapshot(Some(10)).await;
    assert!(restored_records
        .iter()
        .any(|record| record.path == "/stream"
            && record
                .response
                .as_ref()
                .is_some_and(|response| response.body_preview == "hello")));

    drop(stream);
    proxy_handle.abort();
    upstream_handle.abort();
}

#[tokio::test]
async fn response_intercept_drop_records_synthetic_response_version() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_handle = tokio::spawn(async move {
        let (mut socket, _) = upstream.accept().await.unwrap();
        let mut request = [0_u8; 1024];
        let _ = socket.read(&mut request).await.unwrap();
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
            "sniper-test-response-intercept-drop-version-{}",
            uuid::Uuid::new_v4()
        )),
    };
    let state = Arc::new(AppState::new(config).unwrap());
    let session = state.session().await;
    session
        .runtime
        .update(RuntimeSettingsUpdate {
            intercept_enabled: Some(true),
            intercept_scope_only: Some(false),
            ..RuntimeSettingsUpdate::default()
        })
        .await
        .unwrap();
    session
        .intercept_rules
        .upsert(InterceptRule {
            id: uuid::Uuid::new_v4(),
            enabled: true,
            scope: InterceptScope::Response,
            host_pattern: String::new(),
            path_pattern: "/drop-response-version".to_string(),
            method_filter: Vec::new(),
        })
        .await;

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let proxy_state = state.clone();
    let proxy_handle = tokio::spawn(async move {
        serve_proxy(proxy_listener, proxy_state).await.unwrap();
    });

    let client = tokio::spawn(async move {
        let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
        let request = format!(
            "GET http://{upstream_addr}/drop-response-version HTTP/1.1\r\nHost: {upstream_addr}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut buffer = Vec::new();
        stream.read_to_end(&mut buffer).await.unwrap();
        String::from_utf8(buffer).unwrap()
    });

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let pending = session.response_intercepts.list().await;
            if let Some(item) = pending.first() {
                session
                    .response_intercepts
                    .drop_response(item.id)
                    .await
                    .unwrap();
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("response intercept should be queued");

    let response = client.await.unwrap();
    assert!(response.contains("502 Bad Gateway"));

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let records = session.store.snapshot(Some(10)).await;
            if let Some(record) = records
                .iter()
                .find(|record| record.path == "/drop-response-version")
            {
                assert_eq!(record.status, Some(502));
                assert_eq!(record.http_version.as_deref(), Some("HTTP/1.1"));
                assert_eq!(record.response_http_version.as_deref(), Some("HTTP/1.1"));
                assert!(record
                    .notes
                    .iter()
                    .any(|note| note.contains("Response dropped in intercept")));
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("dropped response record should be stored");

    proxy_handle.abort();
    upstream_handle.abort();
}

#[tokio::test]
async fn proxy_records_origin_form_rejection_without_host_header() {
    let config = AppConfig {
        proxy_addr: "127.0.0.1:0".parse().unwrap(),
        ui_addr: "127.0.0.1:0".parse().unwrap(),
        max_entries: 100,
        max_transaction_entries: 100,
        body_preview_bytes: 4096,
        data_dir: std::env::temp_dir().join(format!(
            "sniper-test-missing-host-rejection-{}",
            uuid::Uuid::new_v4()
        )),
    };
    let state = Arc::new(AppState::new(config).unwrap());

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let proxy_state = state.clone();
    let proxy_handle = tokio::spawn(async move {
        serve_proxy(proxy_listener, proxy_state).await.unwrap();
    });

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    stream
        .write_all(b"GET /missing-host HTTP/1.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).await.unwrap();
    let response = String::from_utf8_lossy(&buffer);
    assert!(response.contains("400 Bad Request"));

    tokio::time::sleep(Duration::from_millis(120)).await;
    let session = state.session().await;
    let records = session.store.snapshot(Some(10)).await;
    let record = records
        .iter()
        .find(|record| record.path == "/missing-host")
        .expect("proxy rejection should be recorded");
    assert_eq!(record.status, Some(400));
    assert_eq!(record.http_version.as_deref(), Some("HTTP/1.1"));
    assert_eq!(record.response_http_version.as_deref(), Some("HTTP/1.1"));
    assert!(record
        .notes
        .iter()
        .any(|note| note.contains("Proxy rejected request")));

    proxy_handle.abort();
}

#[tokio::test]
async fn proxy_records_http10_rejection_version() {
    let config = AppConfig {
        proxy_addr: "127.0.0.1:0".parse().unwrap(),
        ui_addr: "127.0.0.1:0".parse().unwrap(),
        max_entries: 100,
        max_transaction_entries: 100,
        body_preview_bytes: 4096,
        data_dir: std::env::temp_dir().join(format!(
            "sniper-test-http10-rejection-{}",
            uuid::Uuid::new_v4()
        )),
    };
    let state = Arc::new(AppState::new(config).unwrap());

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let proxy_state = state.clone();
    let proxy_handle = tokio::spawn(async move {
        serve_proxy(proxy_listener, proxy_state).await.unwrap();
    });

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    stream
        .write_all(b"GET /missing-host-http10 HTTP/1.0\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).await.unwrap();
    let response = String::from_utf8_lossy(&buffer);
    assert!(response.contains("400 Bad Request"));

    tokio::time::sleep(Duration::from_millis(120)).await;
    let session = state.session().await;
    let records = session.store.snapshot(Some(10)).await;
    let record = records
        .iter()
        .find(|record| record.path == "/missing-host-http10")
        .expect("proxy rejection should be recorded");
    assert_eq!(record.status, Some(400));
    assert_eq!(record.http_version.as_deref(), Some("HTTP/1.0"));
    assert_eq!(record.response_http_version.as_deref(), Some("HTTP/1.1"));

    proxy_handle.abort();
}

#[tokio::test]
async fn proxy_rejects_absolute_form_host_mismatch_before_upstream_dial() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let config = AppConfig {
        proxy_addr: "127.0.0.1:0".parse().unwrap(),
        ui_addr: "127.0.0.1:0".parse().unwrap(),
        max_entries: 100,
        max_transaction_entries: 100,
        body_preview_bytes: 4096,
        data_dir: std::env::temp_dir().join(format!(
            "sniper-test-absolute-host-mismatch-{}",
            uuid::Uuid::new_v4()
        )),
    };
    let state = Arc::new(AppState::new(config).unwrap());

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let proxy_state = state.clone();
    let proxy_handle = tokio::spawn(async move {
        serve_proxy(proxy_listener, proxy_state).await.unwrap();
    });

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let request = format!(
        "GET http://{upstream_addr}/blocked HTTP/1.1\r\nHost: attacker.test\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).await.unwrap();
    let response = String::from_utf8_lossy(&buffer);
    assert!(response.contains("400 Bad Request"));
    assert!(
        tokio::time::timeout(Duration::from_millis(150), upstream.accept())
            .await
            .is_err()
    );

    tokio::time::sleep(Duration::from_millis(120)).await;
    let session = state.session().await;
    let records = session.store.snapshot(Some(10)).await;
    let record = records
        .iter()
        .find(|record| record.path == "/blocked")
        .expect("proxy rejection should be recorded");
    assert_eq!(record.status, Some(400));
    assert!(record.notes.iter().any(|note| {
        note.contains("absolute-form request authority does not match Host header")
    }));

    proxy_handle.abort();
}

#[tokio::test]
async fn proxy_rejects_duplicate_host_headers_before_upstream_dial() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let config = AppConfig {
        proxy_addr: "127.0.0.1:0".parse().unwrap(),
        ui_addr: "127.0.0.1:0".parse().unwrap(),
        max_entries: 100,
        max_transaction_entries: 100,
        body_preview_bytes: 4096,
        data_dir: std::env::temp_dir().join(format!(
            "sniper-test-duplicate-host-rejection-{}",
            uuid::Uuid::new_v4()
        )),
    };
    let state = Arc::new(AppState::new(config).unwrap());

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let proxy_state = state.clone();
    let proxy_handle = tokio::spawn(async move {
        serve_proxy(proxy_listener, proxy_state).await.unwrap();
    });

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let request = format!(
        "GET http://{upstream_addr}/duplicate-host HTTP/1.1\r\nHost: {upstream_addr}\r\nHost: duplicate.test\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).await.unwrap();
    let response = String::from_utf8_lossy(&buffer);
    assert!(response.contains("400 Bad Request"));
    assert!(
        tokio::time::timeout(Duration::from_millis(150), upstream.accept())
            .await
            .is_err()
    );

    tokio::time::sleep(Duration::from_millis(120)).await;
    let session = state.session().await;
    let records = session.store.snapshot(Some(10)).await;
    let record = records
        .iter()
        .find(|record| record.path == "/duplicate-host")
        .expect("proxy rejection should be recorded");
    assert_eq!(record.status, Some(400));
    assert!(record
        .notes
        .iter()
        .any(|note| note.contains("multiple Host headers are not supported")));

    proxy_handle.abort();
}

#[tokio::test]
async fn proxy_rejects_origin_form_host_userinfo_before_upstream_dial() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let config = AppConfig {
        proxy_addr: "127.0.0.1:0".parse().unwrap(),
        ui_addr: "127.0.0.1:0".parse().unwrap(),
        max_entries: 100,
        max_transaction_entries: 100,
        body_preview_bytes: 4096,
        data_dir: std::env::temp_dir().join(format!(
            "sniper-test-host-userinfo-rejection-{}",
            uuid::Uuid::new_v4()
        )),
    };
    let state = Arc::new(AppState::new(config).unwrap());

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let proxy_state = state.clone();
    let proxy_handle = tokio::spawn(async move {
        serve_proxy(proxy_listener, proxy_state).await.unwrap();
    });

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let request = format!(
        "GET /userinfo-origin HTTP/1.1\r\nHost: user@{upstream_addr}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).await.unwrap();
    let response = String::from_utf8_lossy(&buffer);
    assert!(response.contains("400 Bad Request"));
    assert!(
        tokio::time::timeout(Duration::from_millis(150), upstream.accept())
            .await
            .is_err()
    );

    tokio::time::sleep(Duration::from_millis(120)).await;
    let session = state.session().await;
    let records = session.store.snapshot(Some(10)).await;
    let record = records
        .iter()
        .find(|record| record.path == "/userinfo-origin")
        .expect("proxy rejection should be recorded");
    assert_eq!(record.status, Some(400));
    assert!(record
        .notes
        .iter()
        .any(|note| note.contains("Host header must not include URI userinfo")));

    proxy_handle.abort();
}

#[tokio::test]
async fn proxy_rejects_absolute_form_userinfo_even_when_host_header_matches() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let config = AppConfig {
        proxy_addr: "127.0.0.1:0".parse().unwrap(),
        ui_addr: "127.0.0.1:0".parse().unwrap(),
        max_entries: 100,
        max_transaction_entries: 100,
        body_preview_bytes: 4096,
        data_dir: std::env::temp_dir().join(format!(
            "sniper-test-absolute-userinfo-rejection-{}",
            uuid::Uuid::new_v4()
        )),
    };
    let state = Arc::new(AppState::new(config).unwrap());

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let proxy_state = state.clone();
    let proxy_handle = tokio::spawn(async move {
        serve_proxy(proxy_listener, proxy_state).await.unwrap();
    });

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let request = format!(
        "GET http://user@{upstream_addr}/userinfo-absolute HTTP/1.1\r\nHost: {upstream_addr}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).await.unwrap();
    let response = String::from_utf8_lossy(&buffer);
    assert!(response.contains("400 Bad Request"));
    assert!(
        tokio::time::timeout(Duration::from_millis(150), upstream.accept())
            .await
            .is_err()
    );

    tokio::time::sleep(Duration::from_millis(120)).await;
    let session = state.session().await;
    let records = session.store.snapshot(Some(10)).await;
    let record = records
        .iter()
        .find(|record| record.path == "/userinfo-absolute")
        .expect("proxy rejection should be recorded");
    assert_eq!(record.status, Some(400));
    assert!(
        record
            .notes
            .iter()
            .any(|note| note
                .contains("absolute-form request authority must not include URI userinfo"))
    );

    proxy_handle.abort();
}

#[tokio::test]
async fn proxy_records_invalid_connect_rejection() {
    let config = AppConfig {
        proxy_addr: "127.0.0.1:0".parse().unwrap(),
        ui_addr: "127.0.0.1:0".parse().unwrap(),
        max_entries: 100,
        max_transaction_entries: 100,
        body_preview_bytes: 4096,
        data_dir: std::env::temp_dir().join(format!(
            "sniper-test-invalid-connect-rejection-{}",
            uuid::Uuid::new_v4()
        )),
    };
    let state = Arc::new(AppState::new(config).unwrap());

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let proxy_state = state.clone();
    let proxy_handle = tokio::spawn(async move {
        serve_proxy(proxy_listener, proxy_state).await.unwrap();
    });

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    stream
        .write_all(
            b"CONNECT example.test HTTP/1.0\r\nHost: example.test\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();

    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).await.unwrap();
    let response = String::from_utf8_lossy(&buffer);
    assert!(response.contains("400 Bad Request"));

    tokio::time::sleep(Duration::from_millis(120)).await;
    let session = state.session().await;
    let records = session.store.snapshot(Some(10)).await;
    let record = records
        .iter()
        .find(|record| record.host == "example.test")
        .expect("CONNECT rejection should be recorded");
    let record_id = record.id;
    assert_eq!(record.status, Some(400));
    assert_eq!(record.http_version.as_deref(), Some("HTTP/1.0"));
    assert_eq!(record.response_http_version.as_deref(), Some("HTTP/1.1"));
    assert!(record.summary().has_response);
    let response_capture = record
        .response
        .as_ref()
        .expect("CONNECT rejection should keep the 400 response capture");
    assert!(response_capture
        .body_preview
        .contains("CONNECT target authority must include a port"));
    assert!(record
        .notes
        .iter()
        .any(|note| note.contains("Proxy rejected CONNECT")));

    let visible_with_response_filter = session
        .store
        .list(&ListFilters {
            hide_without_responses: true,
            ..ListFilters::default()
        })
        .await;
    assert!(visible_with_response_filter
        .iter()
        .any(|summary| summary.id == record_id));

    proxy_handle.abort();
}

#[tokio::test]
async fn proxy_rejects_connect_userinfo_authority() {
    let config = AppConfig {
        proxy_addr: "127.0.0.1:0".parse().unwrap(),
        ui_addr: "127.0.0.1:0".parse().unwrap(),
        max_entries: 100,
        max_transaction_entries: 100,
        body_preview_bytes: 4096,
        data_dir: std::env::temp_dir().join(format!(
            "sniper-test-connect-userinfo-rejection-{}",
            uuid::Uuid::new_v4()
        )),
    };
    let state = Arc::new(AppState::new(config).unwrap());

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let proxy_state = state.clone();
    let proxy_handle = tokio::spawn(async move {
        serve_proxy(proxy_listener, proxy_state).await.unwrap();
    });

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    stream
        .write_all(
            b"CONNECT user@example.test:443 HTTP/1.1\r\nHost: example.test:443\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();

    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).await.unwrap();
    let response = String::from_utf8_lossy(&buffer);
    assert!(response.contains("400 Bad Request"));

    tokio::time::sleep(Duration::from_millis(120)).await;
    let session = state.session().await;
    let records = session.store.snapshot(Some(10)).await;
    let record = records
        .iter()
        .find(|record| record.method == "CONNECT")
        .expect("CONNECT rejection should be recorded");
    assert_eq!(record.status, Some(400));
    assert!(record.response.as_ref().is_some_and(|response| response
        .body_preview
        .contains("CONNECT target authority must not include URI userinfo")));
    assert!(record
        .notes
        .iter()
        .any(|note| note.contains("Proxy rejected CONNECT")));

    proxy_handle.abort();
}

#[tokio::test]
async fn passthrough_connect_returns_bad_gateway_when_upstream_dial_fails() {
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_addr = closed.local_addr().unwrap();
    drop(closed);

    let config = AppConfig {
        proxy_addr: "127.0.0.1:0".parse().unwrap(),
        ui_addr: "127.0.0.1:0".parse().unwrap(),
        max_entries: 100,
        max_transaction_entries: 100,
        body_preview_bytes: 4096,
        data_dir: std::env::temp_dir().join(format!(
            "sniper-test-passthrough-connect-failure-{}",
            uuid::Uuid::new_v4()
        )),
    };
    let state = Arc::new(AppState::new(config).unwrap());
    let session = state.session().await;
    session
        .runtime
        .update(RuntimeSettingsUpdate {
            passthrough_hosts: Some(vec!["127.0.0.1".to_string()]),
            ..RuntimeSettingsUpdate::default()
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
        "CONNECT {closed_addr} HTTP/1.1\r\nHost: {closed_addr}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).await.unwrap();
    let response = String::from_utf8_lossy(&buffer);
    assert!(response.contains("502 Bad Gateway"));

    tokio::time::sleep(Duration::from_millis(120)).await;
    let records = session.store.snapshot(Some(10)).await;
    let record = records
        .iter()
        .find(|record| record.host == closed_addr.to_string())
        .expect("passthrough connect failure should be recorded");
    assert_eq!(record.status, Some(502));
    assert_eq!(record.http_version.as_deref(), Some("HTTP/1.1"));
    assert_eq!(record.response_http_version.as_deref(), Some("HTTP/1.1"));
    assert!(record
        .notes
        .iter()
        .any(|note| note.contains("failed to connect to upstream")));

    proxy_handle.abort();
}
