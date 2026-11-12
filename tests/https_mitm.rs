use std::{convert::Infallible, sync::Arc, time::Duration};

use axum::body::Body;
use http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use rcgen::generate_simple_self_signed;
use rustls::{Certificate, ClientConfig, PrivateKey, RootCertStore, ServerConfig, ServerName};
use sniper::{
    config::AppConfig,
    model::{MessageRecord, TransactionRecord, TransactionSummary},
    proxy::serve_proxy,
    state::AppState,
    store::{ListFilters, TransactionStore},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[tokio::test]
async fn proxy_mitm_captures_inner_https_requests() {
    let upstream = start_https_upstream().await;

    let config = AppConfig {
        proxy_addr: "127.0.0.1:0".parse().unwrap(),
        ui_addr: "127.0.0.1:0".parse().unwrap(),
        max_entries: 100,
        max_transaction_entries: 100,
        body_preview_bytes: 4096,
        data_dir: std::env::temp_dir().join(format!("sniper-test-mitm-{}", uuid::Uuid::new_v4())),
    };
    let state = Arc::new(AppState::new(config).unwrap());

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let proxy_state = state.clone();
    let proxy_handle = tokio::spawn(async move {
        serve_proxy(proxy_listener, proxy_state).await.unwrap();
    });

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let connect_request = format!(
        "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\nConnection: keep-alive\r\n\r\n",
        upstream.port, upstream.port
    );
    stream.write_all(connect_request.as_bytes()).await.unwrap();

    let connect_response = read_headers(&mut stream).await;
    assert!(connect_response.starts_with("HTTP/1.1 200"));

    let mut roots = RootCertStore::empty();
    roots
        .add(&Certificate(state.certificates.root_der_bytes().to_vec()))
        .unwrap();
    let client_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut tls_stream = connector.connect(server_name, stream).await.unwrap();

    let request = format!(
        "GET /secure HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
        upstream.port
    );
    tls_stream.write_all(request.as_bytes()).await.unwrap();

    let mut response = Vec::new();
    tls_stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8_lossy(&response);
    assert!(response.contains("200 OK"));
    assert!(response.contains("secure-world"));

    let session = state.session().await;
    wait_for_record(
        &session.store,
        |record| record.method == "CONNECT",
        "CONNECT tunnel record",
    )
    .await;
    wait_for_record(
        &session.store,
        |record| {
            record.method == "GET"
                && record.host == format!("localhost:{}", upstream.port)
                && record.path == "/secure"
                && record.scheme == "https"
        },
        "inner HTTPS GET record",
    )
    .await;

    proxy_handle.abort();
    upstream.handle.abort();
}

#[tokio::test]
async fn mitm_connect_tls_failure_after_200_records_connect_success_status() {
    let config = AppConfig {
        proxy_addr: "127.0.0.1:0".parse().unwrap(),
        ui_addr: "127.0.0.1:0".parse().unwrap(),
        max_entries: 100,
        max_transaction_entries: 100,
        body_preview_bytes: 4096,
        data_dir: std::env::temp_dir().join(format!(
            "sniper-test-mitm-post-ok-failure-{}",
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
            b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();

    let connect_response = read_headers(&mut stream).await;
    assert!(connect_response.starts_with("HTTP/1.1 200"));

    // Opens like a TLS handshake record, so it goes to TLS and fails there;
    // plain bytes would be relayed as a TCP connection instead.
    stream
        .write_all(b"\x16\x03\x01\x00\x05not a client hello")
        .await
        .unwrap();
    stream.shutdown().await.unwrap();

    let mut ignored = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut ignored)).await;
    let session = state.session().await;
    let record = wait_for_record(
        &session.store,
        |record| record.method == "CONNECT" && record.host == "example.test:443",
        "CONNECT post-200 TLS failure record",
    )
    .await;
    assert_eq!(record.status, Some(200));
    let detail = session.store.get(record.id).await.unwrap();
    assert!(detail.notes.iter().any(|note| {
        note.contains("TLS handshake failed") && note.contains("CONNECT 200 had already been sent")
    }));

    proxy_handle.abort();
}

async fn wait_for_record(
    store: &TransactionStore,
    predicate: impl Fn(&TransactionSummary) -> bool,
    description: &str,
) -> TransactionSummary {
    // Socket completion can precede the journal acknowledgement that publishes
    // a record. Wait for the observable record instead of assuming disk timing.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let records = store.list(&ListFilters::default()).await;
            if let Some(record) = records.into_iter().find(&predicate) {
                return record;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {description}"))
}

#[tokio::test]
async fn record_wait_observes_publication_after_the_old_fixed_delay() {
    let store = TransactionStore::new();
    let record = TransactionRecord::tunnel(
        chrono::Utc::now(),
        "example.test:443".to_string(),
        Some(200),
        0,
        MessageRecord::from_headers_and_body(&http::HeaderMap::new(), &[], 4096),
        Vec::new(),
    );
    let record_id = record.id;
    let waiting = wait_for_record(
        &store,
        |record| record.id == record_id,
        "delayed fixture record",
    );
    tokio::pin!(waiting);

    // Withhold publication beyond the old 150 ms wait without depending on
    // thread or filesystem scheduling to reproduce the race.
    assert!(
        tokio::time::timeout(Duration::from_millis(200), &mut waiting)
            .await
            .is_err()
    );
    store.insert(record).await;
    assert_eq!(waiting.await.id, record_id);
}

struct HttpsUpstream {
    handle: tokio::task::JoinHandle<()>,
    port: u16,
}

async fn start_https_upstream() -> HttpsUpstream {
    let certificate = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = certificate.cert.der().to_vec();
    let key_der = certificate.key_pair.serialize_der();
    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(vec![Certificate(cert_der)], PrivateKey(key_der))
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();

            tokio::spawn(async move {
                let tls_stream = acceptor.accept(stream).await.unwrap();
                let io = TokioIo::new(tls_stream);
                let service = service_fn(|request: Request<Incoming>| async move {
                    let path = request.uri().path().to_string();
                    let body = request.into_body().collect().await.unwrap().to_bytes();
                    let payload = if path == "/secure" && body.is_empty() {
                        "{\"message\":\"secure-world\"}"
                    } else {
                        "{\"message\":\"unexpected\"}"
                    };

                    let response = Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/json")
                        .body(Body::from(payload))
                        .unwrap();
                    Ok::<_, Infallible>(response)
                });

                http1::Builder::new()
                    .serve_connection(io, service)
                    .await
                    .unwrap();
            });
        }
    });

    HttpsUpstream { handle, port }
}

async fn read_headers(stream: &mut TcpStream) -> String {
    let mut response = Vec::new();
    let mut chunk = [0_u8; 1024];

    loop {
        let read = stream.read(&mut chunk).await.unwrap();
        assert!(read > 0, "stream closed before headers completed");
        response.extend_from_slice(&chunk[..read]);

        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            return String::from_utf8(response).unwrap();
        }
    }
}
