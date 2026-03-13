use std::{convert::Infallible, sync::Arc, time::Duration};

use axum::body::Body;
use http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use rcgen::generate_simple_self_signed;
use rustls::{Certificate, ClientConfig, PrivateKey, RootCertStore, ServerConfig, ServerName};
use sniper::{config::AppConfig, proxy::serve_proxy, state::AppState, store::ListFilters};
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
        body_preview_bytes: 4096,
        upstream_insecure: true,
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

    tokio::time::sleep(Duration::from_millis(150)).await;

    let session = state.session().await;
    let list = session.store.list(&ListFilters::default()).await;
    assert!(list.iter().any(|record| record.method == "CONNECT"));
    assert!(list.iter().any(|record| {
        record.method == "GET"
            && record.host == format!("localhost:{}", upstream.port)
            && record.path == "/secure"
            && record.scheme == "https"
    }));

    proxy_handle.abort();
    upstream.handle.abort();
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
