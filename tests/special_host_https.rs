use std::{sync::Arc, time::Duration};

use rustls::{
    pki_types::{CertificateDer, ServerName},
    ClientConfig, RootCertStore,
};
use sniper::{config::AppConfig, proxy::serve_proxy, state::AppState, store::ListFilters};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::TlsConnector;

#[tokio::test]
async fn https_sniper_serves_the_certificate_portal() {
    let config = AppConfig {
        proxy_addr: "127.0.0.1:0".parse().unwrap(),
        ui_addr: "127.0.0.1:0".parse().unwrap(),
        max_entries: 100,
        max_transaction_entries: 100,
        body_preview_bytes: 4096,
        data_dir: std::env::temp_dir()
            .join(format!("sniper-test-special-host-{}", uuid::Uuid::new_v4())),
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
            b"CONNECT sniper:443 HTTP/1.1\r\nHost: sniper:443\r\nConnection: keep-alive\r\n\r\n",
        )
        .await
        .unwrap();

    let connect_response = read_connect_response(&mut stream).await;
    assert!(connect_response.starts_with("HTTP/1.1 200"));

    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(
            state.certificates.root_der_bytes().to_vec(),
        ))
        .unwrap();

    let client_config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from("sniper").unwrap();
    let mut tls_stream = connector.connect(server_name, stream).await.unwrap();

    tls_stream
        .write_all(b"GET / HTTP/1.1\r\nHost: sniper\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let mut response = Vec::new();
    tls_stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8_lossy(&response);

    assert!(response.contains("200 OK"));
    assert!(response.contains("Install the Sniper Root CA"));
    assert!(response.contains("Download PEM"));
    assert!(response.contains("https://sniper"));

    tokio::time::sleep(Duration::from_millis(120)).await;

    let session = state.session().await;
    let list = session.store.list(&ListFilters::default()).await;
    assert!(list.iter().any(|record| {
        record.method == "CONNECT" && record.host == "sniper:443" && record.path.is_empty()
    }));
    assert!(list
        .iter()
        .any(|record| { record.method == "GET" && record.host == "sniper" && record.path == "/" }));

    proxy_handle.abort();
}

#[tokio::test]
async fn https_sniper_head_special_host_does_not_send_body() {
    let config = AppConfig {
        proxy_addr: "127.0.0.1:0".parse().unwrap(),
        ui_addr: "127.0.0.1:0".parse().unwrap(),
        max_entries: 100,
        max_transaction_entries: 100,
        body_preview_bytes: 4096,
        data_dir: std::env::temp_dir().join(format!(
            "sniper-test-special-host-head-{}",
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
            b"CONNECT sniper:443 HTTP/1.1\r\nHost: sniper:443\r\nConnection: keep-alive\r\n\r\n",
        )
        .await
        .unwrap();

    let connect_response = read_connect_response(&mut stream).await;
    assert!(connect_response.starts_with("HTTP/1.1 200"));

    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(
            state.certificates.root_der_bytes().to_vec(),
        ))
        .unwrap();

    let client_config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from("sniper").unwrap();
    let mut tls_stream = connector.connect(server_name, stream).await.unwrap();

    tls_stream
        .write_all(b"HEAD / HTTP/1.1\r\nHost: sniper\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let mut response = Vec::new();
    tls_stream.read_to_end(&mut response).await.unwrap();
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("response should include an HTTP header terminator");
    assert!(
        response[..header_end].starts_with(b"HTTP/1.1 200"),
        "HEAD special-host root should use the same route status as GET"
    );
    assert_eq!(
        &response[header_end + 4..],
        b"",
        "HEAD special-host response must not include a body"
    );

    tokio::time::sleep(Duration::from_millis(120)).await;

    let session = state.session().await;
    let list = session.store.list(&ListFilters::default()).await;
    let head_summary = list
        .iter()
        .find(|record| record.method == "HEAD" && record.host == "sniper" && record.path == "/")
        .expect("HEAD special-host request should be captured");
    let head_record = session
        .store
        .get(head_summary.id)
        .await
        .expect("captured HEAD record detail should be available");
    assert_eq!(head_record.status, Some(200));
    assert_eq!(
        head_record
            .response
            .as_ref()
            .map(|response| response.body_size),
        Some(0)
    );

    proxy_handle.abort();
}

#[tokio::test]
async fn https_sniper_records_non_default_connect_port() {
    let config = AppConfig {
        proxy_addr: "127.0.0.1:0".parse().unwrap(),
        ui_addr: "127.0.0.1:0".parse().unwrap(),
        max_entries: 100,
        max_transaction_entries: 100,
        body_preview_bytes: 4096,
        data_dir: std::env::temp_dir().join(format!(
            "sniper-test-special-host-port-{}",
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
            b"CONNECT sniper:8443 HTTP/1.1\r\nHost: sniper:8443\r\nConnection: keep-alive\r\n\r\n",
        )
        .await
        .unwrap();

    let connect_response = read_connect_response(&mut stream).await;
    assert!(connect_response.starts_with("HTTP/1.1 200"));

    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(
            state.certificates.root_der_bytes().to_vec(),
        ))
        .unwrap();

    let client_config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from("sniper").unwrap();
    let mut tls_stream = connector.connect(server_name, stream).await.unwrap();

    tls_stream
        .write_all(b"GET / HTTP/1.1\r\nHost: sniper:8443\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let mut response = Vec::new();
    tls_stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8_lossy(&response);
    assert!(response.contains("200 OK"));

    tokio::time::sleep(Duration::from_millis(120)).await;

    let session = state.session().await;
    let list = session.store.list(&ListFilters::default()).await;
    assert!(list.iter().any(|record| {
        record.method == "CONNECT" && record.host == "sniper:8443" && record.path.is_empty()
    }));
    assert!(list.iter().any(|record| {
        record.method == "GET" && record.host == "sniper:8443" && record.path == "/"
    }));

    proxy_handle.abort();
}

async fn read_connect_response(stream: &mut TcpStream) -> String {
    let mut response = Vec::new();
    let mut chunk = [0_u8; 1024];

    loop {
        let read = stream.read(&mut chunk).await.unwrap();
        assert!(read > 0, "proxy closed before CONNECT response completed");
        response.extend_from_slice(&chunk[..read]);

        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            return String::from_utf8(response).unwrap();
        }
    }
}
