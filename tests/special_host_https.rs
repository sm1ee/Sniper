use std::{sync::Arc, time::Duration};

use rustls::{Certificate, ClientConfig, RootCertStore, ServerName};
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
        body_preview_bytes: 4096,
        upstream_insecure: false,
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
        .add(&Certificate(state.certificates.root_der_bytes().to_vec()))
        .unwrap();

    let client_config = ClientConfig::builder()
        .with_safe_defaults()
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
