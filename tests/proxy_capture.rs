use std::{sync::Arc, time::Duration};

use axum::{routing::get, Router};
use sniper::{config::AppConfig, proxy::serve_proxy, state::AppState, store::ListFilters};
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
        body_preview_bytes: 4096,
        upstream_insecure: false,
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
