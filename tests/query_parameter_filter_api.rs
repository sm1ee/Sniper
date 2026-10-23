//! Query-filter wording follows the existing shared read predicate. Synthetic
//! rows and a loopback API only; no proxy, upstream requests or body mutation.
use std::sync::Arc;

use http::HeaderMap;
use serde_json::Value;
use sniper::{
    config::AppConfig,
    model::{MessageRecord, TransactionRecord},
    state::AppState,
};
use uuid::Uuid;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_filter_excludes_body_only_fields_but_parameter_inspection_keeps_them() {
    let dir = std::env::temp_dir().join(format!("sniper-query-filter-{}", Uuid::new_v4()));
    let state = Arc::new(
        AppState::new(AppConfig {
            data_dir: dir.clone(),
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
        })
        .unwrap(),
    );
    let session = state.session().await;
    let session_id = session.id().to_string();
    let bodies = [
        ("/json", "application/json", r#"{"field":"value"}"#, "json"),
        (
            "/form",
            "application/x-www-form-urlencoded",
            "field=value",
            "form",
        ),
        (
            "/multipart",
            "multipart/form-data; boundary=fixture",
            "--fixture\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n--fixture--\r\n",
            "multipart",
        ),
    ];
    for (method, path, content_type, body) in [
        ("GET", "/query?field=value", "", ""),
        ("GET", "/empty?", "", ""),
    ]
    .into_iter()
    .chain(
        bodies
            .iter()
            .map(|(path, content_type, body, _)| ("POST", *path, *content_type, *body)),
    ) {
        let mut headers = HeaderMap::new();
        if !content_type.is_empty() {
            headers.insert("content-type", content_type.parse().unwrap());
        }
        let record = TransactionRecord::http(
            chrono::Utc::now(),
            method.into(),
            "https".into(),
            "example.com".into(),
            path.into(),
            Some(200),
            1,
            MessageRecord::from_headers_and_body(&headers, body.as_bytes(), 4096),
            Some(MessageRecord::from_headers_and_body(
                &HeaderMap::new(),
                b"",
                1024,
            )),
            Vec::new(),
            None,
            None,
        );
        session.store.insert(record).await;
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = format!("http://{}", listener.local_addr().unwrap());
    let app = sniper::api::router(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    for (enabled, expected) in [(false, 5), (true, 2)] {
        for endpoint in ["transactions", "target/service-map"] {
            let mut query = vec![
                ("session_id", session_id.clone()),
                ("only_parameterized", enabled.to_string()),
            ];
            if endpoint == "target/service-map" {
                query.extend([("all_rows", "true".into()), ("fresh", "true".into())]);
            }
            let response = client
                .get(format!("{api}/api/{endpoint}"))
                .query(&query)
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json::<Value>()
                .await
                .unwrap();
            if endpoint == "transactions" {
                assert_eq!(response.as_array().unwrap().len(), expected);
                if enabled {
                    assert!(response
                        .as_array()
                        .unwrap()
                        .iter()
                        .all(|row| row["path"].as_str().unwrap().contains('?')));
                }
            } else {
                assert_eq!(response["snapshot"]["included_rows"], expected);
                assert_eq!(
                    response["origins"][0]["endpoints"]
                        .as_array()
                        .unwrap()
                        .len(),
                    expected
                );
                if enabled {
                    assert_eq!(response["snapshot"]["filtered_rows"], 3);
                }
            }
        }
    }
    for (path, _, _, location) in bodies {
        let parameters = client
            .get(format!("{api}/api/target/service-map/parameters"))
            .query(&[
                ("session_id", session_id.as_str()),
                ("origin", "https://example.com"),
                ("method", "POST"),
                ("path", path),
            ])
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        assert_eq!(parameters["available"], true);
        assert_eq!(parameters["parameters"].as_array().unwrap().len(), 1);
        assert_eq!(parameters["parameters"][0]["name"], "field");
        assert_eq!(parameters["parameters"][0]["location"], location);
    }
    server.abort();
    drop(session);
    drop(state);
    let _ = std::fs::remove_dir_all(dir);
}
