//! End-to-end read contracts use inserted synthetic rows and a loopback API only.
//! No proxy listener, upstream service, browser, or captured user data is used.
use std::{path::Path, sync::Arc};

use http::HeaderMap;
use serde_json::{json, Value};
use sniper::{
    config::AppConfig,
    model::{MessageRecord, ObservedSocketPeer, ObservedSocketPeerRoute, TransactionRecord},
    state::AppState,
};
use uuid::Uuid;

async fn read(dir: &Path, api: &str, operation: &str, input: Value) -> Value {
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_sniper-cli"))
        .env("SNIPER_DATA_DIR", dir)
        .args([
            "--api", api, "--output", "compact", "call", operation, "--input",
        ])
        .arg(input.to_string())
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["ok"], true, "{response}");
    assert!(!response.to_string().contains("SYNTHETIC_PRIVATE"));
    response["data"].clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_map_catalog_negotiation_keeps_legacy_reads_and_exact_sources_compatible() {
    const SELECTOR: &str = "x-sniper-technology-catalog-version";
    let dir = std::env::temp_dir().join(format!("sniper-map-catalog-{}", Uuid::new_v4()));
    let state = Arc::new(
        AppState::new(AppConfig {
            data_dir: dir.clone(),
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 1024,
        })
        .unwrap(),
    );
    let session = state.session().await;
    let session_id = session.id();
    let mut record = row("/catalog");
    let response = record.response.as_mut().unwrap();
    response
        .headers
        .retain(|header| !header.name.eq_ignore_ascii_case("server"));
    response.headers.extend([
        sniper::model::HeaderRecord {
            name: "Server".into(),
            value: "nginx/1.26.2 gunicorn/23.0.0 uvicorn/0.30.6 waitress/3.0.0 openresty/1.27.1.2 LiteSpeed/6.3".into(),
        },
        sniper::model::HeaderRecord {
            name: "X-Powered-By".into(),
            value: "Next.js/15.0.0".into(),
        },
    ]);
    let id = record.id;
    session.store.insert(record).await;
    let original = serde_json::to_value(session.store.get(id).await.unwrap()).unwrap();
    let mut events = session.store.subscribe();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = format!("http://{}", listener.local_addr().unwrap());
    let app = sniper::api::router(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let map_url = format!("{api}/api/target/service-map?session_id={session_id}");
    // Every map read has its own observation time and snapshot UUID. Compare
    // all retained metadata and limits without conflating those read receipts.
    let stable_map = |value: &Value| {
        let mut stable = value.clone();
        let snapshot = stable["snapshot"].as_object_mut().unwrap();
        let id = snapshot.remove("id").unwrap();
        Uuid::parse_str(id.as_str().unwrap()).unwrap();
        let captured_at = snapshot.remove("captured_at").unwrap();
        chrono::DateTime::parse_from_rfc3339(captured_at.as_str().unwrap()).unwrap();
        stable
    };
    let legacy: Value = client
        .get(&map_url)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(legacy.get("technology_catalog_version").is_none());
    assert_eq!(
        legacy["origins"][0]["technology_observations"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        legacy["origins"][0]["technology_observations"][0]["product_id"],
        "nginx"
    );
    let mut v1: Value = client
        .get(&map_url)
        .header(SELECTOR, "1")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        v1.as_object_mut()
            .unwrap()
            .remove("technology_catalog_version"),
        Some(json!(1))
    );
    assert_eq!(
        stable_map(&v1),
        stable_map(&legacy),
        "explicit v1 changed legacy metadata or caps"
    );
    let v2: Value = client
        .get(&map_url)
        .header(SELECTOR, "2")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v2["technology_catalog_version"], 2);
    assert_eq!(stable_map(&v2)["snapshot"], stable_map(&legacy)["snapshot"]);
    let expected: std::collections::BTreeSet<_> = [
        "nginx",
        "gunicorn",
        "uvicorn",
        "waitress",
        "openresty",
        "litespeed",
        "next_js",
    ]
    .into_iter()
    .collect();
    let products = |observations: &Value| -> std::collections::BTreeSet<String> {
        observations
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["product_id"].as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(
        products(&v2["origins"][0]["technology_observations"]),
        expected.iter().map(|value| (*value).to_owned()).collect()
    );
    assert!(!v2.to_string().contains("SYNTHETIC_PRIVATE"));
    let token = legacy["origins"][0]["endpoints"][0]["evidence"][0]
        .as_str()
        .unwrap();
    let evidence_url = format!(
        "{api}/api/target/service-map/evidence?session_id={session_id}&evidence_id={token}"
    );
    let legacy_evidence: Value = client
        .get(&evidence_url)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(legacy_evidence.get("technology_catalog_version").is_none());
    let mut evidence_v1: Value = client
        .get(&evidence_url)
        .header(SELECTOR, "1")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        evidence_v1
            .as_object_mut()
            .unwrap()
            .remove("technology_catalog_version"),
        Some(json!(1))
    );
    assert_eq!(evidence_v1, legacy_evidence);
    let evidence_v2: Value = client
        .get(&evidence_url)
        .header(SELECTOR, "2")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(evidence_v2["technology_catalog_version"], 2);
    assert_eq!(evidence_v2["row"]["evidence_id"], token);
    assert_eq!(
        products(&evidence_v2["row"]["technology_observations"]),
        products(&v2["origins"][0]["technology_observations"])
    );

    // Invalid selectors are rejected once, with no captured-content echo.
    for url in [&map_url, &evidence_url] {
        for value in ["", "0", "3", "1,2", "SYNTHETIC_PRIVATE"] {
            let response = client
                .get(url)
                .header(SELECTOR, value)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
            assert!(!response.text().await.unwrap().contains("SYNTHETIC_PRIVATE"));
        }
        let mut headers = reqwest::header::HeaderMap::new();
        headers.append(SELECTOR, "1".parse().unwrap());
        headers.append(SELECTOR, "2".parse().unwrap());
        let response = client.get(url).headers(headers).send().await.unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    }

    let cli_map = read(
        &dir,
        &api,
        "target.service_map.get",
        json!({"session_id":session_id}),
    )
    .await;
    assert_eq!(stable_map(&cli_map), stable_map(&v2));
    let cli_v1 = read(
        &dir,
        &api,
        "target.service_map.get",
        json!({"session_id":session_id,"technology_catalog_version":1}),
    )
    .await;
    assert_eq!(cli_v1["technology_catalog_version"], 1);
    assert_eq!(cli_v1["origins"], legacy["origins"]);
    let cli_evidence = read(
        &dir,
        &api,
        "target.service_map.evidence.get",
        json!({"session_id":session_id,"evidence_id":token}),
    )
    .await;
    assert_eq!(cli_evidence, evidence_v2);

    // The selector does not change the separate explicit URL-reference contract.
    let body_url = format!(
        "{api}/api/target/service-map/body-references?session_id={session_id}&evidence_id={token}"
    );
    let body: Value = client
        .get(&body_url)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let body_with_selector: Value = client
        .get(&body_url)
        .header(SELECTOR, "2")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body, body_with_selector);
    assert!(body.get("technology_catalog_version").is_none());
    assert_eq!(
        original,
        serde_json::to_value(session.store.get(id).await.unwrap()).unwrap()
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert_eq!(state.session().await.id(), session_id);
    server.abort();
    let _ = server.await;
    drop(session);
    drop(state);
    std::fs::remove_dir_all(dir).unwrap();
}

fn row(path: &str) -> TransactionRecord {
    let mut request_headers = HeaderMap::new();
    request_headers.insert("origin", "https://app.example.com".parse().unwrap());
    request_headers.insert("authorization", "Bearer SYNTHETIC_PRIVATE".parse().unwrap());
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        "location",
        "https://auth.example.com/sign-in?key=SYNTHETIC_PRIVATE"
            .parse()
            .unwrap(),
    );
    response_headers.insert("server", "nginx/SYNTHETIC_PRIVATE".parse().unwrap());
    response_headers.insert("content-type", "text/html; charset=utf-8".parse().unwrap());
    let target = if path.starts_with("/users/1") {
        "older.example.com"
    } else {
        "newer.example.com"
    };
    let response_body = format!(
        "<a href=\"https://user:SYNTHETIC_PRIVATE@{target}/private?token=SYNTHETIC_PRIVATE#SYNTHETIC_PRIVATE\">fixture</a>"
    );
    let mut record = TransactionRecord::http(
        chrono::Utc::now(),
        "GET".into(),
        "https".into(),
        "api.example.com".into(),
        path.into(),
        Some(302),
        1,
        MessageRecord::from_headers_and_body(&request_headers, b"SYNTHETIC_PRIVATE", 1024),
        Some(MessageRecord::from_headers_and_body(
            &response_headers,
            response_body.as_bytes(),
            1024,
        )),
        Vec::new(),
        None,
        None,
    );
    let older = path.starts_with("/users/1");
    record.observed_socket_peer = Some(ObservedSocketPeer::from_remote_addr(
        record.started_at,
        if older {
            ObservedSocketPeerRoute::Direct
        } else {
            ObservedSocketPeerRoute::HttpProxy
        },
        Some(
            if older {
                "192.0.2.10:443"
            } else {
                "[2001:db8::20]:8080"
            }
            .parse()
            .unwrap(),
        ),
    ));
    record
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_html_generator_api_and_cli_keep_exact_rows_and_explicit_coverage() {
    let dir = std::env::temp_dir().join(format!("sniper-html-generators-{}", Uuid::new_v4()));
    let state = Arc::new(
        AppState::new(AppConfig {
            data_dir: dir.clone(),
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 1024,
        })
        .unwrap(),
    );
    let session = state.session().await;
    let session_id = session.id();
    let first_body = "<!--☃--><html><head><title>A &amp; B</title><script defer>const text = \"<meta name='generator' content='Drupal 99'>\";</script><meta name='generator' content='WordPress \t6.8.1'></head><body>https://older.example.com/private?secret=SYNTHETIC_PRIVATE</body></html>";
    let second_body = "<html><head><meta content='Drupal 10.4' name='generator'></head>";
    let make_record = |path: &str, body: &str, mime: &str| {
        let mut record = row(path);
        let mut headers = HeaderMap::new();
        headers.insert("content-type", mime.parse().unwrap());
        record.status = Some(200);
        record.response = Some(MessageRecord::from_headers_and_body(
            &headers,
            body.as_bytes(),
            body.len(),
        ));
        record
    };
    let first = make_record("/generators/a", first_body, "text/html; charset=utf-8");
    let duplicate_id = first.id;
    let mut second = make_record("/generators/b", second_body, "text/html");
    second.id = duplicate_id;
    let mut captured_prefix = make_record("/generators/c", second_body, "text/html");
    captured_prefix.response.as_mut().unwrap().preview_truncated = true;
    let large_body = format!("{second_body}{}", " ".repeat(280_000));
    let bounded_prefix = make_record("/generators/d", &large_body, "text/html");
    let unsupported = make_record("/generators/e", second_body, "application/javascript");
    let rejected_version = make_record(
        "/generators/f",
        "<html><head><meta name='generator' content='WordPress SYNTHETIC_PRIVATE'></head>",
        "text/html",
    );
    for record in [
        first,
        second,
        captured_prefix,
        bounded_prefix,
        unsupported,
        rejected_version,
    ] {
        session.store.insert(record).await;
    }
    // The newest duplicate and unique rows are lazy; the older duplicate keeps
    // its own resident preview. Both modes must use the exact retained token.
    session.persist().await.unwrap();
    let mut events = session.store.subscribe();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = format!("http://{}", listener.local_addr().unwrap());
    let app = sniper::api::router(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let map = read(
        &dir,
        &api,
        "target.service_map.get",
        json!({"session_id":session_id}),
    )
    .await;
    assert_eq!(map["snapshot"]["retained_rows"], 6);
    let token_for = |path: &str| {
        map["origins"][0]["endpoints"]
            .as_array()
            .unwrap()
            .iter()
            .find(|endpoint| endpoint["path"] == path)
            .unwrap()["evidence"][0]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let inspect = |token: &str| {
        format!("{api}/api/target/service-map/html-generators?session_id={session_id}&evidence_id={token}")
    };
    let first_token = token_for("/generators/a");
    let first_result = read(
        &dir,
        &api,
        "target.service_map.html_generators.get",
        json!({"session_id":session_id,"evidence_id":first_token}),
    )
    .await;
    assert_eq!(first_result["available"], true);
    assert_eq!(first_result["status"], "scanned");
    assert_eq!(first_result["complete"], true);
    assert_eq!(first_result["head_closed"], true);
    assert!(first_result["parser_stop"].is_null());
    assert_eq!(first_result["observations"].as_array().unwrap().len(), 1);
    assert_eq!(first_result["observations"][0]["product_id"], "wordpress");
    assert_eq!(first_result["observations"][0]["reported_version"], "6.8.1");
    let observation = &first_result["observations"][0];
    for (key, expected) in [("product_span", "WordPress"), ("version_span", "6.8.1")] {
        let start = observation[key]["start"].as_u64().unwrap() as usize;
        let end = observation[key]["end"].as_u64().unwrap() as usize;
        assert_eq!(&first_body[start..end], expected);
    }
    let second_token = token_for("/generators/b");
    let second_result: Value = client
        .get(inspect(&second_token))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(second_result["observations"][0]["product_id"], "drupal");
    assert_eq!(second_result["observations"][0]["reported_version"], "10.4");
    assert_ne!(
        first_result["source_sequence"],
        second_result["source_sequence"]
    );
    assert_eq!(second_result["evidence_id"], second_token);
    assert!(!second_result.to_string().contains("SYNTHETIC_PRIVATE"));

    let capture = read(
        &dir,
        &api,
        "target.service_map.html_generators.get",
        json!({"session_id":session_id,"evidence_id":token_for("/generators/c")}),
    )
    .await;
    assert_eq!(capture["head_closed"], true);
    assert_eq!(capture["complete"], false);
    assert_eq!(capture["capture_preview_truncated"], true);
    assert!(capture["reasons"]
        .as_array()
        .unwrap()
        .contains(&json!("capture_preview_truncated")));
    let bounded = read(
        &dir,
        &api,
        "target.service_map.html_generators.get",
        json!({"session_id":session_id,"evidence_id":token_for("/generators/d")}),
    )
    .await;
    assert_eq!(bounded["head_closed"], true);
    assert_eq!(bounded["complete"], false);
    assert_eq!(bounded["scan_prefix_truncated"], true);
    assert_eq!(bounded["scan_prefix_bytes"], 262_144);
    assert_eq!(bounded["retained_preview_bytes"], large_body.len());
    assert!(bounded["parser_stop"].is_null());
    let unsupported = read(
        &dir,
        &api,
        "target.service_map.html_generators.get",
        json!({"session_id":session_id,"evidence_id":token_for("/generators/e")}),
    )
    .await;
    assert_eq!(unsupported["status"], "unsupported");
    assert_eq!(unsupported["available"], false);
    assert_eq!(unsupported["scan_prefix_bytes"], 0);
    assert!(unsupported["source_origin"].is_null());
    assert!(unsupported["observations"].as_array().unwrap().is_empty());
    let rejected = read(
        &dir,
        &api,
        "target.service_map.html_generators.get",
        json!({"session_id":session_id,"evidence_id":token_for("/generators/f")}),
    )
    .await;
    assert_eq!(
        rejected["observations"][0]["version_status"],
        "unsupported_format"
    );
    assert!(rejected["observations"][0]["reported_version"].is_null());

    // Metadata reads do not acquire body files. Explicit HTML reads fail safely
    // if that exact lazy row is no longer readable, with no alternate lookup.
    let storage = session.storage_dir().join("transactions.ndjson");
    let held = session.storage_dir().join("synthetic-body-file-held");
    std::fs::rename(&storage, &held).unwrap();
    let still_metadata = read(
        &dir,
        &api,
        "target.service_map.get",
        json!({"session_id":session_id}),
    )
    .await;
    assert_eq!(still_metadata["snapshot"]["retained_rows"], 6);
    let missing = read(
        &dir,
        &api,
        "target.service_map.html_generators.get",
        json!({"session_id":session_id,"evidence_id":second_token}),
    )
    .await;
    assert_eq!(missing["status"], "unavailable");
    assert_eq!(missing["reasons"], json!(["body_storage_unavailable"]));
    assert!(missing["observations"].as_array().unwrap().is_empty());
    std::fs::rename(&held, &storage).unwrap();
    let references = read(
        &dir,
        &api,
        "target.service_map.body_references.get",
        json!({"session_id":session_id,"evidence_id":first_token}),
    )
    .await;
    assert_eq!(
        references["references"][0]["target_origin"],
        "https://older.example.com"
    );
    assert!(references.get("generator_catalog_version").is_none());
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert_eq!(state.session().await.id(), session_id);
    assert_eq!(session.store.delete_ids(&[duplicate_id]).await.unwrap(), 1);
    let removed = read(
        &dir,
        &api,
        "target.service_map.html_generators.get",
        json!({"session_id":session_id,"evidence_id":first_token}),
    )
    .await;
    assert_eq!(removed["available"], false);
    assert!(removed["source_sequence"].is_null());
    assert!(removed["observations"].as_array().unwrap().is_empty());
    server.abort();
    let _ = server.await;
    drop(session);
    drop(state);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_map_real_read_routes_and_cli_keep_duplicate_rows_and_stale_evidence_exact() {
    let dir = std::env::temp_dir().join(format!("sniper-service-map-read-{}", Uuid::new_v4()));
    let state = Arc::new(
        AppState::new(AppConfig {
            data_dir: dir.clone(),
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 1024,
        })
        .unwrap(),
    );
    let session = state.session().await;
    let session_id = session.id();
    let first = row("/users/1?secret=SYNTHETIC_PRIVATE");
    let duplicate_id = first.id;
    let mut second = row("/users/2?secret=SYNTHETIC_PRIVATE");
    second.id = duplicate_id;
    let mut events = session.store.subscribe();
    session.store.insert(first).await;
    session.store.insert(second).await;
    for _ in 0..2 {
        let event = events.recv().await.unwrap();
        let summary = serde_json::to_value(event.summary).unwrap();
        assert!(summary.get("observed_socket_peer").is_none());
        assert!(!summary.to_string().contains("192.0.2.10"));
        assert!(!summary.to_string().contains("2001:db8::20"));
    }
    // Exercise the real persistence path: the newest UUID occurrence becomes
    // lazy, while its older retained sibling must keep its own resident body.
    session.persist().await.unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = format!("http://{}", listener.local_addr().unwrap());
    let app = sniper::api::router(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    for (path, content_type, expected) in [
        (
            "/service-map.js",
            "application/javascript; charset=utf-8",
            include_str!("../web/service-map.js"),
        ),
        (
            "/product-icons.js",
            "application/javascript; charset=utf-8",
            include_str!("../web/product-icons.js"),
        ),
        (
            "/app.js",
            "application/javascript; charset=utf-8",
            include_str!("../web/app.js"),
        ),
        (
            "/styles.css",
            "text/css; charset=utf-8",
            include_str!("../web/styles.css"),
        ),
        (
            "/",
            "text/html; charset=utf-8",
            include_str!("../web/index.html"),
        ),
    ] {
        let asset = client.get(format!("{api}{path}")).send().await.unwrap();
        assert_eq!(asset.status(), reqwest::StatusCode::OK, "{path}");
        assert_eq!(asset.headers()["content-type"], content_type, "{path}");
        assert_eq!(asset.text().await.unwrap(), expected, "{path}");
    }
    let map = read(
        &dir,
        &api,
        "target.service_map.get",
        json!({"session_id":session_id}),
    )
    .await;
    assert_eq!(map["snapshot"]["retained_rows"], 2);
    assert!(!map.to_string().contains("observed_socket_peer"));
    assert!(!map.to_string().contains("192.0.2.10"));
    assert!(!map.to_string().contains("2001:db8::20"));
    assert_eq!(map["snapshot"]["complete"], true);
    let origin = &map["origins"][0];
    assert_eq!(origin["request_count"], 2);
    assert_eq!(origin["endpoints"].as_array().unwrap().len(), 2);
    assert_eq!(
        origin["redirects"][0]["target_origin"],
        "https://auth.example.com"
    );
    assert_eq!(origin["redirects"][0]["target_path"], "/sign-in");
    assert_eq!(
        origin["header_links"][0]["source_origin"],
        "https://app.example.com"
    );
    assert_eq!(origin["technology_clues"][0]["name"], "nginx");
    let token = origin["endpoints"][0]["evidence"][0].as_str().unwrap();
    let input = json!({"session_id":session_id,"evidence_id":token});
    let evidence = read(&dir, &api, "target.service_map.evidence.get", input.clone()).await;
    assert_eq!(evidence["available"], true);
    assert_eq!(evidence["row"]["path"], "/users/1");
    assert_eq!(evidence["row"]["record_id"], duplicate_id.to_string());
    assert!(
        evidence.get("socket_peer").is_none(),
        "default evidence shape changed"
    );
    let peer_evidence = read(
        &dir,
        &api,
        "target.service_map.evidence.get",
        json!({"session_id":session_id,"evidence_id":token,"include_socket_peer":true}),
    )
    .await;
    assert_eq!(peer_evidence["socket_peer"]["status"], "observed");
    assert_eq!(
        peer_evidence["socket_peer"]["observation"]["address"]["ip"],
        "192.0.2.10"
    );
    assert_eq!(
        peer_evidence["socket_peer"]["observation"]["route"],
        "direct"
    );

    // saved.v1 has summaries, selections and receipts, not full transaction
    // objects. Its closed response schema remains unchanged even for new rows.
    let saved: Value = client
        .post(format!("{api}/api/saved/v1/call"))
        .json(
            &json!({"operation":"saved.v1.http.list","input":{"session_id":session_id,"limit":1}}),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(saved["ok"], true);
    sniper::saved_contract::validate_output("saved.v1.http.list", &saved["data"]).unwrap();
    assert_eq!(saved["data"]["items"].as_array().unwrap().len(), 1);
    assert!(!saved.to_string().contains("observed_socket_peer"));
    assert!(!saved.to_string().contains("192.0.2.10"));
    assert!(!saved.to_string().contains("2001:db8::20"));
    let full: Value = client
        .get(format!(
            "{api}/api/transactions/{duplicate_id}?session_id={session_id}"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        full["observed_socket_peer"]["address"]["ip"],
        "2001:db8::20"
    );
    assert_eq!(full["observed_socket_peer"]["route"], "http_proxy");

    let body = read(
        &dir,
        &api,
        "target.service_map.body_references.get",
        input.clone(),
    )
    .await;
    assert_eq!(body["available"], true, "{body}");
    assert_eq!(body["status"], "scanned");
    assert_eq!(
        body["references"][0]["target_origin"],
        "https://older.example.com"
    );
    assert_eq!(body["offset_basis"], "retained_utf8_preview");
    assert_eq!(body["evidence_id"], token);
    assert_eq!(body["source_sequence"], evidence["row"]["sequence"]);
    let newest_token = origin["endpoints"][1]["evidence"][0].as_str().unwrap();
    let newest_peer = read(
        &dir,
        &api,
        "target.service_map.evidence.get",
        json!({"session_id":session_id,"evidence_id":newest_token,"include_socket_peer":true}),
    )
    .await;
    assert_eq!(
        newest_peer["socket_peer"]["observation"]["address"]["ip"],
        "2001:db8::20"
    );
    assert_ne!(
        peer_evidence["row"]["sequence"],
        newest_peer["row"]["sequence"]
    );
    let lazy_body = read(
        &dir,
        &api,
        "target.service_map.body_references.get",
        json!({"session_id": session_id, "evidence_id": newest_token}),
    )
    .await;
    assert_eq!(lazy_body["available"], true, "{lazy_body}");
    assert_eq!(
        lazy_body["references"][0]["target_origin"],
        "https://newer.example.com"
    );
    assert_ne!(body["source_sequence"], lazy_body["source_sequence"]);

    // Deletion reports distinct IDs; the map must still account for both rows.
    assert_eq!(session.store.delete_ids(&[duplicate_id]).await.unwrap(), 1);
    assert_eq!(session.store.len().await, 0);
    let missing = read(&dir, &api, "target.service_map.evidence.get", input.clone()).await;
    assert_eq!(missing["available"], false);
    assert!(missing["row"].is_null());
    let missing_peer = read(
        &dir,
        &api,
        "target.service_map.evidence.get",
        json!({"session_id":session_id,"evidence_id":token,"include_socket_peer":true}),
    )
    .await;
    assert_eq!(missing_peer["available"], false);
    assert!(
        missing_peer.get("socket_peer").is_none(),
        "stale source exposed peer evidence"
    );
    let missing_body = read(&dir, &api, "target.service_map.body_references.get", input).await;
    assert_eq!(missing_body["available"], false);
    assert_eq!(missing_body["status"], "unavailable");
    assert!(missing_body["references"].as_array().unwrap().is_empty());
    let empty = read(
        &dir,
        &api,
        "target.service_map.get",
        json!({"session_id":session_id}),
    )
    .await;
    assert_eq!(empty["snapshot"]["retained_rows"], 0);
    assert!(empty["origins"].as_array().unwrap().is_empty());
    assert_eq!(state.session().await.id(), session_id);

    server.abort();
    let _ = server.await;
    drop(session);
    drop(state);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn observed_socket_peer_survives_journal_restart_compaction_and_metadata_rebuild() {
    use sniper::session::SessionRegistry;
    for compact in [false, true] {
        let dir = std::env::temp_dir().join(format!("sniper-peer-restart-{}", Uuid::new_v4()));
        let (registry, active) = SessionRegistry::load_or_create(&dir, 32, 32).unwrap();
        let record = row("/users/2");
        let id = record.id;
        let expected = serde_json::to_value(&record.observed_socket_peer).unwrap();
        let response_body = record.response.as_ref().unwrap().body_preview.clone();
        let session_id = active.id();
        active.store.insert(record).await;
        let mut legacy = row("/legacy");
        legacy.observed_socket_peer = None;
        let legacy_id = legacy.id;
        active.store.insert(legacy).await;
        active.persist().await.unwrap();
        let storage = active.storage_dir().to_path_buf();
        for filename in ["transactions.ndjson", "transactions.meta.ndjson"] {
            let bytes = std::fs::read_to_string(storage.join(filename)).unwrap();
            let rows: Vec<Value> = bytes
                .lines()
                .filter_map(|line| {
                    let value: Value = serde_json::from_str(line).unwrap();
                    if filename == "transactions.meta.ndjson" {
                        value.get("r").cloned()
                    } else {
                        Some(value)
                    }
                })
                .collect();
            assert_eq!(
                rows.iter().find(|row| row["id"] == id.to_string()).unwrap()
                    ["observed_socket_peer"],
                expected
            );
            assert!(rows
                .iter()
                .find(|row| row["id"] == legacy_id.to_string())
                .unwrap()
                .get("observed_socket_peer")
                .is_none());
        }
        active
            .store
            .update_annotations_durable(id, Some(Some("blue".into())), None)
            .await
            .unwrap()
            .unwrap();
        if compact {
            active.persist().await.unwrap();
        }
        drop(active);
        drop(registry);
        let (registry, active) = SessionRegistry::load_or_create(&dir, 32, 32).unwrap();
        assert_eq!(active.id(), session_id);
        let restored = active.store.get(id).await.unwrap();
        assert_eq!(
            serde_json::to_value(&restored.observed_socket_peer).unwrap(),
            expected
        );
        assert_eq!(
            restored.response.as_ref().unwrap().body_preview,
            response_body
        );
        assert!(serde_json::to_value(restored.summary())
            .unwrap()
            .get("observed_socket_peer")
            .is_none());
        drop(active);
        std::fs::remove_file(storage.join("transactions.meta.ndjson")).unwrap();
        let rebuilt = registry.load_context_read_only(session_id).unwrap();
        let restored = rebuilt.store.get(id).await.unwrap();
        assert_eq!(
            serde_json::to_value(&restored.observed_socket_peer).unwrap(),
            expected
        );
        assert_eq!(
            restored.response.as_ref().unwrap().body_preview,
            response_body
        );
        assert!(rebuilt
            .store
            .get(legacy_id)
            .await
            .unwrap()
            .observed_socket_peer
            .is_none());
        drop(rebuilt);
        let active = registry.load_context(session_id).unwrap();
        active.store.delete_ids(&[id]).await.unwrap();
        active.persist().await.unwrap();
        drop(active);
        drop(registry);
        let (registry, restarted) = SessionRegistry::load_or_create(&dir, 32, 32).unwrap();
        assert!(restarted.store.get(id).await.is_none());
        assert_eq!(restarted.store.len().await, 1);
        assert!(restarted
            .store
            .get(legacy_id)
            .await
            .unwrap()
            .observed_socket_peer
            .is_none());
        drop(restarted);
        drop(registry);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_link_declarations_api_and_cli_are_metadata_only_and_exact() {
    let dir = std::env::temp_dir().join(format!("sniper-link-declarations-{}", Uuid::new_v4()));
    let state = Arc::new(
        AppState::new(AppConfig {
            data_dir: dir.clone(),
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 1024,
        })
        .unwrap(),
    );
    let session = state.session().await;
    let session_id = session.id();
    let first_link = "<https://docs.example.com/private?key=SYNTHETIC_PRIVATE#fragment>; title=\"é, retained\"; rel=\"service-doc describedby\"";
    let make_record = |path: &str, method: &str, status: u16, values: &[(&str, &str)]| {
        let mut record = row(path);
        record.method = method.into();
        record.status = Some(status);
        let response = record.response.as_mut().unwrap();
        response.content_type = Some("application/octet-stream".into());
        response.body_encoding = sniper::model::BodyEncoding::Base64;
        response.body_preview = "U1lOVEhFVElDX1BSSVZBVEU=".into();
        response.headers = values
            .iter()
            .map(|(name, value)| sniper::model::HeaderRecord {
                name: (*name).into(),
                value: (*value).into(),
            })
            .collect();
        record
    };
    let first = make_record(
        "/links/a?secret=SYNTHETIC_PRIVATE",
        "GET",
        200,
        &[("Link", first_link)],
    );
    let duplicate_id = first.id;
    let mut second = make_record(
        "/links/b",
        "HEAD",
        200,
        &[("Link", "<https://[2001:db8::20]:443/asset>; rel=preconnect")],
    );
    second.id = duplicate_id;
    let wrong_status = make_record("/links/status", "GET", 404, &[("Link", first_link)]);
    let wrong_method = make_record("/links/method", "POST", 200, &[("Link", first_link)]);
    let mut absent = make_record("/links/absent", "GET", 200, &[]);
    absent.response = None;
    let large_unknown = "x".repeat(32760);
    let bounded = make_record(
        "/links/bounded",
        "GET",
        200,
        &[("X", &large_unknown), ("Link", first_link)],
    );
    let partial = make_record("/links/partial", "GET", 200, &[
        ("Link", "<https://other.example.com/private>; rel=service-doc; anchor=\"https://hidden.example.com/SYNTHETIC_PRIVATE\""),
        ("LINK", "<https://schema.example.com/spec?key=SYNTHETIC_PRIVATE>; rel=service-desc"),
    ]);
    for record in [
        first,
        second,
        wrong_status,
        wrong_method,
        absent,
        bounded,
        partial,
    ] {
        session.store.insert(record).await;
    }
    session.persist().await.unwrap();
    let mut events = session.store.subscribe();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = format!("http://{}", listener.local_addr().unwrap());
    let app = sniper::api::router(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let map = read(
        &dir,
        &api,
        "target.service_map.get",
        json!({"session_id":session_id}),
    )
    .await;
    assert_eq!(map["snapshot"]["retained_rows"], 7);
    assert!(!map.to_string().contains("docs.example.com"));
    let token_for = |path: &str| {
        map["origins"][0]["endpoints"]
            .as_array()
            .unwrap()
            .iter()
            .find(|endpoint| endpoint["path"] == path)
            .unwrap()["evidence"][0]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let first_token = token_for("/links/a");
    let second_token = token_for("/links/b");
    let inspect = |token: &str| {
        format!("{api}/api/target/service-map/link-declarations?session_id={session_id}&evidence_id={token}")
    };

    // Both retained duplicate rows remain inspectable with body storage absent.
    // This endpoint must neither hydrate the latest UUID nor consult its locator.
    let storage = session.storage_dir().join("transactions.ndjson");
    let held = session.storage_dir().join("synthetic-body-file-held");
    std::fs::rename(&storage, &held).unwrap();
    let first_result = read(
        &dir,
        &api,
        "target.service_map.link_declarations.get",
        json!({"session_id":session_id,"evidence_id":first_token}),
    )
    .await;
    assert_eq!(first_result["status"], "scanned");
    assert_eq!(first_result["complete"], true);
    assert_eq!(first_result["source_method"], "GET");
    assert_eq!(first_result["source_status"], 200);
    assert_eq!(first_result["retained_header_count"], 1);
    assert_eq!(first_result["counts"]["headers_inspected"], 1);
    assert_eq!(first_result["observations"].as_array().unwrap().len(), 2);
    let observations = first_result["observations"].as_array().unwrap();
    for (observation, relation) in observations.iter().zip(["service-doc", "describedby"]) {
        assert_eq!(observation["target_origin"], "https://docs.example.com");
        assert_eq!(observation["header_index"], 0);
        assert_eq!(observation["header_value_bytes"], first_link.len());
        assert_eq!(observation["offset_basis"], "retained_header_value_utf8");
        let span = &observation["relation_span"];
        assert_eq!(
            &first_link
                [span["start"].as_u64().unwrap() as usize..span["end"].as_u64().unwrap() as usize],
            relation
        );
    }
    assert_eq!(
        observations[0]["target_span"],
        observations[1]["target_span"]
    );
    assert_eq!(
        observations[0]["link_value_span"],
        observations[1]["link_value_span"]
    );
    for forbidden in ["private", "fragment", "é", "SYNTHETIC_PRIVATE"] {
        assert!(!first_result.to_string().contains(forbidden));
    }
    let second_result = read(
        &dir,
        &api,
        "target.service_map.link_declarations.get",
        json!({"session_id":session_id,"evidence_id":second_token}),
    )
    .await;
    assert_eq!(second_result["source_method"], "HEAD");
    assert_eq!(
        second_result["observations"][0]["target_origin"],
        "https://[2001:db8::20]"
    );
    assert_eq!(second_result["observations"][0]["relation"], "preconnect");
    assert_ne!(
        first_result["source_sequence"],
        second_result["source_sequence"]
    );
    assert!(!storage.exists());
    assert!(held.exists());
    std::fs::rename(&held, &storage).unwrap();

    for path in ["/links/status", "/links/method"] {
        let result = read(
            &dir,
            &api,
            "target.service_map.link_declarations.get",
            json!({"session_id":session_id,"evidence_id":token_for(path)}),
        )
        .await;
        assert_eq!(result["status"], "unsupported");
        assert_eq!(result["reasons"], json!(["unsupported_source_context"]));
        assert!(result["source_method"].is_null());
        assert!(result["retained_header_count"].is_null());
        assert!(result["observations"].as_array().unwrap().is_empty());
    }
    let absent = read(
        &dir,
        &api,
        "target.service_map.link_declarations.get",
        json!({"session_id":session_id,"evidence_id":token_for("/links/absent")}),
    )
    .await;
    assert_eq!(absent["available"], false);
    assert_eq!(absent["reasons"], json!(["response_unavailable"]));
    let bounded = read(
        &dir,
        &api,
        "target.service_map.link_declarations.get",
        json!({"session_id":session_id,"evidence_id":token_for("/links/bounded")}),
    )
    .await;
    assert_eq!(bounded["status"], "scanned");
    assert_eq!(bounded["complete"], false);
    assert_eq!(bounded["retained_header_count"], 2);
    assert_eq!(bounded["counts"]["headers_inspected"], 1);
    assert_eq!(bounded["counts"]["header_bytes_admitted"], 32761);
    assert_eq!(bounded["reasons"], json!(["header_byte_limit"]));
    let partial = read(
        &dir,
        &api,
        "target.service_map.link_declarations.get",
        json!({"session_id":session_id,"evidence_id":token_for("/links/partial")}),
    )
    .await;
    assert_eq!(partial["complete"], false);
    assert_eq!(partial["reasons"], json!(["anchor_present"]));
    assert_eq!(partial["observations"].as_array().unwrap().len(), 1);
    assert_eq!(partial["observations"][0]["header_index"], 1);
    assert_eq!(
        partial["observations"][0]["target_origin"],
        "https://schema.example.com"
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert_eq!(state.session().await.id(), session_id);
    let unknown = client
        .get(format!(
            "{}&unexpected=SYNTHETIC_PRIVATE",
            inspect(&first_token)
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(!unknown.text().await.unwrap().contains("SYNTHETIC_PRIVATE"));
    assert_eq!(session.store.delete_ids(&[duplicate_id]).await.unwrap(), 1);
    let removed = read(
        &dir,
        &api,
        "target.service_map.link_declarations.get",
        json!({"session_id":session_id,"evidence_id":first_token}),
    )
    .await;
    assert_eq!(removed["available"], false);
    assert!(removed["source_sequence"].is_null());
    assert!(removed["observations"].as_array().unwrap().is_empty());
    server.abort();
    let _ = server.await;
    drop(session);
    drop(state);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recorded_peer_matches_api_and_cli_preserve_exact_sources_and_private_defaults() {
    let dir = std::env::temp_dir().join(format!("sniper-peer-matches-{}", Uuid::new_v4()));
    let state = Arc::new(
        AppState::new(AppConfig {
            data_dir: dir.clone(),
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 1024,
        })
        .unwrap(),
    );
    let session = state.session().await;
    let session_id = session.id();
    assert!(
        !session
            .runtime
            .snapshot()
            .await
            .upstream_peer_capture_enabled
    );
    let make = |host: &str, path: &str, route: ObservedSocketPeerRoute, address: Option<&str>| {
        let mut record = row(path);
        record.host = host.into();
        record.observed_socket_peer = Some(ObservedSocketPeer::from_remote_addr(
            record.started_at,
            route,
            address.map(|value| value.parse().unwrap()),
        ));
        record
    };
    let address = "192.0.2.80:443";
    let seed = make(
        "source.allowed.example.com",
        "/peer/source?key=SYNTHETIC_PRIVATE",
        ObservedSocketPeerRoute::Direct,
        Some(address),
    );
    let duplicate = seed.id;
    let mut records = vec![seed];
    for index in 0..4 {
        let mut matching = make(
            "target.allowed.example.com",
            &format!("/peer/match/{index}"),
            ObservedSocketPeerRoute::Direct,
            Some(address),
        );
        matching.id = duplicate;
        records.push(matching);
    }
    records.push(make(
        "target.excluded.example.com",
        "/peer/excluded",
        ObservedSocketPeerRoute::Direct,
        Some(address),
    ));
    records.push(make(
        "port.allowed.example.com",
        "/peer/port",
        ObservedSocketPeerRoute::Direct,
        Some("192.0.2.80:8443"),
    ));
    records.push(make(
        "proxy.allowed.example.com",
        "/peer/proxy",
        ObservedSocketPeerRoute::HttpProxy,
        Some(address),
    ));
    let mut unrecorded = row("/peer/unrecorded");
    unrecorded.observed_socket_peer = None;
    records.push(unrecorded);
    records.push(make(
        "unavailable.allowed.example.com",
        "/peer/unavailable",
        ObservedSocketPeerRoute::Direct,
        None,
    ));
    records.push(make(
        "latest.allowed.example.com",
        "/peer/latest",
        ObservedSocketPeerRoute::Direct,
        Some(address),
    ));
    for record in records {
        session.store.insert(record).await;
    }
    session.persist().await.unwrap();
    let mut events = session.store.subscribe();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = format!("http://{}", listener.local_addr().unwrap());
    let app = sniper::api::router(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let map = read(
        &dir,
        &api,
        "target.service_map.get",
        json!({"session_id":session_id}),
    )
    .await;
    assert_eq!(map["snapshot"]["retained_rows"], 11);
    assert!(!map.to_string().contains("192.0.2.80"));
    let token_for = |path: &str| {
        map["origins"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|origin| origin["endpoints"].as_array().unwrap())
            .find(|endpoint| endpoint["path"] == path)
            .unwrap()["evidence"][0]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let seed_token = token_for("/peer/source");
    let proxy_token = token_for("/peer/proxy");
    let port_token = token_for("/peer/port");
    let excluded_token = token_for("/peer/excluded");
    let ordinary_evidence = read(
        &dir,
        &api,
        "target.service_map.evidence.get",
        json!({"session_id":session_id,"evidence_id":seed_token}),
    )
    .await;
    assert!(ordinary_evidence.get("socket_peer").is_none());
    assert!(!ordinary_evidence.to_string().contains("192.0.2.80"));

    // Retained metadata and exact duplicate-row identity must not depend on the
    // latest UUID's body file or locator, even when grouping several rows.
    let storage = session.storage_dir().join("transactions.ndjson");
    let held = session.storage_dir().join("synthetic-peer-body-file-held");
    std::fs::rename(&storage, &held).unwrap();
    let result = read(
        &dir,
        &api,
        "target.service_map.socket_peer_matches.get",
        json!({"session_id":session_id,"evidence_id":seed_token}),
    )
    .await;
    assert_eq!(result["available"], true);
    assert_eq!(result["status"], "matched");
    assert_eq!(result["complete"], false);
    assert_eq!(result["reasons"], json!(["sample_limit"]));
    assert_eq!(result["source"]["sequence"], "1");
    assert_eq!(result["source"]["in_window"], true);
    assert_eq!(
        result["peer"]["address"],
        json!({"ip":"192.0.2.80","port":443})
    );
    assert_eq!(result["snapshot"]["considered_rows"], 11);
    assert_eq!(result["counts"]["matching_rows"], 6);
    assert_eq!(result["counts"]["returned_matching_rows"], 6);
    assert_eq!(result["counts"]["non_direct_rows"], 1);
    assert_eq!(result["counts"]["different_peer_rows"], 1);
    assert_eq!(result["counts"]["not_recorded_rows"], 1);
    assert_eq!(result["counts"]["unavailable_observation_rows"], 1);
    assert_eq!(result["counts"]["sample_rows"], 5);
    assert_eq!(result["counts"]["omitted_sample_rows"], 1);
    assert_eq!(result["origins"].as_array().unwrap().len(), 3);
    assert!(serde_json::to_vec(&result).unwrap().len() <= 262144);
    for forbidden in [
        "SYNTHETIC_PRIVATE",
        "body_preview",
        "authorization",
        "scope_patterns",
        "/peer/",
    ] {
        assert!(!result.to_string().contains(forbidden), "{forbidden}");
    }
    let group = result["origins"]
        .as_array()
        .unwrap()
        .iter()
        .find(|origin| origin["origin"] == "https://target.allowed.example.com")
        .unwrap();
    assert_eq!(group["matching_rows"], 4);
    assert_eq!(group["omitted_samples"], 1);
    let samples = group["samples"].as_array().unwrap();
    assert_eq!(samples.len(), 3);
    for sample in samples {
        let token = sample["evidence_id"].as_str().unwrap();
        assert_ne!(token, seed_token);
        assert_eq!(token.split('.').last().unwrap(), duplicate.to_string());
        let exact = read(
            &dir,
            &api,
            "target.service_map.evidence.get",
            json!({"session_id":session_id,"evidence_id":token,"include_socket_peer":true}),
        )
        .await;
        assert_eq!(exact["available"], true);
        assert_eq!(exact["row"]["evidence_id"], token);
        assert_eq!(exact["row"]["sequence"], sample["sequence"]);
        assert_eq!(exact["row"]["origin"], group["origin"]);
        assert_eq!(
            exact["socket_peer"]["observation"]["observed_at"],
            sample["observed_at"]
        );
        assert_eq!(
            exact["socket_peer"]["observation"]["address"],
            result["peer"]["address"]
        );
    }
    std::fs::rename(&held, &storage).unwrap();
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));

    let window = read(
        &dir,
        &api,
        "target.service_map.socket_peer_matches.get",
        json!({"session_id":session_id,"evidence_id":seed_token,"max_records":1}),
    )
    .await;
    assert_eq!(window["source"]["in_window"], false);
    assert_eq!(window["snapshot"]["retained_rows"], 11);
    assert_eq!(window["snapshot"]["considered_rows"], 1);
    assert_eq!(window["counts"]["matching_rows"], 1);
    assert_eq!(
        window["origins"][0]["origin"],
        "https://latest.allowed.example.com"
    );
    assert_eq!(
        window["reasons"],
        json!(["max_records", "source_outside_window"])
    );
    let empty = read(
        &dir,
        &api,
        "target.service_map.socket_peer_matches.get",
        json!({"session_id":session_id,"evidence_id":port_token}),
    )
    .await;
    assert_eq!(empty["status"], "no_matches");
    assert_eq!(empty["complete"], true);
    assert_eq!(empty["counts"]["matching_rows"], 0);
    let proxy = read(
        &dir,
        &api,
        "target.service_map.socket_peer_matches.get",
        json!({"session_id":session_id,"evidence_id":proxy_token}),
    )
    .await;
    assert_eq!(proxy["status"], "unavailable");
    assert_eq!(proxy["reasons"], json!(["non_direct_observation"]));
    assert!(proxy["peer"].is_null() && proxy["source"].is_null() && proxy["snapshot"].is_null());

    session
        .runtime
        .update(sniper::runtime::RuntimeSettingsUpdate {
            scope_patterns: Some(vec!["*.allowed.example.com".into()]),
            ..Default::default()
        })
        .await
        .unwrap();
    let scoped = read(
        &dir,
        &api,
        "target.service_map.socket_peer_matches.get",
        json!({"session_id":session_id,"evidence_id":seed_token,"in_scope_only":true}),
    )
    .await;
    assert_eq!(scoped["counts"]["matching_rows"], 5);
    assert_eq!(scoped["counts"]["scope_excluded_rows"], 1);
    assert_eq!(scoped["origins"].as_array().unwrap().len(), 2);
    assert!(scoped["origins"]
        .as_array()
        .unwrap()
        .iter()
        .all(|group| group["in_scope"] == true));
    let outside = read(
        &dir,
        &api,
        "target.service_map.socket_peer_matches.get",
        json!({"session_id":session_id,"evidence_id":excluded_token,"in_scope_only":true}),
    )
    .await;
    assert_eq!(outside["reasons"], json!(["source_out_of_scope"]));
    assert!(outside["peer"].is_null());
    assert!(
        !session
            .runtime
            .snapshot()
            .await
            .upstream_peer_capture_enabled
    );
    let inspect = format!("{api}/api/target/service-map/socket-peer-matches?session_id={session_id}&evidence_id={seed_token}");
    for suffix in [
        "&ip=SYNTHETIC_PRIVATE",
        "&max_records=0",
        "&in_scope_only=null",
        "&max_records=1&max_records=2",
    ] {
        let response = client
            .get(format!("{inspect}{suffix}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
        assert!(!response.text().await.unwrap().contains("SYNTHETIC_PRIVATE"));
    }
    // Deletion acknowledgement counts distinct selected UUIDs, while the
    // retained matching counts above count all five duplicate rows.
    assert_eq!(session.store.delete_ids(&[duplicate]).await.unwrap(), 1);
    let stale: Value = client
        .get(inspect)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(stale["status"], "unavailable");
    assert_eq!(stale["reasons"], json!(["record_missing"]));
    assert!(stale["peer"].is_null() && stale["origins"].as_array().unwrap().is_empty());
    server.abort();
    drop(session);
    drop(state);
    let _ = std::fs::remove_dir_all(dir);
}

fn filter_row(
    host: &str,
    path: &str,
    content_type: &str,
    referer: Option<&str>,
) -> TransactionRecord {
    let mut request_headers = HeaderMap::new();
    if let Some(referer) = referer {
        request_headers.insert("referer", referer.parse().unwrap());
    }
    let mut response_headers = HeaderMap::new();
    response_headers.insert("content-type", content_type.parse().unwrap());
    TransactionRecord::http(
        chrono::Utc::now(),
        "GET".into(),
        "https".into(),
        host.into(),
        path.into(),
        Some(200),
        1,
        MessageRecord::from_headers_and_body(&request_headers, b"", 1024),
        Some(MessageRecord::from_headers_and_body(
            &response_headers,
            b"",
            1024,
        )),
        Vec::new(),
        None,
        None,
    )
}

// A page's image CDN is the noise the Service Map filter removes: its row, its
// card and the page's Referer arrow to it go, through the API and the CLI alike.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_map_display_filter_hides_rows_through_api_and_cli_as_history_does() {
    let dir = std::env::temp_dir().join(format!("sniper-map-filter-{}", Uuid::new_v4()));
    let state = Arc::new(
        AppState::new(AppConfig {
            data_dir: dir.clone(),
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 1024,
        })
        .unwrap(),
    );
    let session = state.session().await;
    let session_id = session.id();
    let page = "https://www.example.com/";
    for record in [
        filter_row("www.example.com", "/", "text/html", None),
        filter_row("cdn.example.com", "/logo.png", "image/png", Some(page)),
        {
            // The API lets the page read it, credentials included.
            let mut row = filter_row(
                "api.example.com",
                "/v1/items",
                "application/json",
                Some(page),
            );
            for (name, value) in [
                ("access-control-allow-origin", "https://www.example.com"),
                ("access-control-allow-credentials", "true"),
            ] {
                row.response
                    .as_mut()
                    .unwrap()
                    .headers
                    .push(sniper::model::HeaderRecord {
                        name: name.into(),
                        value: value.into(),
                    });
            }
            row
        },
    ] {
        session.store.insert(record).await;
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = format!("http://{}", listener.local_addr().unwrap());
    let app = sniper::api::router(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let get = |query: &str| {
        let url = format!("{api}/api/target/service-map?session_id={session_id}{query}");
        let client = client.clone();
        async move {
            client
                .get(url)
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        }
    };
    let origins = |map: &Value| -> Vec<String> {
        let mut ids: Vec<String> = map["origins"]
            .as_array()
            .unwrap()
            .iter()
            .map(|origin| origin["origin"].as_str().unwrap().to_string())
            .collect();
        ids.sort();
        ids
    };
    let cdn = "https://cdn.example.com".to_string();

    let all = get("").await;
    assert!(origins(&all).contains(&cdn));
    assert!(
        all["snapshot"].get("filtered_rows").is_none(),
        "an unfiltered map keeps its earlier shape"
    );
    // Each link counts its rows by request kind, here from the response type,
    // and the CLI passes the counts through its output contract.
    let link = |map: &Value, origin: &str| {
        map["origins"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["origin"] == origin)
            .unwrap()["header_links"][0]
            .clone()
    };
    assert_eq!(
        link(&all, "https://cdn.example.com")["request_kinds"],
        json!({"static": 1})
    );
    assert_eq!(
        link(&all, "https://api.example.com")["request_kinds"],
        json!({"api": 1})
    );
    assert_eq!(link(&all, "https://api.example.com")["request_count"], 1);
    assert_eq!(
        link(&all, "https://api.example.com")["cors_credentials_count"],
        1
    );
    assert!(
        link(&all, "https://cdn.example.com")
            .get("cors_allowed_count")
            .is_none(),
        "a link no response allowed omits the count"
    );
    let cli_all = read(
        &dir,
        &api,
        "target.service_map.get",
        json!({"session_id": session_id}),
    )
    .await;
    for origin in ["https://cdn.example.com", "https://api.example.com"] {
        for field in [
            "request_kinds",
            "request_count",
            "cors_allowed_count",
            "cors_credentials_count",
        ] {
            assert_eq!(
                link(&cli_all, origin).get(field),
                link(&all, origin).get(field),
                "{origin} {field}"
            );
        }
    }

    let filtered = get("&hidden_extensions=PNG,%20css").await;
    assert!(!origins(&filtered).contains(&cdn));
    assert_eq!(filtered["snapshot"]["filtered_rows"], 1);
    assert_eq!(filtered["snapshot"]["considered_rows"], 3);
    let api_origin = filtered["origins"]
        .as_array()
        .unwrap()
        .iter()
        .find(|origin| origin["origin"] == "https://api.example.com")
        .unwrap();
    assert_eq!(
        api_origin["header_links"][0]["source_origin"],
        "https://www.example.com"
    );

    let cli = read(
        &dir,
        &api,
        "target.service_map.get",
        json!({"session_id": session_id, "hidden_extensions": ["png"]}),
    )
    .await;
    assert_eq!(origins(&cli), origins(&filtered));
    let cli_mime = read(
        &dir,
        &api,
        "target.service_map.get",
        json!({"session_id": session_id, "mime_types": ["html", "json"]}),
    )
    .await;
    assert_eq!(origins(&cli_mime), origins(&filtered));
    assert_eq!(cli_mime["snapshot"]["filtered_rows"], 1);

    // The search reads headers, as History's does: only the API's response
    // carries this header.
    let searched = get("&advanced_search=allow-credentials").await;
    assert!(origins(&searched).contains(&"https://api.example.com".to_string()));
    assert!(!origins(&searched).contains(&cdn));
    let invalid = client
        .get(format!(
            "{api}/api/target/service-map?session_id={session_id}&advanced_search=(a)%5C1&advanced_regex=true"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(invalid.status(), reqwest::StatusCode::BAD_REQUEST);

    server.abort();
    drop(session);
    drop(state);
    let _ = std::fs::remove_dir_all(dir);
}

// An endpoint's parameters: query pairs and JSON fields counted per row with a
// few values, newest first, read for the active session only.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_map_parameters_list_an_endpoints_query_and_body_fields() {
    let dir = std::env::temp_dir().join(format!("sniper-map-parameters-{}", Uuid::new_v4()));
    let state = Arc::new(
        AppState::new(AppConfig {
            data_dir: dir.clone(),
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 1024,
        })
        .unwrap(),
    );
    let session = state.session().await;
    let session_id = session.id();
    let request = |method: &str, path: &str, content_type: Option<&str>, body: &[u8]| {
        let mut headers = HeaderMap::new();
        if let Some(content_type) = content_type {
            headers.insert("content-type", content_type.parse().unwrap());
        }
        TransactionRecord::http(
            chrono::Utc::now(),
            method.into(),
            "https".into(),
            "www.example.com".into(),
            path.into(),
            Some(200),
            1,
            MessageRecord::from_headers_and_body(&headers, body, 4096),
            Some(MessageRecord::from_headers_and_body(
                &HeaderMap::new(),
                b"",
                1024,
            )),
            Vec::new(),
            None,
            None,
        )
    };
    for record in [
        request("GET", "/search?q=shoes&page=2", None, b""),
        request("GET", "/search?q=hats", None, b""),
        request(
            "POST",
            "/search",
            Some("application/json"),
            br#"{"q":"bags","limit":5}"#,
        ),
        request(
            "POST",
            "/upload",
            Some("multipart/form-data; boundary=control"),
            b"--control\r\nContent-Disposition: form-data; name=\"file\"; filename=\"fixture.txt\"\r\n\r\nSYNTHETIC_PRIVATE_UPLOAD ; name=\"invented\"\r\nContent-Disposition: form-data; name=\"header_fake\"\r\n\r\n--control--\r\n",
        ),
        request(
            "POST",
            "/upload",
            Some("multipart/form-data; boundary=\"json-Boundary\""),
            b"--json-Boundary\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nSYNTHETIC_PRIVATE_UPLOAD\r\n--json-Boundary--\r\n",
        ),
        request(
            "POST",
            "/suffix-json",
            Some("application/problem+json; profile=x-www-form-urlencoded"),
            br#"{"message":"value"}"#,
        ),
        request(
            "POST",
            "/unsupported",
            Some("text/plain; profile=application/json"),
            br#"{"invented":"value"}"#,
        ),
        request("GET", "/other?x=1", None, b""),
    ] {
        session.store.insert(record).await;
    }
    let custom_methods = [
        "M-SEARCH2!",
        "X.CUSTOM",
        "X+CUSTOM",
        "gEt-Custom",
        "!#$%&'*+-.^_`|~",
    ];
    for method in custom_methods {
        session
            .store
            .insert(request(method, "/custom?q=token", None, b""))
            .await;
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = format!("http://{}", listener.local_addr().unwrap());
    let app = sniper::api::router(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let read = |session: Uuid, origin: &str, method: &str, path: &str| {
        let request = client
            .get(format!("{api}/api/target/service-map/parameters"))
            .query(&[
                ("session_id", session.to_string()),
                ("origin", origin.to_string()),
                ("method", method.to_string()),
                ("path", path.to_string()),
            ]);
        async move { request.send().await.unwrap() }
    };
    let names = |result: &Value| -> Vec<(String, String, u64, Value)> {
        result["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| {
                (
                    item["location"].as_str().unwrap().to_string(),
                    item["name"].as_str().unwrap().to_string(),
                    item["rows"].as_u64().unwrap(),
                    item["examples"].clone(),
                )
            })
            .collect()
    };
    let origin = "https://www.example.com";

    let get: Value = read(session_id, origin, "GET", "/search")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(get["available"], true);
    assert_eq!(get["rows"], 2);
    assert_eq!(
        names(&get),
        [
            ("query".into(), "q".into(), 2, json!(["hats", "shoes"])),
            ("query".into(), "page".into(), 1, json!(["2"])),
        ]
    );
    let post: Value = read(session_id, origin, "POST", "/search")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(
        names(&post),
        [
            ("json".into(), "limit".into(), 1, json!(["5"])),
            ("json".into(), "q".into(), 1, json!(["bags"])),
        ]
    );
    let upload: Value = read(session_id, origin, "POST", "/upload")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(upload["rows"], 2);
    assert_eq!(
        names(&upload),
        [("multipart".into(), "file".into(), 2, json!([]))]
    );
    assert!(!upload.to_string().contains("SYNTHETIC_PRIVATE_UPLOAD"));
    let suffix: Value = read(session_id, origin, "POST", "/suffix-json")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(
        names(&suffix),
        [("json".into(), "message".into(), 1, json!(["value"]))]
    );
    let unsupported: Value = read(session_id, origin, "POST", "/unsupported")
        .await
        .json()
        .await
        .unwrap();
    assert!(names(&unsupported).is_empty());
    // Every exact method advertised in the map must remain inspectable through
    // the CLI, including punctuation and case that a normalized verb would lose.
    let map = self::read(
        &dir,
        &api,
        "target.service_map.get",
        json!({"session_id":session_id,"origin":origin}),
    )
    .await;
    for method in custom_methods {
        assert!(map["origins"][0]["endpoints"]
            .as_array()
            .unwrap()
            .iter()
            .any(|endpoint| endpoint["method"] == method && endpoint["path"] == "/custom"));
        let parameters: Value = read(session_id, origin, method, "/custom")
            .await
            .json()
            .await
            .unwrap();
        assert_eq!(parameters["method"], method);
        assert_eq!(parameters["rows"], 1);
        assert_eq!(
            names(&parameters),
            [("query".into(), "q".into(), 1, json!(["token"]))]
        );
        let called = self::read(
            &dir,
            &api,
            "target.service_map.parameters.get",
            json!({
                "session_id":session_id,"origin":origin,"method":method,"path":"/custom"
            }),
        )
        .await;
        assert_eq!(called, parameters);
    }
    let other: Value = read(Uuid::new_v4(), origin, "GET", "/search")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(other["available"], false);
    assert_eq!(other["reasons"], json!(["inactive_session"]));
    let bad = read(session_id, "https://www.example.com/", "GET", "/search").await;
    assert_eq!(bad.status(), reqwest::StatusCode::BAD_REQUEST);

    server.abort();
    drop(session);
    drop(state);
    let _ = std::fs::remove_dir_all(dir);
}

// An origin's API as OpenAPI 3.1: ID segments as path templates, query and
// body fields typed but without their values, statuses with media types and
// the credentials the rows showed. Pages, preflights and other origins are
// left out, and only the active session is read, by the API and the CLI alike.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_map_openapi_describes_an_origins_api_without_its_values() {
    let dir = std::env::temp_dir().join(format!("sniper-map-openapi-{}", Uuid::new_v4()));
    let state = Arc::new(
        AppState::new(AppConfig {
            data_dir: dir.clone(),
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 1024,
        })
        .unwrap(),
    );
    let session = state.session().await;
    let session_id = session.id();
    let row = |method: &str,
               host: &str,
               path: &str,
               request: &[(&str, &str)],
               body: &[u8],
               status: u16,
               response_type: Option<&str>| {
        let mut headers = HeaderMap::new();
        for (name, value) in request {
            headers.insert(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        let mut response = HeaderMap::new();
        if let Some(content_type) = response_type {
            response.insert("content-type", content_type.parse().unwrap());
        }
        TransactionRecord::http(
            chrono::Utc::now(),
            method.into(),
            "https".into(),
            host.into(),
            path.into(),
            Some(status),
            1,
            MessageRecord::from_headers_and_body(&headers, body, 4096),
            Some(MessageRecord::from_headers_and_body(&response, b"", 1024)),
            Vec::new(),
            None,
            None,
        )
    };
    let bearer = [("authorization", "Bearer SYNTHETIC_PRIVATE_TOKEN")];
    let mut ids = Vec::new();
    for record in [
        row(
            "GET",
            "api.example.com",
            "/v1/items/12?page=2",
            &bearer,
            b"",
            200,
            Some("application/json"),
        ),
        row(
            "GET",
            "api.example.com",
            "/v1/items/34?page=3",
            &bearer,
            b"",
            404,
            None,
        ),
        row(
            "POST",
            "api.example.com",
            "/v1/items",
            &[("content-type", "application/json")],
            br#"{"name":"SYNTHETIC_PRIVATE_NAME","count":5,"code":"42","enabled":"false","label":"[draft","object_label":"{draft","nothing":null}"#,
            201,
            Some("application/json; charset=utf-8"),
        ),
        row(
            "OPTIONS",
            "api.example.com",
            "/v1/items",
            &[],
            b"",
            204,
            None,
        ),
        row(
            "GET",
            "api.example.com",
            "/",
            &[],
            b"",
            200,
            Some("text/html"),
        ),
        row(
            "GET",
            "api.example.com",
            "/fonts/Brand.woff2",
            &[],
            b"",
            200,
            Some("application/octet-stream"),
        ),
        row(
            "GET",
            "other.example.com",
            "/v1/elsewhere",
            &[],
            b"",
            200,
            Some("application/json"),
        ),
    ] {
        ids.push(record.id);
        session.store.insert(record).await;
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = format!("http://{}", listener.local_addr().unwrap());
    let app = sniper::api::router(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let origin = "https://api.example.com";
    let get = |session: Uuid, origin: &str| {
        client
            .get(format!("{api}/api/target/service-map/openapi"))
            .query(&[
                ("session_id", session.to_string()),
                ("origin", origin.to_string()),
            ])
            .send()
    };

    let document: Value = get(session_id, origin).await.unwrap().json().await.unwrap();
    assert_eq!(document["openapi"], "3.1.0");
    assert_eq!(document["servers"], json!([{"url": origin}]));
    let paths = document["paths"].as_object().unwrap();
    assert_eq!(
        paths.keys().collect::<Vec<_>>(),
        ["/v1/items", "/v1/items/{number}"]
    );
    assert_eq!(
        paths["/v1/items"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        ["post"]
    );
    let item = &paths["/v1/items/{number}"];
    assert_eq!(item["parameters"][0]["name"], "number");
    assert_eq!(item["parameters"][0]["in"], "path");
    assert_eq!(
        item["get"]["parameters"],
        json!([{"name": "page", "in": "query", "schema": {"type": "integer"}}])
    );
    assert_eq!(
        item["get"]["responses"],
        json!({
            "200": {"description": "OK", "content": {"application/json": {}}},
            "404": {"description": "Not Found"},
        })
    );
    assert_eq!(item["get"]["security"], json!([{"bearer": []}]));
    assert_eq!(item["get"]["x-sniper-requests"], 2);
    assert_eq!(
        item["get"]["x-sniper-newest-transaction"],
        ids[1].to_string(),
        "the newest of its rows"
    );
    assert_eq!(
        paths["/v1/items"]["post"]["requestBody"],
        json!({"content": {"application/json": {"schema": {"type": "object", "properties": {
            "count": {"type": "integer"},
            "name": {"type": "string"},
            "code": {"type": "string"},
            "enabled": {"type": "string"},
            "label": {"type": "string"},
            "object_label": {"type": "string"},
            "nothing": {"type": "null"},
        }}}}})
    );
    assert_eq!(
        document["components"]["securitySchemes"],
        json!({"bearer": {"type": "http", "scheme": "bearer"}})
    );
    let notes = document["info"]["description"].as_str().unwrap();
    assert!(
        notes.contains("1 operations that only answered with pages or static files are left out")
    );
    // The font never reaches the operation cap: static files are counted apart.
    assert!(notes.contains("1 requests for static files"));
    assert!(!document.to_string().contains("SYNTHETIC_PRIVATE"));

    let via_cli = read(
        &dir,
        &api,
        "target.service_map.openapi.get",
        json!({"session_id": session_id, "origin": origin}),
    )
    .await;
    assert_eq!(via_cli, document);

    // A second ID kind must share the hierarchy without replacing either
    // operation's observations. Read the same result through the CLI too.
    for (method, status) in [("GET", 202), ("PATCH", 204)] {
        session
            .store
            .insert(row(
                method,
                "api.example.com",
                "/v1/items/550e8400-e29b-41d4-a716-446655440000?page=4",
                &bearer,
                b"",
                status,
                Some("application/json"),
            ))
            .await;
    }
    let merged: Value = get(session_id, origin).await.unwrap().json().await.unwrap();
    let paths = merged["paths"].as_object().unwrap();
    assert_eq!(
        paths.keys().collect::<Vec<_>>(),
        ["/v1/items", "/v1/items/{id}"]
    );
    let item = &paths["/v1/items/{id}"];
    assert_eq!(item["get"]["x-sniper-requests"], 3);
    assert_eq!(item["patch"]["x-sniper-requests"], 1);
    for status in ["200", "202", "404"] {
        assert!(item["get"]["responses"].get(status).is_some());
    }
    assert_eq!(
        item["parameters"][0]["schema"]["anyOf"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        read(
            &dir,
            &api,
            "target.service_map.openapi.get",
            json!({"session_id": session_id, "origin": origin}),
        )
        .await,
        merged
    );

    let inactive = get(Uuid::new_v4(), origin).await.unwrap();
    assert_eq!(inactive.status(), reqwest::StatusCode::CONFLICT);
    let bad = get(session_id, "https://api.example.com/").await.unwrap();
    assert_eq!(bad.status(), reqwest::StatusCode::BAD_REQUEST);

    server.abort();
    drop(session);
    drop(state);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_map_etag_304_carries_no_store_and_vary_catalog_headers() {
    const SELECTOR: &str = "x-sniper-technology-catalog-version";
    let dir = std::env::temp_dir().join(format!("sniper-map-etag-headers-{}", Uuid::new_v4()));
    let state = Arc::new(
        AppState::new(AppConfig {
            data_dir: dir.clone(),
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 1024,
        })
        .unwrap(),
    );
    let session = state.session().await;
    let session_id = session.id();
    session.store.insert(row("/etag-check")).await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = format!("http://{}", listener.local_addr().unwrap());
    let app = sniper::api::router(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let url = format!("{api}/api/target/service-map?session_id={session_id}&all_rows=true");

    let first = client.get(&url).header(SELECTOR, "2").send().await.unwrap();
    assert_eq!(first.status(), reqwest::StatusCode::OK);
    let etag = first
        .headers()
        .get(reqwest::header::ETAG)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(
        first
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        first
            .headers()
            .get(reqwest::header::VARY)
            .and_then(|v| v.to_str().ok()),
        Some(SELECTOR)
    );

    let second = client
        .get(&url)
        .header(SELECTOR, "2")
        .header(reqwest::header::IF_NONE_MATCH, &etag)
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), reqwest::StatusCode::NOT_MODIFIED);
    assert_eq!(
        second
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok()),
        Some(etag.as_str())
    );
    assert_eq!(
        second
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        second
            .headers()
            .get(reqwest::header::VARY)
            .and_then(|v| v.to_str().ok()),
        Some(SELECTOR)
    );

    server.abort();
    drop(session);
    drop(state);
    let _ = std::fs::remove_dir_all(dir);
}
