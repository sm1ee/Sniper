//! Saved-data CLI contracts are exercised only with generated local fixtures.
use std::{path::Path, sync::Arc};

use http::HeaderMap;
use serde_json::{json, Value};
use sniper::{
    config::AppConfig,
    model::{MessageRecord, TransactionRecord},
    state::AppState,
};
use uuid::Uuid;

async fn command(dir: &Path, args: &[&str]) -> (bool, Value) {
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_sniper-cli"))
        .env("SNIPER_DATA_DIR", dir)
        .args(["--output", "compact"])
        .args(args)
        .output()
        .await
        .unwrap();
    let value = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
        panic!(
            "invalid CLI JSON: {} / {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output.status.success(), value)
}

async fn call(
    dir: &Path,
    api: &str,
    operation: &str,
    input: Value,
    flag: Option<&str>,
) -> (bool, Value) {
    let text = input.to_string();
    let mut args = vec!["--api", api, "call", operation, "--input", &text];
    if let Some(flag) = flag {
        args.push(flag);
    }
    let (ok, value) = command(dir, &args).await;
    if ok && operation.starts_with("saved.v1.") && value["data"]["dry_run"] != json!(true) {
        if let Some(directory) = std::env::var_os("SNIPER_SCHEMA_CASES_DIR") {
            let directory = std::path::PathBuf::from(directory);
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(
                directory.join(format!("{}.json", Uuid::new_v4())),
                serde_json::to_vec(
                    &json!({"operation":operation,"input":input,"data":value["data"]}),
                )
                .unwrap(),
            )
            .unwrap();
        }
    }
    (ok, value)
}

fn fixture() -> TransactionRecord {
    TransactionRecord::http(
        chrono::Utc::now(),
        "GET".into(),
        "https".into(),
        "example.com".into(),
        "/saved".into(),
        Some(200),
        1,
        MessageRecord::from_headers_and_body(&HeaderMap::new(), b"fixture", 1024),
        None,
        Vec::new(),
        None,
        None,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saved_v1_cli_preserves_legacy_and_records_confirmed_writes() {
    let dir = std::env::temp_dir().join(format!("sniper-v1-cli-{}", Uuid::new_v4()));
    let config = AppConfig {
        data_dir: dir.clone(),
        proxy_addr: "127.0.0.1:0".parse().unwrap(),
        ui_addr: "127.0.0.1:0".parse().unwrap(),
        max_entries: 100,
        max_transaction_entries: 100,
        body_preview_bytes: 1024,
    };
    let state = Arc::new(AppState::new(config).unwrap());
    let session = state.session().await;
    let session_id = session.id();
    session.store.insert(fixture()).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = format!("http://{}", listener.local_addr().unwrap());
    let app = sniper::api::router(state.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let operation_id = Uuid::new_v4();
    let input = json!({"operation_id":operation_id,"session_id":session_id});

    let (ok, dry) = call(
        &dir,
        "http://127.0.0.1:1",
        "saved.v1.http.clear",
        input.clone(),
        Some("--dry-run"),
    )
    .await;
    assert!(ok, "{dry}");
    assert_eq!(dry["schema_version"], "saved.v1");
    assert_eq!(dry["data"]["outcome"], "not_applied");
    assert!(!dir.join("saved-operations-v1").exists());
    let (ok, blocked) = call(&dir, &api, "saved.v1.http.clear", input.clone(), None).await;
    assert!(!ok);
    assert_eq!(blocked["error"]["code"], "CONFIRMATION_REQUIRED");
    assert_eq!(blocked["error"]["details"]["outcome"], "not_applied");
    assert_eq!(session.store.len().await, 1);

    let (ok, legacy) = call(&dir, &api, "capture.http.list", json!({}), None).await;
    assert!(ok, "{legacy}");
    assert!(legacy["data"].is_array());
    assert_eq!(legacy["schema_version"], "2026-06-22");
    let (ok, bare_legacy) = command(&dir, &["--api", &api, "capture", "http", "list"]).await;
    assert!(ok);
    assert!(bare_legacy.is_array());
    let (ok, page) = call(&dir, &api, "saved.v1.http.list", json!({}), None).await;
    assert!(ok, "{page}");
    assert_eq!(page["data"]["session_id"], session_id.to_string());
    assert_eq!(page["data"]["limit"], 50);
    assert_eq!(page["data"]["has_more"], false);
    assert!(page["data"]["continuation"].is_null());

    for invalid in [
        json!({"limit":0}),
        json!({"limit":201}),
        json!({"limit":null}),
        json!({"unknown":true}),
        json!({"session_id":"not-a-uuid"}),
    ] {
        let (ok, value) = call(&dir, &api, "saved.v1.http.list", invalid, None).await;
        assert!(!ok, "{value}");
        assert_eq!(value["error"]["code"], "INVALID_INPUT");
        assert_eq!(value["error"]["retryable"], false);
    }
    let (ok, applied) = call(
        &dir,
        &api,
        "saved.v1.http.clear",
        input.clone(),
        Some("--yes"),
    )
    .await;
    assert!(ok, "{applied}");
    assert_eq!(applied["data"]["receipt"]["outcome"], "applied");
    assert_eq!(applied["data"]["receipt"]["result"]["deleted_count"], 1);
    session.store.insert(fixture()).await;
    let (ok, replayed) = call(
        &dir,
        &api,
        "saved.v1.http.clear",
        input.clone(),
        Some("--yes"),
    )
    .await;
    assert!(ok, "{replayed}");
    assert_eq!(replayed["data"]["replayed"], true);
    assert_eq!(
        session.store.len().await,
        1,
        "replayed clear must retain newer rows"
    );
    let (ok, conflict) = call(
        &dir,
        &api,
        "saved.v1.session.rename",
        json!({"operation_id":operation_id,"session_id":session_id,"name":"Archive"}),
        Some("--yes"),
    )
    .await;
    assert!(!ok, "{conflict}");
    assert_eq!(conflict["error"]["code"], "OPERATION_CONFLICT");
    assert_eq!(conflict["error"]["details"]["outcome"], "not_applied");
    let (ok, renamed) = call(
        &dir,
        &api,
        "saved.v1.session.rename",
        json!({"operation_id":Uuid::new_v4(),"session_id":session_id,"name":"Archive"}),
        Some("--yes"),
    )
    .await;
    assert!(ok, "{renamed}");
    assert_eq!(renamed["data"]["receipt"]["outcome"], "applied");
    assert_eq!(
        renamed["data"]["receipt"]["result"]["session"]["name"],
        "Archive"
    );
    let (ok, receipt) = call(
        &dir,
        &api,
        "saved.v1.operation.get",
        json!({"operation_id":operation_id}),
        None,
    )
    .await;
    assert!(ok, "{receipt}");
    assert_eq!(receipt["data"]["outcome"], "applied");
    assert_eq!(receipt["data"]["receipt"], applied["data"]["receipt"]);
    let (ok, missing) = call(
        &dir,
        &api,
        "saved.v1.operation.get",
        json!({"operation_id":Uuid::new_v4()}),
        None,
    )
    .await;
    assert!(ok, "{missing}");
    assert_eq!(missing["data"]["found"], false);
    assert_eq!(missing["data"]["outcome"], "unknown");

    let (ok, manifest) = command(&dir, &["manifest"]).await;
    assert!(ok);
    for name in sniper::saved_contract::OPERATIONS {
        let operation = manifest["operations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["operation"] == *name)
            .unwrap();
        assert_eq!(operation["input_schema"]["type"], "object");
        assert!(operation["output_schema"]["properties"].is_object());
    }
    server.abort();
    let _ = server.await;
    drop(session);
    drop(state);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saved_v1_cli_rejects_misattributed_and_malformed_responses() {
    use axum::{
        routing::{get, post},
        Json, Router,
    };
    let dir = std::env::temp_dir().join(format!("sniper-v1-cli-wire-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let session_id = Uuid::new_v4();
    let operation_id = Uuid::new_v4();
    let now = chrono::Utc::now().to_rfc3339();
    let input = json!({"operation_id":operation_id,"session_id":session_id});
    let valid_data = json!({"contract_version":"saved.v1","replayed":false,"receipt":{
        "contract_version":"saved.v1","operation_id":Uuid::new_v4(),"session_id":session_id,
        "operation":"saved.v1.http.clear","outcome":"applied","code":"applied","message":"Applied",
        "result":{"kind":"http_cleared","deleted_count":1},"created_at":now,"completed_at":now}});
    let mut wrong_error = json!({"ok":false,"contract_version":"saved.v1","error":{
        "code":"SESSION_NOT_FOUND","message":"Saved session not found","outcome":"not_applied",
        "operation_id":Uuid::new_v4(),"session_id":session_id,"retryable":false}});
    let mut retryable_error = wrong_error.clone();
    retryable_error["error"]["operation_id"] = json!(operation_id);
    retryable_error["error"]["retryable"] = json!(true);
    let cases = vec![
        json!({"ok":true,"contract_version":"legacy","data":valid_data}),
        json!({"ok":true,"contract_version":"saved.v1","data":{}}),
        json!({"ok":true,"contract_version":"saved.v1","data":valid_data}),
        wrong_error.clone(),
        retryable_error,
    ];
    wrong_error["error"]["operation_id"] = json!(operation_id);
    for (wire, expected, outcome) in cases
        .into_iter()
        .map(|wire| (wire, "INVALID_RESPONSE", "unknown"))
        .chain(std::iter::once((
            wrong_error,
            "SESSION_NOT_FOUND",
            "not_applied",
        )))
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = format!("http://{}", listener.local_addr().unwrap());
        let settings = json!({"runtime_instance_id":Uuid::new_v4(),"proxy_addr":"127.0.0.1:0",
            "ui_addr":listener.local_addr().unwrap().to_string(),"data_dir":dir.to_string_lossy(),
            "max_entries":100,"features":["http_capture","session_storage","replay"]});
        let app = Router::new()
            .route("/api/settings", get(move || async move { Json(settings) }))
            .route(
                "/api/saved/v1/call",
                post(move || async move { Json(wire) }),
            );
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let (ok, result) = call(
            &dir,
            &api,
            "saved.v1.http.clear",
            input.clone(),
            Some("--yes"),
        )
        .await;
        assert!(!ok, "{result}");
        assert_eq!(result["error"]["code"], expected, "{result}");
        assert_eq!(result["error"]["details"]["outcome"], outcome, "{result}");
        assert_eq!(
            result["error"]["details"]["operation_id"],
            operation_id.to_string()
        );
        assert_eq!(result["error"]["retryable"], false);
        server.abort();
        let _ = server.await;
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saved_v1_cli_transport_loss_reports_unknown_without_retry() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let dir = std::env::temp_dir().join(format!("sniper-v1-cli-loss-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = format!("http://{}", listener.local_addr().unwrap());
    let settings = json!({"runtime_instance_id":Uuid::new_v4(),"proxy_addr":"127.0.0.1:0",
        "ui_addr":listener.local_addr().unwrap().to_string(),"data_dir":dir.to_string_lossy(),
        "max_entries":100,"features":["http_capture","session_storage","replay"]})
    .to_string();
    let server = tokio::spawn(async move {
        let (mut discovery, _) = listener.accept().await.unwrap();
        let mut buffer = [0u8; 8192];
        let n = discovery.read(&mut buffer).await.unwrap();
        assert!(String::from_utf8_lossy(&buffer[..n]).starts_with("GET /api/settings "));
        discovery.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", settings.len(), settings).as_bytes()).await.unwrap();
        drop(discovery);
        let (mut mutation, _) = listener.accept().await.unwrap();
        let n = mutation.read(&mut buffer).await.unwrap();
        assert!(String::from_utf8_lossy(&buffer[..n]).starts_with("POST /api/saved/v1/call "));
        drop(mutation);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(300), listener.accept())
                .await
                .is_err(),
            "mutation was automatically retried"
        );
    });
    let operation_id = Uuid::new_v4();
    let (ok, result) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        call(
            &dir,
            &api,
            "saved.v1.http.clear",
            json!({"session_id":Uuid::new_v4(),"operation_id":operation_id}),
            Some("--yes"),
        ),
    )
    .await
    .unwrap();
    assert!(!ok);
    assert_eq!(result["error"]["code"], "TRANSPORT_ERROR", "{result}");
    assert_eq!(result["error"]["details"]["outcome"], "unknown");
    assert_eq!(
        result["error"]["details"]["operation_id"],
        operation_id.to_string()
    );
    assert_eq!(result["error"]["retryable"], false);
    server.await.unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saved_v1_cli_never_follows_mutation_redirects() {
    use axum::{
        http::{header, StatusCode},
        routing::{get, post},
        Json, Router,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    let dir = std::env::temp_dir().join(format!("sniper-v1-cli-redirect-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    for status in [
        StatusCode::TEMPORARY_REDIRECT,
        StatusCode::PERMANENT_REDIRECT,
        StatusCode::SEE_OTHER,
    ] {
        let destination_calls = Arc::new(AtomicUsize::new(0));
        let calls = destination_calls.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = format!("http://{}", listener.local_addr().unwrap());
        let settings = json!({"runtime_instance_id":Uuid::new_v4(),"proxy_addr":"127.0.0.1:0",
            "ui_addr":listener.local_addr().unwrap().to_string(),"data_dir":dir.to_string_lossy(),
            "max_entries":100,"features":["http_capture","session_storage","replay"]});
        let app = Router::new()
            .route("/api/settings", get(move || async move { Json(settings) }))
            .route(
                "/api/saved/v1/call",
                post(move || async move { (status, [(header::LOCATION, "/unexpected")]) }),
            )
            .route(
                "/unexpected",
                axum::routing::any(move || async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Json(json!({}))
                }),
            );
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let operation_id = Uuid::new_v4();
        let (ok, output) = call(
            &dir,
            &api,
            "saved.v1.http.clear",
            json!({"session_id":Uuid::new_v4(),"operation_id":operation_id}),
            Some("--yes"),
        )
        .await;
        assert!(!ok, "{output}");
        assert_eq!(output["error"]["code"], "REDIRECT_REFUSED");
        assert_eq!(output["error"]["details"]["outcome"], "unknown");
        assert_eq!(
            output["error"]["details"]["operation_id"],
            operation_id.to_string()
        );
        assert_eq!(destination_calls.load(Ordering::SeqCst), 0);
        server.abort();
        let _ = server.await;
    }
    std::fs::remove_dir_all(dir).unwrap();
}
