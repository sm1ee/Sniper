//! End-to-end CLI checks use only generated records in a unique temporary data directory.
use std::{path::Path, sync::Arc};

use http::HeaderMap;
use serde_json::{json, Value};
use sniper::{
    config::AppConfig,
    model::{MessageRecord, TransactionRecord},
    state::AppState,
};
use uuid::Uuid;

async fn call(
    api: &str,
    dir: &Path,
    operation: &str,
    input: Value,
    flags: &[&str],
) -> (bool, Value) {
    let result = tokio::process::Command::new(env!("CARGO_BIN_EXE_sniper-cli"))
        .env("SNIPER_DATA_DIR", dir)
        .args([
            "--api",
            api,
            "--output",
            "compact",
            "call",
            operation,
            "--input",
            &input.to_string(),
        ])
        .args(flags)
        .output()
        .await
        .unwrap();
    let value = serde_json::from_slice(&result.stdout).unwrap_or_else(|_| {
        panic!(
            "invalid JSON: {} / {}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        )
    });
    (result.status.success(), value)
}

fn record(path: &str) -> TransactionRecord {
    TransactionRecord::http(
        chrono::Utc::now(),
        "GET".into(),
        "https".into(),
        "example.com".into(),
        path.into(),
        Some(200),
        1,
        MessageRecord::from_headers_and_body(&HeaderMap::new(), b"synthetic fixture", 1024),
        None,
        Vec::new(),
        None,
        None,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saved_data_cli_confirms_selection_and_survives_restart() {
    let dir = std::env::temp_dir().join(format!("sniper-saved-data-cli-{}", Uuid::new_v4()));
    let config = AppConfig {
        data_dir: dir.clone(),
        proxy_addr: "127.0.0.1:0".parse().unwrap(),
        ui_addr: "127.0.0.1:0".parse().unwrap(),
        max_entries: 100,
        max_transaction_entries: 100,
        body_preview_bytes: 1024,
    };
    let state = Arc::new(AppState::new(config.clone()).unwrap());
    let session = state.session().await;
    let id = session.id();
    let first = record("/one");
    let first_id = first.id;
    let second = record("/two");
    let second_id = second.id;
    session.store.insert(first).await;
    session.store.insert(second).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = format!("http://{}", listener.local_addr().unwrap());
    let app = sniper::api::router(state.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Dry-run must succeed without a reachable API and may not alter the fixture.
    for (operation, input) in [
        ("capture.http.clear", json!({"session_id":id})),
        (
            "capture.http.delete",
            json!({"session_id":id,"ids":[first_id]}),
        ),
        ("session.rename", json!({"id":id,"name":"Archive"})),
    ] {
        let (ok, output) = call(
            "http://127.0.0.1:1",
            &dir,
            operation,
            input.clone(),
            &["--dry-run"],
        )
        .await;
        assert!(ok, "{output}");
        assert_eq!(output["data"]["dry_run"], true);
        let (ok, output) = call(&api, &dir, operation, input, &[]).await;
        assert!(!ok);
        assert_eq!(output["error"]["code"], "CONFIRMATION_REQUIRED");
        assert_eq!(session.store.len().await, 2);
    }
    let (ok, output) = call(
        &api,
        &dir,
        "session.rename",
        json!({"id":id,"name":" Archive "}),
        &["--yes"],
    )
    .await;
    assert!(ok, "{output}");
    assert_eq!(output["data"]["name"], "Archive");
    let selection = json!({"session_id":id,"host":"example.com"});
    let (ok, preview) = call(&api, &dir, "capture.http.select", selection.clone(), &[]).await;
    assert!(ok, "{preview}");
    assert_eq!(preview["data"]["count"], 2);
    let token = preview["data"]["selection_token"].clone();
    let (ok, output) = call(
        &api,
        &dir,
        "capture.http.delete",
        json!({"session_id":id,"ids":[first_id,Uuid::new_v4()]}),
        &["--yes"],
    )
    .await;
    assert!(!ok, "{output}");
    assert_eq!(session.store.len().await, 2);
    let (ok, output) = call(
        &api,
        &dir,
        "capture.http.delete",
        json!({"session_id":id,"ids":[first_id]}),
        &["--yes"],
    )
    .await;
    assert!(ok, "{output}");
    assert_eq!(output["data"]["removed"], 1);
    let mut deletion = selection.clone();
    deletion["selection_token"] = token;
    let (ok, output) = call(&api, &dir, "capture.http.delete", deletion, &["--yes"]).await;
    assert!(!ok, "{output}");
    assert!(session.store.get(second_id).await.is_some());
    let (ok, preview) = call(&api, &dir, "capture.http.select", selection.clone(), &[]).await;
    assert!(ok, "{preview}");
    let mut deletion = selection;
    deletion["selection_token"] = preview["data"]["selection_token"].clone();
    let (ok, output) = call(&api, &dir, "capture.http.delete", deletion, &["--yes"]).await;
    assert!(ok, "{output}");
    assert_eq!(output["data"]["removed"], 1);
    session.store.insert(record("/clear")).await;
    let (ok, output) = call(
        &api,
        &dir,
        "capture.http.clear",
        json!({"session_id":id}),
        &["--yes"],
    )
    .await;
    assert!(ok, "{output}");
    assert_eq!(output["data"]["removed"], 1);
    let (ok, output) = call(&api, &dir, "session.delete", json!({"id":id}), &["--yes"]).await;
    assert!(!ok, "active session deletion should fail: {output}");
    let (ok, created) = call(
        &api,
        &dir,
        "session.create",
        json!({"name":"Other"}),
        &["--yes"],
    )
    .await;
    assert!(ok, "{created}");
    let other = created["data"]["id"].clone();
    let (ok, output) = call(&api, &dir, "session.switch", json!({"id":id}), &["--yes"]).await;
    assert!(ok, "{output}");
    let (ok, output) = call(
        &api,
        &dir,
        "session.delete",
        json!({"id":other}),
        &["--yes"],
    )
    .await;
    assert!(ok, "{output}");
    server.abort();
    let _ = server.await;
    drop(session);
    drop(state);
    let reopened = AppState::new(config).unwrap();
    assert_eq!(reopened.session().await.id(), id);
    assert_eq!(reopened.session().await.store.len().await, 0);
    assert_eq!(reopened.list_sessions().await[0].name, "Archive");
    drop(reopened);
    std::fs::remove_dir_all(dir).unwrap();
}
