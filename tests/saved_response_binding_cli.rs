//! Read-only saved-data calls against synthetic loopback responses only.
use std::sync::{Arc, Mutex};

use axum::{
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use uuid::Uuid;

fn id(index: u128) -> Uuid {
    Uuid::from_u128(0xabcdef00000000000000000000000000 + index)
}

fn http_item(index: u128, sequence: u64) -> Value {
    json!({"id":id(index),"sequence":sequence,"started_at":"2026-10-10T00:00:00Z",
        "kind":"http","method":"GET","scheme":"https","host":"example.com","path":"/fixture",
        "status":200,"duration_ms":0,"request_bytes":0,"response_bytes":0,"note_count":0,
        "has_response":true,"content_type":null,"is_websocket":false,"has_match_replace":false,
        "has_user_note":false})
}

fn session_item(index: u128) -> Value {
    json!({"id":id(index),"name":"Synthetic saved session","created_at":"2026-10-10T00:00:00Z",
        "updated_at":"2026-10-10T00:00:00Z","last_opened_at":"2026-10-10T00:00:00Z",
        "request_count":0,"websocket_count":0,"event_count":0,"fuzzer_count":0,
        "rule_count":0,"storage_path":"synthetic-unused-path","active":false})
}

fn http_cursor(before: u64, limit: u64) -> Value {
    json!({"session_id":id(1),"store_generation":id(2),"before_sequence":before,"limit":limit})
}

fn http_page(items: Vec<Value>, limit: u64, more: bool) -> Value {
    let continuation = if more {
        http_cursor(items.last().unwrap()["sequence"].as_u64().unwrap(), limit)
    } else {
        Value::Null
    };
    json!({"contract_version":"saved.v1","session_id":id(1),"items":items,"limit":limit,
        "has_more":more,"continuation":continuation})
}

fn session_page(items: Vec<Value>, limit: u64, more: bool) -> Value {
    let continuation = if more {
        json!({"after_id":items.last().unwrap()["id"],"limit":limit})
    } else {
        Value::Null
    };
    json!({"contract_version":"saved.v1","items":items,"limit":limit,
        "has_more":more,"continuation":continuation})
}

fn selection(ids: Value) -> Value {
    json!({"contract_version":"saved.v1","session_id":id(1),"count":ids.as_array().unwrap().len(),
        "ids":ids,"selection_token":"a".repeat(64)})
}

async fn check(operation: &str, input: Value, data: Value, valid: bool) {
    sniper::saved_contract::validate_input(operation, &input).unwrap();
    let dir = std::env::temp_dir().join(format!("sniper-response-binding-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let settings = json!({"runtime_instance_id":id(3),"proxy_addr":"127.0.0.1:0",
        "ui_addr":address.to_string(),"data_dir":dir.to_string_lossy(),"max_entries":100,
        "features":["http_capture","session_storage","replay"]});
    let requests = Arc::new(Mutex::new(Vec::new()));
    let received = requests.clone();
    let expected = data.clone();
    let wire = json!({"ok":true,"contract_version":"saved.v1","data":data});
    let app = Router::new()
        .route("/api/settings", get(move || async move { Json(settings) }))
        .route(
            "/api/saved/v1/call",
            post(move |Json(body): Json<Value>| {
                received.lock().unwrap().push(body);
                let wire = wire.clone();
                async move { Json(wire) }
            }),
        );
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_sniper-cli"))
        .env("SNIPER_DATA_DIR", &dir)
        .args([
            "--output",
            "compact",
            "--api",
            &format!("http://{address}"),
            "call",
            operation,
            "--input",
            &input.to_string(),
        ])
        .output()
        .await
        .unwrap();
    server.abort();
    let _ = server.await;
    std::fs::remove_dir_all(dir).unwrap();
    assert_eq!(
        *requests.lock().unwrap(),
        vec![json!({"operation":operation,"input":input})],
        "the read-only request must be sent exactly once"
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
        panic!(
            "invalid CLI JSON: {} / {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    assert_eq!(
        output.status.success(),
        valid,
        "{operation}: input={input}; response={expected}; CLI={result}"
    );
    if valid {
        assert_eq!(result["data"], expected);
    } else {
        assert_eq!(result["error"]["code"], "INVALID_RESPONSE", "{result}");
        assert_eq!(
            result["error"]["details"]["outcome"], "not_applied",
            "{result}"
        );
        assert_eq!(result["error"]["retryable"], false, "{result}");
        assert!(
            result.get("data").is_none(),
            "invalid rows must not be presented as data"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_selection_matches_uuid_sets_and_rejects_substitutions() {
    let input = json!({"session_id":id(1),"ids":[id(5),id(4)]});
    for ids in [
        json!([id(4), id(6)]),
        json!([id(4)]),
        json!([id(4), id(5), id(6)]),
        json!([]),
    ] {
        check("saved.v1.http.select", input.clone(), selection(ids), false).await;
    }
    check(
        "saved.v1.http.select",
        input.clone(),
        selection(json!([id(4), id(5)])),
        true,
    )
    .await;
    let mut equivalent = input;
    equivalent["session_id"] = json!(id(1).to_string().to_uppercase());
    equivalent["ids"] = json!([
        id(5).to_string().to_uppercase(),
        id(4),
        id(4).to_string().to_uppercase()
    ]);
    check(
        "saved.v1.http.select",
        equivalent,
        selection(json!([id(4), id(5)])),
        true,
    )
    .await;
    check(
        "saved.v1.http.select",
        json!({"session_id":id(1),"host":"example.com"}),
        selection(json!([])),
        true,
    )
    .await;
    check(
        "saved.v1.http.select",
        json!({"session_id":id(1),"host":"example.com"}),
        selection(json!([id(4), id(4).to_string().to_uppercase()])),
        false,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_pages_bind_limits_boundaries_and_store_generation() {
    let input = json!({"continuation":http_cursor(10,2)});
    let good = http_page(vec![http_item(4, 9), http_item(5, 8)], 2, true);
    check("saved.v1.http.list", input.clone(), good.clone(), true).await;
    let mut wrong_generation = good.clone();
    wrong_generation["continuation"]["store_generation"] = json!(id(7));
    check("saved.v1.http.list", input.clone(), wrong_generation, false).await;
    let mut wrong_limit = good.clone();
    wrong_limit["limit"] = json!(3);
    wrong_limit["continuation"]["limit"] = json!(3);
    check("saved.v1.http.list", input.clone(), wrong_limit, false).await;
    for sequence in [10, 11] {
        check(
            "saved.v1.http.list",
            input.clone(),
            http_page(vec![http_item(4, sequence)], 2, false),
            false,
        )
        .await;
    }
    for (rows, more) in [
        (vec![http_item(4, 8), http_item(5, 9)], false),
        (vec![http_item(4, 9), http_item(5, 9)], true),
        (vec![http_item(4, 9), http_item(4, 8)], false),
    ] {
        check(
            "saved.v1.http.list",
            input.clone(),
            http_page(rows, 2, more),
            false,
        )
        .await;
    }
    let mut duplicate_case = good.clone();
    duplicate_case["items"][1]["id"] = json!(id(4).to_string().to_uppercase());
    check("saved.v1.http.list", input.clone(), duplicate_case, false).await;
    for rows in [
        vec![],
        vec![http_item(4, 9)],
        vec![http_item(4, 9), http_item(5, 8)],
    ] {
        check(
            "saved.v1.http.list",
            input.clone(),
            http_page(rows, 2, false),
            true,
        )
        .await;
    }
    let mut equivalent = input;
    equivalent["continuation"]["session_id"] = json!(id(1).to_string().to_uppercase());
    equivalent["continuation"]["store_generation"] = json!(id(2).to_string().to_uppercase());
    let mut equivalent_page = good.clone();
    equivalent_page["continuation"]["session_id"] = json!(id(1).to_string().to_uppercase());
    equivalent_page["continuation"]["store_generation"] = json!(id(2).to_string().to_uppercase());
    check("saved.v1.http.list", equivalent, good, true).await;
    check(
        "saved.v1.http.list",
        json!({"limit":2}),
        equivalent_page,
        true,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_pages_bind_limits_and_strict_uuid_boundaries() {
    let input = json!({"after_id":id(4),"limit":2});
    for rows in [
        vec![session_item(4)],
        vec![session_item(3)],
        vec![session_item(6), session_item(5)],
        vec![session_item(5), session_item(5)],
    ] {
        check(
            "saved.v1.session.list",
            input.clone(),
            session_page(rows, 2, false),
            false,
        )
        .await;
    }
    check(
        "saved.v1.session.list",
        input.clone(),
        session_page(vec![], 3, false),
        false,
    )
    .await;
    for rows in [
        vec![],
        vec![session_item(5)],
        vec![session_item(5), session_item(6)],
    ] {
        check(
            "saved.v1.session.list",
            input.clone(),
            session_page(rows, 2, false),
            true,
        )
        .await;
    }
    let good = session_page(vec![session_item(5), session_item(6)], 2, true);
    check("saved.v1.session.list", input.clone(), good.clone(), true).await;
    check(
        "saved.v1.session.list",
        good["continuation"].clone(),
        session_page(vec![session_item(7)], 2, false),
        true,
    )
    .await;
    let equivalent = json!({"after_id":id(4).to_string().to_uppercase(),"limit":2});
    let mut equivalent_page = good.clone();
    equivalent_page["items"][1]["id"] = json!(id(6).to_string().to_uppercase());
    check("saved.v1.session.list", equivalent, equivalent_page, true).await;
    let mut equivalent_cursor = good;
    equivalent_cursor["continuation"]["after_id"] = json!(id(6).to_string().to_uppercase());
    check("saved.v1.session.list", input, equivalent_cursor, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initial_and_terminal_pages_use_the_effective_requested_limit() {
    for (operation, make_page) in [
        (
            "saved.v1.http.list",
            http_page as fn(Vec<Value>, u64, bool) -> Value,
        ),
        (
            "saved.v1.session.list",
            session_page as fn(Vec<Value>, u64, bool) -> Value,
        ),
    ] {
        for (input, limit, valid) in [
            (json!({}), 50, true),
            (json!({}), 1, false),
            (json!({"limit":1}), 1, true),
            (json!({"limit":1}), 50, false),
            (json!({"limit":200}), 200, true),
        ] {
            check(operation, input, make_page(vec![], limit, false), valid).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operation_lookup_matches_receipt_uuid_identity() {
    let lower = id(4).to_string();
    let upper = lower.to_uppercase();
    let lookup = |outer: &str, inner: &str| {
        json!({"contract_version":"saved.v1","operation_id":outer,"found":true,
            "outcome":"unknown","receipt":{"contract_version":"saved.v1",
                "operation_id":inner,"session_id":id(1),"operation":"saved.v1.http.clear",
                "outcome":"unknown","code":"pending","message":"Pending.",
                "created_at":"2026-10-10T00:00:00Z"}})
    };
    for (outer, inner) in [
        (upper.as_str(), lower.as_str()),
        (lower.as_str(), upper.as_str()),
    ] {
        check(
            "saved.v1.operation.get",
            json!({"operation_id":lower}),
            lookup(outer, inner),
            true,
        )
        .await;
    }
    check(
        "saved.v1.operation.get",
        json!({"operation_id":lower}),
        lookup(&lower, &id(5).to_string()),
        false,
    )
    .await;
    let mut wrong_outcome = lookup(&lower, &upper);
    wrong_outcome["outcome"] = json!("not_applied");
    check(
        "saved.v1.operation.get",
        json!({"operation_id":lower}),
        wrong_outcome,
        false,
    )
    .await;
}
