//! Contract boundary checks use generated records and loopback-only API servers.
use std::sync::Arc;

use http::HeaderMap;
use serde_json::{json, Value};
use sniper::{
    config::AppConfig,
    model::{MessageRecord, TransactionRecord},
    state::AppState,
};
use uuid::Uuid;

struct Fixture {
    state: Arc<AppState>,
    config: AppConfig,
    api: String,
    client: reqwest::Client,
    server: tokio::task::JoinHandle<()>,
}

impl Fixture {
    async fn new() -> Self {
        Self::open(AppConfig {
            data_dir: std::env::temp_dir()
                .join(format!("sniper-saved-v1-review-{}", Uuid::new_v4())),
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 1000,
            body_preview_bytes: 1024,
        })
        .await
    }

    async fn open(config: AppConfig) -> Self {
        let state = Arc::new(AppState::new(config.clone()).unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = format!("http://{}", listener.local_addr().unwrap());
        let router = sniper::api::router(state.clone());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self {
            state,
            config,
            api,
            client: reqwest::Client::builder().no_proxy().build().unwrap(),
            server,
        }
    }

    async fn call(&self, operation: &str, input: Value) -> (reqwest::StatusCode, Value) {
        let response = self
            .client
            .post(format!("{}/api/saved/v1/call", self.api))
            .json(&json!({"operation":operation,"input":input}))
            .send()
            .await
            .unwrap();
        let status = response.status();
        let body = response.json().await.unwrap();
        (status, body)
    }

    async fn ok(&self, operation: &str, input: Value) -> Value {
        let (status, body) = self.call(operation, input.clone()).await;
        assert!(status.is_success(), "{status}: {body}");
        assert_eq!(body["ok"], true, "{body}");
        sniper::saved_contract::validate_output(operation, &body["data"])
            .unwrap_or_else(|error| panic!("{operation}: {error}: {body}"));
        // Optional synthetic fixtures let an independent JSON Schema engine
        // verify actual wire data instead of only validating constructed values.
        if let Some(directory) = std::env::var_os("SNIPER_SCHEMA_CASES_DIR") {
            let directory = std::path::PathBuf::from(directory);
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(
                directory.join(format!("{}.json", Uuid::new_v4())),
                serde_json::to_vec(&json!({
                    "operation":operation,"input":input,"data":body["data"]
                }))
                .unwrap(),
            )
            .unwrap();
        }
        body["data"].clone()
    }

    async fn close(self) -> AppConfig {
        self.server.abort();
        let _ = self.server.await;
        drop(self.state);
        self.config
    }

    async fn remove(self) {
        let config = self.close().await;
        std::fs::remove_dir_all(config.data_dir).unwrap();
    }
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
        MessageRecord::from_headers_and_body(&HeaderMap::new(), b"generated fixture", 1024),
        None,
        Vec::new(),
        None,
        None,
    )
}

fn ids(page: &Value) -> Vec<String> {
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_cursor_stays_pinned_after_new_rows_and_active_session_switch() {
    let fixture = Fixture::new().await;
    let original = fixture.state.session().await;
    let mut expected = Vec::new();
    for index in 0..4 {
        let row = record(&format!("/fixture/{index}"));
        expected.push(row.id.to_string());
        original.store.insert(row).await;
    }
    expected.reverse();
    let first = fixture.ok("saved.v1.http.list", json!({"limit":2})).await;
    assert_eq!(ids(&first), expected[..2]);
    assert_eq!(first["session_id"], original.id().to_string());
    assert_eq!(first["has_more"], true);
    let continuation = first["continuation"].clone();
    original.store.insert(record("/newer-than-page-one")).await;
    let other = fixture
        .state
        .create_session(Some("Other generated session".into()))
        .await
        .unwrap();
    assert_ne!(other.id, original.id());
    fixture
        .state
        .session()
        .await
        .store
        .insert(record("/other-session"))
        .await;

    let second = fixture
        .ok("saved.v1.http.list", json!({"continuation":continuation}))
        .await;
    assert_eq!(second["session_id"], original.id().to_string());
    assert_eq!(ids(&second), expected[2..]);
    assert_eq!(second["has_more"], false);
    assert!(second["continuation"].is_null());

    for extra in [json!({"session_id":other.id}), json!({"limit":1})] {
        let mut input = extra;
        input["continuation"] = first["continuation"].clone();
        let (status, output) = fixture.call("saved.v1.http.list", input).await;
        assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "{output}");
        assert_eq!(output["error"]["code"], "INVALID_INPUT");
    }
    drop(original);
    fixture.remove().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_pages_reject_unbounded_limits_and_terminate_on_empty_or_exact_limit() {
    let fixture = Fixture::new().await;
    let empty = fixture.ok("saved.v1.http.list", json!({})).await;
    assert_eq!(empty["limit"], 50);
    assert!(ids(&empty).is_empty());
    assert_eq!(empty["has_more"], false);
    assert!(empty["continuation"].is_null());
    for limit in [json!(0), json!(201), json!(-1), json!(1.5), json!(null)] {
        let (status, output) = fixture
            .call("saved.v1.http.list", json!({"limit":limit}))
            .await;
        assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "{output}");
        assert_eq!(output["error"]["code"], "INVALID_INPUT");
    }
    let session = fixture.state.session().await;
    session.store.insert(record("/exact/one")).await;
    session.store.insert(record("/exact/two")).await;
    let exact = fixture.ok("saved.v1.http.list", json!({"limit":2})).await;
    assert_eq!(ids(&exact).len(), 2);
    assert_eq!(exact["has_more"], false);
    assert!(exact["continuation"].is_null());
    drop(session);
    fixture.remove().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receipts_prevent_reexecution_and_bind_kind_session_and_input_across_restart() {
    let fixture = Fixture::new().await;
    let session = fixture.state.session().await;
    let session_id = session.id();
    session.store.insert(record("/original")).await;
    let operation_id = Uuid::new_v4();
    let input = json!({"operation_id":operation_id,"session_id":session_id});
    let first = fixture.ok("saved.v1.http.clear", input.clone()).await;
    assert_eq!(first["replayed"], false);
    assert_eq!(first["receipt"]["outcome"], "applied");
    assert_eq!(session.store.len().await, 0);
    let remaining = record("/must-survive-repeated-clear");
    let remaining_id = remaining.id;
    session.store.insert(remaining).await;
    let replay = fixture.ok("saved.v1.http.clear", input.clone()).await;
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["receipt"], first["receipt"]);
    assert!(session.store.get(remaining_id).await.is_some());

    for (operation, conflicting) in [
        (
            "saved.v1.http.clear",
            json!({"operation_id":operation_id,"session_id":Uuid::new_v4()}),
        ),
        (
            "saved.v1.session.rename",
            json!({"operation_id":operation_id,"session_id":session_id,"name":"Unapplied"}),
        ),
    ] {
        let (status, output) = fixture.call(operation, conflicting).await;
        assert_eq!(status, reqwest::StatusCode::CONFLICT, "{output}");
        assert_eq!(output["error"]["code"], "OPERATION_CONFLICT");
    }
    drop(session);
    let config = fixture.close().await;
    let reopened = Fixture::open(config).await;
    let lookup = reopened
        .ok(
            "saved.v1.operation.get",
            json!({"operation_id":operation_id}),
        )
        .await;
    assert_eq!(lookup["found"], true);
    assert_eq!(lookup["receipt"], first["receipt"]);
    let replay = reopened.ok("saved.v1.http.clear", input).await;
    assert_eq!(replay["receipt"], first["receipt"]);
    assert_eq!(replay["replayed"], true);
    assert!(reopened
        .state
        .session()
        .await
        .store
        .get(remaining_id)
        .await
        .is_some());
    let unknown = reopened
        .ok(
            "saved.v1.operation.get",
            json!({"operation_id":Uuid::new_v4()}),
        )
        .await;
    assert_eq!(unknown["found"], false);
    assert_eq!(unknown["outcome"], "unknown");
    assert!(unknown["receipt"].is_null());
    reopened.remove().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_mutations_and_cross_origin_calls_do_not_change_saved_data() {
    let fixture = Fixture::new().await;
    let session = fixture.state.session().await;
    let session_id = session.id();
    session.store.insert(record("/unchanged")).await;
    for input in [
        json!({"operation_id":Uuid::new_v4()}),
        json!({"session_id":session_id}),
        json!({"operation_id":Uuid::new_v4(),"session_id":session_id,"unexpected":true}),
        json!({"operation_id":"not-an-id","session_id":session_id}),
    ] {
        let (status, output) = fixture.call("saved.v1.http.clear", input).await;
        assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "{output}");
        assert_eq!(output["error"]["code"], "INVALID_INPUT");
        assert_eq!(output["error"]["outcome"], "not_applied");
    }
    let response = fixture
        .client
        .post(format!("{}/api/saved/v1/call", fixture.api))
        .header("Origin", "https://example.com")
        .json(&json!({"operation":"saved.v1.http.clear","input":{
            "operation_id":Uuid::new_v4(),"session_id":session_id
        }}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    assert_eq!(session.store.len().await, 1);
    drop(session);
    fixture.remove().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_pages_keep_uuid_order_when_names_change() {
    let fixture = Fixture::new().await;
    for name in ["Third", "First", "Second"] {
        fixture
            .state
            .create_session(Some(name.into()))
            .await
            .unwrap();
    }
    let mut expected: Vec<_> = fixture
        .state
        .list_sessions()
        .await
        .into_iter()
        .map(|item| item.id)
        .collect();
    expected.sort_unstable();
    let first = fixture
        .ok("saved.v1.session.list", json!({"limit":2}))
        .await;
    assert_eq!(
        ids(&first),
        expected[..2]
            .iter()
            .map(Uuid::to_string)
            .collect::<Vec<_>>()
    );
    assert_eq!(first["has_more"], true);
    fixture
        .state
        .rename_session(expected[0], "ZZZ renamed".into())
        .await
        .unwrap();
    let second = fixture
        .ok("saved.v1.session.list", first["continuation"].clone())
        .await;
    assert_eq!(
        ids(&second),
        expected[2..]
            .iter()
            .map(Uuid::to_string)
            .collect::<Vec<_>>()
    );
    assert_eq!(second["has_more"], false);
    assert!(second["continuation"].is_null());
    let empty = fixture
        .ok(
            "saved.v1.session.list",
            json!({"after_id":expected[3],"limit":2}),
        )
        .await;
    assert!(ids(&empty).is_empty());
    assert_eq!(empty["has_more"], false);
    assert!(empty["continuation"].is_null());
    fixture.remove().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_selection_gets_definitive_receipt_and_changed_input_cannot_reuse_its_id() {
    let fixture = Fixture::new().await;
    let session = fixture.state.session().await;
    let session_id = session.id();
    session.store.insert(record("/reviewed")).await;
    let selected = fixture
        .ok(
            "saved.v1.http.select",
            json!({"session_id":session_id,"host":"example.com"}),
        )
        .await;
    assert_eq!(selected["count"], 1);
    session.store.insert(record("/arrived-after-review")).await;
    let input = json!({"session_id":session_id,"operation_id":Uuid::new_v4(),"host":"example.com", "selection_token":selected["selection_token"]});
    let rejected = fixture.ok("saved.v1.http.delete", input.clone()).await;
    assert_eq!(rejected["receipt"]["outcome"], "not_applied");
    assert_eq!(rejected["receipt"]["code"], "selection_mismatch");
    assert_eq!(session.store.len().await, 2);
    let repeated = fixture.ok("saved.v1.http.delete", input.clone()).await;
    assert_eq!(repeated["receipt"], rejected["receipt"]);
    assert_eq!(repeated["replayed"], true);
    let fresh = fixture
        .ok(
            "saved.v1.http.select",
            json!({"session_id":session_id,"host":"example.com"}),
        )
        .await;
    let mut changed = input;
    changed["selection_token"] = fresh["selection_token"].clone();
    let (status, output) = fixture.call("saved.v1.http.delete", changed.clone()).await;
    assert_eq!(status, reqwest::StatusCode::CONFLICT, "{output}");
    assert_eq!(output["error"]["code"], "OPERATION_CONFLICT");
    assert_eq!(session.store.len().await, 2);
    changed["operation_id"] = json!(Uuid::new_v4());
    let applied = fixture.ok("saved.v1.http.delete", changed).await;
    assert_eq!(applied["receipt"]["outcome"], "applied");
    assert_eq!(applied["receipt"]["result"]["deleted_count"], 2);
    assert_eq!(session.store.len().await, 0);
    drop(session);
    fixture.remove().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_continuation_expires_after_restart_instead_of_admitting_reused_sequences() {
    let fixture = Fixture::new().await;
    let session = fixture.state.session().await;
    let session_id = session.id();
    for index in 0..4 {
        session
            .store
            .insert(record(&format!("/original/{index}")))
            .await;
    }
    let first = fixture.ok("saved.v1.http.list", json!({"limit":2})).await;
    assert_eq!(first["has_more"], true);
    fixture
        .ok(
            "saved.v1.http.clear",
            json!({"session_id":session_id,"operation_id":Uuid::new_v4()}),
        )
        .await;
    drop(session);
    let config = fixture.close().await;
    let reopened = Fixture::open(config).await;
    reopened
        .state
        .session()
        .await
        .store
        .insert(record("/new-after-restart"))
        .await;
    let (status, output) = reopened
        .call(
            "saved.v1.http.list",
            json!({"continuation":first["continuation"]}),
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::CONFLICT, "{output}");
    assert_eq!(output["error"]["code"], "STALE_CONTINUATION");
    assert_eq!(output["error"]["outcome"], "not_applied");
    let fresh = reopened
        .ok("saved.v1.http.list", json!({"session_id":session_id}))
        .await;
    assert_eq!(ids(&fresh).len(), 1);
    reopened.remove().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_http_response_still_finishes_receipt_and_cannot_reapply_clear() {
    use tokio::io::AsyncWriteExt;

    let fixture = Fixture::new().await;
    let session = fixture.state.session().await;
    let session_id = session.id();
    session.store.insert(record("/before-response-loss")).await;
    let operation_id = Uuid::new_v4();
    let input = json!({"session_id":session_id,"operation_id":operation_id});
    let mutation_guard = session.mutation_guard().await;
    let address = fixture.api.strip_prefix("http://").unwrap();
    let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
    let body = json!({"operation":"saved.v1.http.clear","input":input}).to_string();
    let request = format!(
        "POST /api/saved/v1/call HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    socket.write_all(request.as_bytes()).await.unwrap();

    let pending = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let lookup = fixture
                .ok(
                    "saved.v1.operation.get",
                    json!({"operation_id":operation_id}),
                )
                .await;
            if lookup["found"] == true {
                break lookup;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("durable intent should appear before the blocked mutation runs");
    assert_eq!(pending["outcome"], "unknown");
    assert_eq!(pending["receipt"]["code"], "pending");
    assert_eq!(session.store.len().await, 1);

    // The server has the full request and a durable intent. Drop the transport
    // before the mutation can finish or a response can be delivered.
    drop(socket);
    drop(mutation_guard);
    let applied = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let lookup = fixture
                .ok(
                    "saved.v1.operation.get",
                    json!({"operation_id":operation_id}),
                )
                .await;
            assert_ne!(lookup["outcome"], "not_applied", "{lookup}");
            if lookup["outcome"] == "applied" {
                break lookup;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("a lost HTTP response must not cancel the mutation or terminal receipt");
    assert_eq!(applied["receipt"]["result"]["deleted_count"], 1);
    assert_eq!(session.store.len().await, 0);

    let later = record("/must-survive-after-response-loss");
    let later_id = later.id;
    session.store.insert(later).await;
    let replay = fixture.ok("saved.v1.http.clear", input).await;
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["receipt"], applied["receipt"]);
    assert!(session.store.get(later_id).await.is_some());
    drop(session);
    fixture.remove().await;
}
