//! Saved tab housekeeping only: generated loopback fixtures cannot replay HTTP,
//! connect a WebSocket, hydrate traffic, or replace a whole workspace.
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{header, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
    Json, Router,
};
use serde_json::{json, Value};
use uuid::Uuid;

const TARGET: &str = " exact saved tab ";
const CONTENT: &str = "synthetic-request-response-history-content-must-not-be-printed";
const OPERATIONS: [&str; 2] = ["replay.close", "replay.duplicate"];

#[derive(Clone, Debug)]
struct RecordedRequest {
    method: String,
    path: String,
    query: BTreeMap<String, String>,
    body: Option<Value>,
}

#[derive(Default)]
struct Faults {
    get_body: Option<String>,
    sessions: Option<Value>,
    post: Option<(StatusCode, String)>,
    switch_after_get: bool,
    stale_revision: bool,
}

struct MockState {
    settings: Value,
    ids: [Uuid; 2],
    active: Mutex<Uuid>,
    workspace: Mutex<Value>,
    requests: Mutex<Vec<RecordedRequest>>,
    faults: Mutex<Faults>,
}

struct MockApi {
    api: String,
    dir: PathBuf,
    state: Arc<MockState>,
    server: tokio::task::JoinHandle<()>,
}

fn fixture(session_id: Uuid) -> Value {
    json!({
        "session_id":session_id, "revision":17, "client_id":"synthetic-desktop", "client_version":9,
        "replay":{
            "active_tab_id":TARGET, "tab_sequence":80,
            "tabs":[
                {"id":"left","type":"http","pinned":false,"sequence":1},
                {"id":"pinned","type":"http","pinned":true,"sequence":70},
                {"id":TARGET,"type":"http","pinned":false,"sequence":80,
                    "request_text":CONTENT,"response_record":{"synthetic":CONTENT},
                    "history_entries":[{"request_text":CONTENT,"response_record":{"synthetic":CONTENT}}],
                    "history_index":0,"target_host":"example.com","custom_label":"fixture label"},
                {"id":"last","type":"http","pinned":false,"sequence":10},
                {"id":"socket","type":"websocket","pinned":true,"sequence":99,"ws_frames":[CONTENT]}
            ]
        },
        "fuzzer":{"synthetic":CONTENT}, "future_workspace_field":{"synthetic":CONTENT}
    })
}

fn session_summary(id: Uuid, active: bool) -> Value {
    json!({"id":id,"name":"Synthetic saved session","created_at":"2026-10-09T00:00:00Z",
        "updated_at":"2026-10-09T00:00:00Z","last_opened_at":"2026-10-09T00:00:00Z",
        "request_count":0,"websocket_count":0,"event_count":0,"fuzzer_count":0,
        "rule_count":0,"storage_path":"synthetic-unused-path","active":active})
}

fn acknowledgement(workspace: &Value, operation: &str) -> Value {
    let duplicate = operation == "replay.duplicate";
    let mut active = workspace["replay"]["active_tab_id"].clone();
    if !duplicate && workspace["replay"]["tabs"].as_array().unwrap().len() == 1 {
        active = Value::Null;
    } else if !duplicate && active == TARGET {
        let mut visual: Vec<_> = workspace["replay"]["tabs"]
            .as_array()
            .unwrap()
            .iter()
            .collect();
        visual.sort_by_key(|tab| tab["pinned"] != true);
        let index = visual.iter().position(|tab| tab["id"] == TARGET).unwrap();
        active = index
            .checked_sub(1)
            .and_then(|previous| visual.get(previous))
            .or_else(|| visual.get(index + 1))
            .map(|tab| tab["id"].clone())
            .unwrap_or(Value::Null);
    }
    let mut ack = json!({"session_id":workspace["session_id"],"revision":workspace["revision"].as_u64().unwrap()+1,"active_tab_id":active});
    if duplicate {
        ack["source_tab_id"] = json!(TARGET);
        ack["new_tab_id"] = json!(Uuid::new_v4());
    } else {
        ack["closed_tab_id"] = json!(TARGET);
    }
    ack
}

impl MockApi {
    async fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("sniper-saved-tab-cli-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ids = [Uuid::new_v4(), Uuid::new_v4()];
        let state = Arc::new(MockState {
            settings: json!({"runtime_instance_id":Uuid::new_v4(),"proxy_addr":"127.0.0.1:0",
                "ui_addr":addr.to_string(),"data_dir":dir.to_string_lossy(),"max_entries":100,
                "features":["http_capture","session_storage","replay"]}),
            ids,
            active: Mutex::new(ids[0]),
            workspace: Mutex::new(fixture(ids[0])),
            requests: Mutex::new(Vec::new()),
            faults: Mutex::new(Faults::default()),
        });
        let app = Router::new()
            .fallback(any(mock_request))
            .with_state(state.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            api: format!("http://{addr}"),
            dir,
            state,
            server,
        }
    }

    async fn command(&self, args: &[&str]) -> (i32, Value) {
        let output = tokio::time::timeout(
            Duration::from_secs(15),
            tokio::process::Command::new(env!("CARGO_BIN_EXE_sniper-cli"))
                .env("SNIPER_DATA_DIR", &self.dir)
                .env_remove("SNIPER_API_ADDR")
                .args(["--output", "compact", "--api", &self.api])
                .args(args)
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("synthetic CLI timed out")
        .unwrap();
        let value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "invalid JSON for {args:?}: {error}: {} / {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
        (output.status.code().unwrap(), value)
    }

    async fn call(&self, operation: &str, input: Value, flag: Option<&str>) -> (i32, Value) {
        let encoded = input.to_string();
        let mut args = vec!["call", operation, "--input", &encoded];
        if let Some(flag) = flag {
            args.push(flag);
        }
        let result = self.command(&args).await;
        if result.0 == 0 && result.1["data"]["dry_run"] != true {
            if let Some(directory) = std::env::var_os("SNIPER_SCHEMA_CASES_DIR") {
                let directory = PathBuf::from(directory);
                std::fs::create_dir_all(&directory).unwrap();
                std::fs::write(
                    directory.join(format!("{}.json", Uuid::new_v4())),
                    serde_json::to_vec(
                        &json!({"operation":operation,"input":input,"data":result.1["data"]}),
                    )
                    .unwrap(),
                )
                .unwrap();
            }
        }
        result
    }

    fn take_requests(&self) -> Vec<RecordedRequest> {
        std::mem::take(&mut *self.state.requests.lock().unwrap())
    }

    fn assert_requests(&self, session_id: Uuid, implicit: bool, post: Option<&str>) {
        let requests = self.take_requests();
        let mut expected = vec![("GET", "/api/settings")];
        if implicit {
            expected.push(("GET", "/api/sessions"));
        }
        expected.push(("GET", "/api/workspace-state"));
        if let Some(operation) = post {
            expected.push((
                "POST",
                if operation == "replay.close" {
                    "/api/replay/tabs/close"
                } else {
                    "/api/replay/tabs/duplicate"
                },
            ));
        }
        assert_eq!(
            requests
                .iter()
                .map(|r| (r.method.as_str(), r.path.as_str()))
                .collect::<Vec<_>>(),
            expected,
            "{requests:?}"
        );
        for request in requests {
            let expected_query = if request.path == "/api/workspace-state" {
                BTreeMap::from([("session_id".into(), session_id.to_string())])
            } else {
                BTreeMap::new()
            };
            assert_eq!(request.query, expected_query, "{request:?}");
            if request.method == "GET" {
                assert!(request.body.is_none());
            } else {
                let mut body = json!({"session_id":session_id,"tab_id":TARGET,"expected_workspace_revision":17});
                if implicit {
                    body["expected_active_session_id"] = json!(session_id);
                }
                assert_eq!(request.body, Some(body));
            }
        }
    }
}

impl Drop for MockApi {
    fn drop(&mut self) {
        self.server.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn mock_request(State(state): State<Arc<MockState>>, request: Request<Body>) -> Response {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, 8192).await.unwrap();
    let body: Option<Value> = (!body.is_empty()).then(|| serde_json::from_slice(&body).unwrap());
    let query: BTreeMap<String, String> =
        url::form_urlencoded::parse(parts.uri.query().unwrap_or_default().as_bytes())
            .into_owned()
            .collect();
    state.requests.lock().unwrap().push(RecordedRequest {
        method: parts.method.to_string(),
        path: parts.uri.path().into(),
        query: query.clone(),
        body: body.clone(),
    });
    let faults = state.faults.lock().unwrap();
    match (parts.method.as_str(), parts.uri.path()) {
        ("GET", "/api/settings") => Json(state.settings.clone()).into_response(),
        ("GET", "/api/sessions") => Json(faults.sessions.clone().unwrap_or_else(|| {
            let active = *state.active.lock().unwrap();
            json!(state
                .ids
                .iter()
                .map(|id| session_summary(*id, *id == active))
                .collect::<Vec<_>>())
        }))
        .into_response(),
        ("GET", "/api/workspace-state") => {
            let session_id = query
                .get("session_id")
                .and_then(|id| Uuid::parse_str(id).ok())
                .expect("workspace read must pin a session");
            assert!(state.ids.contains(&session_id));
            let mut workspace = state.workspace.lock().unwrap().clone();
            workspace["session_id"] = json!(session_id);
            if faults.switch_after_get {
                *state.active.lock().unwrap() = state.ids[1];
            }
            if let Some(body) = &faults.get_body {
                ([(header::CONTENT_TYPE, "application/json")], body.clone()).into_response()
            } else {
                Json(workspace).into_response()
            }
        }
        ("POST", path @ ("/api/replay/tabs/close" | "/api/replay/tabs/duplicate")) => {
            let body = body.unwrap();
            if faults.stale_revision
                || (body.get("expected_active_session_id").is_some()
                    && body["expected_active_session_id"] != json!(*state.active.lock().unwrap()))
            {
                return (
                    StatusCode::CONFLICT,
                    Json(json!({"error":"synthetic conflict","workspace":CONTENT})),
                )
                    .into_response();
            }
            if let Some((status, body)) = &faults.post {
                return (
                    *status,
                    [
                        (header::CONTENT_TYPE, "application/json"),
                        (header::LOCATION, "/unexpected"),
                    ],
                    body.clone(),
                )
                    .into_response();
            }
            let mut workspace = state.workspace.lock().unwrap().clone();
            workspace["session_id"] = body["session_id"].clone();
            Json(acknowledgement(
                &workspace,
                if path.ends_with("duplicate") {
                    "replay.duplicate"
                } else {
                    "replay.close"
                },
            ))
            .into_response()
        }
        _ => (
            StatusCode::METHOD_NOT_ALLOWED,
            "outside saved-tab allowlist",
        )
            .into_response(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saved_tab_cli_gates_and_discovery_are_fully_offline() {
    let api = MockApi::new().await;
    for operation in OPERATIONS {
        let input = json!({"tab_id":TARGET});
        let (status, value) = api.call(operation, input.clone(), None).await;
        assert_ne!(status, 0);
        assert_eq!(value["error"]["code"], "CONFIRMATION_REQUIRED");
        let (status, value) = api.call(operation, input, Some("--dry-run")).await;
        assert_eq!(status, 0, "{value}");
        assert_eq!(value["data"]["dry_run"], true);
        assert_eq!(value["data"]["input"], json!({"tab_id":TARGET}));
        assert_eq!(value["data"]["requires_confirmation"], true);
        assert_eq!(value["data"]["api"]["method"], "POST");
        assert_eq!(
            value["data"]["api"]["path"],
            format!(
                "/api/replay/tabs/{}",
                operation.strip_prefix("replay.").unwrap()
            )
        );
        for kind in ["input", "output"] {
            let (status, schema) = api.command(&["schema", kind, operation]).await;
            assert_eq!(status, 0, "{schema}");
            assert_eq!(schema["schema"]["additionalProperties"], false);
            assert!(schema["schema"]["properties"]["session_id"].is_object());
            if kind == "input" {
                assert_eq!(schema["schema"]["required"], json!(["tab_id"]));
                assert_eq!(schema["schema"]["properties"].as_object().unwrap().len(), 2);
            }
        }
        let (status, examples) = api.command(&["examples", operation]).await;
        assert_eq!(status, 0, "{examples}");
        assert!(examples["examples"].is_array());
    }
    let (status, manifest) = api.command(&["manifest"]).await;
    assert_eq!(status, 0);
    for operation in OPERATIONS {
        let row = manifest["operations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["operation"] == operation)
            .unwrap();
        assert_eq!(row["side_effect"], "write");
        assert_eq!(row["requires_confirmation"], true);
    }
    for action in ["close", "duplicate"] {
        let (status, value) = api
            .command(&["replay", action, "--tab-id", TARGET, "--dry-run"])
            .await;
        assert_eq!(status, 0, "{value}");
        let (status, value) = api.command(&["replay", action, "--tab-id", TARGET]).await;
        assert_ne!(status, 0);
        assert_eq!(value["error"]["code"], "CONFIRMATION_REQUIRED");
    }
    assert!(
        api.take_requests().is_empty(),
        "offline paths must not even probe settings"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saved_tab_cli_invalid_inputs_never_contact_the_api() {
    let api = MockApi::new().await;
    let too_long = "x".repeat(129);
    let utf8_too_long = "é".repeat(65);
    for operation in OPERATIONS {
        for input in [
            json!({}),
            json!({"tab_id":null}),
            json!({"tab_id":false}),
            json!({"tab_id":7}),
            json!({"tab_id":[]}),
            json!({"tab_id":""}),
            json!({"tab_id":" \t\n"}),
            json!({"tab_id":too_long}),
            json!({"tab_id":utf8_too_long}),
            json!({"tab_id":TARGET,"session_id":null}),
            json!({"tab_id":TARGET,"session_id":"invalid"}),
            json!({"tab_id":TARGET,"session_id":9}),
            json!({"tab_id":TARGET,"label":"fixture label"}),
            json!({"tab_id":TARGET,"expected_workspace_revision":17}),
            json!({"tab_id":TARGET,"expected_active_session_id":Uuid::new_v4()}),
            json!({"tab_id":TARGET,"request_text":CONTENT}),
        ] {
            for flag in ["--yes", "--dry-run"] {
                let (status, value) = api.call(operation, input.clone(), Some(flag)).await;
                assert_ne!(status, 0, "{input} {value}");
                assert_eq!(value["error"]["code"], "INVALID_INPUT", "{input} {value}");
            }
        }
    }
    for args in [
        vec!["replay", "close", "--yes"],
        vec![
            "replay",
            "duplicate",
            "--tab-id",
            TARGET,
            "--session-id",
            "invalid",
            "--yes",
        ],
        vec!["replay", "close", "--tab-id", TARGET, "--unknown", "--yes"],
        vec![
            "replay",
            "duplicate",
            "--tab-id",
            TARGET,
            "--dry-run",
            "--yes",
        ],
    ] {
        let (status, value) = api.command(&args).await;
        assert_ne!(status, 0);
        assert_eq!(value["error"]["code"], "INVALID_INPUT", "{value}");
    }
    assert!(api.take_requests().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saved_tab_cli_pins_sessions_and_posts_only_exact_cas_metadata() {
    for operation in OPERATIONS {
        for implicit in [false, true] {
            let api = MockApi::new().await;
            let id = api.state.ids[usize::from(!implicit)];
            let mut input = json!({"tab_id":TARGET});
            if !implicit {
                input["session_id"] = json!(id);
            }
            let (status, value) = api.call(operation, input, Some("--yes")).await;
            assert_eq!(status, 0, "{value}");
            assert_eq!(value["data"]["session_id"], json!(id));
            assert_eq!(value["meta"]["session_id"], json!(id));
            assert_eq!(value["data"]["revision"], 18);
            assert_eq!(
                value["data"]["active_tab_id"],
                if operation == "replay.close" {
                    "left"
                } else {
                    TARGET
                }
            );
            assert_eq!(
                value["data"].as_object().unwrap().len(),
                if operation == "replay.close" { 4 } else { 5 }
            );
            assert!(!value.to_string().contains(CONTENT));
            api.assert_requests(id, implicit, Some(operation));
        }
        let api = MockApi::new().await;
        let id = api.state.ids[0].to_string();
        let (status, value) = api
            .command(&[
                "replay",
                operation.strip_prefix("replay.").unwrap(),
                "--tab-id",
                TARGET,
                "--session-id",
                &id,
                "--yes",
            ])
            .await;
        assert_eq!(status, 0, "{value}");
        assert!(value.get("data").is_none());
        assert_eq!(value["revision"], 18);
        api.assert_requests(api.state.ids[0], false, Some(operation));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saved_tab_cli_accepts_legacy_http_and_validates_visual_focus() {
    for operation in OPERATIONS {
        for legacy in [false, true] {
            let api = MockApi::new().await;
            {
                let mut workspace = api.state.workspace.lock().unwrap();
                if legacy {
                    workspace["replay"]["tabs"][2]
                        .as_object_mut()
                        .unwrap()
                        .remove("type");
                } else {
                    workspace["replay"]["tabs"][2]["type"] = json!("");
                }
            }
            let (status, value) = api
                .call(operation, json!({"tab_id":TARGET}), Some("--yes"))
                .await;
            assert_eq!(status, 0, "{value}");
            api.assert_requests(api.state.ids[0], true, Some(operation));
        }
    }
    for (tabs, active, expected) in [
        (
            json!([{"id":TARGET,"pinned":true},{"id":"next","pinned":true},{"id":"last"}]),
            json!(TARGET),
            json!("next"),
        ),
        (
            json!([{"id":"left"},{"id":TARGET},{"id":"pinned","pinned":true}]),
            json!(TARGET),
            json!("left"),
        ),
        (json!([{"id":TARGET}]), json!(TARGET), Value::Null),
        (
            json!([{"id":TARGET},{"id":"current"}]),
            json!("current"),
            json!("current"),
        ),
        (json!([{"id":TARGET}]), Value::Null, Value::Null),
        (json!([{"id":TARGET}]), json!(""), Value::Null),
    ] {
        let api = MockApi::new().await;
        {
            let mut workspace = api.state.workspace.lock().unwrap();
            workspace["replay"]["tabs"] = tabs;
            workspace["replay"]["active_tab_id"] = active;
        }
        let (status, value) = api
            .call("replay.close", json!({"tab_id":TARGET}), Some("--yes"))
            .await;
        assert_eq!(status, 0, "{value}");
        assert_eq!(value["data"]["active_tab_id"], expected);
        api.assert_requests(api.state.ids[0], true, Some("replay.close"));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saved_tab_cli_rejects_bad_gets_and_non_http_targets_before_posting() {
    for operation in OPERATIONS {
        let api = MockApi::new().await;
        let mut cases = vec![
            "not json".to_owned(),
            "null".to_owned(),
            "[]".to_owned(),
            "{}".to_owned(),
        ];
        for (path, bad) in [
            (vec!["session_id"], json!(Uuid::new_v4())),
            (vec!["session_id"], Value::Null),
            (vec!["revision"], json!("17")),
            (vec!["revision"], json!(-1)),
            (vec!["revision"], json!(17.5)),
            (vec!["revision"], json!(u64::MAX)),
            (vec!["replay"], Value::Null),
            (vec!["replay", "tabs"], json!({})),
            (vec!["replay", "active_tab_id"], json!(9)),
        ] {
            let mut workspace = fixture(api.state.ids[0]);
            if path.len() == 1 {
                workspace[path[0]] = bad;
            } else {
                workspace[path[0]][path[1]] = bad;
            }
            cases.push(workspace.to_string());
        }
        for missing in ["session_id", "revision", "replay"] {
            let mut workspace = fixture(api.state.ids[0]);
            workspace.as_object_mut().unwrap().remove(missing);
            cases.push(workspace.to_string());
        }
        for missing in ["tabs", "active_tab_id"] {
            let mut workspace = fixture(api.state.ids[0]);
            workspace["replay"].as_object_mut().unwrap().remove(missing);
            cases.push(workspace.to_string());
        }
        for bad in [
            json!({"id":TARGET,"type":null}),
            json!({"id":TARGET,"type":false}),
            json!({"id":TARGET,"pinned":"false"}),
            json!({"id":null}),
            json!({"type":"http"}),
            json!({"id":""}),
        ] {
            let mut workspace = fixture(api.state.ids[0]);
            workspace["replay"]["tabs"][2] = bad;
            cases.push(workspace.to_string());
        }
        for (key, value) in [
            ("id", json!("x".repeat(129))),
            ("id", json!("é".repeat(65))),
        ] {
            let mut workspace = fixture(api.state.ids[0]);
            workspace["replay"]["tabs"][2][key] = value;
            cases.push(workspace.to_string());
        }
        let mut too_many = fixture(api.state.ids[0]);
        too_many["replay"]["tabs"] = json!((0..513)
            .map(|index| json!({"id":format!("generated-{index}")}))
            .collect::<Vec<_>>());
        cases.push(too_many.to_string());
        let mut stale_active = fixture(api.state.ids[0]);
        stale_active["replay"]["active_tab_id"] = json!("legacy-stale-focus");
        cases.push(stale_active.to_string());
        let mut long_active = fixture(api.state.ids[0]);
        long_active["replay"]["active_tab_id"] = json!("x".repeat(129));
        cases.push(long_active.to_string());
        let mut duplicate_ids = fixture(api.state.ids[0]);
        duplicate_ids["replay"]["tabs"][0]["id"] = json!(TARGET);
        cases.push(duplicate_ids.to_string());
        for body in cases {
            api.state.faults.lock().unwrap().get_body = Some(body);
            let (status, value) = api
                .call(operation, json!({"tab_id":TARGET}), Some("--yes"))
                .await;
            assert_ne!(status, 0, "{value}");
            assert_eq!(value["error"]["code"], "INVALID_RESPONSE", "{value}");
            assert_eq!(value["error"]["retryable"], false);
            assert_eq!(value["error"]["details"]["outcome"], "not_applied");
            assert!(!value.to_string().contains(CONTENT));
            api.assert_requests(api.state.ids[0], true, None);
        }
        api.state.faults.lock().unwrap().get_body = None;
        for tab_type in ["websocket", "future", "HTTP"] {
            api.state.workspace.lock().unwrap()["replay"]["tabs"][2]["type"] = json!(tab_type);
            let (status, value) = api
                .call(operation, json!({"tab_id":TARGET}), Some("--yes"))
                .await;
            assert_ne!(status, 0);
            assert_eq!(value["error"]["code"], "INVALID_INPUT");
            api.assert_requests(api.state.ids[0], true, None);
        }
        api.state.workspace.lock().unwrap()["replay"]["tabs"][2]["type"] = json!("http");
        for wrong_target in ["fixture label", "exact saved tab", "exact", "missing"] {
            let (status, value) = api
                .call(operation, json!({"tab_id":wrong_target}), Some("--yes"))
                .await;
            assert_ne!(status, 0);
            assert_eq!(value["error"]["code"], "TAB_NOT_FOUND");
            api.assert_requests(api.state.ids[0], true, None);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saved_tab_cli_rejects_ambiguous_session_discovery_without_workspace_read() {
    let api = MockApi::new().await;
    for sessions in [
        json!([]),
        json!({}),
        json!([session_summary(api.state.ids[0], false)]),
        json!([
            session_summary(api.state.ids[0], true),
            session_summary(api.state.ids[1], true)
        ]),
        json!([{"active":true}]),
    ] {
        api.state.faults.lock().unwrap().sessions = Some(sessions);
        let (status, value) = api
            .call("replay.close", json!({"tab_id":TARGET}), Some("--yes"))
            .await;
        assert_ne!(status, 0);
        assert_eq!(value["error"]["code"], "INVALID_RESPONSE");
        assert_eq!(
            api.take_requests()
                .iter()
                .map(|r| r.path.as_str())
                .collect::<Vec<_>>(),
            ["/api/settings", "/api/sessions"]
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saved_tab_cli_rejects_conflicts_without_retrying_or_printing_workspace_content() {
    for operation in OPERATIONS {
        for switched in [false, true] {
            let api = MockApi::new().await;
            {
                let mut faults = api.state.faults.lock().unwrap();
                faults.switch_after_get = switched;
                faults.stale_revision = !switched;
            }
            let (status, value) = api
                .call(operation, json!({"tab_id":TARGET}), Some("--yes"))
                .await;
            assert_ne!(status, 0);
            assert_eq!(value["error"]["code"], "WORKSPACE_CONFLICT");
            assert_eq!(value["error"]["retryable"], false);
            assert_eq!(value["error"]["details"]["outcome"], "not_applied");
            assert!(!value.to_string().contains(CONTENT));
            api.assert_requests(api.state.ids[0], true, Some(operation));
        }
        let api = MockApi::new().await;
        api.state.faults.lock().unwrap().switch_after_get = true;
        let (status, value) = api
            .call(
                operation,
                json!({"tab_id":TARGET,"session_id":api.state.ids[0]}),
                Some("--yes"),
            )
            .await;
        assert_eq!(status, 0, "{value}");
        api.assert_requests(api.state.ids[0], false, Some(operation));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saved_tab_cli_rejects_malformed_or_misattributed_acknowledgements_once() {
    for operation in OPERATIONS {
        let api = MockApi::new().await;
        let ack = acknowledgement(&fixture(api.state.ids[0]), operation);
        let mut cases = vec![
            "".to_owned(),
            "not json".to_owned(),
            "null".to_owned(),
            "[]".to_owned(),
            "{}".to_owned(),
            "x".repeat(4097),
        ];
        for (key, value) in [
            ("session_id", json!(Uuid::new_v4())),
            ("session_id", Value::Null),
            ("revision", json!(17)),
            ("revision", json!(19)),
            ("revision", json!("18")),
            ("revision", json!(-1)),
            ("revision", json!(18.5)),
            ("active_tab_id", json!("wrong-focus")),
            ("active_tab_id", json!(7)),
            (
                if operation == "replay.close" {
                    "closed_tab_id"
                } else {
                    "source_tab_id"
                },
                json!("wrong-target"),
            ),
            ("unexpected_workspace", json!(CONTENT)),
        ] {
            let mut wire = ack.clone();
            wire[key] = value;
            cases.push(wire.to_string());
        }
        for missing in ack.as_object().unwrap().keys() {
            let mut wire = ack.clone();
            wire.as_object_mut().unwrap().remove(missing);
            cases.push(wire.to_string());
        }
        if operation == "replay.duplicate" {
            for id in [
                json!("not-a-uuid"),
                json!(TARGET),
                Value::Null,
                json!(false),
            ] {
                let mut wire = ack.clone();
                wire["new_tab_id"] = id;
                cases.push(wire.to_string());
            }
            let existing = Uuid::new_v4();
            api.state.workspace.lock().unwrap()["replay"]["tabs"][0]["id"] = json!(existing);
            let mut collision = ack.clone();
            collision["new_tab_id"] = json!(existing);
            cases.push(collision.to_string());
        }
        for body in cases {
            api.state.faults.lock().unwrap().post = Some((StatusCode::OK, body));
            let (status, value) = api
                .call(operation, json!({"tab_id":TARGET}), Some("--yes"))
                .await;
            assert_ne!(status, 0, "{value}");
            assert_eq!(value["error"]["code"], "INVALID_RESPONSE", "{value}");
            assert_eq!(value["error"]["retryable"], false);
            assert_eq!(value["error"]["details"]["outcome"], "unknown");
            assert!(!value.to_string().contains(CONTENT));
            api.assert_requests(api.state.ids[0], true, Some(operation));
        }
        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::NOT_FOUND,
            StatusCode::PRECONDITION_REQUIRED,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::TEMPORARY_REDIRECT,
            StatusCode::PERMANENT_REDIRECT,
            StatusCode::SEE_OTHER,
        ] {
            api.state.faults.lock().unwrap().post = Some((status, CONTENT.to_owned()));
            let (exit, value) = api
                .call(operation, json!({"tab_id":TARGET}), Some("--yes"))
                .await;
            assert_ne!(exit, 0);
            assert_eq!(value["error"]["retryable"], false);
            if status.is_redirection() {
                assert_eq!(value["error"]["code"], "REDIRECT_REFUSED");
            }
            assert!(!value.to_string().contains(CONTENT));
            api.assert_requests(api.state.ids[0], true, Some(operation));
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saved_tab_cli_lost_mutation_response_is_unknown_and_never_retried() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for operation in OPERATIONS {
        let mut api = MockApi::new().await;
        api.server.abort();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        api.api = format!("http://{}", listener.local_addr().unwrap());
        let settings = api.state.settings.clone();
        let session_id = api.state.ids[0];
        let workspace = fixture(session_id);
        let server = tokio::spawn(async move {
            for (expected, body) in [
                ("GET /api/settings ".to_owned(), Some(settings)),
                (
                    format!("GET /api/workspace-state?session_id={session_id} "),
                    Some(workspace),
                ),
                (
                    format!(
                        "POST /api/replay/tabs/{} ",
                        operation.strip_prefix("replay.").unwrap()
                    ),
                    None,
                ),
            ] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buffer = [0u8; 8192];
                loop {
                    let count = stream.read(&mut buffer).await.unwrap();
                    assert!(count > 0);
                    request.extend_from_slice(&buffer[..count]);
                    if let Some(header_end) =
                        request.windows(4).position(|window| window == b"\r\n\r\n")
                    {
                        let headers = String::from_utf8_lossy(&request[..header_end]);
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        if request.len() >= header_end + 4 + length {
                            break;
                        }
                    }
                }
                assert!(
                    String::from_utf8_lossy(&request).starts_with(&expected),
                    "{}",
                    String::from_utf8_lossy(&request)
                );
                if body.is_none() {
                    let start = request
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n")
                        .unwrap()
                        + 4;
                    let mutation: Value = serde_json::from_slice(&request[start..]).unwrap();
                    assert_eq!(
                        mutation,
                        json!({"session_id":session_id,"tab_id":TARGET,"expected_workspace_revision":17})
                    );
                }
                if let Some(body) = body {
                    let body = body.to_string();
                    stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).as_bytes()).await.unwrap();
                }
                drop(stream);
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(300), listener.accept())
                    .await
                    .is_err(),
                "lost mutation was retried"
            );
        });
        let (status, value) = api
            .call(
                operation,
                json!({"tab_id":TARGET,"session_id":session_id}),
                Some("--yes"),
            )
            .await;
        assert_ne!(status, 0, "{value}");
        assert_eq!(value["error"]["code"], "TRANSPORT_ERROR");
        assert_eq!(value["error"]["details"]["outcome"], "unknown");
        assert_eq!(value["error"]["retryable"], false);
        server.await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saved_tab_cli_duplicate_rejects_uuid_aliases_and_preserves_existing_focus() {
    let api = MockApi::new().await;
    let source_id = Uuid::new_v4();
    {
        let mut workspace = api.state.workspace.lock().unwrap();
        workspace["replay"]["tabs"][2]["id"] = json!(source_id);
        workspace["replay"]["active_tab_id"] = json!(source_id);
    }
    for new_id in [
        source_id.to_string(),
        source_id.to_string().to_uppercase(),
        source_id.simple().to_string(),
    ] {
        api.state.faults.lock().unwrap().post = Some((
            StatusCode::OK,
            json!({
                "session_id":api.state.ids[0],"revision":18,"active_tab_id":source_id,
                "source_tab_id":source_id,"new_tab_id":new_id
            })
            .to_string(),
        ));
        let (status, value) = api
            .call(
                "replay.duplicate",
                json!({"tab_id":source_id}),
                Some("--yes"),
            )
            .await;
        assert_ne!(status, 0, "{value}");
        assert_eq!(value["error"]["code"], "INVALID_RESPONSE");
        assert_eq!(value["error"]["details"]["outcome"], "unknown");
        let requests = api.take_requests();
        assert_eq!(requests.len(), 4);
        assert_eq!(requests[3].path, "/api/replay/tabs/duplicate");
        assert_eq!(
            requests[3].body,
            Some(json!({"session_id":api.state.ids[0],"tab_id":source_id,
            "expected_workspace_revision":17,"expected_active_session_id":api.state.ids[0]}))
        );
    }
    for active in [json!("left"), Value::Null, json!("")] {
        let api = MockApi::new().await;
        api.state.workspace.lock().unwrap()["replay"]["active_tab_id"] = active.clone();
        let (status, value) = api
            .call("replay.duplicate", json!({"tab_id":TARGET}), Some("--yes"))
            .await;
        assert_eq!(status, 0, "{value}");
        assert_eq!(value["data"]["active_tab_id"], active);
        api.assert_requests(api.state.ids[0], true, Some("replay.duplicate"));
    }
}
