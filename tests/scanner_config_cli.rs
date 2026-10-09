//! Configuration-only CLI tests. The synthetic API cannot capture, replay,
//! rescan, probe or contact an upstream; every request is checked below.
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
    Json, Router,
};
use serde_json::{json, Value};
use sniper::scanner::{ScannerConfig, ScannerConfigSnapshot, BUILTIN_RULES};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

const OPERATIONS: [&str; 8] = [
    "scanner.config.get",
    "scanner.config.set_enabled",
    "scanner.builtin.set_enabled",
    "scanner.custom.list",
    "scanner.custom.get",
    "scanner.custom.create",
    "scanner.custom.update",
    "scanner.custom.delete",
];

fn rule(id: &str) -> Value {
    json!({"id":id,"name":format!("Synthetic {id}"),"enabled":true,
        "target":"response_header","header_name":"X-Example","pattern":"example-marker",
        "severity":"info","category":"example","description":"Synthetic saved configuration."})
}

fn initial_config() -> ScannerConfig {
    let mut config = ScannerConfig::default();
    config.rules.insert("future-toggle".into(), false);
    config.custom_rules = ["first", "middle", "last"]
        .into_iter()
        .map(|id| serde_json::from_value(rule(id)).unwrap())
        .collect();
    config
}

#[derive(Clone, Debug)]
struct RecordedRequest {
    method: String,
    path: String,
    query: BTreeMap<String, String>,
    body: Option<Value>,
}

#[derive(Default)]
struct Faults {
    get_override: Option<Value>,
    post_error: Option<(StatusCode, Value)>,
    switch_after_get: bool,
    concurrent_edit: bool,
    lose_post_response: bool,
    no_active: bool,
}

struct MockState {
    settings: Value,
    ids: [Uuid; 2],
    active: Mutex<Uuid>,
    configs: Mutex<BTreeMap<Uuid, ScannerConfig>>,
    requests: Mutex<Vec<RecordedRequest>>,
    faults: Mutex<Faults>,
}

/// Longest `call --input` value passed as an argument rather than on stdin.
const CALL_INPUT_ARG_MAX_BYTES: usize = 8 * 1024;

struct MockApi {
    api: String,
    dir: PathBuf,
    state: Arc<MockState>,
    server: tokio::task::JoinHandle<()>,
}

impl MockApi {
    async fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("sniper-scanner-cli-{}", Uuid::new_v4()));
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
            configs: Mutex::new(ids.into_iter().map(|id| (id, initial_config())).collect()),
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

    async fn command(&self, args: &[&str], stdin: Option<&str>) -> (i32, Value) {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_sniper-cli"));
        command
            .env("SNIPER_DATA_DIR", &self.dir)
            .env_remove("SNIPER_API_ADDR")
            .args(["--output", "compact", "--api", &self.api])
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .stdin(if stdin.is_some() {
                std::process::Stdio::piped()
            } else {
                std::process::Stdio::null()
            })
            .kill_on_drop(true);
        let mut child = command.spawn().unwrap();
        if let Some(input) = stdin {
            let mut pipe = child.stdin.take().unwrap();
            pipe.write_all(input.as_bytes()).await.unwrap();
            pipe.shutdown().await.unwrap();
        }
        let output = tokio::time::timeout(Duration::from_secs(20), child.wait_with_output())
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
        let input = input.to_string();
        // Windows caps a whole command line at 32,767 characters and refuses to
        // start the process past it, so the cases that send a 64 KiB field go
        // through stdin, which `--input -` reads the same way.
        let stdin = (input.len() > CALL_INPUT_ARG_MAX_BYTES).then_some(input.as_str());
        let source = if stdin.is_some() { "-" } else { input.as_str() };
        let mut args = vec!["call", operation, "--input", source];
        if let Some(flag) = flag {
            args.push(flag);
        }
        self.command(&args, stdin).await
    }

    fn snapshot(&self, id: Uuid) -> ScannerConfigSnapshot {
        ScannerConfigSnapshot::new(id, self.state.configs.lock().unwrap()[&id].clone())
    }

    fn take_requests(&self) -> Vec<RecordedRequest> {
        std::mem::take(&mut *self.state.requests.lock().unwrap())
    }

    fn assert_requests(&self, id: Uuid, implicit: bool, write: bool) -> Vec<RecordedRequest> {
        let requests = self.take_requests();
        let mut expected = vec![("GET", "/api/settings")];
        if implicit {
            expected.push(("GET", "/api/sessions"));
        }
        expected.push(("GET", "/api/scanner-config"));
        if write {
            expected.push(("POST", "/api/scanner-config"));
        }
        assert_eq!(
            requests
                .iter()
                .map(|request| (request.method.as_str(), request.path.as_str()))
                .collect::<Vec<_>>(),
            expected,
            "only discovery and passive configuration access are allowed: {requests:?}"
        );
        for request in &requests {
            if request.path == "/api/scanner-config" {
                let mut query = BTreeMap::from([("session_id".to_owned(), id.to_string())]);
                if request.method == "POST" && implicit {
                    query.insert("expected_active_session_id".into(), id.to_string());
                }
                assert_eq!(request.query, query, "{request:?}");
            } else {
                assert!(request.query.is_empty(), "{request:?}");
            }
            if request.method == "GET" {
                assert!(request.body.is_none(), "{request:?}");
            } else {
                let keys: Vec<_> = request
                    .body
                    .as_ref()
                    .unwrap()
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect();
                assert_eq!(
                    keys,
                    ["custom_rules", "enabled", "expected_config_token", "rules"]
                );
            }
        }
        requests
    }
}

impl Drop for MockApi {
    fn drop(&mut self) {
        self.server.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn session_summary(id: Uuid, active: bool) -> Value {
    json!({"id":id,"name":"Synthetic saved session","created_at":"2026-10-08T12:00:00Z",
        "updated_at":"2026-10-08T12:00:00Z","last_opened_at":"2026-10-08T12:00:00Z",
        "request_count":0,"websocket_count":0,"event_count":0,"fuzzer_count":0,
        "rule_count":0,"storage_path":"synthetic-unused-path","active":active})
}

async fn mock_request(State(state): State<Arc<MockState>>, request: Request<Body>) -> Response {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, 5 * 1024 * 1024).await.unwrap();
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
    match (parts.method.as_str(), parts.uri.path()) {
        ("GET", "/api/settings") => return Json(state.settings.clone()).into_response(),
        ("GET", "/api/sessions") => {
            let active = *state.active.lock().unwrap();
            let no_active = state.faults.lock().unwrap().no_active;
            return Json(
                state
                    .ids
                    .iter()
                    .map(|id| session_summary(*id, !no_active && *id == active))
                    .collect::<Vec<_>>(),
            )
            .into_response();
        }
        ("GET" | "POST", "/api/scanner-config") => (),
        _ => {
            return (
                StatusCode::METHOD_NOT_ALLOWED,
                "request outside configuration allowlist",
            )
                .into_response()
        }
    }
    let id = query
        .get("session_id")
        .and_then(|id| Uuid::parse_str(id).ok())
        .expect("CLI must pin a session");
    let mut configs = state.configs.lock().unwrap();
    let Some(config) = configs.get_mut(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"session not found","session_id":id})),
        )
            .into_response();
    };
    let faults = state.faults.lock().unwrap();
    if parts.method == "GET" {
        let result = faults.get_override.clone().unwrap_or_else(|| {
            serde_json::to_value(ScannerConfigSnapshot::new(id, config.clone())).unwrap()
        });
        if faults.switch_after_get {
            *state.active.lock().unwrap() = state.ids[1];
        }
        if faults.concurrent_edit {
            config.custom_rules[0].description = "Concurrent UI edit".into();
        }
        return Json(result).into_response();
    }
    if let Some((status, error)) = &faults.post_error {
        return (*status, Json(error.clone())).into_response();
    }
    if query
        .get("expected_active_session_id")
        .is_some_and(|guard| *guard != state.active.lock().unwrap().to_string())
    {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error":"active session changed","session_id":id})),
        )
            .into_response();
    }
    let body = body.unwrap();
    if body["expected_config_token"] != ScannerConfigSnapshot::new(id, config.clone()).config_token
    {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error":"scanner config changed; reload before saving","session_id":id})),
        )
            .into_response();
    }
    *config = serde_json::from_value(body).unwrap();
    if faults.lose_post_response {
        return (StatusCode::OK, "lost JSON response").into_response();
    }
    Json(ScannerConfigSnapshot::new(id, config.clone())).into_response()
}

fn assert_ok(code: i32, value: &Value) {
    assert_eq!(code, 0, "{value}");
}
fn assert_invalid(code: i32, value: &Value) {
    assert_eq!(code, 2, "{value}");
    assert_eq!(value["error"]["code"], "INVALID_INPUT", "{value}");
}
fn assert_envelope(value: &Value, operation: &str, id: Uuid) {
    assert_eq!(value["ok"], true);
    assert_eq!(value["operation"], operation);
    assert_eq!(value["schema_version"], "2026-06-22");
    assert_eq!(value["meta"]["session_id"], id.to_string());
    assert_eq!(value["warnings"], json!([]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_and_call_reads_pin_sessions_and_keep_order() {
    let mock = MockApi::new().await;
    for explicit in [false, true] {
        let id = mock.state.ids[usize::from(explicit)];
        let id_text = id.to_string();
        for (operation, group, action) in [
            ("scanner.config.get", "config", "get"),
            ("scanner.custom.list", "custom", "list"),
            ("scanner.custom.get", "custom", "get"),
        ] {
            let mut args = vec!["scanner", group, action];
            let mut input = json!({});
            if operation == "scanner.custom.get" {
                args.extend(["--id", "middle"]);
                input["id"] = json!("middle");
            }
            if explicit {
                args.extend(["--session-id", &id_text]);
                input["session_id"] = json!(id);
            }
            let (code, direct) = mock.command(&args, None).await;
            assert_ok(code, &direct);
            mock.assert_requests(id, !explicit, false);
            let (code, called) = mock.call(operation, input, None).await;
            assert_ok(code, &called);
            assert_envelope(&called, operation, id);
            assert_eq!(called["data"], direct);
            mock.assert_requests(id, !explicit, false);
            if operation == "scanner.config.get" {
                assert_eq!(direct["session_id"], id.to_string());
                assert_eq!(
                    direct["builtins"].as_array().unwrap().len(),
                    BUILTIN_RULES.len()
                );
                assert_eq!(direct["rules"]["future-toggle"], false);
            } else if action == "list" {
                assert_eq!(
                    direct
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|rule| rule["id"].as_str().unwrap())
                        .collect::<Vec<_>>(),
                    ["first", "middle", "last"]
                );
            } else {
                assert_eq!(direct, rule("middle"));
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bounded_mutations_preserve_unrelated_config_and_exact_order() {
    let mock = MockApi::new().await;
    for explicit in [false, true] {
        let id = mock.state.ids[usize::from(explicit)];
        let operations = [
            ("scanner.config.set_enabled", json!({"enabled":false})),
            (
                "scanner.builtin.set_enabled",
                json!({"id":"header","enabled":false}),
            ),
            ("scanner.custom.create", json!({"rule":rule("appended")})),
            (
                "scanner.custom.update",
                json!({"id":"middle","patch":{"enabled":false,"header_name":"","description":"","category":""}}),
            ),
            ("scanner.custom.delete", json!({"id":"first"})),
        ];
        let mut expected = serde_json::to_value(initial_config()).unwrap();
        for (operation, mut input) in operations {
            if explicit {
                input["session_id"] = json!(id);
            }
            let before = mock.snapshot(id);
            let (code, result) = mock.call(operation, input, Some("--yes")).await;
            assert_ok(code, &result);
            assert_envelope(&result, operation, id);
            assert_eq!(result["data"]["changed"], true);
            let requests = mock.assert_requests(id, !explicit, true);
            assert_eq!(
                requests.last().unwrap().body.as_ref().unwrap()["expected_config_token"],
                before.config_token
            );
            match operation {
                "scanner.config.set_enabled" => expected["enabled"] = json!(false),
                "scanner.builtin.set_enabled" => expected["rules"]["header"] = json!(false),
                "scanner.custom.create" => expected["custom_rules"]
                    .as_array_mut()
                    .unwrap()
                    .push(rule("appended")),
                "scanner.custom.update" => {
                    expected["custom_rules"][1]["enabled"] = json!(false);
                    for field in ["header_name", "description", "category"] {
                        expected["custom_rules"][1][field] = json!("");
                    }
                }
                "scanner.custom.delete" => {
                    expected["custom_rules"].as_array_mut().unwrap().remove(0);
                }
                _ => unreachable!(),
            }
            let after = mock.snapshot(id);
            assert_eq!(serde_json::to_value(&after.config).unwrap(), expected);
            assert_eq!(result["data"]["config_token"], after.config_token);
            assert_ne!(after.config_token, before.config_token);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_file_and_stdin_inputs_match_call_and_are_read_once() {
    let mock = MockApi::new().await;
    let id = mock.state.ids[1];
    let id_text = id.to_string();
    let file = mock.dir.join("rule.json");
    std::fs::write(&file, rule("created-file").to_string()).unwrap();
    let (code, created) = mock
        .command(
            &[
                "scanner",
                "custom",
                "create",
                "--file",
                file.to_str().unwrap(),
                "--session-id",
                &id_text,
                "--yes",
            ],
            None,
        )
        .await;
    assert_ok(code, &created);
    assert_eq!(created["id"], "created-file");
    mock.assert_requests(id, false, true);
    let (code, updated) = mock
        .command(
            &[
                "scanner",
                "custom",
                "update",
                "--id",
                "created-file",
                "--stdin",
                "--session-id",
                &id_text,
                "--yes",
            ],
            Some(r#"{"enabled":false,"description":""}"#),
        )
        .await;
    assert_ok(code, &updated);
    mock.assert_requests(id, false, true);
    let current = mock.snapshot(id).config.custom_rules.pop().unwrap();
    assert!(!current.enabled);
    assert_eq!(current.description, "");
    let (code, result) = mock
        .command(
            &[
                "scanner",
                "custom",
                "delete",
                "--id",
                "created-file",
                "--session-id",
                &id_text,
                "--yes",
            ],
            None,
        )
        .await;
    assert_ok(code, &result);
    mock.assert_requests(id, false, true);
    for args in [
        vec![
            "scanner",
            "config",
            "set-enabled",
            "--enabled",
            "false",
            "--yes",
        ],
        vec![
            "scanner",
            "builtin",
            "set-enabled",
            "--id",
            "jwt",
            "--enabled",
            "false",
            "--yes",
        ],
    ] {
        let (code, result) = mock.command(&args, None).await;
        assert_ok(code, &result);
        mock.assert_requests(mock.state.ids[0], true, true);
    }
    let input_file = mock.dir.join("call.json");
    std::fs::write(&input_file, json!({"rule":rule("call-file")}).to_string()).unwrap();
    let source = format!("@{}", input_file.display());
    let (code, result) = mock
        .command(
            &[
                "call",
                "scanner.custom.create",
                "--input",
                &source,
                "--dry-run",
            ],
            None,
        )
        .await;
    assert_ok(code, &result);
    assert_eq!(result["data"]["input"]["rule"], rule("call-file"));
    let (code, result) = mock
        .command(
            &["call", "scanner.custom.update", "--input", "-", "--dry-run"],
            Some(r#"{"id":"middle","patch":{"description":"","enabled":false}}"#),
        )
        .await;
    assert_ok(code, &result);
    assert_eq!(
        result["data"]["input"]["patch"],
        json!({"description":"","enabled":false})
    );
    assert!(mock.take_requests().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unchanged_mutations_do_not_post_or_change_tokens() {
    let mock = MockApi::new().await;
    let id = mock.state.ids[0];
    mock.state
        .configs
        .lock()
        .unwrap()
        .get_mut(&id)
        .unwrap()
        .rules
        .remove("jwt");
    let before = mock.snapshot(id);
    for (operation, input) in [
        ("scanner.config.set_enabled", json!({"enabled":true})),
        (
            "scanner.builtin.set_enabled",
            json!({"id":"jwt","enabled":true}),
        ),
        (
            "scanner.custom.update",
            json!({"id":"middle","patch":{"enabled":true}}),
        ),
    ] {
        let (code, result) = mock.call(operation, input, Some("--yes")).await;
        assert_ok(code, &result);
        assert_eq!(result["data"]["changed"], false);
        assert_eq!(result["data"]["config_token"], before.config_token);
        mock.assert_requests(id, true, false);
    }
    assert_eq!(
        serde_json::to_value(mock.snapshot(id)).unwrap(),
        serde_json::to_value(before).unwrap()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn manifest_schemas_examples_and_every_dry_run_stay_offline() {
    let mock = MockApi::new().await;
    let (code, manifest) = mock.command(&["manifest"], None).await;
    assert_ok(code, &manifest);
    let specs: Vec<_> = manifest["operations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|spec| spec["operation"].as_str().unwrap().starts_with("scanner."))
        .collect();
    assert_eq!(specs.len(), OPERATIONS.len());
    for operation in OPERATIONS {
        let spec = specs
            .iter()
            .find(|spec| spec["operation"] == operation)
            .unwrap();
        let write = !matches!(
            operation,
            "scanner.config.get" | "scanner.custom.list" | "scanner.custom.get"
        );
        assert_eq!(spec["requires_confirmation"], write);
        assert_eq!(spec["side_effect"], if write { "write" } else { "read" });
        assert_eq!(spec["input_schema"]["additionalProperties"], false);
        assert_eq!(
            spec["input_schema"]["properties"]["session_id"]["format"],
            "uuid"
        );
        for kind in ["input", "output"] {
            let (code, result) = mock.command(&["schema", kind, operation], None).await;
            assert_ok(code, &result);
            assert_eq!(result["schema"], spec[format!("{kind}_schema")]);
        }
        let (code, examples) = mock.command(&["examples", operation], None).await;
        assert_ok(code, &examples);
        assert_eq!(examples["examples"], spec["examples"]);
        for input in spec["examples"].as_array().unwrap() {
            let (code, result) = mock.call(operation, input.clone(), Some("--dry-run")).await;
            assert_ok(code, &result);
            assert_eq!(result["data"]["dry_run"], true);
            assert_eq!(result["data"]["operation"], operation);
            assert_eq!(result["data"]["requires_confirmation"], write);
            if write {
                let (code, result) = mock.call(operation, input.clone(), None).await;
                assert_eq!(code, 2, "{result}");
                assert_eq!(result["error"]["code"], "CONFIRMATION_REQUIRED");
            }
        }
    }
    assert!(mock.take_requests().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_inputs_reject_unknown_null_noop_and_bad_regex_before_discovery() {
    let mock = MockApi::new().await;
    let mut cases = vec![
        ("scanner.config.get", json!({"unknown":true})),
        ("scanner.config.set_enabled", json!({})),
        ("scanner.config.set_enabled", json!({"enabled":null})),
        ("scanner.config.set_enabled", json!({"enabled":"false"})),
        (
            "scanner.builtin.set_enabled",
            json!({"id":"unknown","enabled":false}),
        ),
        ("scanner.custom.get", json!({"id":" "})),
        ("scanner.custom.delete", json!({"id":"middle","all":true})),
        ("scanner.custom.create", json!({})),
        (
            "scanner.custom.create",
            json!({"rule":rule("new"),"stdin":true}),
        ),
        ("scanner.custom.create", json!({"file":""})),
        ("scanner.custom.update", json!({"id":"middle","patch":{}})),
        (
            "scanner.custom.update",
            json!({"id":"middle","patch":{"id":"new"}}),
        ),
        (
            "scanner.custom.update",
            json!({"id":"middle","patch":{"enabled":null}}),
        ),
        (
            "scanner.custom.update",
            json!({"id":"middle","patch":{"description":null}}),
        ),
        (
            "scanner.custom.update",
            json!({"id":"middle","patch":{"unknown":true}}),
        ),
        (
            "scanner.custom.update",
            json!({"id":"middle","patch":{"pattern":"["}}),
        ),
        (
            "scanner.custom.update",
            json!({"id":"middle","patch":{"pattern":" "}}),
        ),
        (
            "scanner.custom.update",
            json!({"id":"middle","patch":{"severity":"severe"}}),
        ),
        (
            "scanner.custom.update",
            json!({"id":"middle","patch":{"target":"url"}}),
        ),
        (
            "scanner.custom.update",
            json!({"id":"middle","patch":{"name":""}}),
        ),
    ];
    for (field, value) in [
        ("unknown", json!(true)),
        ("enabled", Value::Null),
        ("name", json!(" ")),
        ("pattern", json!("[")),
        ("target", json!("url")),
        ("description", json!("x".repeat(65537))),
    ] {
        let mut input = rule("new");
        input[field] = value;
        cases.push(("scanner.custom.create", json!({"rule":input})));
    }
    for (operation, input) in cases {
        let (code, result) = mock.call(operation, input, Some("--dry-run")).await;
        assert_invalid(code, &result);
    }
    for args in [
        vec!["scanner", "config", "set-enabled"],
        vec!["scanner", "builtin", "set-enabled", "--id", "header"],
        vec!["scanner", "custom", "create"],
        vec!["scanner", "custom", "update", "--id", "middle"],
    ] {
        let (code, result) = mock.command(&args, None).await;
        assert_invalid(code, &result);
    }
    for operation in [
        "scanner.config.set",
        "scanner.scan",
        "scanner.rescan",
        "scanner.probe",
        "scanner.custom.clear",
    ] {
        let (code, result) = mock.call(operation, json!({}), Some("--dry-run")).await;
        assert_eq!(code, 2, "{result}");
        assert_eq!(result["error"]["code"], "UNKNOWN_OPERATION");
    }
    let (code, result) = mock
        .command(
            &["call", "scanner.custom.create", "--input", "-", "--dry-run"],
            Some(r#"{"stdin":true}"#),
        )
        .await;
    assert_invalid(code, &result);
    assert!(mock.take_requests().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_invalid_files_and_stdin_fail_offline() {
    let mock = MockApi::new().await;
    let file = mock.dir.join("invalid.json");
    for raw in [
        "{",
        r#"{"enabled":false,"unknown":true}"#,
        r#"{"pattern":"["}"#,
        "{}",
    ] {
        std::fs::write(&file, raw).unwrap();
        for file_input in [true, false] {
            let mut args = vec!["scanner", "custom", "update", "--id", "middle", "--dry-run"];
            if file_input {
                args.extend(["--file", file.to_str().unwrap()]);
            } else {
                args.push("--stdin");
            }
            let (code, result) = mock.command(&args, (!file_input).then_some(raw)).await;
            assert_invalid(code, &result);
        }
    }
    assert!(mock.take_requests().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_exact_ids_and_duplicate_create_never_post() {
    let mock = MockApi::new().await;
    let id = mock.state.ids[0];
    for (operation, input) in [
        ("scanner.custom.get", json!({"id":"mid"})),
        (
            "scanner.custom.update",
            json!({"id":"Middle","patch":{"enabled":false}}),
        ),
        ("scanner.custom.delete", json!({"id":" middle"})),
        ("scanner.custom.create", json!({"rule":rule("middle")})),
        ("scanner.custom.create", json!({"rule":rule(" middle ")})),
    ] {
        let (code, result) = mock.call(operation, input, Some("--yes")).await;
        assert_ne!(code, 0, "{result}");
        assert_eq!(result["ok"], false);
        mock.assert_requests(id, true, false);
    }
    assert_eq!(
        serde_json::to_value(mock.snapshot(id).config).unwrap(),
        serde_json::to_value(initial_config()).unwrap()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conflicts_never_retry_and_preserve_concurrent_edits() {
    for active_switch in [false, true] {
        let mock = MockApi::new().await;
        let id = mock.state.ids[0];
        {
            let mut faults = mock.state.faults.lock().unwrap();
            faults.switch_after_get = active_switch;
            faults.concurrent_edit = !active_switch;
        }
        let (code, result) = mock
            .call(
                "scanner.config.set_enabled",
                json!({"enabled":false}),
                Some("--yes"),
            )
            .await;
        assert_eq!(code, 5, "{result}");
        assert_eq!(result["error"]["code"], "HTTP_STATUS_ERROR");
        assert_eq!(result["error"]["details"]["status"], 409);
        assert_eq!(result["error"]["retryable"], false);
        mock.assert_requests(id, true, true);
        let saved = mock.snapshot(id).config;
        assert!(saved.enabled);
        if !active_switch {
            assert_eq!(saved.custom_rules[0].description, "Concurrent UI edit");
        }
        assert_eq!(
            serde_json::to_value(mock.snapshot(mock.state.ids[1]).config).unwrap(),
            serde_json::to_value(initial_config()).unwrap()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_token_or_wrong_session_snapshot_refuses_writes() {
    let mock = MockApi::new().await;
    let id = mock.state.ids[0];
    for fault in [
        "missing_token",
        "empty_token",
        "invalid_token",
        "wrong_session",
        "missing_enabled",
        "missing_rules",
        "missing_custom_rules",
        "unknown_config_field",
        "unknown_rule_field",
        "wrong_content_token",
    ] {
        let mut snapshot = serde_json::to_value(mock.snapshot(id)).unwrap();
        match fault {
            "missing_token" => {
                snapshot.as_object_mut().unwrap().remove("config_token");
            }
            "empty_token" => snapshot["config_token"] = json!(""),
            "invalid_token" => snapshot["config_token"] = json!("not-a-token"),
            "wrong_session" => snapshot["session_id"] = json!(mock.state.ids[1]),
            "missing_enabled" => {
                snapshot.as_object_mut().unwrap().remove("enabled");
            }
            "missing_rules" => {
                snapshot.as_object_mut().unwrap().remove("rules");
            }
            "missing_custom_rules" => {
                snapshot.as_object_mut().unwrap().remove("custom_rules");
            }
            "unknown_config_field" => snapshot["future_setting"] = json!(true),
            "unknown_rule_field" => snapshot["custom_rules"][0]["future_setting"] = json!(true),
            "wrong_content_token" => snapshot["enabled"] = json!(false),
            _ => unreachable!(),
        }
        mock.state.faults.lock().unwrap().get_override = Some(snapshot);
        let (code, result) = mock
            .call(
                "scanner.config.set_enabled",
                json!({"enabled":false}),
                Some("--yes"),
            )
            .await;
        assert_ne!(code, 0, "{fault}: {result}");
        mock.assert_requests(id, true, false);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_or_lost_post_response_never_reports_success_or_retries() {
    for fault in ["persistence", "missing_precondition", "lost_response"] {
        let mock = MockApi::new().await;
        let id = mock.state.ids[0];
        {
            let mut faults = mock.state.faults.lock().unwrap();
            match fault {
                "persistence" => {
                    faults.post_error = Some((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        json!({"error":"configuration persistence failed"}),
                    ))
                }
                "missing_precondition" => {
                    faults.post_error = Some((
                        StatusCode::PRECONDITION_REQUIRED,
                        json!({"error":"expected_config_token is required"}),
                    ))
                }
                "lost_response" => faults.lose_post_response = true,
                _ => unreachable!(),
            }
        }
        let (code, result) = mock
            .call(
                "scanner.config.set_enabled",
                json!({"enabled":false}),
                Some("--yes"),
            )
            .await;
        assert_ne!(code, 0, "{result}");
        assert_eq!(result["ok"], false);
        assert_eq!(result["error"]["retryable"], false);
        mock.assert_requests(id, true, true);
        assert_eq!(mock.snapshot(id).config.enabled, fault != "lost_response");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn absent_active_session_and_unknown_explicit_session_stop_safely() {
    let mock = MockApi::new().await;
    mock.state.faults.lock().unwrap().no_active = true;
    let (code, result) = mock
        .call(
            "scanner.config.set_enabled",
            json!({"enabled":false}),
            Some("--yes"),
        )
        .await;
    assert_invalid(code, &result);
    assert_eq!(
        mock.take_requests()
            .iter()
            .map(|request| request.path.as_str())
            .collect::<Vec<_>>(),
        ["/api/settings", "/api/sessions"]
    );
    let unknown = Uuid::new_v4();
    let (code, result) = mock
        .call("scanner.custom.list", json!({"session_id":unknown}), None)
        .await;
    assert_eq!(code, 5, "{result}");
    assert_eq!(result["error"]["details"]["status"], 404);
    mock.assert_requests(unknown, false, false);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_and_call_dry_run_plans_match_for_every_operation() {
    let mock = MockApi::new().await;
    for explicit in [false, true] {
        let id_text = mock.state.ids[1].to_string();
        let create_json = rule("new").to_string();
        let patch_json = json!({"enabled":false,"description":""}).to_string();
        let cases = [
            (
                "scanner.config.get",
                vec!["scanner", "config", "get"],
                json!({}),
                None,
            ),
            (
                "scanner.config.set_enabled",
                vec!["scanner", "config", "set-enabled", "--enabled", "false"],
                json!({"enabled":false}),
                None,
            ),
            (
                "scanner.builtin.set_enabled",
                vec![
                    "scanner",
                    "builtin",
                    "set-enabled",
                    "--id",
                    "header",
                    "--enabled",
                    "false",
                ],
                json!({"id":"header","enabled":false}),
                None,
            ),
            (
                "scanner.custom.list",
                vec!["scanner", "custom", "list"],
                json!({}),
                None,
            ),
            (
                "scanner.custom.get",
                vec!["scanner", "custom", "get", "--id", "middle"],
                json!({"id":"middle"}),
                None,
            ),
            (
                "scanner.custom.create",
                vec!["scanner", "custom", "create", "--stdin"],
                json!({"rule":rule("new")}),
                Some(create_json.as_str()),
            ),
            (
                "scanner.custom.update",
                vec!["scanner", "custom", "update", "--id", "middle", "--stdin"],
                json!({"id":"middle","patch":{"enabled":false,"description":""}}),
                Some(patch_json.as_str()),
            ),
            (
                "scanner.custom.delete",
                vec!["scanner", "custom", "delete", "--id", "middle"],
                json!({"id":"middle"}),
                None,
            ),
        ];
        for (operation, mut args, mut input, stdin) in cases {
            if explicit {
                args.extend(["--session-id", &id_text]);
                input["session_id"] = json!(id_text);
            }
            args.push("--dry-run");
            let (code, direct) = mock.command(&args, stdin).await;
            assert_ok(code, &direct);
            let (code, called) = mock.call(operation, input, Some("--dry-run")).await;
            assert_ok(code, &called);
            assert_eq!(called["data"], direct, "{operation}");
            if direct["requires_confirmation"] == true {
                args.pop();
                let (code, result) = mock.command(&args, stdin).await;
                assert_eq!(code, 2, "{result}");
                assert_eq!(result["error"]["code"], "CONFIRMATION_REQUIRED");
            }
        }
    }
    assert!(mock.take_requests().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn aggregate_limits_are_checked_on_merged_config_before_post() {
    let mock = MockApi::new().await;
    let id = mock.state.ids[0];
    for byte_limit in [false, true] {
        let mut config = ScannerConfig::default();
        let count = if byte_limit { 63 } else { 250 };
        config.custom_rules = (0..count)
            .map(|index| {
                let mut rule = rule(&format!("saved-{index}"));
                if byte_limit {
                    rule["description"] = json!("x".repeat(65536));
                }
                serde_json::from_value(rule).unwrap()
            })
            .collect();
        sniper::scanner::validate_scanner_config(&config).unwrap();
        mock.state
            .configs
            .lock()
            .unwrap()
            .insert(id, config.clone());
        let mut create = rule("one-more");
        if byte_limit {
            create["description"] = json!("x".repeat(65536));
        }
        let (code, result) = mock
            .call(
                "scanner.custom.create",
                json!({"rule":create}),
                Some("--yes"),
            )
            .await;
        assert_invalid(code, &result);
        mock.assert_requests(id, true, false);
        assert_eq!(
            serde_json::to_value(mock.snapshot(id).config).unwrap(),
            serde_json::to_value(config).unwrap()
        );
    }
}
