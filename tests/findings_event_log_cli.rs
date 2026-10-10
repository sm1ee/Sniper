//! These contracts use synthetic, loopback-only API fixtures. No proxy, scanner,
//! captured transaction, or user data directory is opened by this test suite.
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
use uuid::Uuid;

const ROWS: usize = 120;
const OPERATIONS: [&str; 4] = [
    "findings.list",
    "findings.get",
    "findings.count",
    "event_log.list",
];

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecordedRequest {
    method: String,
    path: String,
    query: BTreeMap<String, String>,
    body_len: usize,
}

struct SessionData {
    id: Uuid,
    findings: Vec<Value>,
    events: Vec<Value>,
}

impl SessionData {
    fn new(label: &str) -> Self {
        let findings = (0..ROWS)
            .map(|index| {
                let mut finding = json!({
                    "id": Uuid::new_v4(),
                    "record_id": Uuid::new_v4(),
                    "found_at": "2026-10-08T12:00:00Z",
                    "rule_id": "synthetic-fixture",
                    "severity": "info",
                    "category": "fixture",
                    "title": format!("{label} finding {index}"),
                    "detail": "Synthetic saved finding detail.",
                    "evidence": "Synthetic saved evidence only.",
                    "host": "example.com",
                    "path": format!("/fixture/{index}"),
                });
                if index % 2 == 0 {
                    finding["location"] = json!({"side":"response","section":"headers","line":1});
                }
                finding
            })
            .collect();
        let events = (0..ROWS)
            .map(|index| {
                json!({
                    "id": Uuid::new_v4(),
                    "captured_at": "2026-10-08T12:00:00Z",
                    "level": "info",
                    "source": "fixture",
                    "title": format!("{label} event {index}"),
                    "message": "Synthetic saved event only.",
                })
            })
            .collect();
        Self {
            id: Uuid::new_v4(),
            findings,
            events,
        }
    }

    fn summaries(&self, limit: usize) -> Value {
        Value::Array(
            self.findings
                .iter()
                .take(limit)
                .map(|finding| {
                    let mut summary = finding.clone();
                    summary.as_object_mut().unwrap().remove("detail");
                    summary.as_object_mut().unwrap().remove("evidence");
                    summary
                })
                .collect(),
        )
    }

    fn expected(&self, operation: &str, limit: usize) -> Value {
        match operation {
            "findings.list" => self.summaries(limit),
            "findings.get" => self.findings[0].clone(),
            "findings.count" => json!({"count": ROWS}),
            "event_log.list" => Value::Array(self.events.iter().take(limit).cloned().collect()),
            _ => panic!("unexpected fixture operation {operation}"),
        }
    }

    fn summary(&self, active: bool) -> Value {
        json!({
            "id": self.id,
            "name": "Synthetic session",
            "created_at": "2026-10-08T12:00:00Z",
            "updated_at": "2026-10-08T12:00:00Z",
            "last_opened_at": "2026-10-08T12:00:00Z",
            "request_count": 0,
            "websocket_count": 0,
            "event_count": ROWS,
            "fuzzer_count": 0,
            "rule_count": 0,
            "storage_path": "synthetic-unused-path",
            "active": active,
        })
    }
}

struct MockState {
    settings: Value,
    sessions: [SessionData; 2],
    requests: Mutex<Vec<RecordedRequest>>,
    active_session: Mutex<Uuid>,
    switch_after_discovery: bool,
    discovery_override: Mutex<Option<Value>>,
    resource_error: Mutex<Option<(StatusCode, Value)>>,
}

struct MockApi {
    api: String,
    dir: PathBuf,
    state: Arc<MockState>,
    server: tokio::task::JoinHandle<()>,
}

impl MockApi {
    async fn new(switch_after_discovery: bool) -> Self {
        let dir = std::env::temp_dir().join(format!("sniper-findings-cli-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let sessions = [SessionData::new("original"), SessionData::new("inactive")];
        let active_session = Mutex::new(sessions[0].id);
        let state = Arc::new(MockState {
            settings: json!({
                "runtime_instance_id": Uuid::new_v4(),
                "proxy_addr": "127.0.0.1:0",
                "ui_addr": addr.to_string(),
                "data_dir": dir.to_string_lossy(),
                "max_entries": ROWS,
                "features": ["http_capture", "session_storage", "replay"],
            }),
            sessions,
            requests: Mutex::new(Vec::new()),
            active_session,
            switch_after_discovery,
            discovery_override: Mutex::new(None),
            resource_error: Mutex::new(None),
        });
        // Log every method and path, including unknown routes, so an accidental
        // linked transaction fetch or write cannot disappear behind a 404.
        let app = Router::new()
            .fallback(any(mock_request))
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            api: format!("http://{addr}"),
            dir,
            state,
            server,
        }
    }

    async fn command(&self, args: &[&str]) -> (i32, Value) {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_sniper-cli"));
        command
            .env("SNIPER_DATA_DIR", &self.dir)
            .env_remove("SNIPER_API_ADDR")
            .args(["--output", "compact", "--api", &self.api])
            .args(args)
            .kill_on_drop(true);
        let output = tokio::time::timeout(Duration::from_secs(20), command.output())
            .await
            .expect("fixture CLI timed out")
            .unwrap();
        let value = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
            panic!(
                "invalid CLI JSON for {args:?}: {} / {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
        (output.status.code().unwrap(), value)
    }

    async fn call(&self, operation: &str, input: Value, dry_run: bool) -> (i32, Value) {
        let input = input.to_string();
        let mut args = vec!["call", operation, "--input", &input];
        if dry_run {
            args.push("--dry-run");
        }
        self.command(&args).await
    }

    fn take_requests(&self) -> Vec<RecordedRequest> {
        std::mem::take(&mut *self.state.requests.lock().unwrap())
    }

    fn assert_reads(
        &self,
        operation: &str,
        session: &SessionData,
        limit: Option<usize>,
        implicit: bool,
    ) {
        let requests = self.take_requests();
        let mut paths = vec!["/api/settings".to_string()];
        if implicit {
            paths.push("/api/sessions".to_string());
        }
        paths.push(resource_path(operation, &session.findings[0]["id"]));
        assert_eq!(
            requests
                .iter()
                .map(|request| request.path.clone())
                .collect::<Vec<_>>(),
            paths,
            "only discovery and the requested saved-data read are allowed: {requests:?}"
        );
        for request in &requests {
            assert_eq!(request.method, "GET", "{request:?}");
            assert_eq!(request.body_len, 0, "{request:?}");
        }
        let mut expected = BTreeMap::from([("session_id".to_string(), session.id.to_string())]);
        if let Some(limit) = limit {
            expected.insert("limit".to_string(), limit.to_string());
        }
        assert_eq!(requests.last().unwrap().query, expected);
    }
}

impl Drop for MockApi {
    fn drop(&mut self) {
        self.server.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn resource_path(operation: &str, finding_id: &Value) -> String {
    match operation {
        "findings.list" => "/api/findings".into(),
        "findings.get" => format!("/api/findings/{}", finding_id.as_str().unwrap()),
        "findings.count" => "/api/findings/count".into(),
        "event_log.list" => "/api/event-log".into(),
        _ => panic!("unexpected fixture operation {operation}"),
    }
}

async fn mock_request(State(state): State<Arc<MockState>>, request: Request<Body>) -> Response {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, 1024).await.unwrap();
    let query: BTreeMap<String, String> =
        url::form_urlencoded::parse(parts.uri.query().unwrap_or_default().as_bytes())
            .into_owned()
            .collect();
    let path = parts.uri.path();
    state.requests.lock().unwrap().push(RecordedRequest {
        method: parts.method.to_string(),
        path: path.into(),
        query: query.clone(),
        body_len: body.len(),
    });
    if parts.method != "GET" {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    match path {
        "/api/settings" => return Json(state.settings.clone()).into_response(),
        "/api/sessions" => {
            if let Some(sessions) = state.discovery_override.lock().unwrap().clone() {
                return Json(sessions).into_response();
            }
            let mut active = state.active_session.lock().unwrap();
            let sessions: Vec<_> = state
                .sessions
                .iter()
                .map(|session| session.summary(session.id == *active))
                .collect();
            // Change the active session before the resource read. A correctly
            // pinned CLI must still read and identify the original session.
            if state.switch_after_discovery {
                *active = state.sessions[1].id;
            }
            return Json(sessions).into_response();
        }
        _ => {}
    }
    if let Some((status, payload)) = state.resource_error.lock().unwrap().clone() {
        return (status, Json(payload)).into_response();
    }
    let session_id = query
        .get("session_id")
        .and_then(|id| Uuid::parse_str(id).ok())
        .unwrap_or_else(|| *state.active_session.lock().unwrap());
    let Some(session) = state
        .sessions
        .iter()
        .find(|session| session.id == session_id)
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"session not found","session_id":session_id})),
        )
            .into_response();
    };
    let limit = query
        .get("limit")
        .map(|limit| limit.parse::<usize>().unwrap())
        .unwrap_or(ROWS);
    match path {
        "/api/findings" => Json(session.summaries(limit)).into_response(),
        "/api/findings/count" => Json(json!({"count":session.findings.len()})).into_response(),
        "/api/event-log" => Json(Value::Array(
            session.events.iter().take(limit).cloned().collect(),
        ))
        .into_response(),
        _ => {
            if let Some(id) = path.strip_prefix("/api/findings/") {
                if let Some(finding) = session.findings.iter().find(|finding| finding["id"] == id) {
                    return Json(finding.clone()).into_response();
                }
            }
            StatusCode::NOT_FOUND.into_response()
        }
    }
}

fn assert_envelope(value: &Value, operation: &str, session_id: Uuid, expected: &Value) {
    assert_eq!(value["ok"], true, "{value}");
    assert_eq!(value["operation"], operation);
    assert_eq!(value["schema_version"], "2026-06-22");
    assert_eq!(value["data"], *expected);
    assert_eq!(value["meta"]["session_id"], session_id.to_string());
    assert_eq!(value["warnings"], json!([]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lists_bound_default_reads_and_preserve_direct_and_call_shapes() {
    let mock = MockApi::new(false).await;
    let session = &mock.state.sessions[0];
    for (operation, command) in [
        ("findings.list", "findings"),
        ("event_log.list", "event-log"),
    ] {
        for limit in [None, Some(1), Some(7), Some(101)] {
            let expected_limit = limit.unwrap_or(100);
            let expected = session.expected(operation, expected_limit);
            let limit_text = expected_limit.to_string();
            let mut args = vec![command, "list"];
            if limit.is_some() {
                args.extend(["--limit", &limit_text]);
            }
            let (code, direct) = mock.command(&args).await;
            assert_eq!(code, 0, "{direct}");
            assert_eq!(direct, expected);
            assert_eq!(direct.as_array().unwrap().len(), expected_limit);
            mock.assert_reads(operation, session, Some(expected_limit), true);

            let input = limit.map_or_else(|| json!({}), |limit| json!({"limit":limit}));
            let (code, called) = mock.call(operation, input, false).await;
            assert_eq!(code, 0, "{called}");
            assert_envelope(&called, operation, session.id, &direct);
            mock.assert_reads(operation, session, Some(expected_limit), true);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn null_optional_inputs_keep_legacy_omission_semantics() {
    let mock = MockApi::new(false).await;
    let session = &mock.state.sessions[0];
    for operation in OPERATIONS {
        let mut input = json!({"session_id":null});
        if operation.ends_with(".list") {
            input["limit"] = Value::Null;
        }
        if operation == "findings.get" {
            input["id"] = session.findings[0]["id"].clone();
        }
        let (code, result) = mock.call(operation, input, false).await;
        assert_eq!(code, 0, "{result}");
        assert_envelope(
            &result,
            operation,
            session.id,
            &session.expected(operation, 100),
        );
        mock.assert_reads(
            operation,
            session,
            operation.ends_with(".list").then_some(100),
            true,
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detail_and_count_preserve_api_data_without_fetching_linked_transactions() {
    let mock = MockApi::new(false).await;
    let session = &mock.state.sessions[0];
    for operation in ["findings.get", "findings.count"] {
        let mut args = vec!["findings", operation.split('.').nth(1).unwrap()];
        let mut input = json!({});
        if operation == "findings.get" {
            args.extend(["--id", session.findings[0]["id"].as_str().unwrap()]);
            input["id"] = session.findings[0]["id"].clone();
        }
        let expected = session.expected(operation, 100);
        let (code, direct) = mock.command(&args).await;
        assert_eq!(code, 0, "{direct}");
        assert_eq!(direct, expected);
        mock.assert_reads(operation, session, None, true);
        let (code, called) = mock.call(operation, input, false).await;
        assert_eq!(code, 0, "{called}");
        assert_envelope(&called, operation, session.id, &direct);
        mock.assert_reads(operation, session, None, true);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_inactive_session_skips_session_discovery_for_every_read() {
    let mock = MockApi::new(false).await;
    let session = &mock.state.sessions[1];
    let session_text = session.id.to_string();
    for operation in OPERATIONS {
        let (command, action) = operation.split_once('.').unwrap();
        let command = command.replace('_', "-");
        let mut args = vec![command.as_str(), action, "--session-id", &session_text];
        let mut input = json!({"session_id":session.id});
        if operation == "findings.get" {
            args.extend(["--id", session.findings[0]["id"].as_str().unwrap()]);
            input["id"] = session.findings[0]["id"].clone();
        }
        let limit = operation.ends_with(".list").then_some(100);
        let expected = session.expected(operation, 100);
        let (code, direct) = mock.command(&args).await;
        assert_eq!(code, 0, "{direct}");
        assert_eq!(direct, expected);
        mock.assert_reads(operation, session, limit, false);
        let (code, called) = mock.call(operation, input, false).await;
        assert_eq!(code, 0, "{called}");
        assert_envelope(&called, operation, session.id, &expected);
        mock.assert_reads(operation, session, limit, false);
        assert_eq!(
            *mock.state.active_session.lock().unwrap(),
            mock.state.sessions[0].id
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn implicit_session_is_resolved_once_and_stays_pinned_across_active_switch() {
    for operation in OPERATIONS {
        for call in [false, true] {
            let mock = MockApi::new(true).await;
            let original = &mock.state.sessions[0];
            let (command, action) = operation.split_once('.').unwrap();
            let command = command.replace('_', "-");
            let mut args = vec![command.as_str(), action];
            let mut input = json!({});
            if operation == "findings.get" {
                args.extend(["--id", original.findings[0]["id"].as_str().unwrap()]);
                input["id"] = original.findings[0]["id"].clone();
            }
            let (code, result) = if call {
                mock.call(operation, input, false).await
            } else {
                mock.command(&args).await
            };
            assert_eq!(code, 0, "{result}");
            let expected = original.expected(operation, 100);
            if call {
                assert_envelope(&result, operation, original.id, &expected);
            } else {
                assert_eq!(result, expected);
            }
            assert_eq!(
                *mock.state.active_session.lock().unwrap(),
                mock.state.sessions[1].id
            );
            mock.assert_reads(
                operation,
                original,
                operation.ends_with(".list").then_some(100),
                true,
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_inputs_fail_locally_before_any_api_or_discovery_request() {
    let mock = MockApi::new(false).await;
    let id = mock.state.sessions[0].findings[0]["id"].clone();
    for operation in OPERATIONS {
        let valid = if operation == "findings.get" {
            json!({"id":id})
        } else {
            json!({})
        };
        let mut cases = vec![json!([]), json!("invalid"), json!(null)];
        for (field, value) in [
            ("unexpected", json!(true)),
            ("session_id", json!("not-a-uuid")),
            ("session_id", json!(123)),
            ("session_id", json!([])),
        ] {
            let mut input = valid.clone();
            input[field] = value;
            cases.push(input);
        }
        if operation.ends_with(".list") {
            for limit in [json!(0), json!(-1), json!(1.5), json!("7"), json!(true)] {
                cases.push(json!({"limit":limit}));
            }
        } else {
            let mut input = valid.clone();
            input["limit"] = json!(10);
            cases.push(input);
        }
        if operation == "findings.get" {
            cases.extend([
                json!({}),
                json!({"id":null}),
                json!({"id":"not-a-uuid"}),
                json!({"id":42}),
            ]);
        }
        for input in cases {
            let (code, result) = mock.call(operation, input.clone(), false).await;
            assert_eq!(code, 2, "{operation} {input}: {result}");
            assert_eq!(result["ok"], false);
            assert_eq!(result["operation"], operation);
            assert_eq!(result["schema_version"], "2026-06-22");
            assert_eq!(result["error"]["code"], "INVALID_INPUT");
            assert_eq!(result["error"]["retryable"], false);
            assert!(
                mock.take_requests().is_empty(),
                "invalid input must not access the API"
            );
        }
    }
    for args in [
        vec!["findings", "list", "--limit", "0"],
        vec!["findings", "list", "--limit=-1"],
        vec!["event-log", "list", "--limit", "0"],
        vec!["event-log", "list", "--limit", "1.5"],
        vec!["findings", "get"],
        vec!["findings", "get", "--id", "not-a-uuid"],
        vec!["findings", "count", "--session-id", "not-a-uuid"],
        vec!["event-log", "list", "--session-id", "not-a-uuid"],
    ] {
        let (code, result) = mock.command(&args).await;
        assert_eq!(code, 2, "{args:?}: {result}");
        assert_eq!(result["error"]["code"], "INVALID_INPUT");
        assert!(mock.take_requests().is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dry_runs_are_get_only_plans_and_never_discover_or_read_api_data() {
    let mock = MockApi::new(false).await;
    let session = &mock.state.sessions[0];
    for operation in OPERATIONS {
        for explicit in [false, true] {
            let (command, action) = operation.split_once('.').unwrap();
            let command = command.replace('_', "-");
            let session_text = session.id.to_string();
            let mut args = vec![command.as_str(), action, "--dry-run"];
            let mut input = json!({});
            if explicit {
                args.extend(["--session-id", &session_text]);
                input["session_id"] = json!(session.id);
            }
            if operation == "findings.get" {
                args.extend(["--id", session.findings[0]["id"].as_str().unwrap()]);
                input["id"] = session.findings[0]["id"].clone();
            }
            let (code, direct) = mock.command(&args).await;
            assert_eq!(code, 0, "{direct}");
            let (code, called) = mock.call(operation, input, true).await;
            assert_eq!(code, 0, "{called}");
            assert_eq!(called["ok"], true);
            assert_eq!(called["schema_version"], "2026-06-22");
            assert_eq!(called["data"], direct);
            assert_eq!(direct["dry_run"], true);
            assert_eq!(direct["operation"], operation);
            assert_eq!(direct["side_effect"], "read");
            assert_eq!(direct["requires_confirmation"], false);
            assert_eq!(direct["api"]["method"], "GET");
            let preview = direct["api"]["path"].as_str().unwrap();
            let url = url::Url::parse(&format!("http://example.com{preview}")).unwrap();
            assert_eq!(
                url.path(),
                resource_path(operation, &session.findings[0]["id"])
            );
            let query: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
            assert_eq!(query.get("session_id"), explicit.then_some(&session_text));
            if operation.ends_with(".list") {
                assert_eq!(query.get("limit").map(String::as_str), Some("100"));
            }
            assert!(
                mock.take_requests().is_empty(),
                "dry run must not even probe the API"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_finding_and_resource_failures_keep_structured_error_envelopes() {
    let mock = MockApi::new(false).await;
    let session = &mock.state.sessions[1];
    let session_text = session.id.to_string();
    let missing = Uuid::new_v4().to_string();
    for call in [false, true] {
        let (code, result) = if call {
            mock.call(
                "findings.get",
                json!({"id":missing,"session_id":session.id}),
                false,
            )
            .await
        } else {
            mock.command(&[
                "findings",
                "get",
                "--id",
                &missing,
                "--session-id",
                &session_text,
            ])
            .await
        };
        assert_eq!(code, 5, "{result}");
        assert_eq!(result["ok"], false);
        assert_eq!(result["operation"], "findings.get");
        assert_eq!(result["schema_version"], "2026-06-22");
        assert_eq!(result["error"]["code"], "HTTP_STATUS_ERROR");
        assert_eq!(result["error"]["details"]["status"], 404);
        assert_eq!(result["error"]["retryable"], false);
        let requests = mock.take_requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].path, "/api/settings");
        assert_eq!(requests[1].path, format!("/api/findings/{missing}"));
        assert!(requests.iter().all(|request| request.method == "GET"));
    }
    for operation in OPERATIONS {
        *mock.state.resource_error.lock().unwrap() = Some((
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"synthetic unavailable"}),
        ));
        let mut input = json!({"session_id":session.id});
        if operation == "findings.get" {
            input["id"] = session.findings[0]["id"].clone();
        }
        let (code, result) = mock.call(operation, input, false).await;
        assert_eq!(code, 6, "{result}");
        assert_eq!(result["ok"], false);
        assert_eq!(result["error"]["code"], "HTTP_STATUS_ERROR");
        assert_eq!(result["error"]["details"]["status"], 503);
        assert_eq!(result["error"]["retryable"], true);
        mock.assert_reads(
            operation,
            session,
            operation.ends_with(".list").then_some(100),
            false,
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_resource_data_fails_without_a_fallback_read() {
    let mock = MockApi::new(false).await;
    let session = &mock.state.sessions[1];
    for operation in OPERATIONS {
        let invalid = match operation {
            "findings.list" | "event_log.list" => json!([{"id":"not-a-uuid"}]),
            "findings.get" => json!({"id":session.findings[0]["id"]}),
            "findings.count" => json!({"count":-1}),
            _ => unreachable!(),
        };
        *mock.state.resource_error.lock().unwrap() = Some((StatusCode::OK, invalid));
        let mut input = json!({"session_id":session.id});
        if operation == "findings.get" {
            input["id"] = session.findings[0]["id"].clone();
        }
        let (code, result) = mock.call(operation, input, false).await;
        assert_ne!(code, 0, "{result}");
        assert_eq!(result["ok"], false);
        assert_eq!(result["operation"], operation);
        assert_eq!(result["schema_version"], "2026-06-22");
        assert!(result["error"]["code"].is_string());
        assert!(result.get("data").is_none());
        mock.assert_reads(
            operation,
            session,
            operation.ends_with(".list").then_some(100),
            false,
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_lists_and_zero_count_are_successful_api_shapes() {
    let mock = MockApi::new(false).await;
    let session = &mock.state.sessions[1];
    let session_text = session.id.to_string();
    for operation in ["findings.list", "findings.count", "event_log.list"] {
        let expected = if operation.ends_with(".list") {
            json!([])
        } else {
            json!({"count":0})
        };
        *mock.state.resource_error.lock().unwrap() = Some((StatusCode::OK, expected.clone()));
        let (command, action) = operation.split_once('.').unwrap();
        let command = command.replace('_', "-");
        let (code, direct) = mock
            .command(&[&command, action, "--session-id", &session_text])
            .await;
        assert_eq!(code, 0, "{direct}");
        assert_eq!(direct, expected);
        mock.assert_reads(
            operation,
            session,
            operation.ends_with(".list").then_some(100),
            false,
        );
        let (code, called) = mock
            .call(operation, json!({"session_id":session.id}), false)
            .await;
        assert_eq!(code, 0, "{called}");
        assert_envelope(&called, operation, session.id, &expected);
        mock.assert_reads(
            operation,
            session,
            operation.ends_with(".list").then_some(100),
            false,
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_reads_do_not_forward_unknown_raw_transaction_fields() {
    let mock = MockApi::new(false).await;
    let session = &mock.state.sessions[1];
    for operation in OPERATIONS {
        let expected = session.expected(operation, 1);
        let mut wire = expected.clone();
        let record = if wire.is_array() {
            &mut wire[0]
        } else {
            &mut wire
        };
        record["request"] = json!({"body":"SYNTHETIC_RAW_BODY_MARKER"});
        record["response"] = json!({"body":"SYNTHETIC_RAW_BODY_MARKER"});
        record["raw_transaction"] = json!("SYNTHETIC_RAW_BODY_MARKER");
        *mock.state.resource_error.lock().unwrap() = Some((StatusCode::OK, wire));
        let mut input = json!({"session_id":session.id});
        if operation.ends_with(".list") {
            input["limit"] = json!(1);
        }
        if operation == "findings.get" {
            input["id"] = session.findings[0]["id"].clone();
        }
        let (code, result) = mock.call(operation, input, false).await;
        assert_eq!(code, 0, "{result}");
        assert_envelope(&result, operation, session.id, &expected);
        assert!(!result.to_string().contains("SYNTHETIC_RAW_BODY_MARKER"));
        mock.assert_reads(
            operation,
            session,
            operation.ends_with(".list").then_some(1),
            false,
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn absent_or_ambiguous_active_session_fails_before_resource_read() {
    let mock = MockApi::new(false).await;
    for sessions in [
        json!([]),
        json!([mock.state.sessions[0].summary(false)]),
        json!([
            mock.state.sessions[0].summary(true),
            mock.state.sessions[1].summary(true)
        ]),
    ] {
        *mock.state.discovery_override.lock().unwrap() = Some(sessions);
        for operation in OPERATIONS {
            let input = if operation == "findings.get" {
                json!({"id":mock.state.sessions[0].findings[0]["id"]})
            } else {
                json!({})
            };
            let (code, result) = mock.call(operation, input, false).await;
            assert_ne!(code, 0, "{result}");
            assert_eq!(result["ok"], false);
            assert_eq!(result["error"]["code"], "INVALID_INPUT");
            assert_eq!(result["error"]["retryable"], false);
            let requests = mock.take_requests();
            assert_eq!(
                requests
                    .iter()
                    .map(|request| request.path.as_str())
                    .collect::<Vec<_>>(),
                ["/api/settings", "/api/sessions"]
            );
            assert!(requests.iter().all(|request| request.method == "GET"));
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discovery_exposes_only_stage_one_reads_without_contacting_api() {
    let mock = MockApi::new(false).await;
    let (code, manifest) = mock.command(&["manifest"]).await;
    assert_eq!(code, 0, "{manifest}");
    let operations = manifest["operations"].as_array().unwrap();
    let names: Vec<_> = operations
        .iter()
        .filter_map(|operation| operation["operation"].as_str())
        .filter(|operation| {
            operation.starts_with("findings.") || operation.starts_with("event_log.")
        })
        .collect();
    assert_eq!(names.len(), OPERATIONS.len());
    for operation in OPERATIONS {
        let spec = operations
            .iter()
            .find(|spec| spec["operation"] == operation)
            .unwrap();
        assert_eq!(spec["side_effect"], "read");
        assert_eq!(spec["requires_confirmation"], false);
        assert_eq!(spec["input_schema"]["type"], "object");
        assert_eq!(spec["input_schema"]["additionalProperties"], false);
        let session_id_schema = &spec["input_schema"]["properties"]["session_id"];
        assert!(session_id_schema.get("format").is_none());
        assert_eq!(session_id_schema["type"], json!(["string", "null"]));
        assert!(session_id_schema["description"]
            .as_str()
            .unwrap()
            .contains("urn:uuid:"));
        let (code, schema) = mock.command(&["schema", "input", operation]).await;
        assert_eq!(code, 0, "{schema}");
        assert_eq!(schema["schema"], spec["input_schema"]);
        let (code, schema) = mock.command(&["schema", "output", operation]).await;
        assert_eq!(code, 0, "{schema}");
        assert_eq!(schema["schema"], spec["output_schema"]);
        let output_schema = &schema["schema"];
        if operation.ends_with(".list") {
            assert_eq!(output_schema["type"], "array");
            assert_eq!(output_schema["items"]["type"], "object");
        } else {
            assert_eq!(output_schema["type"], "object");
        }
        if operation == "findings.count" {
            assert!(output_schema["required"]
                .as_array()
                .unwrap()
                .contains(&json!("count")));
            assert_eq!(output_schema["properties"]["count"]["type"], "integer");
            assert_eq!(output_schema["properties"]["count"]["minimum"], 0);
        }
        let record_schema = if operation.ends_with(".list") {
            &output_schema["items"]
        } else {
            output_schema
        };
        for field in ["detail", "evidence"] {
            assert_eq!(
                record_schema["required"]
                    .as_array()
                    .unwrap()
                    .contains(&json!(field)),
                operation == "findings.get",
                "{operation}: {field} is required only for finding detail"
            );
            if operation == "findings.list" {
                assert!(record_schema["properties"].get(field).is_none());
            }
        }
        let (code, examples) = mock.command(&["examples", operation]).await;
        assert_eq!(code, 0, "{examples}");
        assert!(examples["examples"]
            .as_array()
            .is_some_and(|examples| !examples.is_empty()));
    }
    assert!(mock.take_requests().is_empty());
}
