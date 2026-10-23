//! Synthetic loopback API only: these tests never crawl, query a provider, or
//! open a real Sniper session. Each allowed request is asserted explicitly.
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

const SESSION: &str = "11111111-1111-4111-8111-111111111111";
const JOB: &str = "22222222-2222-4222-8222-222222222222";
const OTHER_SESSION: &str = "33333333-3333-4333-8333-333333333333";
const PRIVATE: &str = "synthetic-provider-sensitive-marker";
const OPERATIONS: [&str; 3] = ["recon.list", "recon.start", "recon.stop"];

fn start_input() -> Value {
    json!({"session_id":SESSION,"target_url":"https://example.com/","sources":["crawler"]})
}

fn start_body() -> Value {
    json!({
        "session_id":SESSION,"target_url":"https://example.com/",
        "sources":["crawler"],"include_subdomains":false,
        "max_requests":0,"max_depth":0,"max_endpoints":0,"max_pages":0,
        "history_acknowledged":false,"scan_acknowledged":false,"scan_visibility":null
    })
}

fn job(status: &str) -> Value {
    json!({
        "id":JOB,"target_url":"https://example.com/","status":status,
        "started_at":"2026-10-20T00:00:00Z","finished_at":null,"error":null,
        "sources":[{
            "source":"crawler","status":"running","requests":1,
            "discovered":1,"truncated":false,"warnings":[]
        }]
    })
}

fn inventory() -> Value {
    json!({
        "session_id":SESSION,"jobs":[job("running")],
        "endpoints":[{
            "url":"https://example.com/path?item=synthetic",
            "method":"GET","raw_urls":["https://example.com/path?item=synthetic#fragment"],
            "evidence":[{
                "source":"crawler","kind":"observed","location":"https://example.com/",
                "timestamp":null,"status":null
            }],
            "first_seen":"2026-10-20T00:00:00Z","last_seen":"2026-10-20T00:00:00Z"
        }]
    })
}

#[derive(Clone, Debug, PartialEq)]
struct Request {
    method: String,
    path: String,
    query: BTreeMap<String, String>,
    body: Option<Value>,
}

#[derive(Clone)]
enum Reply {
    Json(Value),
    Http(u16, Value),
    Raw(String),
    Redirect(u16),
    Disconnect,
}

#[derive(Default)]
struct Faults {
    read: Option<Reply>,
    write: Option<Reply>,
}

struct Fixture {
    api: String,
    root: PathBuf,
    requests: Arc<Mutex<Vec<Request>>>,
    faults: Arc<Mutex<Faults>>,
    server: tokio::task::JoinHandle<()>,
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> Request {
    let mut bytes = Vec::new();
    let header_end = loop {
        assert!(bytes.len() < 32 * 1024);
        assert_ne!(stream.read_buf(&mut bytes).await.unwrap(), 0);
        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break end + 4;
        }
    };
    let headers = std::str::from_utf8(&bytes[..header_end]).unwrap();
    let mut lines = headers.lines();
    let mut first = lines.next().unwrap().split_whitespace();
    let method = first.next().unwrap().to_owned();
    let raw_path = first.next().unwrap().to_owned();
    let (path, query) = raw_path.split_once('?').unwrap_or((&raw_path, ""));
    let path = path.to_owned();
    let query = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    let length = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse::<usize>().unwrap())
        .unwrap_or(0);
    assert!(length < 16 * 1024);
    while bytes.len() < header_end + length {
        assert_ne!(stream.read_buf(&mut bytes).await.unwrap(), 0);
    }
    let body = (length > 0)
        .then(|| serde_json::from_slice(&bytes[header_end..header_end + length]).unwrap());
    Request {
        method,
        path,
        query,
        body,
    }
}

impl Fixture {
    async fn new() -> Self {
        let root = std::env::temp_dir().join(format!("sniper-recon-cli-{}", Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let settings = json!({
            "runtime_instance_id":Uuid::new_v4(),"proxy_addr":"127.0.0.1:0",
            "ui_addr":addr.to_string(),"data_dir":root.join("data").to_string_lossy(),
            "max_entries":100,"features":["http_capture","session_storage","replay"]
        });
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let faults = Arc::new(Mutex::new(Faults::default()));
        let server_faults = faults.clone();
        let server = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request =
                    tokio::time::timeout(Duration::from_secs(5), read_request(&mut stream))
                        .await
                        .unwrap();
                recorded.lock().unwrap().push(request.clone());
                let reply = {
                    let faults = server_faults.lock().unwrap();
                    match (request.method.as_str(), request.path.as_str()) {
                        ("GET", "/api/settings") => Reply::Json(settings.clone()),
                        ("GET", "/api/recon") => faults
                            .read
                            .clone()
                            .unwrap_or_else(|| Reply::Json(inventory())),
                        ("POST", "/api/recon/jobs") => faults.write.clone().unwrap_or_else(|| {
                            let body = request.body.as_ref().unwrap();
                            let mut accepted = job("running");
                            accepted["target_url"] = body["target_url"].clone();
                            accepted["sources"] = json!(body["sources"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|source| {
                                    let mut status = job("running")["sources"][0].clone();
                                    status["source"] = source.clone();
                                    status
                                })
                                .collect::<Vec<_>>());
                            Reply::Json(accepted)
                        }),
                        ("POST", path) if path == format!("/api/recon/jobs/{JOB}/stop") => {
                            faults.write.clone().unwrap_or_else(|| {
                                Reply::Json(json!({"stopped":true,"session_id":SESSION}))
                            })
                        }
                        _ => Reply::Http(405, json!({"error":"outside synthetic Recon allowlist"})),
                    }
                };
                let (status, body, location) = match reply {
                    Reply::Json(value) => (200, value.to_string(), String::new()),
                    Reply::Http(status, value) => (status, value.to_string(), String::new()),
                    Reply::Raw(body) => (200, body, String::new()),
                    Reply::Redirect(status) => (
                        status,
                        json!({"error":PRIVATE}).to_string(),
                        format!("Location: /must-not-follow?token={PRIVATE}\r\n"),
                    ),
                    Reply::Disconnect => continue,
                };
                let response = format!(
                    "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{location}Connection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
        Self {
            api: format!("http://{addr}"),
            root,
            requests,
            faults,
            server,
        }
    }

    async fn run(&self, args: &[&str]) -> (i32, Value) {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_sniper-cli"));
        command
            .env("SNIPER_DATA_DIR", self.root.join("data"))
            .env_remove("SNIPER_API_ADDR")
            .env_remove("HTTP_PROXY")
            .env_remove("HTTPS_PROXY")
            .env_remove("ALL_PROXY")
            .env_remove("http_proxy")
            .env_remove("https_proxy")
            .env_remove("all_proxy")
            .args(["--output", "compact", "--api", &self.api])
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let output = tokio::time::timeout(Duration::from_secs(15), command.output())
            .await
            .expect("synthetic Recon CLI timed out")
            .unwrap();
        let value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "{args:?}: {error}; stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
        assert_eq!(
            std::fs::read_dir(&self.root).unwrap().count(),
            0,
            "Recon CLI must not create a session or alter local state"
        );
        (output.status.code().unwrap(), value)
    }

    async fn call(&self, operation: &str, input: Value, flag: Option<&str>) -> (i32, Value) {
        let input = input.to_string();
        let mut args = vec!["call", operation, "--input", &input];
        if let Some(flag) = flag {
            args.push(flag);
        }
        self.run(&args).await
    }

    fn take_requests(&self) -> Vec<Request> {
        std::mem::take(&mut *self.requests.lock().unwrap())
    }

    fn assert_requests(&self, method: &str, path: &str, body: Option<Value>) {
        let query = if method == "GET" {
            BTreeMap::from([("session_id".into(), SESSION.into())])
        } else {
            BTreeMap::new()
        };
        assert_eq!(
            self.take_requests(),
            [
                Request {
                    method: "GET".into(),
                    path: "/api/settings".into(),
                    query: BTreeMap::new(),
                    body: None,
                },
                Request {
                    method: method.into(),
                    path: path.into(),
                    query,
                    body,
                },
            ],
            "Only discovery and one explicit Recon request are allowed; never poll, retry, or switch sessions"
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn success(result: (i32, Value), call: bool) -> Value {
    assert_eq!(result.0, 0, "{result:?}");
    if call {
        assert_eq!(result.1["ok"], true, "{result:?}");
        result.1["data"].clone()
    } else {
        result.1
    }
}

fn failure(result: (i32, Value)) -> Value {
    assert_ne!(result.0, 0, "{result:?}");
    assert_eq!(result.1["ok"], false, "{result:?}");
    assert!(result.1["error"]["code"].is_string(), "{result:?}");
    result.1
}

fn recon_failure(result: (i32, Value), write: bool) -> Value {
    let error = failure(result);
    assert_eq!(error["error"]["retryable"], false, "{error}");
    assert_eq!(
        error["error"]["details"]["outcome"],
        if write { "unknown" } else { "not_applied" },
        "{error}"
    );
    assert!(!error.to_string().contains(PRIVATE), "{error}");
    error
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recon_discovery_is_offline_and_examples_are_executable_plans() {
    let fixture = Fixture::new().await;
    let manifest = success(fixture.run(&["manifest"]).await, false);
    for operation in OPERATIONS {
        let spec = manifest["operations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|spec| spec["operation"] == operation)
            .unwrap_or_else(|| panic!("{operation} missing from manifest"));
        let write = operation != "recon.list";
        assert_eq!(spec["requires_confirmation"], write);
        assert_eq!(spec["side_effect"], if write { "write" } else { "read" });
        for kind in ["input", "output"] {
            let discovery = success(fixture.run(&["schema", kind, operation]).await, false);
            assert_eq!(discovery["schema"], spec[format!("{kind}_schema")]);
            assert_eq!(discovery["schema"]["type"], "object");
            assert!(discovery["schema"]["properties"].is_object());
        }
        assert_eq!(spec["input_schema"]["additionalProperties"], false);
        assert!(spec["input_schema"]["required"]
            .as_array()
            .unwrap()
            .contains(&json!("session_id")));
        assert_eq!(
            spec["input_schema"]["properties"]["session_id"]["format"],
            "uuid"
        );
        let examples = success(fixture.run(&["examples", operation]).await, false);
        assert_eq!(examples["examples"], spec["examples"]);
        assert!(!examples["examples"].as_array().unwrap().is_empty());
        for example in examples["examples"].as_array().unwrap() {
            let plan = success(
                fixture
                    .call(operation, example.clone(), Some("--dry-run"))
                    .await,
                true,
            );
            assert_eq!(plan["operation"], operation);
            assert_eq!(plan["requires_confirmation"], write);
        }
    }
    assert!(fixture.take_requests().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recon_list_preserves_inventory_and_explicit_session_in_both_entrypoints() {
    let fixture = Fixture::new().await;
    let direct = success(
        fixture
            .run(&["recon", "list", "--session-id", SESSION])
            .await,
        false,
    );
    assert_eq!(direct, inventory());
    fixture.assert_requests("GET", "/api/recon", None);
    let called = fixture
        .call("recon.list", json!({"session_id":SESSION}), None)
        .await;
    assert_eq!(called.1["meta"]["session_id"], SESSION);
    assert_eq!(success(called, true), direct);
    fixture.assert_requests("GET", "/api/recon", None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recon_start_and_stop_are_single_explicit_writes_without_polling() {
    let fixture = Fixture::new().await;
    let start = [
        "recon",
        "start",
        "--session-id",
        SESSION,
        "--target-url",
        "https://example.com/",
        "--source",
        "crawler",
        "--yes",
    ];
    let direct = success(fixture.run(&start).await, false);
    assert_eq!(direct, job("running"));
    fixture.assert_requests("POST", "/api/recon/jobs", Some(start_body()));
    let called = fixture
        .call("recon.start", start_input(), Some("--yes"))
        .await;
    assert_eq!(called.1["meta"]["session_id"], SESSION);
    assert_eq!(success(called, true), direct);
    fixture.assert_requests("POST", "/api/recon/jobs", Some(start_body()));
    let stop_path = format!("/api/recon/jobs/{JOB}/stop");
    let direct = success(
        fixture
            .run(&[
                "recon",
                "stop",
                "--session-id",
                SESSION,
                "--id",
                JOB,
                "--yes",
            ])
            .await,
        false,
    );
    assert_eq!(direct, json!({"stopped":true,"session_id":SESSION}));
    fixture.assert_requests("POST", &stop_path, Some(json!({"session_id":SESSION})));
    let called = fixture
        .call(
            "recon.stop",
            json!({"session_id":SESSION,"id":JOB}),
            Some("--yes"),
        )
        .await;
    assert_eq!(called.1["meta"]["session_id"], SESSION);
    assert_eq!(success(called, true), direct);
    fixture.assert_requests("POST", &stop_path, Some(json!({"session_id":SESSION})));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recon_provider_consent_and_collection_budgets_have_call_flag_parity() {
    let fixture = Fixture::new().await;
    let mut input = start_body();
    input["sources"] = json!(["crawler", "urlscan", "wayback", "urlscan_submit"]);
    input["include_subdomains"] = json!(true);
    input["max_requests"] = json!(12);
    input["max_depth"] = json!(3);
    input["max_endpoints"] = json!(40);
    input["max_pages"] = json!(2);
    input["history_acknowledged"] = json!(true);
    input["scan_acknowledged"] = json!(true);
    input["scan_visibility"] = json!("private");
    let called = success(
        fixture
            .call("recon.start", input.clone(), Some("--yes"))
            .await,
        true,
    );
    fixture.assert_requests("POST", "/api/recon/jobs", Some(input.clone()));
    let direct = success(
        fixture
            .run(&[
                "recon",
                "start",
                "--session-id",
                SESSION,
                "--target-url",
                "https://example.com/",
                "--source",
                "crawler",
                "--source",
                "urlscan",
                "--source",
                "wayback",
                "--source",
                "urlscan_submit",
                "--include-subdomains",
                "--max-requests",
                "12",
                "--max-depth",
                "3",
                "--max-endpoints",
                "40",
                "--max-pages",
                "2",
                "--history-acknowledged",
                "--scan-acknowledged",
                "--scan-visibility",
                "private",
                "--yes",
            ])
            .await,
        false,
    );
    assert_eq!(called, direct);
    fixture.assert_requests("POST", "/api/recon/jobs", Some(input));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recon_confirmation_and_dry_runs_contact_nothing() {
    let fixture = Fixture::new().await;
    for (operation, input, args, method, path, body) in [
        (
            "recon.start",
            start_input(),
            vec![
                "recon",
                "start",
                "--session-id",
                SESSION,
                "--target-url",
                "https://example.com/",
                "--source",
                "crawler",
            ],
            "POST",
            "/api/recon/jobs".to_owned(),
            start_body(),
        ),
        (
            "recon.stop",
            json!({"session_id":SESSION,"id":JOB}),
            vec!["recon", "stop", "--session-id", SESSION, "--id", JOB],
            "POST",
            format!("/api/recon/jobs/{JOB}/stop"),
            json!({"session_id":SESSION}),
        ),
    ] {
        assert_eq!(
            failure(fixture.run(&args).await)["error"]["code"],
            "CONFIRMATION_REQUIRED"
        );
        assert_eq!(
            failure(fixture.call(operation, input.clone(), None).await)["error"]["code"],
            "CONFIRMATION_REQUIRED"
        );
        let mut preview = args;
        preview.push("--dry-run");
        let direct = success(fixture.run(&preview).await, false);
        let called = success(
            fixture.call(operation, input, Some("--dry-run")).await,
            true,
        );
        assert_eq!(called, direct);
        assert_eq!(direct["dry_run"], true);
        assert_eq!(direct["api"]["method"], method);
        assert_eq!(direct["api"]["path"], path);
        assert_eq!(direct["api"]["body"], body);
    }
    assert!(fixture.take_requests().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recon_rejects_invalid_or_unacknowledged_call_input_before_discovery() {
    let fixture = Fixture::new().await;
    let mut cases = vec![
        ("recon.list", json!({})),
        ("recon.list", json!({"session_id":null})),
        (
            "recon.list",
            json!({"session_id":SESSION,"unexpected":true}),
        ),
        ("recon.stop", json!({"session_id":SESSION})),
        ("recon.stop", json!({"session_id":SESSION,"id":null})),
        (
            "recon.stop",
            json!({"session_id":SESSION,"id":"not-a-uuid"}),
        ),
    ];
    for (field, value) in [
        ("session_id", Value::Null),
        ("target_url", json!("relative/path")),
        ("target_url", json!("ftp://example.com/")),
        (
            "target_url",
            json!("https://user:synthetic-secret@example.com/"),
        ),
        ("target_url", json!("https://example.com:0/")),
        ("sources", json!([])),
        ("sources", json!(["crawler", "crawler"])),
        ("sources", json!(["unknown"])),
        ("sources", json!(["urlscan"])),
        ("sources", json!(["wayback"])),
        ("sources", json!(["urlscan_submit"])),
        ("sources", Value::Null),
        ("sources", json!("crawler")),
        ("max_requests", json!(-1)),
        ("max_depth", json!(1.5)),
        ("max_endpoints", Value::Null),
        ("max_pages", json!("2")),
        ("include_subdomains", Value::Null),
        ("history_acknowledged", Value::Null),
        ("scan_acknowledged", Value::Null),
        ("scan_visibility", json!("unsupported")),
        ("unexpected", json!(true)),
    ] {
        let mut input = start_input();
        input[field] = value;
        cases.push(("recon.start", input));
    }
    for missing in ["session_id", "target_url", "sources"] {
        let mut input = start_input();
        input.as_object_mut().unwrap().remove(missing);
        cases.push(("recon.start", input));
    }
    for target in [
        "https://example.com/?token=synthetic",
        "https://example.com/#synthetic",
    ] {
        let mut input = start_input();
        input["target_url"] = json!(target);
        input["sources"] = json!(["urlscan_submit"]);
        input["scan_acknowledged"] = json!(true);
        input["scan_visibility"] = json!("private");
        cases.push(("recon.start", input));
    }
    for (operation, input) in cases {
        for flag in ["--dry-run", "--yes"] {
            let result = failure(fixture.call(operation, input.clone(), Some(flag)).await);
            assert_eq!(result["operation"], operation);
            assert!(
                !result.to_string().contains("synthetic-secret"),
                "Rejected target credentials must not appear in errors"
            );
        }
    }
    assert!(fixture.take_requests().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recon_invalid_flags_and_missing_scope_cannot_contact_the_api() {
    let fixture = Fixture::new().await;
    for args in [
        vec!["recon", "list", "--dry-run"],
        vec!["recon", "stop", "--session-id", SESSION, "--dry-run"],
        vec![
            "recon",
            "start",
            "--session-id",
            SESSION,
            "--source",
            "crawler",
            "--dry-run",
        ],
        vec![
            "recon",
            "start",
            "--session-id",
            SESSION,
            "--target-url",
            "https://example.com/",
            "--dry-run",
        ],
        vec![
            "recon",
            "start",
            "--session-id",
            SESSION,
            "--target-url",
            "https://example.com/",
            "--source",
            "crawler",
            "--source",
            "crawler",
            "--yes",
        ],
        vec![
            "recon",
            "start",
            "--session-id",
            SESSION,
            "--target-url",
            "https://example.com/",
            "--source",
            "urlscan",
            "--yes",
        ],
        vec![
            "recon",
            "start",
            "--session-id",
            SESSION,
            "--target-url",
            "https://example.com/",
            "--source",
            "urlscan_submit",
            "--scan-acknowledged",
            "--yes",
        ],
        vec![
            "recon",
            "start",
            "--session-id",
            SESSION,
            "--target-url",
            "http://127.0.0.1/",
            "--source",
            "crawler",
            "--include-subdomains",
            "--yes",
        ],
    ] {
        failure(fixture.run(&args).await);
    }
    assert!(fixture.take_requests().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recon_failed_or_lost_writes_are_never_repeated_or_polled() {
    let fixture = Fixture::new().await;
    for reply in [
        Reply::Http(
            409,
            json!({"error":"A Recon job is already running in this session."}),
        ),
        Reply::Http(503, json!({"error":PRIVATE})),
        Reply::Disconnect,
    ] {
        fixture.faults.lock().unwrap().write = Some(reply);
        recon_failure(
            fixture
                .call("recon.start", start_input(), Some("--yes"))
                .await,
            true,
        );
        fixture.assert_requests("POST", "/api/recon/jobs", Some(start_body()));
        recon_failure(
            fixture
                .run(&[
                    "recon",
                    "stop",
                    "--session-id",
                    SESSION,
                    "--id",
                    JOB,
                    "--yes",
                ])
                .await,
            true,
        );
        fixture.assert_requests(
            "POST",
            &format!("/api/recon/jobs/{JOB}/stop"),
            Some(json!({"session_id":SESSION})),
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recon_incomplete_source_results_remain_visible_in_inventory() {
    let fixture = Fixture::new().await;
    let mut partial = inventory();
    // Completion describes the worker lifecycle, not exhaustive coverage.
    partial["jobs"][0]["status"] = json!("completed");
    partial["jobs"][0]["finished_at"] = json!("2026-10-20T00:01:00Z");
    partial["jobs"][0]["sources"][0]["status"] = json!("completed");
    partial["jobs"][0]["sources"][0]["truncated"] = json!(true);
    partial["jobs"][0]["sources"][0]["warnings"] = json!(["Request budget reached."]);
    fixture.faults.lock().unwrap().read = Some(Reply::Json(partial.clone()));
    assert_eq!(
        success(
            fixture
                .call("recon.list", json!({"session_id":SESSION}), None)
                .await,
            true,
        ),
        partial,
    );
    fixture.assert_requests("GET", "/api/recon", None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recon_response_binding_and_malformed_data_fail_closed_without_diagnostics() {
    let fixture = Fixture::new().await;
    let mut wrong_session = inventory();
    wrong_session["session_id"] = json!(OTHER_SESSION);
    wrong_session["jobs"][0]["error"] = json!(PRIVATE);
    let mut malformed_inventory = inventory();
    malformed_inventory["endpoints"][0]["first_seen"] = json!(PRIVATE);
    for reply in [
        Reply::Json(wrong_session),
        Reply::Json(malformed_inventory),
        Reply::Json(json!({"error":PRIVATE})),
        Reply::Raw(format!("{{not-json:{PRIVATE}")),
    ] {
        fixture.faults.lock().unwrap().read = Some(reply);
        let result = recon_failure(
            fixture
                .call("recon.list", json!({"session_id":SESSION}), None)
                .await,
            false,
        );
        assert_eq!(result["error"]["code"], "INVALID_RESPONSE");
        fixture.assert_requests("GET", "/api/recon", None);
    }

    let mut wrong_target = job("running");
    wrong_target["target_url"] = json!(format!("https://example.com/other?token={PRIVATE}"));
    let mut wrong_sources = job("running");
    wrong_sources["sources"][0]["source"] = json!(PRIVATE);
    let mut malformed_job = job("running");
    malformed_job["id"] = json!(PRIVATE);
    for reply in [
        Reply::Json(wrong_target),
        Reply::Json(wrong_sources),
        Reply::Json(malformed_job),
        Reply::Json(json!({"error":PRIVATE})),
        Reply::Raw(format!("{{not-json:{PRIVATE}")),
    ] {
        fixture.faults.lock().unwrap().write = Some(reply);
        let result = recon_failure(
            fixture
                .call("recon.start", start_input(), Some("--yes"))
                .await,
            true,
        );
        assert_eq!(result["error"]["code"], "INVALID_RESPONSE");
        fixture.assert_requests("POST", "/api/recon/jobs", Some(start_body()));
    }
    for reply in [
        Reply::Json(json!({"session_id":OTHER_SESSION,"stopped":true,"error":PRIVATE})),
        Reply::Json(json!({"session_id":SESSION,"stopped":false,"error":PRIVATE})),
        Reply::Json(json!({"session_id":SESSION,"stopped":PRIVATE})),
        Reply::Json(json!({"error":PRIVATE})),
        Reply::Raw(format!("{{not-json:{PRIVATE}")),
    ] {
        fixture.faults.lock().unwrap().write = Some(reply);
        let result = recon_failure(
            fixture
                .call(
                    "recon.stop",
                    json!({"session_id":SESSION,"id":JOB}),
                    Some("--yes"),
                )
                .await,
            true,
        );
        assert_eq!(result["error"]["code"], "INVALID_RESPONSE");
        fixture.assert_requests(
            "POST",
            &format!("/api/recon/jobs/{JOB}/stop"),
            Some(json!({"session_id":SESSION})),
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recon_post_redirects_are_not_followed_retried_or_exposed() {
    let fixture = Fixture::new().await;
    for status in [302, 307, 308] {
        fixture.faults.lock().unwrap().write = Some(Reply::Redirect(status));
        let result = recon_failure(
            fixture
                .call("recon.start", start_input(), Some("--yes"))
                .await,
            true,
        );
        assert_eq!(result["error"]["details"]["status"], status);
        fixture.assert_requests("POST", "/api/recon/jobs", Some(start_body()));
        let result = recon_failure(
            fixture
                .run(&[
                    "recon",
                    "stop",
                    "--session-id",
                    SESSION,
                    "--id",
                    JOB,
                    "--yes",
                ])
                .await,
            true,
        );
        assert_eq!(result["error"]["details"]["status"], status);
        fixture.assert_requests(
            "POST",
            &format!("/api/recon/jobs/{JOB}/stop"),
            Some(json!({"session_id":SESSION})),
        );
    }
}
