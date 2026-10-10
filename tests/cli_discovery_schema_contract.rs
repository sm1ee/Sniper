//! Offline discovery and synthetic loopback checks. No proxy, saved session,
//! captured traffic, or user data directory is opened.
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sniper::model::{TrafficKind, TransactionSummary};
use sniper::session::SessionSummary;
use std::process::Command;
use uuid::Uuid;

fn cli(args: &[&str], expected_code: i32) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_sniper-cli"))
        .args(["--output", "compact", "--api", "http://127.0.0.1:1"])
        .args(args)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(expected_code), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

fn spec(operation: &str) -> Value {
    cli(&["manifest"], 0)["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|spec| spec["operation"] == operation)
        .unwrap()
        .clone()
}

fn output_schema(operation: &str) -> Value {
    let schema = cli(&["schema", "output", operation], 0)["schema"].clone();
    assert_eq!(schema, spec(operation)["output_schema"]);
    let input = json!({"kind":"output", "operation":operation}).to_string();
    let called = cli(&["call", "schema", "--input", &input], 0);
    assert_eq!(called["data"]["schema"], schema);
    schema
}

// Only the JSON Schema vocabulary used by these read-only output contracts.
fn matches_schema(value: &Value, schema: &Value) -> bool {
    if schema["allOf"].as_array().is_some_and(|constraints| {
        !constraints
            .iter()
            .all(|constraint| matches_schema(value, constraint))
    }) {
        return false;
    }
    if let Some(ty) = schema.get("type") {
        let matches_type = |ty: &Value| match ty.as_str().unwrap() {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "integer" => value.is_i64() || value.is_u64(),
            "boolean" => value.is_boolean(),
            "null" => value.is_null(),
            other => panic!("unexpected schema type {other}"),
        };
        if let Some(types) = ty.as_array() {
            if !types.iter().any(matches_type) {
                return false;
            }
        } else if !matches_type(ty) {
            return false;
        }
    }
    if schema["enum"]
        .as_array()
        .is_some_and(|items| !items.contains(value))
    {
        return false;
    }
    if let Some(fields) = value.as_object() {
        if schema["required"].as_array().is_some_and(|required| {
            required
                .iter()
                .any(|name| !fields.contains_key(name.as_str().unwrap()))
        }) {
            return false;
        }
        for (key, item) in fields {
            if let Some(property) = schema["properties"].get(key) {
                if !matches_schema(item, property) {
                    return false;
                }
            } else if schema["additionalProperties"] == false {
                return false;
            }
        }
    }
    if let Some(items) = value.as_array() {
        if let Some(item_schema) = schema.get("items") {
            if items.iter().any(|item| !matches_schema(item, item_schema)) {
                return false;
            }
        }
    }
    if value.is_number() {
        let integer = value
            .as_u64()
            .map(i128::from)
            .or_else(|| value.as_i64().map(i128::from));
        if schema["minimum"]
            .as_u64()
            .is_some_and(|min| integer.is_none_or(|n| n < i128::from(min)))
            || schema["maximum"]
                .as_u64()
                .is_some_and(|max| integer.is_none_or(|n| n > i128::from(max)))
        {
            return false;
        }
    }
    if let Some(text) = value.as_str() {
        if schema["pattern"]
            .as_str()
            .is_some_and(|pattern| !regex::Regex::new(pattern).unwrap().is_match(text))
        {
            return false;
        }
        match schema["format"].as_str() {
            Some("uuid") if Uuid::parse_str(text).is_err() => return false,
            Some("date-time") if DateTime::parse_from_rfc3339(text).is_err() => return false,
            _ => {}
        }
    }
    if schema["anyOf"]
        .as_array()
        .is_some_and(|choices| !choices.iter().any(|choice| matches_schema(value, choice)))
    {
        return false;
    }
    if schema["oneOf"].as_array().is_some_and(|choices| {
        choices
            .iter()
            .filter(|choice| matches_schema(value, choice))
            .count()
            != 1
    }) {
        return false;
    }
    true
}

fn assert_schema(value: &Value, schema: &Value) {
    assert!(
        matches_schema(value, schema),
        "{value} does not match {schema}"
    );
}

fn summary(annotated: bool) -> TransactionSummary {
    TransactionSummary {
        id: Uuid::from_u128(1),
        started_at: "2026-10-10T12:00:00Z".parse().unwrap(),
        kind: TrafficKind::Http,
        sequence: 42,
        method: "GET".into(),
        scheme: "https".into(),
        host: "example.com".into(),
        path: "/fixture".into(),
        status: annotated.then_some(200),
        duration_ms: 0,
        request_bytes: 0,
        response_bytes: 0,
        note_count: 0,
        has_response: annotated,
        content_type: annotated.then(|| "text/plain".into()),
        is_websocket: false,
        has_match_replace: false,
        color_tag: annotated.then(|| "blue".into()),
        has_user_note: annotated,
        note_preview: annotated.then(|| "Synthetic note".into()),
        annotation_revision: u64::from(annotated),
        header_search_text: if annotated {
            "Accept: text/plain".into()
        } else {
            String::new()
        },
    }
}

fn labeled_summary(annotated: bool) -> Value {
    let mut row = serde_json::to_value(summary(annotated)).unwrap();
    row["label"] = json!("#42 GET example.com/fixture");
    row
}

#[test]
fn examples_output_schema_describes_catalog_and_specific_data() {
    let schema = output_schema("examples");
    let catalog = cli(&["examples"], 0);
    assert_schema(&catalog, &schema);
    assert_eq!(schema["oneOf"].as_array().unwrap().len(), 2);
    assert_schema(&json!([]), &schema);
    for input in ["{}", r#"{"operation":null}"#] {
        let envelope = cli(&["call", "examples", "--input", input], 0);
        assert_schema(&envelope["data"], &schema);
        assert!(!matches_schema(&envelope, &schema));
    }
    let specific = cli(&["examples", "session.list"], 0);
    assert_schema(&specific, &schema);
    let called = cli(
        &[
            "call",
            "examples",
            "--input",
            r#"{"operation":"session.list"}"#,
        ],
        0,
    );
    assert_schema(&called["data"], &schema);
    // Example values belong to each operation's input contract, not a shared
    // catalog contract that assumes every legacy input has identical fields.
    assert_schema(
        &json!({"operation":"example", "examples":[null, true, 1, "text", [], {}]}),
        &schema,
    );
    for malformed in [
        json!({}),
        json!([{"operation":"example", "examples":[]}]),
        json!({"operation":"example", "examples":{}}),
    ] {
        assert!(!matches_schema(&malformed, &schema));
    }
}

#[test]
fn history_output_schema_matches_labeled_summaries_and_nullable_page_metadata() {
    let schema = output_schema("capture.http.list");
    assert_schema(&json!([labeled_summary(false)]), &schema);
    let alternatives = schema["oneOf"].as_array().unwrap();
    assert_eq!(alternatives.len(), 2);
    let array = alternatives
        .iter()
        .find(|choice| choice["type"] == "array")
        .unwrap();
    let page = alternatives
        .iter()
        .find(|choice| choice["type"] == "object")
        .unwrap();
    let mut expected_summary = sniper::saved_contract::transaction_summary_schema();
    expected_summary["properties"]["label"] = json!({"type":"string"});
    expected_summary["required"]
        .as_array_mut()
        .unwrap()
        .push(json!("label"));
    assert_eq!(array["items"], expected_summary);
    assert_eq!(page["properties"]["items"], *array);
    assert_schema(&json!([]), &schema);
    for annotated in [false, true] {
        let row = labeled_summary(annotated);
        assert_schema(&json!([row]), &schema);
        for metadata in [
            json!({"total":12, "filtered_total":8, "hidden_connect_total":1, "offset":5, "limit":1, "has_more":true}),
            json!({"total":null, "filtered_total":null, "hidden_connect_total":null, "offset":null, "limit":null, "has_more":null}),
        ] {
            let mut value = metadata;
            value["items"] = json!([row]);
            assert_schema(&value, &schema);
            value.as_object_mut().unwrap().remove("offset");
            assert!(!matches_schema(&value, &schema));
        }
        let mut missing_label = row.clone();
        missing_label.as_object_mut().unwrap().remove("label");
        assert!(!matches_schema(&json!([missing_label]), &schema));
        let mut nullable_optional = row;
        nullable_optional["note_preview"] = Value::Null;
        assert!(!matches_schema(&json!([nullable_optional]), &schema));
    }
    for malformed in [json!({}), json!([{}]), json!({"ok":true,"data":[]})] {
        assert!(!matches_schema(&malformed, &schema));
    }
}

#[test]
fn examples_discovery_matches_optional_nullable_operation() {
    let spec = spec("examples");
    let schema = cli(&["schema", "input", "examples"], 0)["schema"].clone();
    assert_eq!(schema, spec["input_schema"]);
    assert_eq!(spec["command"], "examples [operation]");
    assert_eq!(schema["required"], json!([]));
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["properties"]["operation"]["type"],
        json!(["string", "null"])
    );
    assert!(spec["examples"].as_array().unwrap().contains(&json!({})));

    let catalog = cli(&["examples"], 0);
    assert!(catalog.as_array().is_some_and(|items| !items.is_empty()));
    for input in ["{}", r#"{"operation":null}"#] {
        let envelope = cli(&["call", "examples", "--input", input], 0);
        assert_eq!(envelope["ok"], true);
        assert_eq!(envelope["operation"], "examples");
        assert_eq!(envelope["data"], catalog);
    }
    let specific = cli(&["examples", "session.list"], 0);
    let called = cli(
        &[
            "call",
            "examples",
            "--input",
            r#"{"operation":"session.list"}"#,
        ],
        0,
    );
    assert_eq!(called["data"], specific);
    assert_eq!(specific["operation"], "session.list");
    for input in [
        r#"{"operation":1}"#,
        r#"{"operation":true}"#,
        r#"{"operation":[]}"#,
        r#"{"operation":{}}"#,
        r#"{"unexpected":null}"#,
    ] {
        let error = cli(&["call", "examples", "--input", input], 2);
        assert_eq!(error["ok"], false);
        assert_eq!(error["error"]["code"], "INVALID_INPUT");
    }
}

#[test]
fn session_list_discovery_describes_serialized_summary_array() {
    let spec = spec("session.list");
    let schema = cli(&["schema", "output", "session.list"], 0)["schema"].clone();
    assert_eq!(schema, spec["output_schema"]);
    let called = cli(
        &[
            "call",
            "schema",
            "--input",
            r#"{"kind":"output","operation":"session.list"}"#,
        ],
        0,
    );
    assert_eq!(called["data"]["schema"], schema);
    assert_eq!(schema["type"], "array");
    // Adding the output schema must not advertise a new runtime input.
    assert_eq!(spec["input_schema"]["properties"], json!({}));
    assert_eq!(spec["input_schema"]["required"], json!([]));

    let timestamp = "2026-10-10T12:00:00Z".parse::<DateTime<Utc>>().unwrap();
    let rows = serde_json::to_value(vec![SessionSummary {
        id: Uuid::nil(),
        name: "Synthetic offline fixture".into(),
        created_at: timestamp,
        updated_at: timestamp,
        last_opened_at: timestamp,
        request_count: 0,
        websocket_count: 1,
        event_count: 2,
        fuzzer_count: 0,
        rule_count: 0,
        storage_path: "synthetic-session".into(),
        active: false,
    }])
    .unwrap();
    let row = rows[0].as_object().unwrap();
    let item = &schema["items"];
    let properties = item["properties"].as_object().unwrap();
    assert_eq!(item["type"], "object");
    assert_eq!(*item, sniper::saved_contract::session_summary_schema());
    assert_eq!(properties.len(), row.len());
    assert_eq!(item["required"].as_array().unwrap().len(), row.len());
    for (name, value) in row {
        assert!(item["required"].as_array().unwrap().contains(&json!(name)));
        let field = &properties[name];
        match field["type"].as_str().unwrap() {
            "string" => assert!(value.is_string(), "{name}"),
            "integer" => {
                assert!(value.is_u64(), "{name}");
                assert_eq!(field["minimum"], 0, "{name}");
            }
            "boolean" => assert!(value.is_boolean(), "{name}"),
            other => panic!("unexpected field type: {name}: {other}"),
        }
    }
    assert_eq!(properties["id"]["format"], "uuid");
    for name in ["created_at", "updated_at", "last_opened_at"] {
        assert_eq!(properties[name]["format"], "date-time");
    }
    assert!(!properties.contains_key("intruder_count"));
}

mod history_fixture {
    use super::{assert_schema, labeled_summary, output_schema, summary};
    use axum::{
        body::{to_bytes, Body},
        extract::State,
        http::{Request, StatusCode},
        response::{IntoResponse, Response},
        routing::any,
        Json, Router,
    };
    use serde_json::{json, Value};
    use std::{
        collections::BTreeMap,
        path::PathBuf,
        sync::{Arc, Mutex},
        time::Duration,
    };
    use uuid::Uuid;

    #[derive(Debug)]
    struct RecordedRequest {
        method: String,
        path: String,
        query: BTreeMap<String, String>,
        body_len: usize,
    }

    struct MockState {
        settings: Value,
        payload: Mutex<Value>,
        requests: Mutex<Vec<RecordedRequest>>,
    }

    struct MockApi {
        api: String,
        unused_dir: PathBuf,
        state: Arc<MockState>,
        server: tokio::task::JoinHandle<()>,
    }

    impl MockApi {
        async fn new() -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let unused_dir =
                std::env::temp_dir().join(format!("sniper-history-schema-{}", Uuid::new_v4()));
            let state = Arc::new(MockState {
                settings: json!({
                    "runtime_instance_id":Uuid::new_v4(),
                    "proxy_addr":"127.0.0.1:0", "ui_addr":addr.to_string(),
                    "data_dir":unused_dir, "max_entries":2,
                    "features":["http_capture","session_storage","replay"]
                }),
                payload: Mutex::new(json!([])),
                requests: Mutex::new(Vec::new()),
            });
            let app = Router::new()
                .fallback(any(mock_request))
                .with_state(state.clone());
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            Self {
                api: format!("http://{addr}"),
                unused_dir,
                state,
                server,
            }
        }

        async fn command(&self, args: &[&str]) -> Value {
            let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_sniper-cli"));
            command
                .args(["--output", "compact", "--api", &self.api])
                .args(args)
                .env("SNIPER_DATA_DIR", &self.unused_dir)
                .env("HOME", self.unused_dir.join("home"))
                .env("USERPROFILE", self.unused_dir.join("home"))
                .env_remove("SNIPER_API_ADDR")
                .kill_on_drop(true);
            let output = tokio::time::timeout(Duration::from_secs(20), command.output())
                .await
                .expect("synthetic CLI fixture timed out")
                .unwrap();
            assert!(output.status.success(), "{args:?}: {output:?}");
            assert!(output.stderr.is_empty(), "{args:?}: {output:?}");
            assert!(
                !self.unused_dir.exists(),
                "read-only fixture created a data directory"
            );
            serde_json::from_slice(&output.stdout).unwrap()
        }

        fn assert_reads(&self, path: &str, expected_query: &[(&str, &str)]) {
            let requests = std::mem::take(&mut *self.state.requests.lock().unwrap());
            assert_eq!(requests.len(), 2, "{requests:?}");
            assert_eq!(requests[0].path, "/api/settings", "{requests:?}");
            assert!(requests[0].query.is_empty(), "{requests:?}");
            assert_eq!(requests[1].path, path, "{requests:?}");
            let mut expected =
                BTreeMap::from([("session_id".to_string(), Uuid::nil().to_string())]);
            expected.extend(
                expected_query
                    .iter()
                    .map(|(key, value)| (key.to_string(), value.to_string())),
            );
            assert_eq!(requests[1].query, expected, "{requests:?}");
            for request in requests {
                assert_eq!(request.method, "GET", "{request:?}");
                assert_eq!(request.body_len, 0, "{request:?}");
            }
        }
    }

    impl Drop for MockApi {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    async fn mock_request(State(state): State<Arc<MockState>>, request: Request<Body>) -> Response {
        let (parts, body) = request.into_parts();
        let body = to_bytes(body, 1024).await.unwrap();
        state.requests.lock().unwrap().push(RecordedRequest {
            method: parts.method.to_string(),
            path: parts.uri.path().into(),
            query: url::form_urlencoded::parse(parts.uri.query().unwrap_or_default().as_bytes())
                .into_owned()
                .collect(),
            body_len: body.len(),
        });
        if parts.method != "GET" {
            return StatusCode::METHOD_NOT_ALLOWED.into_response();
        }
        match parts.uri.path() {
            "/api/settings" => Json(state.settings.clone()).into_response(),
            "/api/transactions" | "/api/transactions-page" => {
                Json(state.payload.lock().unwrap().clone()).into_response()
            }
            _ => StatusCode::NOT_FOUND.into_response(),
        }
    }

    fn response_variants(rows: &Value) -> [(Value, Value); 3] {
        let unknown_metadata = json!({"total":null,"filtered_total":null,"hidden_connect_total":null,"offset":null,"limit":null,"has_more":null});
        let metadata = json!({"total":12,"filtered_total":null,"hidden_connect_total":1,"offset":5,"limit":2,"has_more":false});
        let mut complete_page = metadata.clone();
        complete_page["items"] = rows.clone();
        complete_page["ignored_upstream_field"] = json!(true);
        [
            (rows.clone(), unknown_metadata.clone()),
            (
                json!({"items":rows,"total":null,"ignored_upstream_field":true}),
                unknown_metadata,
            ),
            (complete_page, metadata),
        ]
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn history_read_modes_preserve_output_and_match_schema() {
        let schema = output_schema("capture.http.list");
        let mock = MockApi::new().await;
        let mut legacy_row = serde_json::to_value(summary(false)).unwrap();
        for field in ["sequence", "has_match_replace", "has_user_note"] {
            legacy_row.as_object_mut().unwrap().remove(field);
        }
        legacy_row["ignored_upstream_field"] = json!(true);
        legacy_row["label"] = json!("upstream label is not used");
        let mut legacy_output = labeled_summary(false);
        legacy_output["sequence"] = json!(0);
        legacy_output["label"] = json!("#0 GET example.com/fixture");
        let mut tunnel_row = serde_json::to_value(summary(true)).unwrap();
        tunnel_row["kind"] = json!("tunnel");
        tunnel_row["id"] = json!(Uuid::from_u128(2));
        let mut tunnel_output = tunnel_row.clone();
        tunnel_output["label"] = json!("#42 GET example.com/fixture");
        let rows = json!([legacy_row, tunnel_row]);
        let expected_rows = json!([legacy_output, tunnel_output]);
        let session_id = Uuid::nil().to_string();
        let cases = [
            (json!({}), vec![], "/api/transactions", vec![]),
            (json!({"page":false}), vec![], "/api/transactions", vec![]),
            (
                json!({"page":true,"offset":5,"limit":2}),
                vec!["--page", "--offset", "5", "--limit", "2"],
                "/api/transactions-page",
                vec![("offset", "5"), ("limit", "2")],
            ),
            (
                json!({"offset":5}),
                vec!["--offset", "5"],
                "/api/transactions-page",
                vec![("offset", "5")],
            ),
            (
                json!({"sort_key":"host","sort_direction":"asc"}),
                vec!["--sort-key", "host", "--sort-direction", "asc"],
                "/api/transactions-page",
                vec![("sort_key", "host"), ("sort_direction", "asc")],
            ),
            (
                json!({"sort_direction":"desc"}),
                vec!["--sort-direction", "desc"],
                "/api/transactions-page",
                vec![("sort_direction", "desc")],
            ),
            (
                json!({"before_sequence":42}),
                vec!["--before-sequence", "42"],
                "/api/transactions-page",
                vec![
                    ("before_sequence", "42"),
                    ("sort_key", "index"),
                    ("sort_direction", "desc"),
                ],
            ),
        ];
        for (payload, metadata) in response_variants(&rows) {
            *mock.state.payload.lock().unwrap() = payload;
            for (input, flags, path, query) in &cases {
                let expected = if input["page"] == true {
                    let mut expected = metadata.clone();
                    expected["items"] = expected_rows.clone();
                    expected
                } else {
                    expected_rows.clone()
                };
                let mut args = vec!["capture", "http", "list", "--session-id", &session_id];
                args.extend(flags.iter().copied());
                let direct = mock.command(&args).await;
                assert_eq!(direct, expected);
                assert_schema(&direct, &schema);
                mock.assert_reads(path, query);

                let mut input = input.clone();
                input["session_id"] = json!(session_id);
                let input = input.to_string();
                let called = mock
                    .command(&["call", "capture.http.list", "--input", &input])
                    .await;
                assert_eq!(called["ok"], true);
                assert_eq!(called["operation"], "capture.http.list");
                assert_eq!(called["data"], direct);
                assert_schema(&called["data"], &schema);
                assert!(!super::matches_schema(&called, &schema));
                mock.assert_reads(path, query);
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn empty_history_read_variants_match_schema() {
        let schema = output_schema("capture.http.list");
        let mock = MockApi::new().await;
        for (payload, metadata) in response_variants(&json!([])) {
            *mock.state.payload.lock().unwrap() = payload;
            for page in [false, true] {
                let input = json!({"session_id":Uuid::nil(),"page":page}).to_string();
                let called = mock
                    .command(&["call", "capture.http.list", "--input", &input])
                    .await;
                let expected = if page {
                    let mut expected = metadata.clone();
                    expected["items"] = json!([]);
                    expected
                } else {
                    json!([])
                };
                assert_eq!(called["data"], expected);
                assert_schema(&called["data"], &schema);
                mock.assert_reads(
                    if page {
                        "/api/transactions-page"
                    } else {
                        "/api/transactions"
                    },
                    &[],
                );
            }
        }
    }
}
