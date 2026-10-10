//! Discovery-only checks: no API, proxy, saved session, or user data is opened.
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
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
