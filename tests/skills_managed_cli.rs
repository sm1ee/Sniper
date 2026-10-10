//! Host-local fixture coverage: enrollment and staging never contact Sniper or activate skills.
use serde_json::{json, Value};
use sniper::{skill_managed, skills};
use std::{
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::Command,
};
use uuid::Uuid;

#[path = "support/schema_vocabulary.rs"]
mod schema_vocabulary;

struct Fixture {
    root: PathBuf,
    listener: TcpListener,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("sniper-skills-managed-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        Self { root, listener }
    }

    fn cli(&self, args: &[&str], exit_code: i32) -> Value {
        let output = Command::new(env!("CARGO_BIN_EXE_sniper-cli"))
            .args([
                "--output",
                "compact",
                "--api",
                &format!("http://{}", self.listener.local_addr().unwrap()),
            ])
            .args(args)
            .env("HOME", self.root.join("home"))
            .env("USERPROFILE", self.root.join("home"))
            .env("CODEX_HOME", self.root.join("codex-home"))
            .env("CLAUDE_HOME", self.root.join("claude-home"))
            .env("SNIPER_DATA_DIR", self.root.join("data"))
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(exit_code), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
        assert_eq!(
            self.listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "CLI contacted the API"
        );
        assert!(!self.root.join("data").exists());
        assert!(!self.root.join("home").exists());
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn call(&self, operation: &str, input: &Value, flag: Option<&str>, exit_code: i32) -> Value {
        let input = input.to_string();
        let mut args = vec!["call", operation, "--input", &input];
        args.extend(flag);
        self.cli(&args, exit_code)
    }

    fn root_for(&self, agent: &str) -> PathBuf {
        self.root.join(agent)
    }

    fn put(&self, agent: &str, contents: &str) -> PathBuf {
        let path = self.root_for(agent).join("sniper-operator/SKILL.md");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, contents).unwrap();
        path
    }

    fn input(&self) -> Value {
        json!({"codex":true,"codex_dir":self.root_for("codex")})
    }

    fn preview(&self) -> Value {
        self.call("skills.update_preview", &self.input(), None, 0)["data"].clone()
    }

    fn schema(&self, kind: &str, operation: &str) -> Value {
        self.cli(&["schema", kind, operation], 0)["schema"].clone()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

// Validate the JSON Schema vocabulary used by these three strict contracts.
fn matches_schema(value: &Value, schema: &Value) -> bool {
    schema_vocabulary::assert_supported(
        schema,
        &[
            "type",
            "const",
            "enum",
            "required",
            "properties",
            "additionalProperties",
            "items",
            "minLength",
            "pattern",
            "minItems",
            "maxItems",
            "allOf",
            "anyOf",
            "oneOf",
        ],
        &["object", "array", "string", "boolean", "null"],
        &[],
    );
    matches_schema_value(value, schema)
}

fn matches_schema_value(value: &Value, schema: &Value) -> bool {
    if schema["allOf"].as_array().is_some_and(|constraints| {
        !constraints
            .iter()
            .all(|constraint| matches_schema_value(value, constraint))
    }) {
        return false;
    }
    if let Some(ty) = schema.get("type") {
        let matches_type = |ty: &Value| match ty.as_str().unwrap() {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
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
    if let Some(expected) = schema.get("const") {
        if value != expected {
            return false;
        }
    }
    if let Some(values) = schema["enum"].as_array() {
        if !values.contains(value) {
            return false;
        }
    }
    if let Some(fields) = value.as_object() {
        if let Some(required) = schema["required"].as_array() {
            if required
                .iter()
                .any(|key| !fields.contains_key(key.as_str().unwrap()))
            {
                return false;
            }
        }
        for (key, value) in fields {
            if let Some(field) = schema["properties"].get(key) {
                if !matches_schema_value(value, field) {
                    return false;
                }
            } else if schema["additionalProperties"] == false {
                return false;
            }
        }
    }
    if let Some(text) = value.as_str() {
        if schema["minLength"]
            .as_u64()
            .is_some_and(|min| text.chars().count() < min as usize)
        {
            return false;
        }
        if let Some(pattern) = schema["pattern"].as_str() {
            if !regex::Regex::new(pattern).unwrap().is_match(text) {
                return false;
            }
        }
    }
    if let Some(rows) = value.as_array() {
        if schema["minItems"]
            .as_u64()
            .is_some_and(|min| rows.len() < min as usize)
            || schema["maxItems"]
                .as_u64()
                .is_some_and(|max| rows.len() > max as usize)
        {
            return false;
        }
        if let Some(items) = schema.get("items") {
            if rows.iter().any(|row| !matches_schema_value(row, items)) {
                return false;
            }
        }
    }
    if let Some(choices) = schema["anyOf"].as_array() {
        if !choices
            .iter()
            .any(|choice| matches_schema_value(value, choice))
        {
            return false;
        }
    }
    if let Some(choices) = schema["oneOf"].as_array() {
        if choices
            .iter()
            .filter(|choice| matches_schema_value(value, choice))
            .count()
            != 1
        {
            return false;
        }
    }
    true
}

fn assert_schema(value: &Value, schema: &Value) {
    assert!(
        matches_schema(value, schema),
        "value {value} fails schema {schema}"
    );
}

#[test]
fn schema_matcher_guards_its_subset_and_checks_constants() {
    for schema in [
        json!({"properties":{"optional":{"type":"string","format":"date-time"}}}),
        json!({"properties":{"optional":{"type":"integer"}}}),
        json!({"type":["object","integer"]}),
        json!({"type":["object",false]}),
        json!({"anyOf":[{}, {"type":"integer"}]}),
        json!({"properties":{"optional":{"minLength":-1}}}),
        json!({"anyOf":[{}, {"minItems":1.5}]}),
        json!({"anyOf":[{}, {"maxItems":"2"}]}),
        json!({"properties":{"optional":{"pattern":false}}}),
        json!({"anyOf":[{}, {"pattern":"(?=a)"}]}),
    ] {
        assert!(
            std::panic::catch_unwind(|| matches_schema(&json!({}), &schema)).is_err(),
            "unsupported schema was accepted: {schema}"
        );
    }
    let schema = json!({"type":"boolean","const":false});
    assert!(matches_schema(&json!(false), &schema));
    assert!(!matches_schema(&json!(true), &schema));
}

#[test]
fn discovery_examples_and_dry_runs_agree_without_api_contact_or_files() {
    let f = Fixture::new();
    let manifest = f.cli(&["manifest"], 0);
    for operation in [
        "skills.enroll",
        "skills.update_preview",
        "skills.stage_update",
    ] {
        let spec = manifest["operations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|spec| spec["operation"] == operation)
            .unwrap();
        let write = operation != "skills.update_preview";
        assert_eq!(spec["side_effect"], if write { "write" } else { "read" });
        assert_eq!(spec["requires_confirmation"], write);
        for kind in ["input", "output"] {
            assert_eq!(f.schema(kind, operation), spec[format!("{kind}_schema")]);
            assert_eq!(
                spec[format!("{kind}_schema")]["additionalProperties"],
                false
            );
        }
        assert_eq!(
            f.cli(&["examples", operation], 0)["examples"],
            spec["examples"]
        );
        for example in spec["examples"].as_array().unwrap() {
            assert_schema(example, &spec["input_schema"]);
            let plan = f.call(operation, example, Some("--dry-run"), 0);
            assert_eq!(plan["data"]["operation"], operation);
            assert_eq!(plan["data"]["api"], json!({"local":true}));
            assert_eq!(plan["data"]["requires_confirmation"], write);
        }
    }
    assert_eq!(fs::read_dir(&f.root).unwrap().count(), 0);
}

#[test]
fn invalid_inputs_and_direct_parse_errors_are_safe_and_canonical() {
    let f = Fixture::new();
    for (operation, inputs) in [
        (
            "skills.enroll",
            vec![
                json!({}),
                json!({"all":true}),
                json!({"codex":true,"claude":true}),
                json!({"codex":"true"}),
                json!({"codex":null}),
                json!({"codex":true,"codex_dir":""}),
                json!({"codex":true,"codex_dir":"a\0b"}),
                json!({"codex":true,"claude_dir":5}),
                json!({"codex":true,"unknown":true}),
            ],
        ),
        (
            "skills.stage_update",
            vec![
                json!({"codex":true}),
                json!({"codex":true,"staging_dir":null}),
                json!({"codex":true,"staging_dir":""}),
                json!({"codex":true,"staging_dir":5}),
                json!({"codex":true,"staging_dir":"a\0b"}),
                json!({"codex":true,"claude":true,"staging_dir":"candidate"}),
                json!({"all":true,"staging_dir":"candidate"}),
            ],
        ),
        (
            "skills.update_preview",
            vec![
                json!({}),
                json!({"all":false}),
                json!({"all":"true"}),
                json!({"claude":true,"claude_dir":""}),
                json!({"all":true,"unknown":1}),
            ],
        ),
    ] {
        let schema = f.schema("input", operation);
        for input in inputs {
            assert!(!matches_schema(&input, &schema), "{operation}: {input}");
            let result = f.call(operation, &input, Some("--dry-run"), 2);
            assert_eq!(result["error"]["code"], "INVALID_INPUT", "{result}");
        }
    }
    for (args, operation) in [
        (vec!["skills", "enroll"], "skills.enroll"),
        (
            vec!["skills", "enroll", "--codex", "--claude"],
            "skills.enroll",
        ),
        (
            vec!["skills", "stage-update", "--codex"],
            "skills.stage_update",
        ),
        (
            vec!["skills", "update-preview", "--unknown"],
            "skills.update_preview",
        ),
    ] {
        let result = f.cli(&args, 2);
        assert_eq!(result["operation"], operation);
        assert_eq!(result["error"]["code"], "INVALID_INPUT");
    }
    assert_eq!(fs::read_dir(&f.root).unwrap().count(), 0);
}

#[test]
fn preview_reports_missing_and_unmanaged_without_claiming_ownership() {
    let f = Fixture::new();
    let schema = f.schema("output", "skills.update_preview");
    let missing = f.preview();
    assert_schema(&missing, &schema);
    assert_eq!(missing["entries"][0]["state"], "missing");
    assert!(!f.root_for("codex").exists());
    let path = f.put("codex", skills::CODEX_SKILL_TEMPLATE);
    for contents in [
        skills::CODEX_SKILL_TEMPLATE,
        "Synthetic old or modified skill.\n",
    ] {
        fs::write(&path, contents).unwrap();
        let before = fs::metadata(&path).unwrap().modified().unwrap();
        let preview = f.preview();
        assert_eq!(
            preview,
            f.cli(
                &[
                    "skills",
                    "update-preview",
                    "--codex",
                    "--codex-dir",
                    f.root_for("codex").to_str().unwrap()
                ],
                0
            )
        );
        assert_schema(&preview, &schema);
        assert_eq!(preview["entries"][0]["state"], "unmanaged");
        assert_eq!(preview["entries"][0]["stage_eligible"], false);
        assert!(preview["entries"][0]["enrolled_sha256"].is_null());
        assert!(!Path::new(preview["entries"][0]["receipt_path"].as_str().unwrap()).exists());
        assert_eq!(fs::read_to_string(&path).unwrap(), contents);
        assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), before);
        assert!(!preview.to_string().contains("Synthetic old or modified"));
    }
    f.put("claude", skills::CLAUDE_SKILL_TEMPLATE);
    let all = f.cli(
        &[
            "skills",
            "update-preview",
            "--all",
            "--codex-dir",
            f.root_for("codex").to_str().unwrap(),
            "--claude-dir",
            f.root_for("claude").to_str().unwrap(),
        ],
        0,
    );
    assert_schema(&all, &schema);
    assert_eq!(all["entries"].as_array().unwrap().len(), 2);
}

#[test]
fn explicit_enrollment_preserves_active_skill_and_does_not_authorize_automatic_updates() {
    let f = Fixture::new();
    let path = f.put("codex", skills::CODEX_SKILL_TEMPLATE);
    let before = fs::metadata(&path).unwrap().modified().unwrap();
    let input = f.input();
    let receipt = f.preview()["entries"][0]["receipt_path"]
        .as_str()
        .unwrap()
        .to_owned();
    let denied = f.call("skills.enroll", &input, None, 2);
    assert_eq!(denied["error"]["code"], "CONFIRMATION_REQUIRED");
    assert!(!Path::new(&receipt).exists());
    let plan = f.cli(
        &[
            "skills",
            "enroll",
            "--codex",
            "--codex-dir",
            f.root_for("codex").to_str().unwrap(),
            "--dry-run",
        ],
        0,
    );
    assert_eq!(plan["dry_run"], true);
    assert!(!Path::new(&receipt).exists());
    let result = f.call("skills.enroll", &input, Some("--yes"), 0);
    assert_schema(&result["data"], &f.schema("output", "skills.enroll"));
    assert_eq!(result["data"]["allows_automatic_updates"], false);
    assert!(Path::new(&receipt).is_file());
    let preview = f.preview();
    assert_eq!(preview["entries"][0]["state"], "current");
    assert_eq!(preview["entries"][0]["stage_eligible"], false);
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        skills::CODEX_SKILL_TEMPLATE
    );
    assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), before);

    let claude_path = f.put("claude", skills::CLAUDE_SKILL_TEMPLATE);
    let direct = f.cli(
        &[
            "skills",
            "enroll",
            "--claude",
            "--claude-dir",
            f.root_for("claude").to_str().unwrap(),
            "--yes",
        ],
        0,
    );
    assert_schema(&direct, &f.schema("output", "skills.enroll"));
    assert_eq!(direct["agent"], "claude");
    assert_eq!(
        fs::read_to_string(claude_path).unwrap(),
        skills::CLAUDE_SKILL_TEMPLATE
    );
}

#[test]
fn stage_lifecycle_writes_only_candidate_and_receipt_and_never_activates() {
    let f = Fixture::new();
    let old = "Synthetic earlier bundle for lifecycle fixture.\n";
    let active = f.put("codex", old);
    let root = f.root_for("codex");
    // A real prior enrollment, created with an earlier synthetic bundle/version.
    let enrollment = skill_managed::enroll_skill("codex", &root, old, "0.0.0").unwrap();
    let original_receipt = fs::read(&enrollment.receipt_path).unwrap();
    let preview = f.preview();
    assert_schema(&preview, &f.schema("output", "skills.update_preview"));
    assert_eq!(preview["entries"][0]["state"], "update_available");
    assert_eq!(preview["entries"][0]["stage_eligible"], true);
    let staging = f.root.join("staged");
    let input = json!({"codex":true,"codex_dir":root,"staging_dir":staging});
    assert_eq!(
        f.call("skills.stage_update", &input, None, 2)["error"]["code"],
        "CONFIRMATION_REQUIRED"
    );
    assert!(!staging.exists());
    let plan = f.call("skills.stage_update", &input, Some("--dry-run"), 0);
    assert_eq!(plan["data"]["input"]["staging_dir"], json!(staging));
    assert!(!staging.exists());
    let result = f.cli(
        &[
            "skills",
            "stage-update",
            "--codex",
            "--codex-dir",
            root.to_str().unwrap(),
            "--staging-dir",
            staging.to_str().unwrap(),
            "--yes",
        ],
        0,
    );
    assert_schema(&result, &f.schema("output", "skills.stage_update"));
    assert_eq!(result["activated"], false);
    assert_eq!(fs::read_dir(&staging).unwrap().count(), 2);
    assert_eq!(
        fs::read_to_string(result["candidate_path"].as_str().unwrap()).unwrap(),
        skills::CODEX_SKILL_TEMPLATE
    );
    assert!(Path::new(result["receipt_path"].as_str().unwrap()).is_file());
    assert_eq!(fs::read_to_string(&active).unwrap(), old);
    assert_eq!(
        fs::read(&enrollment.receipt_path).unwrap(),
        original_receipt
    );
    assert_eq!(f.preview()["entries"][0]["state"], "update_available");

    let another = f.root.join("another-candidate");
    let mut call_input = input.clone();
    call_input["staging_dir"] = json!(another);
    let called = f.call("skills.stage_update", &call_input, Some("--yes"), 0);
    assert_schema(&called["data"], &f.schema("output", "skills.stage_update"));
    assert_eq!(called["data"]["activated"], false);
    assert_eq!(fs::read_to_string(&active).unwrap(), old);
    assert_eq!(
        fs::read(&enrollment.receipt_path).unwrap(),
        original_receipt
    );
}

#[test]
fn unsafe_or_ineligible_writes_return_bounded_errors_without_active_changes() {
    let f = Fixture::new();
    let secret = "Synthetic private content must never appear in an error.\n";
    let active = f.put("codex", secret);
    let denied = f.call("skills.enroll", &f.input(), Some("--yes"), 5);
    assert_eq!(denied["error"]["code"], "MANAGED_SKILL_ERROR");
    assert_eq!(denied["error"]["retryable"], false);
    assert_eq!(
        denied["error"]["details"]["reason"],
        "installed_not_current"
    );
    assert!(denied["error"]["hint"]
        .as_str()
        .unwrap()
        .contains("preserve customizations"));
    assert!(!denied.to_string().contains(secret.trim()));
    let staging = f.root.join("not-created");
    let input = json!({"codex":true,"codex_dir":f.root_for("codex"),"staging_dir":staging});
    let denied = f.call("skills.stage_update", &input, Some("--yes"), 5);
    assert_eq!(denied["error"]["code"], "MANAGED_SKILL_ERROR");
    assert!(!staging.exists());
    assert_eq!(fs::read_to_string(&active).unwrap(), secret);

    skill_managed::enroll_skill("codex", &f.root_for("codex"), secret, "0.0.0").unwrap();
    fs::write(&active, "Modified after enrollment.\n").unwrap();
    assert_eq!(f.preview()["entries"][0]["state"], "modified");
    f.call("skills.stage_update", &input, Some("--yes"), 5);
    assert!(!staging.exists());
    assert_eq!(
        fs::read_to_string(&active).unwrap(),
        "Modified after enrollment.\n"
    );

    fs::write(&active, secret).unwrap();
    fs::create_dir(&staging).unwrap();
    fs::write(staging.join("sentinel"), b"keep").unwrap();
    let collision = f.call("skills.stage_update", &input, Some("--yes"), 5);
    assert_eq!(collision["error"]["details"]["reason"], "already_exists");
    assert_eq!(
        collision["error"]["message"],
        "The staging directory or an output path already exists."
    );
    assert!(collision["error"]["hint"]
        .as_str()
        .unwrap()
        .contains("partial output"));
    assert_eq!(fs::read_dir(&staging).unwrap().count(), 1);
    assert_eq!(fs::read(staging.join("sentinel")).unwrap(), b"keep");
    assert_eq!(fs::read_to_string(&active).unwrap(), secret);
}

#[test]
fn malformed_receipt_is_reported_without_exposing_or_replacing_contents() {
    let f = Fixture::new();
    let active = f.put("codex", skills::CODEX_SKILL_TEMPLATE);
    let receipt = active
        .parent()
        .unwrap()
        .join(skill_managed::ENROLLMENT_FILE);
    let contents = b"Synthetic private malformed receipt content.\n";
    fs::write(&receipt, contents).unwrap();
    let before = fs::metadata(&receipt).unwrap().modified().unwrap();
    let preview = f.preview();
    assert_schema(&preview, &f.schema("output", "skills.update_preview"));
    assert_eq!(preview["entries"][0]["state"], "error");
    assert_eq!(preview["entries"][0]["error_code"], "invalid_receipt");
    assert_eq!(preview["entries"][0]["stage_eligible"], false);
    assert!(!preview.to_string().contains("Synthetic private malformed"));
    let error = f.call("skills.enroll", &f.input(), Some("--yes"), 5);
    assert_eq!(error["error"]["code"], "MANAGED_SKILL_ERROR");
    assert_eq!(error["error"]["details"]["reason"], "already_exists");
    assert_eq!(
        error["error"]["message"],
        "The enrollment receipt path already exists."
    );
    assert!(error["error"]["hint"]
        .as_str()
        .unwrap()
        .contains("malformed"));
    assert!(!error.to_string().contains("Synthetic private malformed"));
    assert_eq!(fs::read(&receipt).unwrap(), contents);
    assert_eq!(fs::metadata(&receipt).unwrap().modified().unwrap(), before);
    assert_eq!(
        fs::read_to_string(active).unwrap(),
        skills::CODEX_SKILL_TEMPLATE
    );
}

#[test]
fn repeated_enrollment_reports_existing_path_and_preserves_active_and_receipt() {
    let f = Fixture::new();
    let active = f.put("codex", skills::CODEX_SKILL_TEMPLATE);
    let enrolled = f.call("skills.enroll", &f.input(), Some("--yes"), 0);
    let receipt = Path::new(enrolled["data"]["receipt_path"].as_str().unwrap());
    let receipt_bytes = fs::read(receipt).unwrap();
    let active_modified = fs::metadata(&active).unwrap().modified().unwrap();
    let receipt_modified = fs::metadata(receipt).unwrap().modified().unwrap();

    let result = f.call("skills.enroll", &f.input(), Some("--yes"), 5);
    assert_eq!(result["error"]["code"], "MANAGED_SKILL_ERROR");
    assert_eq!(result["error"]["details"]["reason"], "already_exists");
    assert_eq!(result["error"]["retryable"], false);
    assert_eq!(
        result["error"]["message"],
        "The enrollment receipt path already exists."
    );
    assert!(result["error"]["hint"]
        .as_str()
        .unwrap()
        .contains("skills update-preview"));
    assert_eq!(
        fs::read_to_string(&active).unwrap(),
        skills::CODEX_SKILL_TEMPLATE
    );
    assert_eq!(fs::read(receipt).unwrap(), receipt_bytes);
    assert_eq!(
        fs::metadata(&active).unwrap().modified().unwrap(),
        active_modified
    );
    assert_eq!(
        fs::metadata(receipt).unwrap().modified().unwrap(),
        receipt_modified
    );
    assert_eq!(fs::read_dir(active.parent().unwrap()).unwrap().count(), 2);
}

#[test]
fn staging_current_bundle_points_to_status_without_mutation() {
    let f = Fixture::new();
    let root = f.root_for("codex");
    let active = f.put("codex", skills::CODEX_SKILL_TEMPLATE);
    let enrollment =
        skill_managed::enroll_skill("codex", &root, skills::CODEX_SKILL_TEMPLATE, "0.0.0").unwrap();
    let receipt_bytes = fs::read(&enrollment.receipt_path).unwrap();
    let active_modified = fs::metadata(&active).unwrap().modified().unwrap();
    let receipt_modified = fs::metadata(&enrollment.receipt_path)
        .unwrap()
        .modified()
        .unwrap();
    let staging = f.root.join("not-created-current");
    let input = json!({"codex":true,"codex_dir":root,"staging_dir":staging});
    let called = f.call("skills.stage_update", &input, Some("--yes"), 5);
    let direct = f.cli(
        &[
            "skills",
            "stage-update",
            "--codex",
            "--codex-dir",
            root.to_str().unwrap(),
            "--staging-dir",
            staging.to_str().unwrap(),
            "--yes",
        ],
        5,
    );
    for result in [called, direct] {
        assert_eq!(result["error"]["code"], "MANAGED_SKILL_ERROR");
        assert_eq!(result["error"]["details"]["reason"], "already_current");
        assert_eq!(result["error"]["retryable"], false);
        assert_eq!(
            result["error"]["message"],
            "The active skill already matches this binary's bundled template."
        );
        assert!(result["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("skills status"));
    }
    assert!(!staging.exists());
    assert_eq!(
        fs::read_to_string(&active).unwrap(),
        skills::CODEX_SKILL_TEMPLATE
    );
    assert_eq!(fs::read(&enrollment.receipt_path).unwrap(), receipt_bytes);
    assert_eq!(
        fs::metadata(&active).unwrap().modified().unwrap(),
        active_modified
    );
    assert_eq!(
        fs::metadata(&enrollment.receipt_path)
            .unwrap()
            .modified()
            .unwrap(),
        receipt_modified
    );
}

#[test]
fn manual_activation_can_be_current_with_a_modified_recorded_baseline() {
    let f = Fixture::new();
    let root = f.root_for("codex");
    let old = "Synthetic historical template.\n";
    let active = f.put("codex", old);
    let enrollment = skill_managed::enroll_skill("codex", &root, old, "0.0.0").unwrap();
    let receipt_bytes = fs::read(&enrollment.receipt_path).unwrap();
    fs::write(&active, skills::CODEX_SKILL_TEMPLATE).unwrap();
    let active_modified = fs::metadata(&active).unwrap().modified().unwrap();
    let receipt_modified = fs::metadata(&enrollment.receipt_path)
        .unwrap()
        .modified()
        .unwrap();

    let status = f.call("skills.status", &f.input(), None, 0);
    assert_eq!(status["data"]["entries"][0]["status"], "current");
    let preview = f.preview();
    assert_eq!(preview["entries"][0]["state"], "modified");
    assert_eq!(preview["entries"][0]["stage_eligible"], false);
    let staging = f.root.join("not-created-modified");
    let input = json!({"codex":true,"codex_dir":root,"staging_dir":staging});
    let result = f.call("skills.stage_update", &input, Some("--yes"), 5);
    assert_eq!(result["error"]["code"], "MANAGED_SKILL_ERROR");
    assert_eq!(result["error"]["details"]["reason"], "installed_modified");
    assert_eq!(result["error"]["retryable"], false);
    assert_eq!(
        result["error"]["message"],
        "The active skill differs from its recorded enrollment baseline."
    );
    let hint = result["error"]["hint"].as_str().unwrap();
    for fragment in [
        "skills status",
        "skills update-preview",
        "Manual activation",
        "old receipt",
        "optional receipt recovery",
    ] {
        assert!(hint.contains(fragment), "{fragment}");
    }
    assert!(!staging.exists());
    assert_eq!(
        fs::read_to_string(&active).unwrap(),
        skills::CODEX_SKILL_TEMPLATE
    );
    assert_eq!(fs::read(&enrollment.receipt_path).unwrap(), receipt_bytes);
    assert_eq!(
        fs::metadata(&active).unwrap().modified().unwrap(),
        active_modified
    );
    assert_eq!(
        fs::metadata(&enrollment.receipt_path)
            .unwrap()
            .modified()
            .unwrap(),
        receipt_modified
    );
}
