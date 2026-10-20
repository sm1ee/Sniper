//! Explicit host-local activation coverage. Every path and API destination is synthetic.
use serde_json::{json, Value};
use sniper::{skill_managed, skills};
use std::{
    collections::BTreeMap,
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::Command,
    time::SystemTime,
};
use uuid::Uuid;

#[path = "support/schema_vocabulary.rs"]
mod schema_vocabulary;

const OPERATION: &str = "12345678-abcd-4321-8765-123456789abc";
const OLD: &str = "Synthetic historical skill for activation fixtures.\n";

struct Fixture {
    root: PathBuf,
    listener: TcpListener,
}

impl Fixture {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("sniper-skills-activation-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        Self { root, listener }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sniper-cli"));
        command
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
            .env("SNIPER_DATA_DIR", self.root.join("data"));
        command
    }

    fn cli(&self, args: &[&str], exit_code: i32) -> Value {
        let output = self.command(args).output().unwrap();
        assert_eq!(output.status.code(), Some(exit_code), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
        self.assert_local_only();
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn assert_local_only(&self) {
        assert_eq!(
            self.listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "CLI contacted the API"
        );
        for name in ["data", "home", "codex-home", "claude-home"] {
            assert!(
                !self.root.join(name).exists(),
                "Unexpected host discovery output: {name}"
            );
        }
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
    fn active(&self, agent: &str) -> PathBuf {
        self.root_for(agent).join("sniper-operator/SKILL.md")
    }
    fn stage(&self) -> PathBuf {
        self.root.join("reviewed-candidate")
    }
    fn input(&self, agent: &str, apply: bool) -> Value {
        let mut input = json!({agent:true, format!("{agent}_dir"):self.root_for(agent), "operation_id":OPERATION});
        if apply {
            input["staging_dir"] = json!(self.stage());
        }
        input
    }
    fn schema(&self, kind: &str, operation: &str) -> Value {
        self.cli(&["schema", kind, operation], 0)["schema"].clone()
    }
    fn prepare(&self, agent: &str, version: &str) -> Vec<u8> {
        let active = self.active(agent);
        fs::create_dir_all(active.parent().unwrap()).unwrap();
        fs::write(&active, OLD).unwrap();
        let enrolled =
            skill_managed::enroll_skill(agent, &self.root_for(agent), OLD, version).unwrap();
        let original_receipt = fs::read(enrolled.receipt_path).unwrap();
        let bundle = if agent == "codex" {
            skills::CODEX_SKILL_TEMPLATE
        } else {
            skills::CLAUDE_SKILL_TEMPLATE
        };
        skill_managed::stage_skill_update(
            agent,
            &self.root_for(agent),
            bundle,
            env!("CARGO_PKG_VERSION"),
            &self.stage(),
        )
        .unwrap();
        original_receipt
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, (bool, Vec<u8>, SystemTime)> {
    fn visit(path: &Path, files: &mut BTreeMap<PathBuf, (bool, Vec<u8>, SystemTime)>) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let metadata = fs::symlink_metadata(entry.path()).unwrap();
            if metadata.is_dir() {
                files.insert(
                    entry.path(),
                    (true, Vec::new(), metadata.modified().unwrap()),
                );
                visit(&entry.path(), files);
            } else if metadata.is_file() {
                files.insert(
                    entry.path(),
                    (
                        false,
                        fs::read(entry.path()).unwrap(),
                        metadata.modified().unwrap(),
                    ),
                );
            } else {
                panic!("Unexpected fixture object: {:?}", entry.path());
            }
        }
    }
    let mut files = BTreeMap::new();
    visit(root, &mut files);
    files
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
            "maxLength",
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
        if schema["maxLength"]
            .as_u64()
            .is_some_and(|max| text.chars().count() > max as usize)
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
fn activation_discovery_and_dry_runs_are_coherent_and_argument_only() {
    let f = Fixture::new();
    let manifest = f.cli(&["manifest"], 0);
    for operation in [
        "skills.apply_update",
        "skills.update_result",
        "skills.rollback_update",
    ] {
        let spec = manifest["operations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|spec| spec["operation"] == operation)
            .unwrap();
        let write = operation != "skills.update_result";
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
            assert_eq!(plan["operation"], operation);
            assert_eq!(plan["data"]["operation"], operation);
            assert_eq!(plan["data"]["api"], json!({"local":true}));
            assert_eq!(plan["data"]["requires_confirmation"], write);
        }
        // Missing roots and stages must remain uninspected during dry run.
        let command = operation.strip_prefix("skills.").unwrap().replace('_', "-");
        let mut args = vec![
            "skills",
            &command,
            "--codex",
            "--operation-id",
            OPERATION,
            "--dry-run",
        ];
        let stage = f.stage();
        if operation == "skills.apply_update" {
            args.extend(["--staging-dir", stage.to_str().unwrap()]);
        }
        let direct = f.cli(&args, 0);
        assert_eq!(direct["operation"], operation);
        assert_eq!(direct["input"]["operation_id"], OPERATION);
        assert_eq!(direct["api"], json!({"local":true}));
    }
    assert_eq!(fs::read_dir(&f.root).unwrap().count(), 0);
}

#[test]
fn activation_input_schema_and_preflight_reject_noncanonical_ids_and_ambiguous_targets() {
    let f = Fixture::new();
    for operation in [
        "skills.apply_update",
        "skills.update_result",
        "skills.rollback_update",
    ] {
        let input = f.input("codex", operation == "skills.apply_update");
        let schema = f.schema("input", operation);
        assert_schema(&input, &schema);
        let mut invalid = Vec::new();
        for id in [
            "",
            "12345678ABCD43218765123456789ABC",
            "12345678-ABCD-4321-8765-123456789ABC",
            "{12345678-abcd-4321-8765-123456789abc}",
            "urn:uuid:12345678-abcd-4321-8765-123456789abc",
            " 12345678-abcd-4321-8765-123456789abc",
            "12345678-abcd-4321-8765-123456789abc\n",
            "not-a-uuid",
        ] {
            let mut bad = input.clone();
            bad["operation_id"] = json!(id);
            invalid.push(bad);
        }
        for value in [Value::Null, json!(3), json!(true)] {
            let mut bad = input.clone();
            bad["operation_id"] = value;
            invalid.push(bad);
        }
        for (key, value) in [
            ("claude", json!(true)),
            ("codex", json!(false)),
            ("all", json!(true)),
            ("claude_dir", json!("/tmp/unselected")),
            ("codex_dir", json!("")),
            ("codex_dir", json!("contains\0nul")),
            ("unknown", json!(false)),
        ] {
            let mut bad = input.clone();
            bad[key] = value;
            invalid.push(bad);
        }
        let mut missing = input.clone();
        missing.as_object_mut().unwrap().remove("operation_id");
        invalid.push(missing);
        if operation == "skills.apply_update" {
            for value in [Value::Null, json!(""), json!("contains\0nul"), json!(false)] {
                let mut bad = input.clone();
                bad["staging_dir"] = value;
                invalid.push(bad);
            }
            let mut missing = input.clone();
            missing.as_object_mut().unwrap().remove("staging_dir");
            invalid.push(missing);
        }
        for bad in invalid {
            assert!(
                !matches_schema(&bad, &schema),
                "accepted invalid input {bad}"
            );
            let error = f.call(operation, &bad, Some("--dry-run"), 2);
            assert_eq!(error["operation"], operation);
            assert_eq!(error["error"]["code"], "INVALID_INPUT", "{bad}: {error}");
        }
        let command = operation.strip_prefix("skills.").unwrap().replace('_', "-");
        let mut args = vec![
            "skills",
            &command,
            "--codex",
            "--operation-id",
            "12345678ABCD43218765123456789ABC",
            "--dry-run",
        ];
        if operation == "skills.apply_update" {
            args.extend(["--staging-dir", "/tmp/uninspected-stage"]);
        }
        assert_eq!(f.cli(&args, 2)["error"]["code"], "INVALID_INPUT");
        let null_unselected = {
            let mut valid = input.clone();
            valid["claude_dir"] = Value::Null;
            valid
        };
        assert_schema(&null_unselected, &schema);
        f.call(operation, &null_unselected, Some("--dry-run"), 0);
    }
    assert_eq!(fs::read_dir(&f.root).unwrap().count(), 0);
}

#[test]
fn activation_writes_require_confirmation_and_readback_never_creates_a_transaction() {
    let f = Fixture::new();
    for operation in ["skills.apply_update", "skills.rollback_update"] {
        let input = f.input("codex", operation == "skills.apply_update");
        let error = f.call(operation, &input, None, 2);
        assert_eq!(error["error"]["code"], "CONFIRMATION_REQUIRED");
        let command = operation.strip_prefix("skills.").unwrap().replace('_', "-");
        let mut args = vec!["skills", &command, "--codex", "--operation-id", OPERATION];
        if operation == "skills.apply_update" {
            args.extend(["--staging-dir", "/tmp/uninspected-stage"]);
        }
        assert_eq!(f.cli(&args, 2)["error"]["code"], "CONFIRMATION_REQUIRED");
    }
    let missing = f.call("skills.update_result", &f.input("codex", false), None, 5);
    assert_eq!(missing["error"]["code"], "MANAGED_SKILL_ERROR");
    assert_eq!(missing["error"]["retryable"], false);
    assert!(missing["error"]["hint"]
        .as_str()
        .unwrap()
        .contains("original --operation-id"));
    assert_eq!(fs::read_dir(&f.root).unwrap().count(), 0);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn explicit_activation_readback_idempotency_and_rollback_preserve_contracts() {
    for agent in ["codex", "claude"] {
        let f = Fixture::new();
        let original_receipt = f.prepare(agent, "0.0.0");
        let apply = f.input(agent, true);
        let query = f.input(agent, false);
        let before = snapshot(&f.root);
        f.call("skills.apply_update", &apply, Some("--dry-run"), 0);
        assert_eq!(snapshot(&f.root), before);
        let applied = f.call("skills.apply_update", &apply, Some("--yes"), 0);
        assert_schema(&applied["data"], &f.schema("output", "skills.apply_update"));
        assert_eq!(applied["data"]["state"], "applied");
        assert_eq!(applied["data"]["current_state"], "updated");
        assert_eq!(applied["data"]["operation_id"], OPERATION);
        assert_eq!(applied["data"]["allows_automatic_updates"], false);
        assert_eq!(applied["data"]["agent_reloaded"], false);
        let bundle = if agent == "codex" {
            skills::CODEX_SKILL_TEMPLATE
        } else {
            skills::CLAUDE_SKILL_TEMPLATE
        };
        assert_eq!(fs::read_to_string(f.active(agent)).unwrap(), bundle);
        let after = snapshot(&f.root);
        let readback = f.call("skills.update_result", &query, None, 0);
        assert_schema(
            &readback["data"],
            &f.schema("output", "skills.update_result"),
        );
        assert_eq!(readback["data"], applied["data"]);
        assert_eq!(snapshot(&f.root), after);
        let repeated = f.call("skills.apply_update", &apply, Some("--yes"), 0);
        assert_eq!(repeated["data"], applied["data"]);
        assert_eq!(snapshot(&f.root), after);

        // An operation UUID cannot be rebound to a different stage, even if its bytes agree.
        let other_stage = f.root.join("another-candidate");
        fs::create_dir(&other_stage).unwrap();
        for entry in fs::read_dir(f.stage()).unwrap() {
            let entry = entry.unwrap();
            fs::copy(entry.path(), other_stage.join(entry.file_name())).unwrap();
        }
        let before_conflict = snapshot(&f.root);
        let mut conflicting = apply.clone();
        conflicting["staging_dir"] = json!(other_stage);
        let denied = f.call("skills.apply_update", &conflicting, Some("--yes"), 5);
        assert_eq!(denied["error"]["code"], "MANAGED_SKILL_ERROR");
        assert_eq!(denied["error"]["retryable"], false);
        assert_eq!(snapshot(&f.root), before_conflict);

        // A committed operation is recoverable even after the reviewed stage is archived.
        fs::rename(f.stage(), f.root.join("archived-candidate")).unwrap();
        let archived = snapshot(&f.root);
        let repeated = f.call("skills.apply_update", &apply, Some("--yes"), 0);
        assert_eq!(repeated["data"], applied["data"]);
        assert_eq!(snapshot(&f.root), archived);

        let root = f.root_for(agent);
        let selector = format!("--{agent}");
        let override_arg = format!("--{agent}-dir");
        let rolled_back = f.cli(
            &[
                "skills",
                "rollback-update",
                &selector,
                &override_arg,
                root.to_str().unwrap(),
                "--operation-id",
                OPERATION,
                "--yes",
            ],
            0,
        );
        assert_schema(&rolled_back, &f.schema("output", "skills.rollback_update"));
        assert_eq!(rolled_back["state"], "rolled_back");
        assert_eq!(rolled_back["current_state"], "baseline");
        assert_eq!(fs::read_to_string(f.active(agent)).unwrap(), OLD);
        assert_eq!(
            fs::read(
                f.active(agent)
                    .parent()
                    .unwrap()
                    .join(skill_managed::ENROLLMENT_FILE)
            )
            .unwrap(),
            original_receipt
        );
        let restored = snapshot(&f.root);
        let result = f.call("skills.update_result", &query, None, 0);
        assert_eq!(result["data"], rolled_back);
        assert_eq!(snapshot(&f.root), restored);
        let repeated_rollback = f.call("skills.rollback_update", &query, Some("--yes"), 0);
        assert_eq!(repeated_rollback["data"], rolled_back);
        assert_eq!(snapshot(&f.root), restored);
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn activation_refuses_edited_baselines_or_candidates_without_exposing_text() {
    for tamper_active in [true, false] {
        let f = Fixture::new();
        f.prepare("codex", "0.0.0");
        let private = b"Synthetic private customization must not appear in JSON.\n";
        let target = if tamper_active {
            f.active("codex")
        } else {
            f.stage().join("SKILL.md")
        };
        fs::write(target, private).unwrap();
        let before = snapshot(&f.root);
        let refused = f.call(
            "skills.apply_update",
            &f.input("codex", true),
            Some("--yes"),
            5,
        );
        assert_eq!(refused["error"]["code"], "MANAGED_SKILL_ERROR");
        assert_eq!(refused["error"]["retryable"], false);
        assert!(!refused
            .to_string()
            .contains("Synthetic private customization"));
        assert_eq!(snapshot(&f.root), before);
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn readback_reports_post_apply_edits_without_changing_them() {
    let f = Fixture::new();
    f.prepare("codex", "0.0.0");
    f.call(
        "skills.apply_update",
        &f.input("codex", true),
        Some("--yes"),
        0,
    );
    fs::write(f.active("codex"), b"Synthetic later edit.\n").unwrap();
    let before = snapshot(&f.root);
    let result = f.call("skills.update_result", &f.input("codex", false), None, 0);
    assert_schema(&result["data"], &f.schema("output", "skills.update_result"));
    assert_eq!(result["data"]["current_state"], "changed");
    assert_eq!(snapshot(&f.root), before);
    fs::rename(f.active("codex"), f.root.join("saved-later-edit")).unwrap();
    let absent = snapshot(&f.root);
    let result = f.call("skills.update_result", &f.input("codex", false), None, 0);
    assert_schema(&result["data"], &f.schema("output", "skills.update_result"));
    assert_eq!(result["data"]["state"], "applied");
    assert_eq!(result["data"]["current_state"], "unavailable");
    assert_eq!(result["data"]["installed_sha256"], Value::Null);
    assert_eq!(snapshot(&f.root), absent);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn activation_rejects_equal_precedence_and_downgrades_before_mutation() {
    for (version, code) in [
        (env!("CARGO_PKG_VERSION").to_string(), "version_conflict"),
        (
            format!("{}+synthetic", env!("CARGO_PKG_VERSION")),
            "version_conflict",
        ),
        ("99.0.0".to_string(), "downgrade"),
    ] {
        let f = Fixture::new();
        f.prepare("codex", &version);
        let before = snapshot(&f.root);
        let result = f.call(
            "skills.apply_update",
            &f.input("codex", true),
            Some("--yes"),
            5,
        );
        assert_eq!(result["error"]["code"], "MANAGED_SKILL_ERROR");
        assert_eq!(result["error"]["details"]["reason"], code);
        assert_eq!(result["error"]["retryable"], false);
        assert_eq!(snapshot(&f.root), before);
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn direct_apply_and_result_keep_the_existing_raw_output_shape() {
    let f = Fixture::new();
    f.prepare("codex", "0.0.0");
    let root = f.root_for("codex");
    let stage = f.stage();
    let applied = f.cli(
        &[
            "skills",
            "apply-update",
            "--codex",
            "--codex-dir",
            root.to_str().unwrap(),
            "--staging-dir",
            stage.to_str().unwrap(),
            "--operation-id",
            OPERATION,
            "--yes",
        ],
        0,
    );
    assert!(applied.get("data").is_none());
    assert_eq!(applied["state"], "applied");
    assert_schema(&applied, &f.schema("output", "skills.apply_update"));
    let before = snapshot(&f.root);
    let result = f.cli(
        &[
            "skills",
            "update-result",
            "--codex",
            "--codex-dir",
            root.to_str().unwrap(),
            "--operation-id",
            OPERATION,
        ],
        0,
    );
    assert_eq!(result, applied);
    assert_eq!(snapshot(&f.root), before);
}

#[cfg(target_os = "linux")]
#[test]
fn activation_lost_output_can_be_inspected_without_repeating_the_mutation() {
    for broken_pipe in [false, true] {
        let f = Fixture::new();
        f.prepare("codex", "0.0.0");
        let input = f.input("codex", true).to_string();
        let mut command = f.command(&["call", "skills.apply_update", "--input", &input, "--yes"]);
        if broken_pipe {
            let (writer, reader) = std::os::unix::net::UnixStream::pair().unwrap();
            drop(reader);
            command.stdout(std::os::fd::OwnedFd::from(writer));
        } else {
            command.stdout(
                fs::OpenOptions::new()
                    .write(true)
                    .open("/dev/full")
                    .unwrap(),
            );
        }
        let output = command.output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(if broken_pipe { 0 } else { 1 }),
            "{output:?}"
        );
        assert!(output.stdout.is_empty());
        f.assert_local_only();
        let before = snapshot(&f.root);
        let result = f.call("skills.update_result", &f.input("codex", false), None, 0);
        assert_eq!(result["data"]["state"], "applied");
        assert_eq!(result["data"]["current_state"], "updated");
        assert_eq!(snapshot(&f.root), before);
    }
}

#[cfg(windows)]
#[test]
fn windows_activation_is_explicitly_unsupported_without_active_changes() {
    let f = Fixture::new();
    f.prepare("codex", "0.0.0");
    let before = snapshot(&f.root);
    let result = f.call(
        "skills.apply_update",
        &f.input("codex", true),
        Some("--yes"),
        5,
    );
    assert_eq!(result["error"]["details"]["reason"], "platform_unsupported");
    assert_eq!(snapshot(&f.root), before);
}
