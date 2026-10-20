//! Host-local opt-in coverage; every profile, policy, installation and API is synthetic.
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

const OPERATIONS: [&str; 4] = [
    "skills.auto_update_status",
    "skills.enable_auto_updates",
    "skills.disable_auto_updates",
    "skills.auto_update_once",
];
const OLD: &str = "Synthetic older skill baseline.\n";

struct Fixture {
    root: PathBuf,
    listener: TcpListener,
}

impl Fixture {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("sniper-skills-auto-update-{}", Uuid::new_v4()));
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
            .env("SNIPER_DATA_DIR", self.root.join("data"))
            .env("TMPDIR", self.root.join("tmp"))
            .env("TMP", self.root.join("tmp"))
            .env("TEMP", self.root.join("tmp"));
        command
    }

    fn cli(&self, args: &[&str], exit_code: i32) -> Value {
        let output = self.command(args).output().unwrap();
        assert_eq!(output.status.code(), Some(exit_code), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
        assert_eq!(
            self.listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "CLI contacted the API"
        );
        for name in ["home", "codex-home", "claude-home", "tmp"] {
            assert!(!self.root.join(name).exists(), "Touched unrelated {name}");
        }
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn call(&self, operation: &str, input: &Value, flag: Option<&str>, exit_code: i32) -> Value {
        let input = input.to_string();
        let mut args = vec!["call", operation, "--input", &input];
        args.extend(flag);
        self.cli(&args, exit_code)
    }

    fn schema(&self, kind: &str, operation: &str) -> Value {
        self.cli(&["schema", kind, operation], 0)["schema"].clone()
    }

    fn root_for(&self, agent: &str) -> PathBuf {
        self.root.join(agent)
    }
    fn active(&self, agent: &str) -> PathBuf {
        self.root_for(agent).join("sniper-operator/SKILL.md")
    }
    fn input(&self, agent: &str, enable: bool) -> Value {
        let mut input = json!({agent:true});
        if enable {
            input[format!("{agent}_dir")] = json!(self.root_for(agent));
        }
        input
    }
    fn prepare(&self, agent: &str, contents: &str, version: &str) {
        let active = self.active(agent);
        fs::create_dir_all(active.parent().unwrap()).unwrap();
        fs::write(active, contents).unwrap();
        skill_managed::enroll_skill(agent, &self.root_for(agent), contents, version).unwrap();
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

// Validate the JSON Schema vocabulary used by the strict host-policy contracts.
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
            "minimum",
            "maximum",
            "allOf",
            "anyOf",
            "oneOf",
        ],
        &["object", "array", "string", "integer", "boolean", "null"],
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
    if value.is_number() {
        if let Some(min) = schema["minimum"].as_u64() {
            if value.as_u64().is_none_or(|number| number < min) {
                return false;
            }
        }
        if let Some(max) = schema["maximum"].as_u64() {
            if value.as_u64().is_none_or(|number| number > max) {
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
fn auto_update_discovery_schemas_examples_and_dry_runs_are_offline() {
    let f = Fixture::new();
    let manifest = f.cli(&["manifest"], 0);
    for operation in OPERATIONS {
        let spec = manifest["operations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|spec| spec["operation"] == operation)
            .unwrap();
        let read = operation == "skills.auto_update_status";
        assert_eq!(spec["side_effect"], if read { "read" } else { "write" });
        assert_eq!(spec["requires_confirmation"], !read);
        let schema = f.schema("input", operation);
        assert_eq!(schema, spec["input_schema"]);
        assert_eq!(f.schema("output", operation), spec["output_schema"]);
        let examples = f.cli(&["examples", operation], 0);
        assert_eq!(examples["examples"], spec["examples"]);
        for input in examples["examples"].as_array().unwrap() {
            assert_schema(input, &schema);
            let preview = f.call(operation, input, Some("--dry-run"), 0);
            assert_eq!(preview["operation"], operation);
        }
        for agent in ["codex", "claude"] {
            let input = f.input(agent, operation == "skills.enable_auto_updates");
            assert_schema(&input, &schema);
            f.call(operation, &input, Some("--dry-run"), 0);
            let command = operation.strip_prefix("skills.").unwrap().replace('_', "-");
            let selector = format!("--{agent}");
            f.cli(&["skills", &command, &selector, "--dry-run"], 0);
        }
    }
    assert!(
        snapshot(&f.root).is_empty(),
        "Offline commands touched filesystem"
    );
}

#[test]
fn auto_update_commands_require_exactly_one_agent_and_forbid_stored_target_redirection() {
    let f = Fixture::new();
    for operation in OPERATIONS {
        let schema = f.schema("input", operation);
        for input in [
            json!({}),
            json!({"codex":false}),
            json!({"codex":true,"claude":true}),
            json!({"all":true}),
            json!({"codex":"true"}),
        ] {
            assert!(!matches_schema(&input, &schema), "{input}");
            assert_eq!(
                f.call(operation, &input, Some("--dry-run"), 2)["error"]["code"],
                "INVALID_INPUT"
            );
        }
        let command = operation.strip_prefix("skills.").unwrap().replace('_', "-");
        f.cli(&["skills", &command, "--dry-run"], 2);
        f.cli(&["skills", &command, "--codex", "--claude", "--dry-run"], 2);
        f.cli(&["skills", &command, "--all", "--dry-run"], 2);
        if operation != "skills.enable_auto_updates" {
            for field in [
                "codex_dir",
                "claude_dir",
                "policy_revision",
                "operation_id",
                "staging_dir",
            ] {
                let input = json!({"codex":true,field:null});
                assert!(!matches_schema(&input, &schema));
                f.call(operation, &input, Some("--dry-run"), 2);
            }
            f.cli(
                &[
                    "skills",
                    &command,
                    "--codex",
                    "--codex-dir",
                    "/uninspected",
                    "--dry-run",
                ],
                2,
            );
        }
    }
    assert!(snapshot(&f.root).is_empty());
}

#[test]
fn enable_revision_and_path_schema_match_canonical_call_validation() {
    let f = Fixture::new();
    let op = "skills.enable_auto_updates";
    let schema = f.schema("input", op);
    for revision in [json!(null), json!(0), json!(1), json!(u64::MAX)] {
        let input = json!({"codex":true,"claude":null,"codex_dir":null,"claude_dir":null,"policy_revision":revision});
        assert_schema(&input, &schema);
        f.call(op, &input, Some("--dry-run"), 0);
    }
    for revision in [
        json!(-1),
        json!(1.5),
        json!("2"),
        json!(true),
        json!({}),
        json!([]),
    ] {
        let input = json!({"codex":true,"policy_revision":revision});
        assert!(!matches_schema(&input, &schema));
        f.call(op, &input, Some("--dry-run"), 2);
    }
    for input in [
        json!({"codex":true,"claude_dir":"/uninspected"}),
        json!({"codex":true,"codex_dir":""}),
        json!({"codex":true,"codex_dir":"bad\u{0000}path"}),
    ] {
        assert!(!matches_schema(&input, &schema));
        f.call(op, &input, Some("--dry-run"), 2);
    }
    f.cli(
        &[
            "skills",
            "enable-auto-updates",
            "--codex",
            "--policy-revision",
            "0",
            "--dry-run",
        ],
        0,
    );
    f.cli(
        &[
            "skills",
            "enable-auto-updates",
            "--codex",
            "--policy-revision",
            "-1",
            "--dry-run",
        ],
        2,
    );
    assert!(snapshot(&f.root).is_empty());
}

#[test]
fn absent_policy_status_is_read_only_and_mutations_require_confirmation() {
    let f = Fixture::new();
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let status = f.cli(&["skills", "auto-update-status", "--codex"], 0);
        assert_schema(&status, &f.schema("output", "skills.auto_update_status"));
        assert_eq!(status["state"], "disabled");
        assert_eq!(status["enabled"], false);
        assert_eq!(status["revision"], Value::Null);
        assert_eq!(status["agent_reloaded"], false);
        let called = f.call("skills.auto_update_status", &json!({"codex":true}), None, 0);
        assert_eq!(called["data"], status);
        for operation in ["skills.disable_auto_updates", "skills.auto_update_once"] {
            let result = f.call(operation, &json!({"codex":true}), Some("--yes"), 0);
            assert_eq!(result["data"], status);
            assert_schema(&result["data"], &f.schema("output", operation));
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let error = f.cli(&["skills", "auto-update-status", "--codex"], 5);
        assert_eq!(error["error"]["details"]["reason"], "platform_unsupported");
    }
    for operation in &OPERATIONS[1..] {
        let error = f.call(operation, &json!({"codex":true}), None, 2);
        assert_eq!(error["error"]["code"], "CONFIRMATION_REQUIRED");
        let command = operation.strip_prefix("skills.").unwrap().replace('_', "-");
        assert_eq!(
            f.cli(&["skills", &command, "--codex"], 2)["error"]["code"],
            "CONFIRMATION_REQUIRED"
        );
    }
    assert!(snapshot(&f.root).is_empty());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn enable_records_consent_only_then_once_updates_the_stored_target() {
    for agent in ["codex", "claude"] {
        let f = Fixture::new();
        f.prepare(agent, OLD, "0.0.0");
        let active_before = fs::read(f.active(agent)).unwrap();
        let receipt = f
            .active(agent)
            .parent()
            .unwrap()
            .join(skill_managed::ENROLLMENT_FILE);
        let receipt_before = fs::read(&receipt).unwrap();
        let before = snapshot(&f.root);
        f.call(
            "skills.enable_auto_updates",
            &f.input(agent, true),
            Some("--dry-run"),
            0,
        );
        assert_eq!(snapshot(&f.root), before);
        let enabled = f.call(
            "skills.enable_auto_updates",
            &f.input(agent, true),
            Some("--yes"),
            0,
        )["data"]
            .clone();
        assert_schema(&enabled, &f.schema("output", "skills.enable_auto_updates"));
        assert_eq!(enabled["state"], "enabled");
        assert_eq!(enabled["enabled"], true);
        assert_eq!(fs::read(f.active(agent)).unwrap(), active_before);
        assert_eq!(fs::read(&receipt).unwrap(), receipt_before);
        assert!(f.root.join("data/host-skill-updates").is_dir());
        let after_enable = snapshot(&f.root);
        let status = f.call("skills.auto_update_status", &f.input(agent, false), None, 0);
        assert_schema(
            &status["data"],
            &f.schema("output", "skills.auto_update_status"),
        );
        assert_eq!(snapshot(&f.root), after_enable);
        assert_eq!(status["data"]["path"], json!(f.active(agent)));
        let updated = f.call(
            "skills.auto_update_once",
            &f.input(agent, false),
            Some("--yes"),
            0,
        )["data"]
            .clone();
        assert_schema(&updated, &f.schema("output", "skills.auto_update_once"));
        assert_eq!(updated["state"], "updated");
        assert_eq!(updated["generation"], enabled["generation"]);
        assert!(updated["operation_id"].is_string());
        let bundled = if agent == "codex" {
            skills::CODEX_SKILL_TEMPLATE
        } else {
            skills::CLAUDE_SKILL_TEMPLATE
        };
        assert_eq!(fs::read_to_string(f.active(agent)).unwrap(), bundled);
        let before_current = snapshot(&f.root);
        let current = f.call(
            "skills.auto_update_once",
            &f.input(agent, false),
            Some("--yes"),
            0,
        )["data"]
            .clone();
        assert_schema(&current, &f.schema("output", "skills.auto_update_once"));
        assert_eq!(current["state"], "current");
        assert_eq!(fs::read_to_string(f.active(agent)).unwrap(), bundled);
        assert_eq!(snapshot(&f.root), before_current);
        let disabled = f.call(
            "skills.disable_auto_updates",
            &f.input(agent, false),
            Some("--yes"),
            0,
        )["data"]
            .clone();
        assert_schema(
            &disabled,
            &f.schema("output", "skills.disable_auto_updates"),
        );
        assert_eq!(disabled["enabled"], false);
        assert_eq!(disabled["state"], "disabled");
        assert_eq!(fs::read_to_string(f.active(agent)).unwrap(), bundled);
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn pause_preserves_edits_and_reenable_requires_current_revision_and_new_generation() {
    let f = Fixture::new();
    f.prepare(
        "codex",
        skills::CODEX_SKILL_TEMPLATE,
        env!("CARGO_PKG_VERSION"),
    );
    let enabled = f.call(
        "skills.enable_auto_updates",
        &f.input("codex", true),
        Some("--yes"),
        0,
    )["data"]
        .clone();
    let private = b"Synthetic private edits that must not leak into JSON.\n";
    fs::write(f.active("codex"), private).unwrap();
    let paused = f.call(
        "skills.auto_update_once",
        &f.input("codex", false),
        Some("--yes"),
        0,
    )["data"]
        .clone();
    assert_schema(&paused, &f.schema("output", "skills.auto_update_once"));
    assert_eq!(paused["state"], "paused");
    assert!(!paused.to_string().contains("Synthetic private edits"));
    assert_eq!(fs::read(f.active("codex")).unwrap(), private);
    let before_status = snapshot(&f.root);
    let status = f.call(
        "skills.auto_update_status",
        &f.input("codex", false),
        None,
        0,
    )["data"]
        .clone();
    assert_eq!(status["state"], "paused");
    assert_eq!(snapshot(&f.root), before_status);
    fs::write(f.active("codex"), skills::CODEX_SKILL_TEMPLATE).unwrap();
    for revision in [None, Some(json!(u64::MAX))] {
        let mut input = f.input("codex", true);
        if let Some(revision) = revision {
            input["policy_revision"] = revision;
        }
        let before = snapshot(&f.root);
        let rejected = f.call("skills.enable_auto_updates", &input, Some("--yes"), 5);
        assert_eq!(rejected["error"]["code"], "MANAGED_SKILL_ERROR");
        assert_eq!(rejected["error"]["retryable"], false);
        assert!(rejected["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("auto-update-status"));
        assert_eq!(snapshot(&f.root), before);
    }
    let mut input = f.input("codex", true);
    input["policy_revision"] = status["revision"].clone();
    let renewed = f.call("skills.enable_auto_updates", &input, Some("--yes"), 0)["data"].clone();
    assert_eq!(renewed["state"], "enabled");
    assert_ne!(renewed["generation"], enabled["generation"]);
    assert!(renewed["revision"].as_u64().unwrap() > status["revision"].as_u64().unwrap());
    assert_eq!(
        fs::read_to_string(f.active("codex")).unwrap(),
        skills::CODEX_SKILL_TEMPLATE
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn direct_enable_disable_and_disabled_once_preserve_active_files_and_policy_history() {
    let f = Fixture::new();
    f.prepare(
        "codex",
        skills::CODEX_SKILL_TEMPLATE,
        env!("CARGO_PKG_VERSION"),
    );
    let root = f.root_for("codex");
    let enabled = f.cli(
        &[
            "skills",
            "enable-auto-updates",
            "--codex",
            "--codex-dir",
            root.to_str().unwrap(),
            "--yes",
        ],
        0,
    );
    assert_schema(&enabled, &f.schema("output", "skills.enable_auto_updates"));
    assert!(enabled.get("data").is_none());
    assert_eq!(enabled["enabled"], true);
    let disabled = f.cli(&["skills", "disable-auto-updates", "--codex", "--yes"], 0);
    assert_schema(
        &disabled,
        &f.schema("output", "skills.disable_auto_updates"),
    );
    assert_eq!(disabled["enabled"], false);
    assert_eq!(disabled["generation"], enabled["generation"]);
    let before = snapshot(&f.root);
    let once = f.cli(&["skills", "auto-update-once", "--codex", "--yes"], 0);
    assert_eq!(once, disabled);
    assert_eq!(snapshot(&f.root), before);
    assert_eq!(
        fs::read_to_string(f.active("codex")).unwrap(),
        skills::CODEX_SKILL_TEMPLATE
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn non_newer_bundles_pause_without_replacing_files_or_minting_retry_ids() {
    for (version, reason) in [
        (env!("CARGO_PKG_VERSION").to_owned(), "version_conflict"),
        (
            format!("{}+synthetic", env!("CARGO_PKG_VERSION")),
            "version_conflict",
        ),
        ("99.0.0".to_owned(), "bundle_downgrade"),
    ] {
        let f = Fixture::new();
        f.prepare("codex", OLD, &version);
        f.call(
            "skills.enable_auto_updates",
            &f.input("codex", true),
            Some("--yes"),
            0,
        );
        let receipt = f
            .active("codex")
            .parent()
            .unwrap()
            .join(skill_managed::ENROLLMENT_FILE);
        let receipt_before = fs::read(&receipt).unwrap();
        let result = f.call(
            "skills.auto_update_once",
            &f.input("codex", false),
            Some("--yes"),
            0,
        )["data"]
            .clone();
        assert_schema(&result, &f.schema("output", "skills.auto_update_once"));
        assert_eq!(result["state"], "paused");
        assert_eq!(result["error_code"], reason);
        assert_eq!(result["operation_id"], Value::Null);
        assert_eq!(fs::read_to_string(f.active("codex")).unwrap(), OLD);
        assert_eq!(fs::read(&receipt).unwrap(), receipt_before);
        let before = snapshot(&f.root);
        let repeated = f.call(
            "skills.auto_update_once",
            &f.input("codex", false),
            Some("--yes"),
            0,
        )["data"]
            .clone();
        assert_eq!(repeated["state"], "paused");
        assert_eq!(repeated["error_code"], "policy_paused");
        assert_eq!(repeated["pause_reason"], reason);
        assert_eq!(repeated["operation_id"], Value::Null);
        assert_eq!(snapshot(&f.root), before);
    }
}

#[test]
fn policy_call_dry_run_rejects_external_input_sources_before_reading() {
    let f = Fixture::new();
    let missing = format!("@{}", f.root.join("private-nonexistent-input").display());
    for operation in OPERATIONS {
        for source in [&missing, "-", "@"] {
            let result = f.cli(&["call", operation, "--input", source, "--dry-run"], 2);
            assert_eq!(result["error"]["code"], "INVALID_INPUT");
            assert!(result["error"]["message"]
                .as_str()
                .unwrap()
                .contains("require inline JSON"));
            assert!(!result.to_string().contains("private-nonexistent-input"));
        }
    }
    assert!(snapshot(&f.root).is_empty());
}

#[cfg(unix)]
#[test]
fn policy_call_dry_run_never_opens_fifo_or_waits_for_stdin() {
    use std::{
        ffi::CString,
        os::unix::ffi::OsStrExt,
        process::Stdio,
        time::{Duration, Instant},
    };
    let f = Fixture::new();
    let fifo = f.root.join("unread-input-fifo");
    let path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let source = format!("@{}", fifo.display());
    for operation in OPERATIONS {
        for source in [source.as_str(), "-"] {
            let mut child = f
                .command(&["call", operation, "--input", source, "--dry-run"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            while child.try_wait().unwrap().is_none() {
                if Instant::now() >= deadline {
                    child.kill().unwrap();
                    let output = child.wait_with_output().unwrap();
                    panic!("Dry run opened or waited for external input: {output:?}");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let output = child.wait_with_output().unwrap();
            assert_eq!(output.status.code(), Some(2), "{output:?}");
            assert!(output.stderr.is_empty());
            let result: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(result["error"]["code"], "INVALID_INPUT");
            assert!(result["error"]["message"]
                .as_str()
                .unwrap()
                .contains("require inline JSON"));
        }
    }
    assert_eq!(
        f.listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(fs::read_dir(&f.root).unwrap().count(), 1);
    assert!(fs::symlink_metadata(fifo).is_ok());
}
