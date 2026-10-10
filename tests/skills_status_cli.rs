//! Synthetic local skill files only: status must never contact an API or mutate files.
use serde_json::{json, Value};
use sniper::{skill_status::MAX_SKILL_BYTES, skills};
use std::{
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::Command,
};
use uuid::Uuid;

struct Fixture {
    root: PathBuf,
    listener: TcpListener,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("sniper-skills-status-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        Self { root, listener }
    }
    fn cli(&self, args: &[&str], success: bool) -> Value {
        self.cli_format(args, success, "compact")
    }
    fn cli_format(&self, args: &[&str], success: bool, format: &str) -> Value {
        let output = Command::new(env!("CARGO_BIN_EXE_sniper-cli"))
            .args([
                "--output",
                format,
                "--api",
                &format!("http://{}", self.listener.local_addr().unwrap()),
            ])
            .args(args)
            .env("HOME", self.root.join("home"))
            .env("USERPROFILE", self.root.join("home"))
            .env("CODEX_HOME", self.root.join("codex-home"))
            .env("SNIPER_DATA_DIR", self.root.join("data"))
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(if success { 0 } else { 2 }),
            "{output:?}"
        );
        assert!(output.stderr.is_empty(), "{output:?}");
        assert_eq!(
            self.listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "CLI contacted API"
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }
    fn root_for(&self, agent: &str) -> PathBuf {
        self.root.join(agent)
    }
    fn put(&self, agent: &str, contents: &[u8]) -> PathBuf {
        let path = self.root_for(agent).join("sniper-operator/SKILL.md");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, contents).unwrap();
        path
    }
    fn direct(&self, root: &Path) -> Value {
        self.cli(
            &[
                "skills",
                "status",
                "--codex",
                "--codex-dir",
                root.to_str().unwrap(),
            ],
            true,
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn assert_row_schema(row: &Value, schema: &Value) {
    let fields = row.as_object().unwrap();
    for name in schema["required"].as_array().unwrap() {
        assert!(fields.contains_key(name.as_str().unwrap()));
    }
    for (name, value) in fields {
        let field = &schema["properties"][name];
        assert!(!field.is_null(), "unknown field {name}");
        if value.is_null() {
            assert!(field["type"].as_array().unwrap().contains(&json!("null")));
        } else {
            assert!(value.is_string(), "{name}");
        }
        if let Some(values) = field["enum"].as_array() {
            assert!(values.contains(value));
        }
        if name.ends_with("sha256") && !value.is_null() {
            let hash = value.as_str().unwrap();
            assert_eq!(hash.len(), 64);
            assert!(hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        }
    }
}

#[test]
fn missing_current_different_and_call_match_without_writes() {
    let f = Fixture::new();
    let root = f.root_for("codex");
    let missing = f.direct(&root);
    assert_eq!(missing["scope"], "cli_host");
    assert_eq!(missing["bundled_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(missing["entries"][0]["status"], "missing");
    assert!(missing["entries"][0]["installed_sha256"].is_null());
    assert!(!root.exists());
    let path = f.put("codex", skills::CODEX_SKILL_TEMPLATE.as_bytes());
    let before = fs::metadata(&path).unwrap().modified().unwrap();
    let current = f.direct(&root);
    assert_eq!(current["entries"][0]["status"], "current");
    assert_eq!(
        current["entries"][0]["installed_sha256"],
        current["entries"][0]["bundled_sha256"]
    );
    let input = json!({"codex":true,"codex_dir":root}).to_string();
    let called = f.cli(&["call", "skills.status", "--input", &input], true);
    assert_eq!(called["ok"], true);
    assert_eq!(called["operation"], "skills.status");
    assert_eq!(called["data"], current);
    assert_eq!(
        f.cli_format(
            &["call", "skills.status", "--input", &input],
            true,
            "pretty"
        ),
        called
    );
    assert_eq!(
        f.cli_format(
            &[
                "skills",
                "status",
                "--codex",
                "--codex-dir",
                root.to_str().unwrap()
            ],
            true,
            "pretty"
        ),
        current
    );

    assert_eq!(
        fs::read(&path).unwrap(),
        skills::CODEX_SKILL_TEMPLATE.as_bytes()
    );
    assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), before);
    f.put(
        "codex",
        b"Synthetic different content; never print this text.\n",
    );
    let changed = f.direct(&root);
    assert_eq!(changed["entries"][0]["status"], "modified_or_outdated");
    assert!(!changed.to_string().contains("Synthetic different content"));
    assert_eq!(
        fs::read(&path).unwrap(),
        b"Synthetic different content; never print this text.\n"
    );
    let claude_path = f.put("claude", skills::CLAUDE_SKILL_TEMPLATE.as_bytes());
    let all = f.cli(
        &[
            "skills",
            "status",
            "--all",
            "--codex-dir",
            root.to_str().unwrap(),
            "--claude-dir",
            f.root_for("claude").to_str().unwrap(),
        ],
        true,
    );
    assert_eq!(all["entries"].as_array().unwrap().len(), 2);
    assert_eq!(all["entries"][1]["agent"], "claude");
    assert_eq!(all["entries"][1]["status"], "current");
    assert_eq!(
        fs::read(claude_path).unwrap(),
        skills::CLAUDE_SKILL_TEMPLATE.as_bytes()
    );
    let schema = f.cli(&["schema", "output", "skills.status"], true)["schema"].clone();
    for result in [&missing, &current, &changed, &all] {
        assert_eq!(result.as_object().unwrap().len(), 3);
        for row in result["entries"].as_array().unwrap() {
            assert_row_schema(row, &schema["properties"]["entries"]["items"]);
        }
    }
    assert!(!f.root.join("data").exists());
    assert!(!f.root.join("home").exists());
}

#[test]
fn strict_discovery_validation_and_dry_run_stay_offline() {
    let f = Fixture::new();
    let manifest = f.cli(&["manifest"], true);
    let spec = manifest["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|op| op["operation"] == "skills.status")
        .unwrap();
    assert_eq!(spec["side_effect"], "read");
    assert_eq!(spec["requires_confirmation"], false);
    for kind in ["input", "output"] {
        let schema = f.cli(&["schema", kind, "skills.status"], true);
        assert_eq!(schema["schema"], spec[format!("{kind}_schema")]);
        assert_eq!(schema["schema"]["additionalProperties"], false);
    }
    let examples = f.cli(&["examples", "skills.status"], true);
    assert_eq!(examples["examples"], spec["examples"]);
    let root = f.root_for("not-created");
    let dry = f.cli(
        &[
            "skills",
            "status",
            "--all",
            "--codex-dir",
            root.to_str().unwrap(),
            "--claude-dir",
            root.to_str().unwrap(),
            "--dry-run",
        ],
        true,
    );
    assert!(!dry.to_string().contains("installed_sha256"));
    assert!(!root.exists());
    for input in [
        "{}",
        r#"{"all":false}"#,
        r#"{"codex":null}"#,
        r#"{"all":true,"unexpected":1}"#,
        r#"{"codex":"true"}"#,
        r#"{"claude":true,"claude_dir":4}"#,
        r#"{"codex":true,"codex_dir":""}"#,
    ] {
        let error = f.cli(
            &["call", "skills.status", "--input", input, "--dry-run"],
            false,
        );
        assert_eq!(error["ok"], false);
        assert_eq!(error["error"]["code"], "INVALID_INPUT");
    }
    f.cli(&["skills", "status"], false);
    assert_eq!(fs::read_dir(&f.root).unwrap().count(), 0);
}

#[test]
fn oversized_and_non_regular_files_are_reported_without_changes() {
    let f = Fixture::new();
    let path = f.put("codex", b"");
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(MAX_SKILL_BYTES + 1)
        .unwrap();
    let result = f.direct(&f.root_for("codex"));
    assert_eq!(result["entries"][0]["status"], "unsupported");
    assert_eq!(result["entries"][0]["error_code"], "file_too_large");
    assert_eq!(fs::metadata(&path).unwrap().len(), MAX_SKILL_BYTES + 1);
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    let result = f.direct(&f.root_for("codex"));
    assert_eq!(result["entries"][0]["error_code"], "non_regular_file");
    assert!(path.is_dir());
    assert_eq!(fs::read_dir(path).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn symlink_is_not_followed_or_replaced() {
    let f = Fixture::new();
    let outside = f.root.join("synthetic-target");
    fs::write(&outside, skills::CODEX_SKILL_TEMPLATE).unwrap();
    let path = f.put("codex", b"");
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&outside, &path).unwrap();
    let result = f.direct(&f.root_for("codex"));
    assert_eq!(result["entries"][0]["status"], "unsupported");
    assert_eq!(result["entries"][0]["error_code"], "symlink");
    assert!(result["entries"][0]["installed_sha256"].is_null());
    assert_eq!(fs::read_link(path).unwrap(), outside);
    assert_eq!(
        fs::read(outside).unwrap(),
        skills::CODEX_SKILL_TEMPLATE.as_bytes()
    );
}
