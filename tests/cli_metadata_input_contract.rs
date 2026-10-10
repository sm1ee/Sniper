//! Offline metadata and dry-run checks. No skills, sessions or runtime are opened.
use serde_json::{json, Value};
use std::{fs, net::TcpListener, path::PathBuf, process::Command};
use uuid::Uuid;

struct Fixture {
    root: PathBuf,
    listener: TcpListener,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("sniper-metadata-input-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        Self { root, listener }
    }

    fn cli(&self, args: &[&str], exit_code: i32) -> Value {
        let output = Command::new(env!("CARGO_BIN_EXE_sniper-cli"))
            .env_clear()
            .env("HOME", self.root.join("home"))
            .env("USERPROFILE", self.root.join("home"))
            .env("CODEX_HOME", self.root.join("codex-home"))
            .env("SNIPER_DATA_DIR", self.root.join("data"))
            .current_dir(&self.root)
            .args([
                "--output",
                "compact",
                "--api",
                &format!("http://{}", self.listener.local_addr().unwrap()),
            ])
            .args(args)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(exit_code),
            "{args:?}: {output:?}"
        );
        assert!(output.stderr.is_empty(), "{output:?}");
        assert_eq!(
            self.listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "CLI contacted the API"
        );
        assert_eq!(
            fs::read_dir(&self.root).unwrap().count(),
            0,
            "CLI wrote files"
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn call(&self, operation: &str, input: Value, exit_code: i32) -> Value {
        self.cli(
            &[
                "--dry-run",
                "call",
                operation,
                "--input",
                &input.to_string(),
            ],
            exit_code,
        )
    }

    fn input_schema(&self, operation: &str) -> Value {
        let schema = self.cli(&["schema", "input", operation], 0)["schema"].clone();
        let manifest = self.cli(&["manifest"], 0);
        let spec = manifest["operations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|spec| spec["operation"] == operation)
            .unwrap();
        assert_eq!(schema, spec["input_schema"]);
        let input = json!({"kind":"input","operation":operation}).to_string();
        let called = self.cli(&["call", "schema", "--input", &input], 0);
        assert_eq!(called["data"]["schema"], schema);
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        schema
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn assert_invalid(output: &Value, operation: &str) {
    assert_eq!(output["ok"], false);
    assert_eq!(output["operation"], operation);
    assert_eq!(output["error"]["code"], "INVALID_INPUT");
}

#[test]
fn schema_discovery_types_match_call_conversion() {
    let f = Fixture::new();
    let schema = f.input_schema("schema");
    assert_eq!(schema["required"], json!(["kind", "operation"]));
    assert_eq!(schema["properties"]["kind"]["type"], "string");
    assert_eq!(
        schema["properties"]["kind"]["enum"],
        json!(["input", "output"])
    );
    assert_eq!(schema["properties"]["operation"]["type"], "string");
    for input in [
        json!({}),
        json!({"kind":null,"operation":"session.list"}),
        json!({"kind":1,"operation":"session.list"}),
        json!({"kind":"other","operation":"session.list"}),
        json!({"kind":"input","operation":null}),
        json!({"kind":"input","operation":1}),
    ] {
        assert_invalid(&f.call("schema", input, 2), "schema");
    }
    for kind in ["input", "output"] {
        let input = json!({"kind":kind,"operation":"session.list"});
        assert_eq!(f.call("schema", input.clone(), 0)["data"]["input"], input);
        f.cli(&["--dry-run", "schema", kind, "session.list"], 0);
    }
}

#[test]
fn install_schema_and_preflight_require_targets_and_valid_path_strings() {
    let f = Fixture::new();
    let schema = f.input_schema("skills.install");
    for operation in ["skills.status", "skills.update_preview"] {
        assert_eq!(schema, f.input_schema(operation));
    }
    assert_eq!(schema["required"], json!([]));
    for field in ["codex", "claude", "all"] {
        assert_eq!(
            schema["properties"][field]["type"],
            json!(["boolean", "null"])
        );
        assert_eq!(schema["properties"][field]["default"], false);
        assert!(schema["anyOf"].as_array().unwrap().iter().any(|branch| {
            branch["required"] == json!([field]) && branch["properties"][field]["const"] == true
        }));
        assert_invalid(
            &f.call("skills.install", json!({field:"true"}), 2),
            "skills.install",
        );
    }
    for field in ["codex_dir", "claude_dir"] {
        assert_eq!(
            schema["properties"][field]["type"],
            json!(["string", "null"])
        );
        assert_eq!(schema["properties"][field]["minLength"], 1);
        assert_eq!(schema["properties"][field]["pattern"], "^[^\\u0000]*$");
        for value in [json!(""), json!("relative\0path"), json!(1)] {
            assert_invalid(
                &f.call("skills.install", json!({"all":true,field:value}), 2),
                "skills.install",
            );
        }
    }
    for input in [
        json!({}),
        json!({"all":false,"codex":null,"claude":false}),
        json!({"codex_dir":"relative"}),
        json!({"codex":true,"claude_dir":""}),
        json!({"claude":true,"codex_dir":"relative\0path"}),
    ] {
        assert_invalid(&f.call("skills.install", input, 2), "skills.install");
    }
    for args in [
        vec!["--dry-run", "skills", "install"],
        vec!["--dry-run", "skills", "install", "--codex-dir", "relative"],
        vec![
            "--dry-run",
            "skills",
            "install",
            "--codex",
            "--codex-dir",
            "",
        ],
    ] {
        assert_invalid(&f.cli(&args, 2), "skills.install");
    }
}

#[test]
fn install_dry_run_keeps_nullable_defaults_and_does_not_resolve_paths() {
    let f = Fixture::new();
    for input in [
        json!({"codex":true}),
        json!({"claude":true}),
        json!({"all":true}),
        json!({"codex":true,"claude":true,"all":true}),
        json!({"codex":true,"claude":null,"all":null,"codex_dir":null,"claude_dir":null}),
        json!({"codex":true,"codex_dir":"relative/path","claude_dir":"unused/path"}),
        json!({"codex":true,"codex_dir":" "}),
        // Resolving or comparing these targets belongs to execution, not planning.
        json!({"all":true,"codex_dir":".","claude_dir":"."}),
    ] {
        let output = f.call("skills.install", input, 0);
        assert_eq!(output["data"]["dry_run"], true);
        assert_eq!(output["data"]["api"], json!({"local":true}));
    }
    for target in ["--codex", "--claude", "--all"] {
        f.cli(&["--dry-run", "skills", "install", target], 0);
    }
    f.cli(
        &[
            "--dry-run",
            "skills",
            "install",
            "--all",
            "--codex-dir",
            ".",
            "--claude-dir",
            ".",
        ],
        0,
    );
}

#[test]
fn session_create_keeps_nullable_and_blank_name_semantics() {
    let f = Fixture::new();
    let schema = f.input_schema("session.create");
    let name_schema = &schema["properties"]["name"];
    assert_eq!(schema["required"], json!([]));
    assert_eq!(name_schema["type"], json!(["string", "null"]));
    for constraint in ["minLength", "maxLength", "pattern"] {
        assert!(name_schema.get(constraint).is_none());
    }
    for input in [json!({}), json!({"name":null})] {
        assert_eq!(
            f.call("session.create", input, 0)["data"]["input"],
            json!({"name":null})
        );
    }
    for name in [
        "".to_owned(),
        " \t\n ".to_owned(),
        "  Review  ".to_owned(),
        "a\nb".to_owned(),
        " ".repeat(300),
    ] {
        let called = f.call("session.create", json!({"name":name}), 0);
        let direct = f.cli(&["--dry-run", "session", "create", "--name", &name], 0);
        assert_eq!(called["data"]["input"], direct["input"]);
        assert_eq!(direct["input"]["name"], name);
    }
    for name in [json!(1), json!(true), json!([]), json!({})] {
        assert_invalid(
            &f.call("session.create", json!({"name":name}), 2),
            "session.create",
        );
    }
}

#[test]
fn session_create_validates_trimmed_utf8_bytes_without_normalizing_previews() {
    let f = Fixture::new();
    let direct_default = f.cli(&["--dry-run", "session", "create"], 0);
    assert_eq!(direct_default["input"], json!({"name": null}));
    for name in [
        "x".repeat(256),
        "é".repeat(128),
        "😀".repeat(64),
        "\u{2003}".repeat(300),
        "a\nb".to_owned(),
    ] {
        for raw in [name.clone(), format!(" \t\u{2003}{name}\n ")] {
            let called = f.call("session.create", json!({"name":raw}), 0);
            let direct = f.cli(&["--dry-run", "session", "create", "--name", &raw], 0);
            assert_eq!(called["data"]["input"], json!({"name":raw}));
            assert_eq!(called["data"]["input"], direct["input"]);
            assert_eq!(called["data"]["api"], direct["api"]);
            assert_eq!(direct["api"]["body"], json!({"name":raw}));
        }
    }
    // NUL cannot be passed as an OS argument, but remains valid in JSON input.
    let raw = " \u{2003}a\0b\n ";
    let called = f.call("session.create", json!({"name":raw}), 0);
    assert_eq!(called["data"]["input"], json!({"name":raw}));
    assert_eq!(called["data"]["api"]["body"], json!({"name":raw}));
    for name in ["x".repeat(257), "é".repeat(129), "😀".repeat(65)] {
        for raw in [name.clone(), format!(" \t\u{2003}{name}\n ")] {
            for output in [
                f.call("session.create", json!({"name":raw}), 2),
                f.cli(&["--dry-run", "session", "create", "--name", &raw], 2),
            ] {
                assert_invalid(&output, "session.create");
                assert_eq!(
                    output["error"]["message"],
                    "session name cannot exceed 256 bytes"
                );
            }
        }
    }
}

#[test]
fn oversized_session_creation_fails_before_confirmation_or_api_discovery() {
    let f = Fixture::new();
    let name = "é".repeat(129);
    let input = json!({"name": name}).to_string();
    for args in [
        vec!["session", "create", "--name", name.as_str()],
        vec!["call", "session.create", "--input", input.as_str()],
        vec!["--yes", "session", "create", "--name", name.as_str()],
        vec!["--yes", "call", "session.create", "--input", input.as_str()],
    ] {
        assert_invalid(&f.cli(&args, 2), "session.create");
    }
}

#[test]
fn legacy_session_uuid_inputs_keep_all_accepted_spellings() {
    let f = Fixture::new();
    let canonical = "aabbccdd-0011-2233-4455-66778899aabb";
    let spellings = [
        canonical.to_owned(),
        canonical.to_uppercase(),
        canonical.replace('-', ""),
        format!("{{{canonical}}}"),
        format!("urn:uuid:{canonical}"),
        "00000000-0000-0000-0000-000000000000".to_owned(),
    ];
    for (operation, action, field, option) in [
        ("session.switch", "switch", "id", "--id"),
        ("session.delete", "delete", "id", "--id"),
        ("session.reveal", "reveal", "id", "--id"),
        ("replay.list", "list", "session_id", "--session-id"),
    ] {
        let schema = f.input_schema(operation);
        let field_schema = &schema["properties"][field];
        assert!(field_schema.get("format").is_none());
        let optional = operation == "replay.list";
        assert_eq!(
            field_schema["type"],
            if optional {
                json!(["string", "null"])
            } else {
                json!("string")
            }
        );
        assert_eq!(
            schema["required"],
            if optional { json!([]) } else { json!(["id"]) }
        );
        let group = if optional { "replay" } else { "session" };
        for spelling in &spellings {
            let called = f.call(operation, json!({field:spelling}), 0);
            let direct = f.cli(&["--dry-run", group, action, option, spelling], 0);
            assert_eq!(called["data"]["input"], direct["input"]);
            assert_eq!(
                direct["input"][field],
                Uuid::parse_str(spelling).unwrap().to_string()
            );
        }
        for invalid in [
            json!(1),
            json!(true),
            json!([]),
            json!({}),
            json!("not-a-uuid"),
            json!(format!(" {canonical}")),
            json!(format!("URN:UUID:{canonical}")),
        ] {
            assert_invalid(&f.call(operation, json!({field:invalid}), 2), operation);
        }
        for input in [json!({}), json!({field:null})] {
            let output = f.call(operation, input, if optional { 0 } else { 2 });
            if optional {
                assert_eq!(output["data"]["input"], json!({"session_id":null}));
            } else {
                assert_invalid(&output, operation);
            }
        }
    }
}

#[test]
fn discovery_rejects_unknown_targets_before_dry_run() {
    let f = Fixture::new();
    for target in ["missing.operation", "", " session.list"] {
        for dry_run in [false, true] {
            for kind in ["input", "output"] {
                let mut args = vec!["schema", kind, target];
                if dry_run {
                    args.insert(0, "--dry-run");
                }
                let direct = f.cli(&args, 2);
                assert_eq!(direct["error"]["code"], "UNKNOWN_OPERATION");
                let input = json!({"kind":kind,"operation":target}).to_string();
                let mut args = vec!["call", "schema", "--input", &input];
                if dry_run {
                    args.insert(0, "--dry-run");
                }
                let called = f.cli(&args, 2);
                assert_eq!(called["error"]["code"], "UNKNOWN_OPERATION");
            }
            let mut args = vec!["examples", target];
            if dry_run {
                args.insert(0, "--dry-run");
            }
            assert_eq!(f.cli(&args, 2)["error"]["code"], "UNKNOWN_OPERATION");
            let input = json!({"operation":target}).to_string();
            let mut args = vec!["call", "examples", "--input", &input];
            if dry_run {
                args.insert(0, "--dry-run");
            }
            assert_eq!(f.cli(&args, 2)["error"]["code"], "UNKNOWN_OPERATION");
        }
    }
    for target in ["session.list", "saved.v1.session.list", "skills.status"] {
        for kind in ["input", "output"] {
            f.cli(&["--dry-run", "schema", kind, target], 0);
            f.call("schema", json!({"kind":kind,"operation":target}), 0);
        }
        f.cli(&["--dry-run", "examples", target], 0);
        f.call("examples", json!({"operation":target}), 0);
    }
    f.cli(&["--dry-run", "examples"], 0);
    f.call("examples", json!({}), 0);
    f.call("examples", json!({"operation":null}), 0);
}
