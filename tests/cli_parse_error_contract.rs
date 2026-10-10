//! Parse-error checks stay offline and never open a saved session or runtime.
use serde_json::Value;
use std::process::Command;

#[test]
fn input_before_operation_does_not_leak_into_parse_error_metadata() {
    for (operation, input) in [
        ("findings.list", r#"{"private":"synthetic saved metadata"}"#),
        ("saved.v1.http.list", "@synthetic-private-file.json"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_sniper-cli"))
            .env_clear()
            .args([
                "--output",
                "compact",
                "call",
                "--input",
                input,
                operation,
                "--unknown",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stderr.is_empty());
        let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(envelope["ok"], false);
        assert_eq!(envelope["operation"], operation);
        assert_eq!(
            envelope["schema_version"],
            if operation.starts_with("saved.v1.") {
                "saved.v1"
            } else {
                "2026-06-22"
            }
        );
        assert_eq!(envelope["error"]["code"], "INVALID_INPUT");
        assert!(!String::from_utf8_lossy(&output.stdout).contains(input));
    }
}

fn parse_error(args: &[&str]) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_sniper-cli"))
        .env_clear()
        .args(["--output", "compact"])
        .args(args)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{args:?}");
    assert!(output.stderr.is_empty(), "{args:?}");
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["ok"], false, "{args:?}");
    assert_eq!(envelope["error"]["code"], "INVALID_INPUT", "{args:?}");
    assert_eq!(envelope["schema_version"], "2026-06-22", "{args:?}");
    envelope
}

#[test]
fn direct_aliases_and_hyphenated_actions_use_manifest_operations() {
    for (args, expected) in [
        (
            vec!["replay", "set-pinned", "--unknown"],
            "replay.set_pinned",
        ),
        (
            vec!["repeater", "set-pinned", "--unknown"],
            "replay.set_pinned",
        ),
        (
            vec!["capture", "history", "list", "--unknown"],
            "capture.http.list",
        ),
        (vec!["http", "list", "--unknown"], "capture.http.list"),
        (vec!["history", "list", "--unknown"], "capture.http.list"),
        (
            vec!["capture", "websocket", "list", "--unknown"],
            "capture.websocket.list",
        ),
        (
            vec!["capture", "web-socket", "list", "--unknown"],
            "capture.websocket.list",
        ),
        (
            vec!["web-socket", "list", "--unknown"],
            "capture.websocket.list",
        ),
        (
            vec!["websocket", "list", "--unknown"],
            "capture.websocket.list",
        ),
        (
            vec!["capture", "match-replace", "list", "--unknown"],
            "capture.auto_replace.list",
        ),
        (
            vec!["match-replace", "list", "--unknown"],
            "capture.auto_replace.list",
        ),
        (
            vec!["auto-replace", "list", "--unknown"],
            "capture.auto_replace.list",
        ),
        (vec!["target", "get-scope", "--unknown"], "scope.get"),
        (vec!["event-log", "list", "--unknown"], "event_log.list"),
        (vec!["sequence", "run-get", "--unknown"], "sequence.run_get"),
        (
            vec!["skills", "update-preview", "--unknown"],
            "skills.update_preview",
        ),
    ] {
        assert_eq!(parse_error(&args)["operation"], expected, "{args:?}");
    }
}

#[test]
fn direct_option_operands_are_not_operations() {
    for (args, expected) in [
        (
            vec!["--dry-run", "skills", "status", "--unknown"],
            "skills.status",
        ),
        (
            vec!["--yes", "skills", "status", "--unknown"],
            "skills.status",
        ),
        (
            vec![
                "skills",
                "--codex-dir",
                "SYNTHETIC_PRIVATE_PATH",
                "status",
                "--unknown",
            ],
            "skills.status",
        ),
        (
            vec!["skills", "--codex-dir", "status", "--unknown"],
            "skills",
        ),
        (vec!["skills", "--codex-dir=status", "--unknown"], "skills"),
        (
            vec!["skills", "--codex-dir", "status", "install", "--unknown"],
            "skills.install",
        ),
        (
            vec!["skills", "--claude-dir", "install", "status", "--unknown"],
            "skills.status",
        ),
        (
            vec!["skills", "--codex-dir=status", "install", "--unknown"],
            "skills.install",
        ),
        (
            vec![
                "skills",
                "--codex-dir",
                "--output",
                "compact",
                "status",
                "--unknown",
            ],
            "skills.status",
        ),
        (
            vec!["capture", "--browser", "browser", "list", "--unknown"],
            "capture",
        ),
        (vec!["--api", "skills", "--unknown"], "parse"),
        (
            vec!["--api", "skills", "skills", "status", "--unknown"],
            "skills.status",
        ),
    ] {
        let envelope = parse_error(&args);
        assert_eq!(envelope["operation"], expected, "{args:?}");
        assert!(!envelope.to_string().contains("SYNTHETIC_PRIVATE_PATH"));
    }
}

#[test]
fn ambiguous_direct_tokens_use_only_known_group_fallbacks() {
    for (args, expected) in [
        (vec!["skills", "--unknown", "status"], "skills"),
        (vec!["skills", "--unknown=status", "install"], "skills"),
        (
            vec!["skills", "SYNTHETIC_PRIVATE_ACTION", "--unknown"],
            "skills",
        ),
        (vec!["SYNTHETIC_PRIVATE_ACTION", "--unknown"], "parse"),
        (
            vec!["repeater", "SYNTHETIC_PRIVATE_ACTION", "--unknown"],
            "replay",
        ),
        (vec!["capture", "proxy", "--stdin", "--unknown"], "capture"),
        (vec!["capture", "proxy", "--unknown"], "capture"),
        (vec!["skills", "--", "status", "--unknown"], "skills"),
        (vec!["--", "skills", "status", "--unknown"], "parse"),
    ] {
        assert_eq!(parse_error(&args)["operation"], expected, "{args:?}");
    }
}
