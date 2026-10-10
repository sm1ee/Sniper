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

#[cfg(unix)]
mod non_unicode {
    use serde_json::Value;
    use std::{ffi::OsString, fs, os::unix::ffi::OsStringExt, process::Command};
    use uuid::Uuid;

    fn check(args: &[&[u8]], operation: &str, compact: bool) {
        let root = std::env::temp_dir().join(format!("sniper-nonunicode-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_sniper-cli"))
            .env_clear()
            .env("HOME", root.join("home"))
            .env("USERPROFILE", root.join("home"))
            .env("CODEX_HOME", root.join("codex-home"))
            .env("SNIPER_DATA_DIR", root.join("data"))
            .current_dir(&root)
            .arg("--dry-run")
            .args(args.iter().map(|arg| OsString::from_vec(arg.to_vec())))
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
        let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(envelope["ok"], false);
        assert_eq!(envelope["operation"], operation);
        assert_eq!(envelope["error"]["code"], "INVALID_INPUT");
        assert_eq!(envelope["error"]["details"]["kind"], "InvalidUtf8");
        assert_eq!(envelope["error"]["retryable"], false);
        assert_eq!(
            envelope["schema_version"],
            if operation.starts_with("saved.v1.") {
                "saved.v1"
            } else {
                "2026-06-22"
            }
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(!stdout.contains("SYNTHETIC_PRIVATE"));
        assert!(!stdout.contains('\u{fffd}'));
        assert_eq!(stdout.lines().count() == 1, compact, "{stdout}");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn invalid_unicode_operands_keep_canonical_operation_metadata() {
        let cases: &[(&[&[u8]], &str)] = &[
            (
                &[
                    b"call",
                    b"manifest",
                    b"--input",
                    b"@SYNTHETIC_PRIVATE_\xff.json",
                ],
                "manifest",
            ),
            (
                &[
                    b"call",
                    b"--input",
                    b"@SYNTHETIC_PRIVATE_\xff.json",
                    b"saved.v1.http.list",
                ],
                "saved.v1.http.list",
            ),
            (
                &[
                    b"call",
                    b"--input=@SYNTHETIC_PRIVATE_\xff.json",
                    b"manifest",
                ],
                "manifest",
            ),
            (
                &[
                    b"skills",
                    b"--codex-dir",
                    b"SYNTHETIC_PRIVATE_\xff",
                    b"status",
                    b"--unknown",
                ],
                "skills.status",
            ),
            (
                &[
                    b"skills",
                    b"--codex-dir=SYNTHETIC_PRIVATE_\xff",
                    b"status",
                    b"--unknown",
                ],
                "skills.status",
            ),
        ];
        for (args, operation) in cases {
            let mut compact_args = vec![b"--output".as_slice(), b"compact".as_slice()];
            compact_args.extend_from_slice(args);
            check(&compact_args, operation, true);
        }
    }

    #[test]
    fn invalid_unicode_command_tokens_use_private_safe_fallbacks() {
        let cases: &[(&[&[u8]], &str)] = &[
            (&[b"call", b"SYNTHETIC_PRIVATE_\xff"], "call"),
            (&[b"call", b"--", b"SYNTHETIC_PRIVATE_\xff"], "call"),
            (&[b"SYNTHETIC_PRIVATE_\xff"], "parse"),
            (&[b"skills", b"SYNTHETIC_PRIVATE_\xff"], "skills"),
            (&[b"--SYNTHETIC_PRIVATE_\xff"], "parse"),
            (
                &[
                    b"--api",
                    b"--SYNTHETIC_PRIVATE_\xff",
                    b"call",
                    b"SYNTHETIC_PRIVATE_OPERATION",
                ],
                "parse",
            ),
            (
                &[
                    b"call",
                    b"--SYNTHETIC_PRIVATE_\xff",
                    b"SYNTHETIC_PRIVATE_OPERATION",
                ],
                "call",
            ),
        ];
        for (args, operation) in cases {
            check(args, operation, false);
        }
    }

    #[test]
    fn invalid_unicode_arguments_preserve_output_format_selection() {
        for args in [
            vec![
                b"--output".as_slice(),
                b"SYNTHETIC_PRIVATE_\xff",
                b"manifest",
            ],
            vec![b"--output=SYNTHETIC_PRIVATE_\xff".as_slice(), b"manifest"],
        ] {
            check(&args, "manifest", false);
        }
        for args in [
            vec![
                b"call".as_slice(),
                b"--input",
                b"SYNTHETIC_PRIVATE_\xff",
                b"manifest",
                b"--output",
                b"compact",
            ],
            vec![
                b"--output=compact".as_slice(),
                b"call",
                b"manifest",
                b"--input",
                b"SYNTHETIC_PRIVATE_\xff",
            ],
        ] {
            check(&args, "manifest", true);
        }
    }
}
