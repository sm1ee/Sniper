//! Call input failures stay offline and return one stable JSON error envelope.
use serde_json::Value;
use std::{
    fs,
    io::Write,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use uuid::Uuid;

struct Fixture {
    root: PathBuf,
    listener: TcpListener,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("sniper-call-input-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        Self { root, listener }
    }

    fn call(&self, operation: &str, source: &str, stdin: &[u8], exit_code: i32) -> Value {
        let mut child = Command::new(env!("CARGO_BIN_EXE_sniper-cli"))
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
                "--dry-run",
                "call",
                operation,
                "--input",
                source,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(stdin).unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(exit_code), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
        assert_eq!(
            self.listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "CLI contacted the API"
        );
        for name in ["home", "codex-home", "data"] {
            assert!(!self.root.join(name).exists(), "CLI created {name}");
        }
        let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(envelope["operation"], operation);
        assert_eq!(
            envelope["schema_version"],
            if operation.starts_with("saved.v1.") {
                "saved.v1"
            } else {
                "2026-06-22"
            }
        );
        assert_eq!(
            output.stdout.iter().filter(|&&byte| byte == b'\n').count(),
            1
        );
        envelope
    }

    fn invalid(&self, operation: &str, source: &str, stdin: &[u8]) -> Value {
        let envelope = self.call(operation, source, stdin, 2);
        assert_eq!(envelope["ok"], false);
        assert_eq!(envelope["error"]["code"], "INVALID_INPUT");
        assert_eq!(envelope["error"]["retryable"], false);
        assert!(envelope["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("schema input"));
        if operation.starts_with("saved.v1.") {
            assert_eq!(envelope["error"]["details"]["outcome"], "not_applied");
            assert!(!envelope.to_string().contains(self.root.to_str().unwrap()));
        }
        envelope
    }

    fn source(path: &Path) -> String {
        format!("@{}", path.display())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn local_input_errors_ignore_misleading_filename_words() {
    let f = Fixture::new();
    for operation in ["manifest", "saved.v1.session.list"] {
        for name in [
            "missing.json",
            "failed to probe Sniper API.json",
            "unknown operation.json",
            "requires --dry-run or --yes.json",
            "workspace state revision conflict.json",
            "request failed (503).json",
        ] {
            f.invalid(operation, &Fixture::source(&f.root.join(name)), b"");
        }
        f.invalid(operation, "@", b"");
        f.invalid(operation, &Fixture::source(&f.root), b"");
    }
}

#[test]
fn malformed_and_non_utf8_input_is_invalid_without_echoing_content() {
    let f = Fixture::new();
    for operation in ["manifest", "saved.v1.session.list"] {
        for bytes in [
            b"{\"SYNTHETIC_PRIVATE_INPUT\":\"failed to probe Sniper API".as_slice(),
            b"\xff SYNTHETIC_PRIVATE_INPUT".as_slice(),
        ] {
            let path = f.root.join("input.json");
            fs::write(&path, bytes).unwrap();
            for (source, stdin) in [
                ("-".to_string(), bytes),
                (Fixture::source(&path), b"".as_slice()),
            ] {
                let envelope = f.invalid(operation, &source, stdin);
                assert!(!envelope.to_string().contains("SYNTHETIC_PRIVATE_INPUT"));
                assert!(!envelope.to_string().contains("failed to probe Sniper API"));
            }
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
        for source in ["{", "null", "[]", "12"] {
            f.invalid(operation, source, b"");
        }
    }
}

#[test]
fn empty_input_preserves_default_object_behavior() {
    let f = Fixture::new();
    let path = f.root.join("empty.json");
    fs::write(&path, b" \n\t").unwrap();
    for operation in ["manifest", "saved.v1.session.list"] {
        for (source, stdin) in [
            ("".to_string(), b"".as_slice()),
            (" ".to_string(), b"".as_slice()),
            ("-".to_string(), b" \n\t".as_slice()),
            (Fixture::source(&path), b"".as_slice()),
        ] {
            let envelope = f.call(operation, &source, stdin, 0);
            assert_eq!(envelope["ok"], true);
            assert_eq!(envelope["data"]["input"], serde_json::json!({}));
        }
    }
}

#[cfg(unix)]
#[test]
fn unreadable_input_is_invalid_when_permissions_are_enforced() {
    use std::os::unix::fs::PermissionsExt;

    let f = Fixture::new();
    let path = f.root.join("failed to probe Sniper API.json");
    fs::write(&path, b"{}").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0)).unwrap();
    // Root can read mode-000 files; do not mistake that privilege for a CLI bug.
    if fs::File::open(&path).is_err() {
        for operation in ["manifest", "saved.v1.session.list"] {
            f.invalid(operation, &Fixture::source(&path), b"");
        }
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
}
