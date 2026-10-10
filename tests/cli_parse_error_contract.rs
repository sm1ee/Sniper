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
