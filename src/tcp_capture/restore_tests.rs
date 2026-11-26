use super::*;
use serde_json::{json, Value};

fn stored_count(path: &std::path::Path) -> Option<usize> {
    let mut budget = SUMMARY_READ_BUDGET;
    stored_connection_count(path, &mut budget)
}
fn directory() -> PathBuf {
    std::env::temp_dir().join(format!("sniper-tcp-restore-{}", Uuid::new_v4()))
}
fn connection() -> Value {
    json!({
        "id": Uuid::new_v4(), "started_at": "2026-11-04T00:00:00Z",
        "ended_at": "2026-11-04T00:00:01Z", "peer": "127.0.0.1:1",
        "target": "example.com:443", "status": "closed", "durable": true,
        "client_bytes": 1, "server_bytes": 0, "captured_bytes": 1,
        "capture_truncated": false, "client_received_bytes": 1,
        "server_received_bytes": 0, "intercept_events": [],
        "intercept_captured_bytes": 0, "intercept_truncated": false,
        "intercept_event_count": 0, "intercept_schema_version": 1,
        "pending_count": 0, "pending_directions": [],
        "chunks": [{"sequence": 0, "at": "2026-11-04T00:00:00Z",
            "direction": "client_to_server", "offset": 0, "data_base64": "QQ=="}]
    })
}
fn intercepted() -> Value {
    let mut value = connection();
    value["client_bytes"] = json!(2);
    value["captured_bytes"] = json!(2);
    value["chunks"][0]["data_base64"] = json!("QkI=");
    value["intercept_event_count"] = json!(1);
    value["intercept_captured_bytes"] = json!(3);
    value["intercept_events"] = json!([{
        "pending_id": Uuid::new_v4(), "direction": "client_to_server", "sequence": 0,
        "revision": 2, "received_at": "2026-11-04T00:00:00Z",
        "decided_at": "2026-11-04T00:00:00Z", "ended_at": "2026-11-04T00:00:01Z",
        "original_offset": 0, "destination_offset": 0,
        "original_length": 1, "original_base64": "QQ==", "selected_length": 2,
        "edited": true, "selected_base64": "QkI=", "written_bytes": 2,
        "state": "forwarded", "preview_truncated": false
    }]);
    value
}
fn save(root: &std::path::Path, value: &Value) -> PathBuf {
    std::fs::create_dir_all(root).unwrap();
    let path = root.join(format!("{}.json", value["id"].as_str().unwrap()));
    std::fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
    path
}
fn rejected(value: Value) {
    let root = directory();
    let path = save(&root, &value);
    let before = std::fs::read(&path).unwrap();
    assert!(read_stored_connection(&path).is_err(), "accepted {value}");
    let loaded = TcpCapture::load(root.clone());
    assert!(loaded.history.lock().unwrap().load_error);
    assert!(loaded.history.lock().unwrap().records.is_empty());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn restore_rejects_invalid_metadata_and_chunk_ranges_without_rewriting() {
    for (pointer, replacement) in [
        ("/peer", json!("")),
        ("/target", json!("bad\nhost:80")),
        ("/peer", json!("p".repeat(MAX_PEER_BYTES + 1))),
        ("/target", json!("t".repeat(MAX_TARGET_BYTES + 1))),
        ("/status", json!("nonsense")),
        ("/status", json!("s".repeat(100_000))),
        ("/ended_at", Value::Null),
        ("/status", json!("open")),
        ("/status", json!("interrupted")),
        ("/chunks/0/sequence", json!(999)),
        ("/chunks/0/offset", json!(999)),
        ("/chunks/0/offset", json!(u64::MAX)),
        ("/chunks/0/data_base64", json!("")),
        (
            "/chunks/0/data_base64",
            json!("A".repeat(MAX_CHUNK_BASE64_BYTES + 1)),
        ),
        ("/client_bytes", json!(0)),
        ("/client_bytes", json!(2)),
        ("/captured_bytes", json!(2)),
        ("/pending_count", json!(3)),
        (
            "/pending_directions",
            json!(["client_to_server", "client_to_server", "server_to_client"]),
        ),
        ("/intercept_event_count", json!(1)),
    ] {
        let mut value = connection();
        *value.pointer_mut(pointer).unwrap() = replacement;
        rejected(value);
    }
    let mut value = connection();
    value["failure"] = json!("connect_failed");
    rejected(value);
    let mut value = connection();
    value["pending_count"] = json!(2);
    value["pending_directions"] = json!(["client_to_server", "client_to_server"]);
    rejected(value);
}

#[test]
fn restore_rejects_invalid_intercept_counters_offsets_and_lifecycle() {
    for (pointer, replacement) in [
        ("/intercept_events/0/sequence", json!(1)),
        ("/intercept_events/0/original_offset", json!(1)),
        ("/intercept_events/0/original_offset", json!(u64::MAX)),
        ("/intercept_events/0/destination_offset", json!(1)),
        ("/intercept_events/0/destination_offset", json!(u64::MAX)),
        ("/intercept_events/0/original_length", json!(0)),
        (
            "/intercept_events/0/selected_length",
            json!(MAX_PENDING_BYTES + 1),
        ),
        ("/intercept_events/0/written_bytes", json!(3)),
        ("/intercept_events/0/state", json!("pending")),
        ("/intercept_events/0/state", json!("x".repeat(100_000))),
        ("/intercept_events/0/revision", json!(u64::MAX)),
        ("/intercept_events/0/ended_at", Value::Null),
        ("/intercept_events/0/decided_at", Value::Null),
        ("/intercept_events/0/edited", json!(false)),
        ("/intercept_events/0/selected_base64", Value::Null),
        (
            "/intercept_events/0/original_base64",
            json!("A".repeat(MAX_EVENT_BASE64_BYTES + 1)),
        ),
        ("/intercept_event_count", json!(u64::MAX)),
        ("/intercept_captured_bytes", json!(2)),
        ("/client_received_bytes", json!(0)),
    ] {
        let mut value = intercepted();
        *value.pointer_mut(pointer).unwrap() = replacement;
        rejected(value);
    }
    for duplicate_id in [true, false] {
        let mut value = intercepted();
        let mut second = value["intercept_events"][0].clone();
        if !duplicate_id {
            second["pending_id"] = json!(Uuid::new_v4());
        }
        if duplicate_id {
            second["sequence"] = json!(1);
        }
        value["client_received_bytes"] = json!(2);
        value["intercept_event_count"] = json!(2);
        value["intercept_captured_bytes"] = json!(6);
        value["intercept_events"]
            .as_array_mut()
            .unwrap()
            .push(second);
        rejected(value);
    }
}

#[test]
fn restore_bounds_deserialization_before_collecting_entire_arrays() {
    for (field, entry, limit) in [
        ("chunks", connection()["chunks"][0].clone(), MAX_CHUNKS),
        (
            "intercept_events",
            intercepted()["intercept_events"][0].clone(),
            MAX_EVENTS,
        ),
        ("pending_directions", json!("client_to_server"), 2),
    ] {
        let mut value = connection();
        value[field] = Value::Array(vec![entry; limit + 1]);
        let error = serde_json::from_slice::<TcpConnection>(&serde_json::to_vec(&value).unwrap())
            .unwrap_err()
            .to_string();
        assert!(error.contains("entry limit"), "{field}: {error}");
        rejected(value);
    }
    // Escapes are decoded before applying byte limits; multi-byte UTF-8 counts
    // bytes rather than characters. Parser scratch remains file-size bounded.
    let mut value = connection();
    value["peer"] = json!("é".repeat(MAX_PEER_BYTES / 2 + 1));
    rejected(value);
}

#[tokio::test]
async fn restore_keeps_legacy_truncation_and_expanding_interception_records() {
    let root = directory();
    let mut variants = vec![connection(), intercepted()];
    let mut legacy = connection();
    for field in [
        "client_received_bytes",
        "server_received_bytes",
        "intercept_events",
        "intercept_event_count",
        "intercept_captured_bytes",
        "intercept_truncated",
        "intercept_schema_version",
        "pending_count",
        "pending_directions",
    ] {
        legacy.as_object_mut().unwrap().remove(field);
    }
    variants.push(legacy);
    let mut truncated = connection();
    truncated["capture_truncated"] = json!(true);
    truncated["client_bytes"] = json!(u64::MAX);
    variants.push(truncated);
    let mut boundaries = connection();
    boundaries["peer"] = json!("p".repeat(MAX_PEER_BYTES));
    boundaries["target"] = json!(format!("{}:65535", "t".repeat(253)));
    variants.push(boundaries);
    let mut future_failure = connection();
    future_failure["status"] = json!("failed");
    future_failure["failure"] = json!("future_failure");
    variants.push(future_failure);
    for mut value in variants {
        value["id"] = json!(Uuid::new_v4());
        let path = save(&root, &value);
        let before = std::fs::read(&path).unwrap();
        let expected = read_stored_connection(&path).unwrap();
        let loaded = TcpCapture::load(root.clone());
        assert!(!loaded.status().await.load_error);
        assert_eq!(
            serde_json::to_value(loaded.detail(expected.id).await.unwrap().unwrap()).unwrap(),
            serde_json::to_value(expected).unwrap()
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(loaded
            .history
            .lock()
            .unwrap()
            .records
            .values()
            .all(|r| r.chunks.is_empty()));
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn summary_rejects_unbounded_metadata_without_touching_disk() {
    for field in ["peer", "target", "status"] {
        let root = directory();
        let mut value = connection();
        value[field] = json!("a".repeat(1_048_576));
        let path = save(&root, &value);
        let before = std::fs::read(&path).unwrap();
        assert_eq!(stored_count(&root), None);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(TcpCapture::load(root.clone())
            .history
            .lock()
            .unwrap()
            .records
            .is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(unix)]
#[tokio::test]
async fn root_symlinks_and_replaced_roots_never_read_or_write_external_history() {
    use std::os::unix::fs::symlink;
    let external = directory();
    let value = connection();
    let external_path = save(&external, &value);
    let external_bytes = std::fs::read(&external_path).unwrap();
    let root = directory();
    symlink(&external, &root).unwrap();
    let capture = Arc::new(TcpCapture::load(root.clone()));
    assert!(capture.status().await.load_error);
    assert_eq!(capture.status().await.history_count, 0);
    assert_eq!(stored_count(&root), None);
    assert!(capture
        .start(TcpSettings {
            local_port: 12345,
            target_host: "127.0.0.1".into(),
            target_port: 9,
            ..Default::default()
        })
        .await
        .is_err());
    capture.stop().await.unwrap();
    assert!(
        !capture
            .persist(&serde_json::from_value(connection()).unwrap())
            .await
    );
    assert_eq!(std::fs::read_dir(&external).unwrap().count(), 1);
    assert_eq!(std::fs::read(&external_path).unwrap(), external_bytes);
    std::fs::remove_file(&root).unwrap();

    let own = connection();
    let own_path = save(&root, &own);
    let own_id = Uuid::parse_str(own["id"].as_str().unwrap()).unwrap();
    let own_bytes = std::fs::read(&own_path).unwrap();
    let loaded = TcpCapture::load(root.clone());
    let held = directory();
    std::fs::rename(&root, &held).unwrap();
    symlink(&external, &root).unwrap();
    assert!(loaded.detail(own_id).await.is_err());
    assert!(
        !loaded
            .persist(&serde_json::from_value(connection()).unwrap())
            .await
    );
    assert_eq!(std::fs::read_dir(&external).unwrap().count(), 1);
    assert_eq!(std::fs::read(&external_path).unwrap(), external_bytes);
    assert_eq!(
        std::fs::read(held.join(own_path.file_name().unwrap())).unwrap(),
        own_bytes
    );
    std::fs::remove_file(&root).unwrap();
    std::fs::remove_dir_all(held).unwrap();
    std::fs::remove_dir_all(external).unwrap();
}

#[cfg(unix)]
#[test]
fn record_symlinks_and_fifos_are_rejected_without_blocking() {
    use std::os::unix::{
        ffi::OsStrExt,
        fs::{symlink, FileTypeExt},
    };
    let root = directory();
    std::fs::create_dir(&root).unwrap();
    let outside = directory();
    let value = connection();
    let outside_path = save(&outside, &value);
    let name = outside_path.file_name().unwrap();
    symlink(&outside_path, root.join(name)).unwrap();
    assert!(
        TcpCapture::load(root.clone())
            .history
            .lock()
            .unwrap()
            .load_error
    );
    std::fs::remove_file(root.join(name)).unwrap();
    let fifo = std::ffi::CString::new(root.join(name).as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let began = std::time::Instant::now();
    assert!(
        TcpCapture::load(root.clone())
            .history
            .lock()
            .unwrap()
            .load_error
    );
    assert!(began.elapsed() < Duration::from_secs(2));
    assert!(std::fs::symlink_metadata(root.join(name))
        .unwrap()
        .file_type()
        .is_fifo());
    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_dir_all(outside).unwrap();
}

#[cfg(unix)]
#[test]
fn unreadable_regular_orphan_remains_ignored_without_permission_changes() {
    use std::os::unix::fs::PermissionsExt;
    let root = directory();
    let value = connection();
    let path = save(&root, &value);
    let orphan = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    std::fs::write(&orphan, b"unfinished private write").unwrap();
    std::fs::set_permissions(&orphan, std::fs::Permissions::from_mode(0)).unwrap();
    let loaded = TcpCapture::load(root.clone());
    assert_eq!(loaded.connection_count(), Some(1));
    assert_eq!(stored_count(&root), Some(1));
    assert_eq!(
        std::fs::metadata(&orphan).unwrap().permissions().mode() & 0o777,
        0
    );
    assert_eq!(std::fs::metadata(&orphan).unwrap().len(), 24);
    std::fs::remove_dir_all(root).unwrap();
}
