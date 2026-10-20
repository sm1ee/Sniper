//! Saved-tab operations are exercised through the production router, with only
//! generated saved records and a loopback listener. No replay is sent upstream.
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use chrono::Utc;
use http::HeaderMap;
use reqwest::StatusCode;
use serde_json::{json, Value};
use tokio::{sync::broadcast::error::TryRecvError, task::JoinHandle};
use uuid::Uuid;

use crate::{
    api,
    config::AppConfig,
    fuzzer::{FuzzerAttackRecord, FuzzerAttackStatus},
    model::{
        BodyEncoding, EditableRequest, HeaderRecord, MessageRecord, TransactionRecord,
        WebSocketSessionRecord,
    },
    scanner::{ScannerFinding, Severity},
    session::SessionContext,
    state::AppState,
    workspace::{
        ReplayHistoryEntryState, ReplayTabState, WorkspaceStateSnapshot, MAX_WORKSPACE_REPLAY_TABS,
    },
};

struct Fixture {
    state: Arc<AppState>,
    config: AppConfig,
    client: reqwest::Client,
    base: String,
    server: JoinHandle<()>,
}

impl Fixture {
    async fn new() -> Self {
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            max_transaction_entries: 100,
            body_preview_bytes: 4096,
            data_dir: std::env::temp_dir()
                .join(format!("sniper-saved-http-tabs-{}", Uuid::new_v4())),
        };
        let state = Arc::new(AppState::new(config.clone()).unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let router = api::router(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Self {
            state,
            config,
            client: reqwest::Client::builder().no_proxy().build().unwrap(),
            base,
            server,
        }
    }

    async fn post(&self, operation: &str, body: Value) -> (StatusCode, String) {
        post(&self.client, &self.base, operation, body).await
    }

    async fn seed(
        &self,
        snapshot: WorkspaceStateSnapshot,
    ) -> (Arc<SessionContext>, WorkspaceStateSnapshot) {
        let session = self.state.session().await;
        let snapshot = session.workspace.replace_snapshot(snapshot).await;
        session.persist().await.unwrap();
        (session, snapshot)
    }

    fn inactive(
        &self,
        mut snapshot: WorkspaceStateSnapshot,
    ) -> (Uuid, PathBuf, WorkspaceStateSnapshot) {
        let id = self
            .state
            .sessions
            .create_session(Some("Saved synthetic session".into()))
            .unwrap()
            .id;
        let path = self.state.session_storage_path(id).unwrap();
        snapshot.session_id = Some(id);
        snapshot.revision = 7;
        api::validate_workspace_state(&snapshot).unwrap();
        std::fs::write(
            path.join("workspace.json"),
            serde_json::to_vec(&snapshot).unwrap(),
        )
        .unwrap();
        (id, path, snapshot)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
        let _ = std::fs::remove_dir_all(&self.config.data_dir);
    }
}

async fn post(
    client: &reqwest::Client,
    base: &str,
    operation: &str,
    body: Value,
) -> (StatusCode, String) {
    let response = client
        .post(format!("{base}/api/replay/tabs/{operation}"))
        .json(&body)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .unwrap();
    let status = response.status();
    (status, response.text().await.unwrap())
}

fn payload(id: Uuid, tab: &str, revision: u64) -> Value {
    json!({ "session_id": id, "tab_id": tab, "expected_workspace_revision": revision })
}

fn operation_payload(operation: &str, mut body: Value) -> Value {
    if operation == "set-pinned" {
        body["pinned"] = json!(false);
    }
    body
}

fn request() -> EditableRequest {
    EditableRequest {
        scheme: "https".into(),
        host: "example.com".into(),
        method: "POST".into(),
        path: "/synthetic?draft=yes".into(),
        headers: vec![
            HeaderRecord {
                name: "Host".into(),
                value: "example.com".into(),
            },
            HeaderRecord {
                name: "X-Synthetic".into(),
                value: "saved only".into(),
            },
        ],
        body: "saved request body".into(),
        body_encoding: BodyEncoding::Utf8,
        preview_truncated: false,
    }
}

fn record(path: &str) -> TransactionRecord {
    let mut record = TransactionRecord::http(
        Utc::now(),
        "POST".into(),
        "https".into(),
        "example.com".into(),
        path.into(),
        Some(201),
        37,
        MessageRecord::from_headers_and_body(&HeaderMap::new(), b"saved request body", 4096),
        Some(MessageRecord::from_headers_and_body(
            &HeaderMap::new(),
            b"saved response body",
            4096,
        )),
        vec!["synthetic saved result".into()],
        None,
        None,
    );
    record.user_note = Some("retain my saved note".into());
    record.color_tag = Some("blue".into());
    record
}

fn tab(id: &str, sequence: usize, pinned: bool) -> ReplayTabState {
    ReplayTabState {
        id: id.into(),
        tab_type: "http".into(),
        sequence,
        pinned,
        ..ReplayTabState::default()
    }
}

fn workspace() -> WorkspaceStateSnapshot {
    let response = record("/saved-response");
    let source = ReplayTabState {
        id: " legacy tab ".into(),
        tab_type: String::new(),
        sequence: 23,
        custom_label: "Saved draft label".into(),
        base_request: Some(request()),
        source_transaction_id: Some(Uuid::new_v4()),
        notice: "Retain the saved notice".into(),
        // This is intentionally not parseable HTTP. Duplicating a saved draft
        // must never normalize it or require it to be sendable.
        request_text: "unfinished draft\r\n  preserve spacing\n".into(),
        http_version_mode: "http2".into(),
        response_record: Some(response.clone()),
        response_record_complete: Some(true),
        target_scheme: "https".into(),
        target_host: "example.com".into(),
        target_port: "443".into(),
        target_manually_edited: true,
        history_entries: vec![ReplayHistoryEntryState {
            request: Some(request()),
            request_text: "old draft\nwith exact formatting".into(),
            http_version_mode: "http1".into(),
            response_record: Some(response),
            notice: "History notice".into(),
            target_scheme: "https".into(),
            target_host: "example.com".into(),
            target_port: "443".into(),
        }],
        history_index: Some(0),
        history_entries_complete: Some(true),
        pinned: true,
        ..ReplayTabState::default()
    };
    let mut snapshot = WorkspaceStateSnapshot::default();
    snapshot.client_id = Some("previous-editor".into());
    snapshot.client_version = 19;
    snapshot.replay.tabs = vec![
        source,
        tab("other-http", 81, false),
        ReplayTabState {
            id: Uuid::new_v4().to_string(),
            tab_type: "websocket".into(),
            sequence: 90,
            custom_label: "Saved WS tab".into(),
            ws_scheme: "wss".into(),
            ws_host: "example.com".into(),
            ws_port: json!(443),
            ws_path: "/socket".into(),
            ws_editor_text: "saved WS draft".into(),
            ws_message_type: "text".into(),
            ..ReplayTabState::default()
        },
    ];
    snapshot.replay.active_tab_id = Some("other-http".into());
    snapshot.replay.tab_sequence = 12;
    snapshot.fuzzer.base_request = Some(request());
    snapshot.fuzzer.request_text = "saved fuzzer draft".into();
    snapshot.fuzzer.payloads_text = "alpha\nbeta".into();
    snapshot.fuzzer.notice = "saved fuzzer notice".into();
    snapshot.fuzzer.attack_record_id = Some(Uuid::new_v4());
    snapshot
}

fn serialized<T: serde::Serialize + ?Sized>(value: &T) -> Value {
    serde_json::to_value(value).unwrap()
}

fn files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn collect(root: &Path, current: &Path, output: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(current).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect(root, &path, output);
            } else {
                output.insert(
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    std::fs::read(path).unwrap(),
                );
            }
        }
    }
    let mut result = BTreeMap::new();
    collect(root, root, &mut result);
    result
}

fn without_workspace(mut saved: BTreeMap<PathBuf, Vec<u8>>) -> BTreeMap<PathBuf, Vec<u8>> {
    saved.remove(Path::new("workspace.json"));
    saved
}

fn ack(status: StatusCode, text: &str) -> Value {
    assert_eq!(status, StatusCode::OK, "{text}");
    serde_json::from_str(text).unwrap()
}

#[tokio::test]
async fn saved_http_tab_duplicate_clones_every_saved_field_without_focus_or_capture_changes() {
    let fixture = Fixture::new().await;
    let (session, before) = fixture.seed(workspace()).await;
    let captured = record("/unrelated-capture");
    let captured_id = captured.id;
    session.store.insert(captured).await;
    let ws: WebSocketSessionRecord = serde_json::from_value(json!({
        "id": Uuid::new_v4(), "started_at": Utc::now(), "closed_at": Utc::now(),
        "duration_ms": 9, "scheme": "wss", "host": "example.com", "path": "/captured-socket",
        "status": 101, "request": {"body_preview": "saved handshake"}, "response": null,
        "notes": ["generated closed WS capture"]
    }))
    .unwrap();
    let ws_id = ws.id;
    session.websockets.open(ws).await;
    let attack = FuzzerAttackRecord {
        id: Uuid::new_v4(),
        started_at: Utc::now(),
        completed_at: Utc::now(),
        status: FuzzerAttackStatus::Completed,
        template: request(),
        payload_count: 2,
        marker_count: 1,
        results: vec![],
        notes: vec!["generated saved fuzzer run".into()],
    };
    let attack_id = attack.id;
    session.fuzzer.insert(attack).await;
    let finding = ScannerFinding {
        id: Uuid::new_v4(),
        record_id: captured_id,
        found_at: Utc::now(),
        rule_id: "synthetic".into(),
        severity: Severity::Info,
        category: "fixture".into(),
        title: "Generated finding".into(),
        detail: "Preserve saved detail".into(),
        evidence: "synthetic".into(),
        host: "example.com".into(),
        path: "/unrelated-capture".into(),
        location: None,
    };
    let finding_id = finding.id;
    session.scanner.push(finding).await;
    session.persist().await.unwrap();
    let captured_before = serialized(&session.store.get(captured_id).await.unwrap());
    let ws_before = serialized(&session.websockets.get(ws_id).await.unwrap());
    let attack_before = serialized(&session.fuzzer.get(attack_id).await.unwrap());
    let finding_before = serialized(&session.scanner.get(finding_id).await.unwrap());
    let disk_before = files(session.storage_dir());
    let mut events = session.workspace.subscribe();
    let (status, text) = fixture
        .post(
            "duplicate",
            payload(session.id(), " legacy tab ", before.revision),
        )
        .await;
    let result = ack(status, &text);
    let new_id = result["new_tab_id"].as_str().unwrap();
    Uuid::parse_str(new_id).unwrap();
    assert_eq!(
        result.as_object().unwrap().len(),
        5,
        "ack must be metadata only"
    );
    assert_eq!(result["source_tab_id"], " legacy tab ");
    assert_eq!(result["session_id"], session.id().to_string());
    assert_eq!(result["revision"], before.revision + 1);
    assert_eq!(result["active_tab_id"], "other-http");
    let after = session.workspace.snapshot().await;
    assert_eq!(after.replay.tabs.len(), before.replay.tabs.len() + 1);
    assert_eq!(
        serialized(&after.replay.tabs[..3]),
        serialized(&before.replay.tabs)
    );
    let duplicate = after.replay.tabs.last().unwrap();
    assert_eq!(duplicate.sequence, 91);
    assert_eq!(after.replay.tab_sequence, 91);
    assert!(!duplicate.pinned);
    let mut expected = before.replay.tabs[0].clone();
    expected.id = new_id.into();
    expected.sequence = 91;
    expected.pinned = false;
    assert_eq!(serialized(duplicate), serialized(&expected));
    assert_eq!(duplicate.response_record_complete, Some(true));
    assert_eq!(duplicate.history_entries_complete, Some(true));
    assert_eq!(serialized(&after.fuzzer), serialized(&before.fuzzer));
    assert!(after.client_id.is_none());
    assert_eq!(after.client_version, 0);
    assert!(after.expected_active_session_id.is_none());
    let event = events.try_recv().unwrap();
    assert_eq!(event.revision, after.revision);
    assert_eq!(event.session_id, Some(session.id()));
    assert!(event.client_id.is_none());
    assert!(matches!(events.try_recv(), Err(TryRecvError::Empty)));
    assert_eq!(
        serialized(&session.store.get(captured_id).await.unwrap()),
        captured_before
    );
    assert_eq!(
        serialized(&session.websockets.get(ws_id).await.unwrap()),
        ws_before
    );
    assert_eq!(
        serialized(&session.fuzzer.get(attack_id).await.unwrap()),
        attack_before
    );
    assert_eq!(
        serialized(&session.scanner.get(finding_id).await.unwrap()),
        finding_before
    );
    assert_eq!(
        without_workspace(files(session.storage_dir())),
        without_workspace(disk_before)
    );
    let disk: WorkspaceStateSnapshot = serde_json::from_slice(
        &std::fs::read(session.storage_dir().join("workspace.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(serialized(&disk), serialized(&after));
    let restarted = AppState::new(fixture.config.clone()).unwrap();
    assert_eq!(
        serialized(&restarted.session().await.workspace.snapshot().await),
        serialized(&after)
    );
}

#[tokio::test]
async fn saved_http_tab_close_uses_pinned_first_previous_then_next_and_retains_sequence() {
    let fixture = Fixture::new().await;
    // Physical order differs from visual order: pinned-a, pinned-b, loose-a, loose-b.
    for (active, close, expected) in [
        ("loose-a", "loose-a", Some("pinned-b")),
        ("pinned-a", "pinned-a", Some("pinned-b")),
        ("pinned-b", "pinned-b", Some("pinned-a")),
        ("loose-b", "loose-a", Some("loose-b")),
    ] {
        let mut snapshot = WorkspaceStateSnapshot::default();
        snapshot.replay.tabs = vec![
            tab("loose-a", 1, false),
            tab("pinned-a", 2, true),
            tab("loose-b", 3, false),
            tab("pinned-b", 4, true),
        ];
        snapshot.replay.active_tab_id = Some(active.into());
        snapshot.replay.tab_sequence = 72;
        let (session, before) = fixture.seed(snapshot).await;
        let (status, text) = fixture
            .post("close", payload(session.id(), close, before.revision))
            .await;
        let result = ack(status, &text);
        assert_eq!(result.as_object().unwrap().len(), 4);
        assert_eq!(result["closed_tab_id"], close);
        assert_eq!(result["active_tab_id"].as_str(), expected);
        let after = session.workspace.snapshot().await;
        assert_eq!(after.replay.active_tab_id.as_deref(), expected);
        assert_eq!(after.replay.tab_sequence, 72);
        let retained: Vec<_> = before
            .replay
            .tabs
            .into_iter()
            .filter(|saved| saved.id != close)
            .collect();
        assert_eq!(serialized(&after.replay.tabs), serialized(&retained));
    }
    let mut only = WorkspaceStateSnapshot::default();
    only.replay.tabs = vec![tab("only", 18, true)];
    only.replay.active_tab_id = Some("only".into());
    only.replay.tab_sequence = 72;
    let (session, before) = fixture.seed(only).await;
    let (status, text) = fixture
        .post("close", payload(session.id(), "only", before.revision))
        .await;
    assert!(ack(status, &text)["active_tab_id"].is_null());
    let after = session.workspace.snapshot().await;
    assert!(after.replay.tabs.is_empty());
    assert!(after.replay.active_tab_id.is_none());
    assert_eq!(after.replay.tab_sequence, 72);
    let restarted = AppState::new(fixture.config.clone()).unwrap();
    assert_eq!(
        serialized(&restarted.session().await.workspace.snapshot().await),
        serialized(&after)
    );
}

#[tokio::test]
async fn saved_http_tab_routes_reject_malformed_unknown_and_inexact_payloads_without_writes() {
    let fixture = Fixture::new().await;
    let (session, before) = fixture.seed(workspace()).await;
    let valid = payload(session.id(), " legacy tab ", before.revision);
    let mut invalid = Vec::new();
    for key in ["session_id", "tab_id", "expected_workspace_revision"] {
        let mut body = valid.clone();
        body.as_object_mut().unwrap().remove(key);
        invalid.push(body);
    }
    for (key, value) in [
        ("session_id", json!("bad-uuid")),
        ("session_id", Value::Null),
        ("tab_id", json!(7)),
        ("tab_id", json!("")),
        ("tab_id", json!("   ")),
        ("tab_id", json!("x".repeat(129))),
        ("tab_id", json!("legacy tab")),
        ("tab_id", json!("missing")),
        ("expected_workspace_revision", json!(-1)),
        ("expected_workspace_revision", json!(1.5)),
        ("expected_workspace_revision", Value::Null),
        ("expected_active_session_id", json!("invalid")),
        ("client_id", json!("previous-editor")),
        ("revision", json!(before.revision)),
        ("tabs", json!([])),
    ] {
        let mut body = valid.clone();
        body[key] = value;
        invalid.push(body);
    }
    let disk = files(&fixture.config.data_dir);
    let mut events = session.workspace.subscribe();
    for operation in ["close", "duplicate", "set-pinned"] {
        for body in &invalid {
            let (status, text) = fixture
                .post(operation, operation_payload(operation, body.clone()))
                .await;
            assert!(status.is_client_error(), "{operation}: {status} {text}");
            assert_eq!(
                serialized(&session.workspace.snapshot().await),
                serialized(&before)
            );
            assert_eq!(files(&fixture.config.data_dir), disk);
        }
    }
    assert!(matches!(events.try_recv(), Err(TryRecvError::Empty)));
}

#[tokio::test]
async fn saved_http_tab_wrong_kind_and_stale_uncached_inactive_requests_do_not_repair_files() {
    let fixture = Fixture::new().await;
    let active = fixture.state.session().await.id();
    for (operation, target, stale) in [
        ("close", "missing", false),
        ("duplicate", "missing", false),
        ("close", "websocket", false),
        ("duplicate", "websocket", false),
        ("close", "unknown", false),
        ("duplicate", "unknown", false),
        ("close", " legacy tab ", true),
        ("duplicate", " legacy tab ", true),
        ("set-pinned", "missing", false),
        ("set-pinned", "websocket", false),
        ("set-pinned", "unknown", false),
        ("set-pinned", " legacy tab ", true),
    ] {
        let mut snapshot = workspace();
        snapshot.replay.tabs.push(ReplayTabState {
            id: "unknown".into(),
            tab_type: "future-kind".into(),
            ..ReplayTabState::default()
        });
        let ws_id = snapshot.replay.tabs[2].id.clone();
        let target = if target == "websocket" {
            ws_id.as_str()
        } else {
            target
        };
        let (id, path, before) = fixture.inactive(snapshot);
        // A writable load would repair/quarantine these unrelated files.
        for name in [
            "transactions.journal",
            "websockets.journal",
            "transactions.meta.ndjson",
        ] {
            std::fs::write(path.join(name), b"damaged synthetic journal\n{incomplete").unwrap();
        }
        let disk = files(&fixture.config.data_dir);
        let revision = if stale {
            before.revision - 1
        } else {
            before.revision
        };
        let (status, text) = fixture
            .post(
                operation,
                operation_payload(operation, payload(id, target, revision)),
            )
            .await;
        assert_eq!(
            status,
            if stale {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_REQUEST
            },
            "{text}"
        );
        assert_eq!(
            files(&fixture.config.data_dir),
            disk,
            "{operation} {target} changed unrelated files"
        );
        assert_eq!(fixture.state.session().await.id(), active);
        let loaded = fixture.state.read_session_context_for_id(id).await.unwrap();
        assert_eq!(
            serialized(&loaded.workspace.snapshot().await),
            serialized(&before)
        );
        assert_eq!(files(&fixture.config.data_dir), disk);
    }
}

#[tokio::test]
async fn saved_http_tab_inactive_cached_cas_survives_writable_promotion_activation_and_restart() {
    let fixture = Fixture::new().await;
    let active = fixture.state.session().await.id();
    let (id, path, before) = fixture.inactive(workspace());
    for name in ["transactions.journal", "websockets.journal"] {
        std::fs::write(path.join(name), b"damaged synthetic journal\n{incomplete").unwrap();
    }
    let disk = files(&path);
    let cached = fixture.state.read_session_context_for_id(id).await.unwrap();
    let mut events = cached.workspace.subscribe();
    let (status, text) = fixture
        .post("duplicate", payload(id, " legacy tab ", before.revision))
        .await;
    let result = ack(status, &text);
    assert_eq!(result["revision"], before.revision + 1);
    let after = cached.workspace.snapshot().await;
    assert_eq!(after.replay.tabs.len(), before.replay.tabs.len() + 1);
    assert_eq!(events.try_recv().unwrap().revision, after.revision);
    assert_eq!(fixture.state.session().await.id(), active);
    assert_eq!(without_workspace(files(&path)), without_workspace(disk));
    let readonly_again = fixture.state.read_session_context_for_id(id).await.unwrap();
    assert!(
        Arc::ptr_eq(&cached, &readonly_again),
        "saved mutation must keep its read-only context"
    );
    let disk_after = files(&path);
    let (status, _) = fixture
        .post("close", payload(id, " legacy tab ", before.revision))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(files(&path), disk_after);
    assert!(matches!(events.try_recv(), Err(TryRecvError::Empty)));
    let promoted = fixture.state.session_context_for_id(id).await.unwrap();
    assert!(!Arc::ptr_eq(&cached, &promoted));
    assert_eq!(
        serialized(&promoted.workspace.snapshot().await),
        serialized(&after)
    );
    fixture.state.activate_session(id).await.unwrap();
    assert_eq!(
        serialized(&fixture.state.session().await.workspace.snapshot().await),
        serialized(&after)
    );
    fixture.state.persist_active_session().await.unwrap();
    let restarted = AppState::new(fixture.config.clone()).unwrap();
    assert_eq!(restarted.session().await.id(), id);
    assert_eq!(
        serialized(&restarted.session().await.workspace.snapshot().await),
        serialized(&after)
    );
}

#[tokio::test]
async fn saved_http_tab_cas_prevents_same_revision_writers_and_legacy_client_resurrection() {
    let fixture = Fixture::new().await;
    for (first, second) in [
        ("duplicate", "duplicate"),
        ("close", "close"),
        ("close", "duplicate"),
        ("set-pinned", "set-pinned"),
        ("set-pinned", "close"),
        ("duplicate", "set-pinned"),
    ] {
        let (session, before) = fixture.seed(workspace()).await;
        let mut events = session.workspace.subscribe();
        let body = payload(session.id(), " legacy tab ", before.revision);
        let (one, two) = tokio::join!(
            fixture.post(first, operation_payload(first, body.clone())),
            fixture.post(second, operation_payload(second, body))
        );
        let mut statuses = [one.0.as_u16(), two.0.as_u16()];
        statuses.sort();
        assert_eq!(statuses, [200, 409], "{first}/{second}: {one:?} {two:?}");
        let after = session.workspace.snapshot().await;
        assert_eq!(after.revision, before.revision + 1);
        assert_eq!(events.try_recv().unwrap().revision, after.revision);
        assert!(matches!(events.try_recv(), Err(TryRecvError::Empty)));
        let mut stale = before.clone();
        stale.session_id = Some(session.id());
        stale.client_version += 100;
        let response = fixture
            .client
            .post(format!("{}/api/workspace-state", fixture.base))
            .json(&stale)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            serialized(&session.workspace.snapshot().await),
            serialized(&after)
        );
    }
}

#[tokio::test]
async fn saved_http_tab_rechecks_cas_after_operation_and_mutation_lock_waits() {
    for operation in ["duplicate", "set-pinned"] {
        let fixture = Fixture::new().await;
        for mutation_lock in [false, true] {
            let (session, before) = fixture.seed(workspace()).await;
            let operation_lock = fixture.state.session_operation_lock(session.id()).await;
            let operation_guard = if mutation_lock {
                None
            } else {
                Some(operation_lock.lock().await)
            };
            let mutation_guard = if mutation_lock {
                Some(session.mutation_guard().await)
            } else {
                None
            };
            let client = fixture.client.clone();
            let base = fixture.base.clone();
            let body = payload(session.id(), " legacy tab ", before.revision);
            let mut pending = tokio::spawn(async move {
                post(
                    &client,
                    &base,
                    operation,
                    operation_payload(operation, body),
                )
                .await
            });
            assert!(
                tokio::time::timeout(Duration::from_millis(100), &mut pending)
                    .await
                    .is_err(),
                "writer ignored held lock"
            );
            let mut newer = before.clone();
            newer.replay.tabs[1].notice = "concurrent editor changed this".into();
            let newer = session.workspace.replace_snapshot(newer).await;
            drop(mutation_guard);
            drop(operation_guard);
            let (status, text) = tokio::time::timeout(Duration::from_secs(5), pending)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(status, StatusCode::CONFLICT, "{text}");
            assert_eq!(
                serialized(&session.workspace.snapshot().await),
                serialized(&newer)
            );
        }
    }
}

#[tokio::test]
async fn saved_http_tab_active_guard_is_checked_again_after_a_queued_session_switch() {
    for operation in ["close", "set-pinned"] {
        let fixture = Fixture::new().await;
        let (session, before) = fixture.seed(workspace()).await;
        let other = fixture
            .state
            .sessions
            .create_session(Some("Other generated session".into()))
            .unwrap()
            .id;
        let operation_lock = fixture.state.session_operation_lock(session.id()).await;
        let guard = operation_lock.lock().await;
        let mut switching = Box::pin(fixture.state.activate_session(other));
        // Polling the real activation future while holding the old session lock
        // deterministically queues the switch before the request in Tokio's FIFO mutex.
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut switching)
                .await
                .is_err()
        );
        let mut body = payload(session.id(), " legacy tab ", before.revision);
        body["expected_active_session_id"] = json!(session.id());
        let client = fixture.client.clone();
        let base = fixture.base.clone();
        let mut pending = tokio::spawn(async move {
            post(
                &client,
                &base,
                operation,
                operation_payload(operation, body),
            )
            .await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut pending)
                .await
                .is_err()
        );
        drop(guard);
        switching.await.unwrap();
        let (status, text) = tokio::time::timeout(Duration::from_secs(5), pending)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status, StatusCode::CONFLICT, "{text}");
        assert_eq!(fixture.state.session().await.id(), other);
        assert_eq!(
            serialized(&session.workspace.snapshot().await),
            serialized(&before)
        );
    }
}

#[tokio::test]
async fn saved_http_tab_precommit_disk_failure_preserves_memory_revision_and_real_sse_stream() {
    let fixture = Fixture::new().await;
    let (session, before) = fixture.seed(workspace()).await;
    let mut stream = fixture
        .client
        .get(format!(
            "{}/api/events?session_id={}",
            fixture.base,
            session.id()
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(stream.status(), StatusCode::OK);
    let mut events = session.workspace.subscribe();
    let path = session.storage_dir().join("workspace.json");
    let backup = session.storage_dir().join("workspace.before-test");
    // A full session save may still keep its workspace embedded in state.json.
    // Establish a standalone saved file before injecting a rename failure.
    std::fs::write(&path, serde_json::to_vec(&before).unwrap()).unwrap();
    std::fs::rename(&path, &backup).unwrap();
    std::fs::create_dir(&path).unwrap();
    let disk = files(session.storage_dir());
    for operation in ["close", "duplicate", "set-pinned"] {
        let (status, text) = fixture
            .post(
                operation,
                operation_payload(
                    operation,
                    payload(session.id(), " legacy tab ", before.revision),
                ),
            )
            .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{text}");
        assert_eq!(
            serialized(&session.workspace.snapshot().await),
            serialized(&before)
        );
        assert_eq!(files(session.storage_dir()), disk);
        assert!(matches!(events.try_recv(), Err(TryRecvError::Empty)));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), stream.chunk())
                .await
                .is_err()
        );
    }
    std::fs::remove_dir(&path).unwrap();
    std::fs::rename(&backup, &path).unwrap();
    let (status, text) = fixture
        .post(
            "set-pinned",
            operation_payload(
                "set-pinned",
                payload(session.id(), " legacy tab ", before.revision),
            ),
        )
        .await;
    ack(status, &text);
    let chunk = tokio::time::timeout(Duration::from_secs(5), stream.chunk())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let event = std::str::from_utf8(&chunk).unwrap();
    assert!(event.contains("event: workspace_state"), "{event}");
    let data = event
        .lines()
        .find_map(|line| line.strip_prefix("data: "))
        .unwrap();
    let data: Value = serde_json::from_str(data).unwrap();
    assert_eq!(data["revision"], before.revision + 1);
    assert_eq!(data["session_id"], session.id().to_string());
    assert!(data["client_id"].is_null());
}

#[tokio::test]
async fn saved_http_tab_duplicate_rejects_caps_and_invalid_saved_fields_without_trimming() {
    let fixture = Fixture::new().await;
    let session = fixture.state.session().await;
    for kind in [
        "tabs",
        "history",
        "text",
        "embedded-record",
        "serialized-workspace",
        "sequence",
    ] {
        let mut snapshot = WorkspaceStateSnapshot::default();
        snapshot.replay.tabs = vec![tab("source", 1, false)];
        snapshot.replay.active_tab_id = Some("source".into());
        snapshot.replay.tab_sequence = 1;
        match kind {
            "tabs" => {
                for index in 1..MAX_WORKSPACE_REPLAY_TABS {
                    snapshot
                        .replay
                        .tabs
                        .push(tab(&format!("tab-{index}"), index, false));
                }
            }
            "history" => {
                snapshot.replay.tabs[0].history_entries =
                    vec![ReplayHistoryEntryState::default(); 501]
            }
            "text" => snapshot.replay.tabs[0].request_text = "x".repeat(2 * 1024 * 1024 + 1),
            "embedded-record" => {
                let mut saved = record("/oversized-synthetic");
                saved.response.as_mut().unwrap().body_preview = "x".repeat(16 * 1024 * 1024);
                snapshot.replay.tabs[0].response_record = Some(saved);
            }
            "serialized-workspace" => {
                let mut saved = record("/large-synthetic");
                saved.response.as_mut().unwrap().body_preview = "x".repeat(13 * 1024 * 1024);
                snapshot.replay.tabs[0].response_record = Some(saved);
                for index in 1..3 {
                    let mut next = snapshot.replay.tabs[0].clone();
                    next.id = format!("large-{index}");
                    snapshot.replay.tabs.push(next);
                }
                api::validate_workspace_state(&snapshot).unwrap();
            }
            "sequence" => snapshot.replay.tab_sequence = usize::MAX - 1,
            _ => unreachable!(),
        }
        // Install directly into the actual workspace store so the operation has
        // to reject old oversized state rather than silently truncate it. Its
        // normal persistence entrypoint would rightly reject the fixture first.
        let before = session.workspace.replace_snapshot(snapshot).await;
        let disk = files(session.storage_dir());
        let mut events = session.workspace.subscribe();
        let (status, text) = fixture
            .post(
                "duplicate",
                payload(session.id(), "source", before.revision),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{kind}: {text}");
        assert_eq!(
            serialized(&session.workspace.snapshot().await),
            serialized(&before),
            "{kind}"
        );
        assert_eq!(files(session.storage_dir()), disk, "{kind}");
        assert!(
            matches!(events.try_recv(), Err(TryRecvError::Empty)),
            "{kind}"
        );
    }
}

#[tokio::test]
async fn saved_http_tab_uncached_inactive_close_only_writes_workspace_and_keeps_active_session() {
    let fixture = Fixture::new().await;
    let active = fixture.state.session().await.id();
    let (id, path, before) = fixture.inactive(workspace());
    for name in ["transactions.journal", "websockets.journal"] {
        std::fs::write(path.join(name), b"damaged synthetic journal\n{incomplete").unwrap();
    }
    let disk = files(&path);
    let (status, text) = fixture
        .post("close", payload(id, " legacy tab ", before.revision))
        .await;
    let result = ack(status, &text);
    assert_eq!(result["closed_tab_id"], " legacy tab ");
    assert_eq!(result["active_tab_id"], "other-http");
    assert_eq!(result["revision"], before.revision + 1);
    assert_eq!(fixture.state.session().await.id(), active);
    assert_eq!(without_workspace(files(&path)), without_workspace(disk));
    let cached = fixture.state.read_session_context_for_id(id).await.unwrap();
    let after = cached.workspace.snapshot().await;
    assert_eq!(
        serialized(&after.replay.tabs),
        serialized(&before.replay.tabs[1..])
    );
    assert_eq!(serialized(&after.fuzzer), serialized(&before.fuzzer));
    // A stale lower sequence must not be reused after removing a saved tab.
    assert_eq!(after.replay.tab_sequence, 90);
    let restarted = AppState::new(fixture.config.clone()).unwrap();
    assert_eq!(restarted.session().await.id(), active);
    assert_eq!(
        serialized(
            &restarted
                .read_session_context_for_id(id)
                .await
                .unwrap()
                .workspace
                .snapshot()
                .await
        ),
        serialized(&after)
    );
}

#[tokio::test]
async fn saved_http_tab_immediate_active_guard_and_unknown_session_fail_without_changes() {
    let fixture = Fixture::new().await;
    let (session, before) = fixture.seed(workspace()).await;
    let disk = files(&fixture.config.data_dir);
    for operation in ["close", "duplicate", "set-pinned"] {
        let mut wrong_active = payload(session.id(), " legacy tab ", before.revision);
        wrong_active["expected_active_session_id"] = json!(Uuid::new_v4());
        let (status, text) = fixture
            .post(operation, operation_payload(operation, wrong_active))
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{text}");
        let (status, text) = fixture
            .post(
                operation,
                operation_payload(
                    operation,
                    payload(Uuid::new_v4(), " legacy tab ", before.revision),
                ),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{text}");
    }
    assert_eq!(
        serialized(&session.workspace.snapshot().await),
        serialized(&before)
    );
    assert_eq!(files(&fixture.config.data_dir), disk);
}

#[tokio::test]
async fn saved_http_tab_concurrent_uncached_inactive_writers_share_the_same_revision_cas() {
    let fixture = Fixture::new().await;
    let active = fixture.state.session().await.id();
    for (first, second) in [
        ("duplicate", "duplicate"),
        ("close", "close"),
        ("close", "duplicate"),
        ("set-pinned", "set-pinned"),
        ("set-pinned", "close"),
        ("duplicate", "set-pinned"),
    ] {
        let (id, path, before) = fixture.inactive(workspace());
        for name in ["transactions.journal", "websockets.journal"] {
            std::fs::write(path.join(name), b"damaged synthetic journal\n{incomplete").unwrap();
        }
        let disk = files(&path);
        let body = payload(id, " legacy tab ", before.revision);
        let (one, two) = tokio::join!(
            fixture.post(first, operation_payload(first, body.clone())),
            fixture.post(second, operation_payload(second, body))
        );
        let mut statuses = [one.0.as_u16(), two.0.as_u16()];
        statuses.sort();
        assert_eq!(statuses, [200, 409], "{first}/{second}: {one:?} {two:?}");
        let cached = fixture.state.read_session_context_for_id(id).await.unwrap();
        let after = cached.workspace.snapshot().await;
        assert_eq!(after.revision, before.revision + 1);
        let persisted: WorkspaceStateSnapshot =
            serde_json::from_slice(&std::fs::read(path.join("workspace.json")).unwrap()).unwrap();
        assert_eq!(serialized(&persisted), serialized(&after));
        assert_eq!(fixture.state.session().await.id(), active);
        assert_eq!(without_workspace(files(&path)), without_workspace(disk));
    }
}

#[tokio::test]
async fn saved_http_tab_successful_close_blocks_stale_same_client_keepalive_resurrection() {
    let fixture = Fixture::new().await;
    let (session, mut before) = fixture.seed(workspace()).await;
    before.session_id = Some(session.id());
    let (status, text) = fixture
        .post(
            "close",
            payload(session.id(), " legacy tab ", before.revision),
        )
        .await;
    ack(status, &text);
    let after = session.workspace.snapshot().await;
    let disk = files(session.storage_dir());
    let mut events = session.workspace.subscribe();
    assert!(after.replay.tabs.iter().all(|tab| tab.id != " legacy tab "));
    assert!(after.client_id.is_none());
    before.client_version += 100;
    for complete in [false, true] {
        let mut stale = serialized(&before);
        stale["keepalive"] = json!({
            "replay_tabs_complete": complete,
            "replay_tab_ids": before.replay.tabs.iter().map(|tab| tab.id.clone()).collect::<Vec<_>>(),
            "fuzzer_complete": complete,
            "text_complete": complete,
        });
        let response = fixture
            .client
            .post(format!("{}/api/workspace-state/keepalive", fixture.base))
            .json(&stale)
            .send()
            .await
            .unwrap();
        let status = response.status();
        let text = response.text().await.unwrap();
        assert_eq!(status, StatusCode::CONFLICT, "complete={complete}: {text}");
        assert_eq!(
            serialized(&session.workspace.snapshot().await),
            serialized(&after)
        );
        assert_eq!(files(session.storage_dir()), disk);
        assert!(matches!(events.try_recv(), Err(TryRecvError::Empty)));
    }
}

#[tokio::test]
async fn saved_http_tab_set_pinned_is_idempotent_desired_state_only_and_survives_restart() {
    for inactive in [false, true] {
        let fixture = Fixture::new().await;
        let active = fixture.state.session().await.id();
        let (session, mut before) = if inactive {
            let (id, path, before) = fixture.inactive(workspace());
            for name in ["transactions.journal", "websockets.journal"] {
                std::fs::write(path.join(name), b"damaged synthetic journal\n{incomplete").unwrap();
            }
            (
                fixture.state.read_session_context_for_id(id).await.unwrap(),
                before,
            )
        } else {
            fixture.seed(workspace()).await
        };
        let disk_before = without_workspace(files(session.storage_dir()));
        let mut events = session.workspace.subscribe();
        // Repeating the desired state is not a toggle. Each accepted CAS still
        // commits one revision, including a pin value already stored on disk.
        for (tab_id, pinned) in [
            (" legacy tab ", false),
            (" legacy tab ", false),
            (" legacy tab ", true),
            (" legacy tab ", true),
            ("other-http", true),
            ("other-http", false),
        ] {
            let mut body = payload(session.id(), tab_id, before.revision);
            body["pinned"] = json!(pinned);
            let (status, text) = fixture.post("set-pinned", body).await;
            assert_eq!(
                ack(status, &text),
                json!({
                    "session_id": session.id(),
                    "revision": before.revision + 1,
                    "active_tab_id": before.replay.active_tab_id,
                    "tab_id": tab_id,
                    "pinned": pinned,
                })
            );
            let mut expected = before.clone();
            expected
                .replay
                .tabs
                .iter_mut()
                .find(|tab| tab.id == tab_id)
                .unwrap()
                .pinned = pinned;
            expected.revision += 1;
            expected.session_id = Some(session.id());
            expected.client_id = None;
            expected.client_version = 0;
            expected.expected_active_session_id = None;
            let after = session.workspace.snapshot().await;
            // Full equality preserves physical order, focus, the deliberately
            // lagging sequence, every saved HTTP/WS field, and unrelated drafts.
            assert_eq!(serialized(&after), serialized(&expected));
            assert_eq!(fixture.state.session().await.id(), active);
            assert_eq!(without_workspace(files(session.storage_dir())), disk_before);
            let persisted: WorkspaceStateSnapshot = serde_json::from_slice(
                &std::fs::read(session.storage_dir().join("workspace.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(serialized(&persisted), serialized(&expected));
            let event = events.try_recv().unwrap();
            assert_eq!(event.revision, after.revision);
            assert_eq!(event.session_id, Some(session.id()));
            assert!(event.client_id.is_none());
            assert!(matches!(events.try_recv(), Err(TryRecvError::Empty)));
            before = after;
        }
        let restarted = AppState::new(fixture.config.clone()).unwrap();
        assert_eq!(restarted.session().await.id(), active);
        let loaded = restarted
            .read_session_context_for_id(session.id())
            .await
            .unwrap();
        assert_eq!(
            serialized(&loaded.workspace.snapshot().await),
            serialized(&before)
        );
    }
}

#[tokio::test]
async fn saved_http_tab_set_pinned_requires_strict_boolean_and_rejects_unknown_fields() {
    let fixture = Fixture::new().await;
    let (session, before) = fixture.seed(workspace()).await;
    let valid = payload(session.id(), " legacy tab ", before.revision);
    let mut invalid = vec![valid.clone()]; // Missing pinned must not default to false.
    for pinned in [
        Value::Null,
        json!("true"),
        json!("false"),
        json!(0),
        json!(1),
        json!([]),
        json!({}),
    ] {
        let mut body = valid.clone();
        body["pinned"] = pinned;
        invalid.push(body);
    }
    for key in ["toggle", "pin", "client_version", "request_text"] {
        let mut body = valid.clone();
        body["pinned"] = json!(true);
        body[key] = json!(true);
        invalid.push(body);
    }
    let disk = files(&fixture.config.data_dir);
    let mut events = session.workspace.subscribe();
    for body in invalid {
        let (status, text) = fixture.post("set-pinned", body).await;
        assert!(status.is_client_error(), "{status}: {text}");
        assert_eq!(
            serialized(&session.workspace.snapshot().await),
            serialized(&before)
        );
        assert_eq!(files(&fixture.config.data_dir), disk);
        assert!(matches!(events.try_recv(), Err(TryRecvError::Empty)));
    }
}
