//! What sniper-cli does in Replay is marked for the person working beside it:
//! a tab it opens says who opened it, and a change it makes to a tab the
//! person opened is flagged, with who made it, until the person looks at it.
//! The server writes the marks, so a CLI that predates them neither misses
//! them nor erases them.
use std::{path::PathBuf, sync::Arc};

use serde_json::{json, Value};
use sniper::{config::AppConfig, state::AppState};
use tokio::task::JoinHandle;
use uuid::Uuid;

struct Fixture {
    dir: PathBuf,
    api: String,
    server: JoinHandle<()>,
}

impl Fixture {
    async fn start() -> Self {
        let dir = std::env::temp_dir().join(format!("sniper-replay-agent-{}", Uuid::new_v4()));
        let state = Arc::new(
            AppState::new(AppConfig {
                data_dir: dir.clone(),
                proxy_addr: "127.0.0.1:0".parse().unwrap(),
                ui_addr: "127.0.0.1:0".parse().unwrap(),
                max_entries: 100,
                max_transaction_entries: 100,
                body_preview_bytes: 1024,
            })
            .unwrap(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = format!("http://{}", listener.local_addr().unwrap());
        let app = sniper::api::router(state);
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        std::fs::create_dir_all(&dir).unwrap();
        Self { dir, api, server }
    }

    /// Runs sniper-cli with only the given variables to say who drives it.
    async fn command(&self, actor: &[(&str, &str)], args: &[&str]) -> Value {
        let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_sniper-cli"))
            .env_remove("SNIPER_ACTOR")
            .env_remove("CLAUDECODE")
            .env_remove("CODEX_THREAD_ID")
            .env_remove("CODEX_SANDBOX")
            .env_remove("CODEX_MANAGED_PACKAGE_ROOT")
            .envs(actor.iter().copied())
            .env("SNIPER_DATA_DIR", &self.dir)
            .args(["--output", "compact", "--api", &self.api])
            .args(args)
            .output()
            .await
            .unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {} / {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn tab<'a>(list: &'a Value, id: &str) -> &'a Value {
        let tabs = list.get("data").unwrap_or(list)["tabs"].as_array().unwrap();
        tabs.iter().find(|tab| tab["id"] == id).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A tab saved the way the UI saves the workspace, as a person's.
async fn save_as_the_ui(fixture: &Fixture, sequence: u64) -> String {
    let client = reqwest::Client::new();
    let url = format!("{}/api/workspace-state", fixture.api);
    let mut workspace: Value = client.get(&url).send().await.unwrap().json().await.unwrap();
    let id = Uuid::new_v4().to_string();
    workspace["replay"]["tabs"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id": id, "type": "http", "sequence": sequence,
            "request_text": "GET /mine HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "target_scheme": "https", "target_host": "example.com", "target_port": "443",
        }));
    workspace["client_id"] = json!("synthetic-ui");
    workspace["client_version"] = json!(sequence);
    let saved = client.post(&url).json(&workspace).send().await.unwrap();
    assert!(
        saved.status().is_success(),
        "{}",
        saved.text().await.unwrap()
    );
    id
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tab_says_who_opened_it_and_who_changed_a_persons_tab() {
    let fixture = Fixture::start().await;
    let opened = fixture
        .command(&[("CLAUDECODE", "1")], &["replay", "open", "--yes"])
        .await;
    let claudes = opened.get("data").unwrap_or(&opened)["id"]
        .as_str()
        .unwrap()
        .to_string();
    let edited = save_as_the_ui(&fixture, 50).await;
    let relabelled = save_as_the_ui(&fixture, 51).await;
    let untouched = save_as_the_ui(&fixture, 52).await;

    // A whole-workspace save, a saved-tab call, and a copy of a tab.
    fixture
        .command(
            &[("SNIPER_ACTOR", "Codex")],
            &[
                "replay",
                "update",
                "--tab-id",
                &edited,
                "--host",
                "www.example.com",
                "--yes",
            ],
        )
        .await;
    fixture
        .command(
            &[],
            &[
                "replay",
                "update",
                "--tab-id",
                &relabelled,
                "--label",
                "Found",
                "--yes",
            ],
        )
        .await;
    let copied = fixture
        .command(
            &[("CLAUDECODE", "1")],
            &["replay", "duplicate", "--tab-id", &edited, "--yes"],
        )
        .await;
    let copy = copied.get("data").unwrap_or(&copied)["new_tab_id"]
        .as_str()
        .unwrap()
        .to_string();

    let list = fixture.command(&[], &["replay", "list"]).await;
    let marks = |id: &str| {
        let tab = Fixture::tab(&list, id);
        (
            tab.get("opened_by").cloned(),
            tab.get("changed_by").cloned(),
        )
    };
    assert_eq!(marks(&claudes), (Some(json!("Claude")), None));
    assert_eq!(marks(&edited), (None, Some(json!("Codex"))));
    assert_eq!(marks(&relabelled), (None, Some(json!("CLI"))));
    assert_eq!(marks(&copy), (Some(json!("Claude")), None));
    // Saving the whole workspace marks only the tab the command changed.
    assert_eq!(marks(&untouched), (None, None));
}

/// Codex is named without being told: it sets CODEX_THREAD_ID on the commands
/// it runs, CODEX_SANDBOX when it sandboxes them, and its npm launcher sets
/// CODEX_MANAGED_PACKAGE_ROOT. Codex started from Claude Code, as Claude
/// Code's Codex plugin starts it, also inherits CLAUDECODE=1.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tab_codex_opens_says_codex() {
    let fixture = Fixture::start().await;
    let cases: [(&[(&str, &str)], &str); 6] = [
        (&[("CODEX_THREAD_ID", "thread")], "Codex"),
        (&[("CODEX_SANDBOX", "seatbelt")], "Codex"),
        (&[("CODEX_MANAGED_PACKAGE_ROOT", "/opt/codex")], "Codex"),
        (
            &[("CLAUDECODE", "1"), ("CODEX_THREAD_ID", "thread")],
            "Codex",
        ),
        // Claude Code's Codex plugin marks Claude's own commands too.
        (
            &[
                ("CLAUDECODE", "1"),
                ("CODEX_COMPANION_SESSION_ID", "session"),
            ],
            "Claude",
        ),
        (
            &[("SNIPER_ACTOR", "Reviewer"), ("CODEX_THREAD_ID", "thread")],
            "Reviewer",
        ),
    ];
    let mut opened = Vec::new();
    for (actor, expected) in cases {
        let tab = fixture.command(actor, &["replay", "open", "--yes"]).await;
        let id = tab.get("data").unwrap_or(&tab)["id"]
            .as_str()
            .unwrap()
            .to_string();
        opened.push((id, expected));
    }
    let list = fixture.command(&[], &["replay", "list"]).await;
    for (id, expected) in opened {
        assert_eq!(Fixture::tab(&list, &id)["opened_by"], expected, "{id}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cli_that_predates_the_marks_neither_misses_nor_erases_them() {
    let fixture = Fixture::start().await;
    let opened = fixture
        .command(&[("CLAUDECODE", "1")], &["replay", "open", "--yes"])
        .await;
    let claudes = opened.get("data").unwrap_or(&opened)["id"]
        .as_str()
        .unwrap()
        .to_string();

    // An older sniper-cli saves the whole workspace without the fields it does
    // not know and without saying who drives it, with a tab of its own.
    let client = reqwest::Client::new();
    let url = format!("{}/api/workspace-state", fixture.api);
    let mut workspace: Value = client.get(&url).send().await.unwrap().json().await.unwrap();
    for tab in workspace["replay"]["tabs"].as_array_mut().unwrap() {
        tab.as_object_mut().unwrap().remove("opened_by");
    }
    let olds = Uuid::new_v4().to_string();
    workspace["replay"]["tabs"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id": olds, "type": "http", "sequence": 60}));
    workspace["client_id"] = json!("sniper-cli");
    workspace["client_version"] = json!(1);
    let saved = client.post(&url).json(&workspace).send().await.unwrap();
    assert!(
        saved.status().is_success(),
        "{}",
        saved.text().await.unwrap()
    );

    let list = fixture.command(&[], &["replay", "list"]).await;
    assert_eq!(Fixture::tab(&list, &claudes)["opened_by"], "Claude");
    assert_eq!(Fixture::tab(&list, &olds)["opened_by"], "CLI");
}
