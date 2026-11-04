//! What an agent does in Replay through sniper-cli is marked for the person
//! working beside it: a tab it opens says so, and a change it makes to a tab
//! the person opened is flagged until the person looks at it.
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

    async fn command(&self, args: &[&str]) -> Value {
        let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_sniper-cli"))
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agents_tab_says_so_and_its_change_to_a_persons_tab_is_flagged() {
    let fixture = Fixture::start().await;
    let opened = fixture.command(&["replay", "open", "--yes"]).await;
    let agent_tab = opened.get("data").unwrap_or(&opened)["id"]
        .as_str()
        .unwrap()
        .to_string();

    // A tab the person opened, saved the way the UI saves the workspace.
    let client = reqwest::Client::new();
    let url = format!("{}/api/workspace-state", fixture.api);
    let mut workspace: Value = client.get(&url).send().await.unwrap().json().await.unwrap();
    let person_tab = Uuid::new_v4().to_string();
    workspace["replay"]["tabs"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id": person_tab, "type": "http", "sequence": 50,
            "request_text": "GET /mine HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "target_scheme": "https", "target_host": "example.com", "target_port": "443",
        }));
    workspace["client_id"] = json!("synthetic-ui");
    workspace["client_version"] = json!(1);
    let saved = client.post(&url).json(&workspace).send().await.unwrap();
    assert!(
        saved.status().is_success(),
        "{}",
        saved.text().await.unwrap()
    );

    fixture
        .command(&[
            "replay",
            "update",
            "--tab-id",
            &person_tab,
            "--host",
            "www.example.com",
            "--yes",
        ])
        .await;

    let list = fixture.command(&["replay", "list"]).await;
    let agents = Fixture::tab(&list, &agent_tab);
    assert_eq!(agents["opened_by_agent"], true);
    assert!(agents.get("agent_edited").is_none());
    let persons = Fixture::tab(&list, &person_tab);
    assert_eq!(persons["agent_edited"], true);
    assert!(persons.get("opened_by_agent").is_none());
}
