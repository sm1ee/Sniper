//! Synthetic GET fixtures only: no Sniper runtime, traffic, or user data.
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

const SESSION: &str = "00000000-0000-4000-8000-000000000001";

#[derive(Clone)]
struct Reply {
    status: u16,
    body: String,
    incomplete: bool,
    disconnect: bool,
}

struct Fixture {
    root: PathBuf,
    api: String,
    reply: Arc<Mutex<Reply>>,
    requests: Arc<Mutex<Vec<String>>>,
    server: tokio::task::JoinHandle<()>,
}

impl Fixture {
    async fn new() -> Self {
        let root = std::env::temp_dir().join(format!("sniper-read-response-{}", Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let settings = json!({
            "runtime_instance_id":SESSION, "proxy_addr":"127.0.0.1:0",
            "ui_addr":addr.to_string(), "data_dir":"synthetic-unused-path",
            "max_entries":100, "features":["http_capture","session_storage","replay"]
        })
        .to_string();
        let reply = Arc::new(Mutex::new(Reply {
            status: 200,
            body: String::new(),
            incomplete: false,
            disconnect: false,
        }));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let server_reply = reply.clone();
        let server_requests = requests.clone();
        let server = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(
                        tokio::time::timeout(Duration::from_secs(2), stream.read_u8())
                            .await
                            .unwrap()
                            .unwrap(),
                    );
                    assert!(request.len() < 16 * 1024);
                }
                let request = String::from_utf8(request).unwrap();
                let mut line = request.lines().next().unwrap().split_whitespace();
                assert_eq!(line.next(), Some("GET"));
                let path = line.next().unwrap();
                server_requests.lock().unwrap().push(path.to_owned());
                let reply = if path == "/api/settings" {
                    Reply {
                        status: 200,
                        body: settings.clone(),
                        incomplete: false,
                        disconnect: false,
                    }
                } else {
                    assert!(matches!(
                        path.split('?').next().unwrap(),
                        "/api/transactions-search" | "/api/transactions"
                    ));
                    server_reply.lock().unwrap().clone()
                };
                if !reply.disconnect {
                    let len = reply.body.len() + usize::from(reply.incomplete) * 100;
                    let status = reqwest::StatusCode::from_u16(reply.status).unwrap();
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{}",
                        reply.body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                }
                let _ = stream.shutdown().await;
            }
        });
        Self {
            root,
            api: format!("http://{addr}"),
            reply,
            requests,
            server,
        }
    }

    async fn command(
        &self,
        action: &str,
        term: &str,
        call: bool,
        format: &str,
    ) -> (i32, Value, String) {
        let operation = format!("capture.http.{action}");
        let field = if action == "search" { "value" } else { "query" };
        let mut input = json!({"session_id":SESSION});
        input[field] = json!(term);
        let input = input.to_string();
        let flag = format!("--{field}");
        let args = if call {
            vec!["call", &operation, "--input", &input]
        } else {
            vec![
                "capture",
                "http",
                action,
                "--session-id",
                SESSION,
                &flag,
                term,
            ]
        };
        let mut cli = tokio::process::Command::new(env!("CARGO_BIN_EXE_sniper-cli"));
        cli.env_clear()
            .env("HOME", self.root.join("home"))
            .env("USERPROFILE", self.root.join("home"))
            .env("CODEX_HOME", self.root.join("codex-home"))
            .env("SNIPER_DATA_DIR", self.root.join("data"))
            .current_dir(&self.root)
            .args(["--api", &self.api, "--output", format])
            .args(args)
            .kill_on_drop(true);
        #[cfg(windows)]
        if let Some(system_root) = std::env::var_os("SystemRoot") {
            cli.env("SystemRoot", system_root);
        }
        let output = tokio::time::timeout(Duration::from_secs(5), cli.output())
            .await
            .expect("synthetic CLI read timed out")
            .unwrap();
        assert!(output.stderr.is_empty(), "{output:?}");
        if format == "compact" {
            assert_eq!(
                output.stdout.iter().filter(|&&byte| byte == b'\n').count(),
                1
            );
        }
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        let requests = std::mem::take(&mut *self.requests.lock().unwrap());
        assert_eq!(requests.len(), 2, "reads must not retry: {requests:?}");
        assert_eq!(requests[0], "/api/settings");
        let endpoint = if action == "search" {
            "transactions-search"
        } else {
            "transactions"
        };
        let path = &requests[1];
        assert_eq!(path.split('?').next().unwrap(), format!("/api/{endpoint}"));
        let url = reqwest::Url::parse(&format!("http://example.com{path}")).unwrap();
        let params: std::collections::BTreeMap<_, _> = url.query_pairs().collect();
        let key = if action == "search" { "value" } else { "q" };
        assert_eq!(params.get(key).unwrap().as_ref(), term);
        assert_eq!(params.get("session_id").unwrap().as_ref(), SESSION);
        for name in ["home", "codex-home", "data"] {
            assert!(!self.root.join(name).exists(), "CLI created {name}");
        }
        (output.status.code().unwrap(), value, path.clone())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[tokio::test]
async fn valid_query_words_do_not_reclassify_read_transport_or_decode_failures() {
    let fixture = Fixture::new().await;
    for (disconnect, incomplete, body) in [
        (true, false, ""),
        (false, false, "{synthetic malformed JSON"),
        (false, true, "[]"),
    ] {
        *fixture.reply.lock().unwrap() = Reply {
            status: 200,
            body: body.to_owned(),
            incomplete,
            disconnect,
        };
        for action in ["search", "list"] {
            for term in ["plain", "invalid", "conflicts"] {
                for format in ["compact", "pretty"] {
                    let direct = fixture.command(action, term, false, format).await;
                    let called = fixture.command(action, term, true, format).await;
                    assert_eq!(direct, called);
                    let (exit, value, path) = direct;
                    assert_eq!(exit, 1, "{value}");
                    assert_eq!(value["ok"], false);
                    assert_eq!(value["operation"], format!("capture.http.{action}"));
                    assert_eq!(value["schema_version"], "2026-06-22");
                    assert_eq!(value["error"]["code"], "CLI_ERROR");
                    assert_eq!(value["error"]["retryable"], false);
                    assert_eq!(value["error"]["hint"], Value::Null);
                    assert_eq!(value["error"]["details"], json!({}));
                    let prefix = if disconnect {
                        "failed to GET"
                    } else {
                        "failed to decode JSON response from"
                    };
                    assert_eq!(value["error"]["message"], format!("{prefix} {path}"));
                }
            }
        }
    }
}

#[tokio::test]
async fn typed_read_context_preserves_http_status_errors_and_successful_output() {
    let fixture = Fixture::new().await;
    for status in [200, 400, 503] {
        *fixture.reply.lock().unwrap() = Reply {
            status,
            body: if status == 200 {
                "[]".to_owned()
            } else {
                "synthetic private server diagnostic: invalid input".to_owned()
            },
            incomplete: status != 200,
            disconnect: false,
        };
        for action in ["search", "list"] {
            let (exit, direct, _) = fixture.command(action, "invalid", false, "compact").await;
            let (call_exit, called, _) = fixture.command(action, "invalid", true, "compact").await;
            assert_eq!(exit, call_exit);
            if status == 200 {
                assert_eq!(exit, 0);
                assert_eq!(direct, json!([]));
                assert_eq!(called["ok"], true);
                assert_eq!(called["data"], direct);
            } else {
                assert_eq!(direct, called);
                assert_eq!(exit, if status >= 500 { 6 } else { 5 });
                assert_eq!(direct["error"]["code"], "HTTP_STATUS_ERROR");
                assert_eq!(direct["error"]["details"], json!({"status":status}));
                assert_eq!(direct["error"]["retryable"], status >= 500);
                assert_eq!(
                    direct["error"]["message"],
                    format!(
                        "API read failed ({})",
                        reqwest::StatusCode::from_u16(status).unwrap()
                    )
                );
                assert!(!direct.to_string().contains("synthetic private"));
            }
        }
    }
}
