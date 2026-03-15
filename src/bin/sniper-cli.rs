use std::{
    env, fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use clap::{ArgAction, Args, Parser, Subcommand};
use reqwest::{Method, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::json;
use sniper::{
    certificate::default_data_dir,
    intercept::{InterceptRecord, InterceptSummary},
    fuzzer::FuzzerAttackRecord,
    match_replace::{MatchReplaceRule, MatchReplaceRulesPayload},
    model::{
        BodyEncoding, EditableRequest, HeaderRecord, RequestTargetOverride, TransactionRecord,
        TransactionSummary, WebSocketSessionRecord, WebSocketSessionSummary,
    },
    runtime::RuntimeSettingsSnapshot,
    runtime_state::load_runtime_state,
    session::SessionSummary,
    workspace::{
        ReplayHistoryEntryState, ReplayTabState, ReplayWorkspaceState, WorkspaceStateSnapshot,
    },
};
use url::Url;
use uuid::Uuid;

const CODEX_SKILL_NAME: &str = "sniper-operator";
const CLAUDE_SKILL_NAME: &str = "sniper-operator";
const CODEX_SKILL_TEMPLATE: &str =
    include_str!("../../packaging/skills/codex/sniper-operator/SKILL.md");
const CLAUDE_SKILL_TEMPLATE: &str =
    include_str!("../../packaging/skills/claude/sniper-operator/SKILL.md");

#[derive(Parser, Debug)]
#[command(name = "sniper-cli", version = env!("CARGO_PKG_VERSION"), about = "Operate a local Sniper proxy through its JSON API.")]
struct Cli {
    #[arg(long, global = true)]
    api: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Session {
        #[command(subcommand)]
        command: SessionCommand,
    },
    Capture {
        #[command(subcommand)]
        command: CaptureCommand,
    },
    #[command(name = "scope", visible_alias = "target")]
    Scope {
        #[command(subcommand)]
        command: TargetCommand,
    },
    #[command(name = "replay", visible_alias = "repeater")]
    Replay {
        #[command(subcommand)]
        command: ReplayCommand,
    },
    Fuzzer {
        #[command(subcommand)]
        command: FuzzerCommand,
    },
    Skills {
        #[command(subcommand)]
        command: SkillsCommand,
    },
    #[command(name = "http", visible_alias = "history", hide = true)]
    History {
        #[command(subcommand)]
        command: HistoryCommand,
    },
    #[command(hide = true)]
    Intercept {
        #[command(subcommand)]
        command: InterceptCommand,
    },
    #[command(name = "web-socket", visible_alias = "websocket", hide = true)]
    Websocket {
        #[command(subcommand)]
        command: WebSocketCommand,
    },
    #[command(name = "auto-replace", visible_alias = "match-replace", hide = true)]
    AutoReplace {
        #[command(subcommand)]
        command: AutoReplaceCommand,
    },
}

#[derive(Subcommand, Debug)]
enum CaptureCommand {
    #[command(name = "http", visible_alias = "history")]
    Http {
        #[command(subcommand)]
        command: HistoryCommand,
    },
    Intercept {
        #[command(subcommand)]
        command: InterceptCommand,
    },
    #[command(name = "web-socket", visible_alias = "websocket")]
    WebSocket {
        #[command(subcommand)]
        command: WebSocketCommand,
    },
    #[command(name = "auto-replace", visible_alias = "match-replace")]
    AutoReplace {
        #[command(subcommand)]
        command: AutoReplaceCommand,
    },
}

#[derive(Subcommand, Debug)]
enum SessionCommand {
    List,
    Create(CreateSessionArgs),
    Switch(SessionSwitchArgs),
}

#[derive(Args, Debug)]
struct CreateSessionArgs {
    #[arg(long)]
    name: Option<String>,
}

#[derive(Args, Debug)]
struct SessionSwitchArgs {
    #[arg(long)]
    id: Uuid,
}

#[derive(Subcommand, Debug)]
enum HistoryCommand {
    List(HistoryListArgs),
    Get(HistoryGetArgs),
    Replay(HistoryReplayArgs),
    Fuzzer(HistoryFuzzerArgs),
    Annotate(HistoryAnnotateArgs),
}

#[derive(Args, Debug, Default)]
struct HistoryListArgs {
    #[arg(long)]
    query: Option<String>,
    #[arg(long)]
    method: Option<String>,
    #[arg(long)]
    limit: Option<usize>,
}

#[derive(Args, Debug)]
struct HistoryGetArgs {
    #[arg(long)]
    id: Uuid,
}

#[derive(Args, Debug, Default)]
struct HistoryReplayArgs {
    #[arg(long)]
    id: Uuid,
    #[arg(long)]
    scheme: Option<String>,
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    port: Option<String>,
}

#[derive(Args, Debug)]
struct HistoryFuzzerArgs {
    #[arg(long)]
    id: Uuid,
}

#[derive(Args, Debug)]
struct HistoryAnnotateArgs {
    #[arg(long)]
    id: Uuid,
    /// Set color tag (e.g. red, orange, yellow, green, blue, purple). Use --clear-color to remove.
    #[arg(long)]
    color: Option<String>,
    /// Remove the color tag.
    #[arg(long)]
    clear_color: bool,
    /// Set a user note on the transaction.
    #[arg(long)]
    note: Option<String>,
    /// Remove the user note.
    #[arg(long)]
    clear_note: bool,
}

#[derive(Subcommand, Debug)]
enum TargetCommand {
    GetScope,
    SetScope(TargetSetScopeArgs),
}

#[derive(Args, Debug, Default)]
struct TargetSetScopeArgs {
    #[arg(long = "pattern", action = ArgAction::Append)]
    patterns: Vec<String>,
    #[arg(long)]
    file: Option<PathBuf>,
    #[arg(long)]
    stdin: bool,
}

#[derive(Subcommand, Debug)]
enum ReplayCommand {
    List,
    Open(ReplayOpenArgs),
    Update(ReplayUpdateArgs),
    Send(ReplaySendArgs),
}

#[derive(Args, Debug, Default)]
struct ReplayOpenArgs {
    #[arg(long)]
    transaction_id: Option<Uuid>,
    #[arg(long)]
    request_file: Option<PathBuf>,
    #[arg(long)]
    stdin: bool,
    #[arg(long)]
    scheme: Option<String>,
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    port: Option<String>,
}

#[derive(Args, Debug, Default)]
struct ReplayUpdateArgs {
    #[arg(long)]
    tab_id: String,
    #[arg(long)]
    request_file: Option<PathBuf>,
    #[arg(long)]
    stdin: bool,
    #[arg(long)]
    scheme: Option<String>,
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    port: Option<String>,
}

#[derive(Args, Debug)]
struct ReplaySendArgs {
    #[arg(long)]
    tab_id: String,
}

#[derive(Subcommand, Debug)]
enum FuzzerCommand {
    SetTemplate(FuzzerSetTemplateArgs),
    SetPayloads(FuzzerSetPayloadsArgs),
    Run,
}

#[derive(Args, Debug, Default)]
struct FuzzerSetTemplateArgs {
    #[arg(long)]
    transaction_id: Option<Uuid>,
    #[arg(long)]
    request_file: Option<PathBuf>,
    #[arg(long)]
    stdin: bool,
}

#[derive(Args, Debug, Default)]
struct FuzzerSetPayloadsArgs {
    #[arg(long = "payload", action = ArgAction::Append)]
    payloads: Vec<String>,
    #[arg(long)]
    file: Option<PathBuf>,
    #[arg(long)]
    stdin: bool,
}

#[derive(Subcommand, Debug)]
enum InterceptCommand {
    On,
    Off,
    List,
    Forward(InterceptForwardArgs),
    Drop(InterceptDropArgs),
}

#[derive(Args, Debug, Default)]
struct InterceptForwardArgs {
    #[arg(long)]
    id: Uuid,
    #[arg(long)]
    request_file: Option<PathBuf>,
    #[arg(long)]
    stdin: bool,
}

#[derive(Args, Debug)]
struct InterceptDropArgs {
    #[arg(long)]
    id: Uuid,
}

#[derive(Subcommand, Debug)]
enum WebSocketCommand {
    List(WebSocketListArgs),
    Get(WebSocketGetArgs),
}

#[derive(Subcommand, Debug)]
enum AutoReplaceCommand {
    List,
    Set(AutoReplaceSetArgs),
}

#[derive(Args, Debug, Default)]
struct WebSocketListArgs {
    #[arg(long)]
    limit: Option<usize>,
}

#[derive(Args, Debug)]
struct WebSocketGetArgs {
    #[arg(long)]
    id: Uuid,
}

#[derive(Subcommand, Debug)]
enum SkillsCommand {
    Install(SkillsInstallArgs),
}

#[derive(Args, Debug, Default)]
struct SkillsInstallArgs {
    #[arg(long)]
    codex: bool,
    #[arg(long)]
    claude: bool,
    #[arg(long)]
    all: bool,
    #[arg(long)]
    codex_dir: Option<PathBuf>,
    #[arg(long)]
    claude_dir: Option<PathBuf>,
}

#[derive(Args, Debug, Default)]
struct AutoReplaceSetArgs {
    #[arg(long)]
    file: Option<PathBuf>,
    #[arg(long)]
    stdin: bool,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AutoReplaceInput {
    Rules(Vec<MatchReplaceRule>),
    Payload(MatchReplaceRulesPayload),
}

#[derive(Clone)]
struct ApiClient {
    base_url: String,
    client: reqwest::Client,
}

impl ApiClient {
    async fn discover(cli_api: Option<String>) -> Result<Self> {
        let base_url = discover_api_base_url(cli_api)?;
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .context("failed to build sniper-cli HTTP client")?;
        Ok(Self { base_url, client })
    }

    async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.request_json(Method::GET, path, Option::<()>::None)
            .await
    }

    async fn post_json<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        self.request_json(Method::POST, path, Some(body)).await
    }

    async fn post_status<B: Serialize>(&self, path: &str, body: &B) -> Result<StatusCode> {
        let response = self
            .client
            .post(self.url(path))
            .json(body)
            .send()
            .await
            .with_context(|| format!("failed to POST {}", path))?;
        let status = response.status();
        if !status.is_success() {
            let message = response.text().await.unwrap_or_else(|_| String::new());
            let detail = if message.trim().is_empty() {
                status.to_string()
            } else {
                message
            };
            bail!("request to {} failed ({}): {}", path, status, detail);
        }
        Ok(status)
    }

    async fn request_json<B: Serialize, T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<B>,
    ) -> Result<T> {
        let request = self.client.request(method.clone(), self.url(path));
        let response = match body {
            Some(body) => request.json(&body).send().await,
            None => request.send().await,
        }
        .with_context(|| format!("failed to {} {}", method, path))?;

        let status = response.status();
        if !status.is_success() {
            let message = response.text().await.unwrap_or_else(|_| status.to_string());
            bail!("request to {} failed: {}", path, message);
        }

        response
            .json::<T>()
            .await
            .with_context(|| format!("failed to decode JSON response from {}", path))
    }

    fn url(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }
}

#[derive(Serialize)]
struct ScopeOutput {
    scope_patterns: Vec<String>,
}

#[derive(Serialize)]
struct InterceptActionResult {
    ok: bool,
    action: &'static str,
    id: Uuid,
}

#[derive(Serialize)]
struct SkillsInstallResult {
    installed: Vec<InstalledSkill>,
}

#[derive(Serialize)]
struct InstalledSkill {
    agent: &'static str,
    path: String,
}

#[derive(Serialize)]
struct RuntimeUpdatePayload {
    intercept_enabled: Option<bool>,
    websocket_capture_enabled: Option<bool>,
    scope_patterns: Option<Vec<String>>,
}

#[derive(Serialize)]
struct CreateSessionPayload {
    name: Option<String>,
}

#[derive(Serialize)]
struct ReplaySendPayload {
    request: EditableRequest,
    target: Option<RequestTargetOverride>,
    source_transaction_id: Option<Uuid>,
}

#[derive(Serialize)]
struct FuzzerRunPayload {
    template: EditableRequest,
    payloads: Vec<String>,
    source_transaction_id: Option<Uuid>,
}

#[derive(Serialize)]
struct InterceptForwardPayload {
    request: EditableRequest,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    run(cli).await
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Skills {
            command: SkillsCommand::Install(args),
        } => {
            let result = install_skills(args)?;
            print_json(&result)
        }
        command => {
            let api = ApiClient::discover(cli.api).await?;
            match command {
                Command::Session { command } => handle_session(api, command).await,
                Command::Capture { command } => match command {
                    CaptureCommand::Http { command } => handle_history(api, command).await,
                    CaptureCommand::Intercept { command } => handle_intercept(api, command).await,
                    CaptureCommand::WebSocket { command } => handle_websocket(api, command).await,
                    CaptureCommand::AutoReplace { command } => {
                        handle_auto_replace(api, command).await
                    }
                },
                Command::Scope { command } => handle_target(api, command).await,
                Command::Replay { command } => handle_replay(api, command).await,
                Command::Fuzzer { command } => handle_fuzzer(api, command).await,
                Command::Skills { .. } => unreachable!(),
                Command::History { command } => handle_history(api, command).await,
                Command::Intercept { command } => handle_intercept(api, command).await,
                Command::Websocket { command } => handle_websocket(api, command).await,
                Command::AutoReplace { command } => handle_auto_replace(api, command).await,
            }
        }
    }
}

async fn handle_session(api: ApiClient, command: SessionCommand) -> Result<()> {
    match command {
        SessionCommand::List => {
            let sessions: Vec<SessionSummary> = api.get_json("/api/sessions").await?;
            print_json(&sessions)
        }
        SessionCommand::Create(args) => {
            let session: SessionSummary = api
                .post_json("/api/sessions", &CreateSessionPayload { name: args.name })
                .await?;
            print_json(&session)
        }
        SessionCommand::Switch(args) => {
            let session: SessionSummary = api
                .post_json(&format!("/api/sessions/{}/activate", args.id), &json!({}))
                .await?;
            print_json(&session)
        }
    }
}

async fn handle_history(api: ApiClient, command: HistoryCommand) -> Result<()> {
    match command {
        HistoryCommand::List(args) => {
            let mut params = Vec::new();
            if let Some(query) = args.query {
                params.push(("q".to_string(), query));
            }
            if let Some(method) = args.method {
                params.push(("method".to_string(), method));
            }
            if let Some(limit) = args.limit {
                params.push(("limit".to_string(), limit.to_string()));
            }
            let query = encode_query(params);
            let path = if query.is_empty() {
                "/api/transactions".to_string()
            } else {
                format!("/api/transactions?{query}")
            };
            let history: Vec<TransactionSummary> = api.get_json(&path).await?;
            print_json(&history)
        }
        HistoryCommand::Get(args) => {
            let record: TransactionRecord = api
                .get_json(&format!("/api/transactions/{}", args.id))
                .await?;
            print_json(&record)
        }
        HistoryCommand::Replay(args) => {
            let tab = open_replay_tab(
                &api,
                Some(args.id),
                None,
                false,
                args.scheme,
                args.host,
                args.port,
            )
            .await?;
            print_json(&tab)
        }
        HistoryCommand::Fuzzer(args) => {
            let mut workspace: WorkspaceStateSnapshot = api.get_json("/api/workspace-state").await?;
            let (base_request, source_transaction_id, request_text) =
                resolve_request_source(&api, Some(args.id), None, false).await?;
            workspace.fuzzer.base_request = base_request;
            workspace.fuzzer.source_transaction_id = source_transaction_id;
            workspace.fuzzer.request_text = request_text;
            workspace.fuzzer.notice.clear();
            let snapshot: WorkspaceStateSnapshot =
                api.post_json("/api/workspace-state", &workspace).await?;
            print_json(&snapshot.fuzzer)
        }
        HistoryCommand::Annotate(args) => {
            let color_tag: Option<Option<String>> = if args.clear_color {
                Some(None)
            } else {
                args.color.map(Some)
            };
            let user_note: Option<Option<String>> = if args.clear_note {
                Some(None)
            } else {
                args.note.map(Some)
            };
            if color_tag.is_none() && user_note.is_none() {
                bail!("provide at least one of --color, --clear-color, --note, or --clear-note");
            }
            let payload = json!({
                "color_tag": color_tag,
                "user_note": user_note,
            });
            let summary: TransactionSummary = api
                .request_json(
                    Method::PATCH,
                    &format!("/api/transactions/{}/annotations", args.id),
                    Some(&payload),
                )
                .await?;
            print_json(&summary)
        }
    }
}

async fn handle_target(api: ApiClient, command: TargetCommand) -> Result<()> {
    match command {
        TargetCommand::GetScope => {
            let runtime: RuntimeSettingsSnapshot = api.get_json("/api/runtime").await?;
            print_json(&ScopeOutput {
                scope_patterns: runtime.scope_patterns,
            })
        }
        TargetCommand::SetScope(args) => {
            let scope_patterns = read_lines_input(args.patterns, args.file, args.stdin)?;
            let runtime: RuntimeSettingsSnapshot = api
                .post_json(
                    "/api/runtime",
                    &RuntimeUpdatePayload {
                        intercept_enabled: None,
                        websocket_capture_enabled: None,
                        scope_patterns: Some(scope_patterns),
                    },
                )
                .await?;
            print_json(&ScopeOutput {
                scope_patterns: runtime.scope_patterns,
            })
        }
    }
}

async fn handle_replay(api: ApiClient, command: ReplayCommand) -> Result<()> {
    match command {
        ReplayCommand::List => {
            let workspace: WorkspaceStateSnapshot = api.get_json("/api/workspace-state").await?;
            print_json(&workspace.replay)
        }
        ReplayCommand::Open(args) => {
            let tab = open_replay_tab(
                &api,
                args.transaction_id,
                args.request_file,
                args.stdin,
                args.scheme,
                args.host,
                args.port,
            )
            .await?;
            print_json(&tab)
        }
        ReplayCommand::Update(args) => {
            let mut workspace: WorkspaceStateSnapshot =
                api.get_json("/api/workspace-state").await?;
            let tab = find_replay_tab_mut(&mut workspace.replay, &args.tab_id)?;
            if args.request_file.is_some() || args.stdin {
                let request_text = read_text_input(args.request_file, args.stdin)?;
                if !request_text.trim().is_empty() {
                    tab.request_text = request_text;
                }
            }
            let normalized = normalize_target_inputs(
                args.scheme,
                args.host,
                args.port,
                tab.base_request.as_ref(),
            );
            if !normalized.scheme.is_empty() {
                tab.target_scheme = normalized.scheme;
            }
            if !normalized.host.is_empty() {
                tab.target_host = normalized.host;
            }
            if !normalized.port.is_empty() {
                tab.target_port = normalized.port;
            }
            let snapshot: WorkspaceStateSnapshot =
                api.post_json("/api/workspace-state", &workspace).await?;
            let tab = find_replay_tab(&snapshot.replay, &args.tab_id)?;
            print_json(tab)
        }
        ReplayCommand::Send(args) => {
            let mut workspace: WorkspaceStateSnapshot =
                api.get_json("/api/workspace-state").await?;
            let tab = find_replay_tab_mut(&mut workspace.replay, &args.tab_id)?.clone();
            let request = parse_editable_raw_request(&tab.request_text, tab.base_request.as_ref())?;
            let target =
                build_target_override(&tab.target_scheme, &tab.target_host, &tab.target_port);
            let record: TransactionRecord = api
                .post_json(
                    "/api/replay/send",
                    &ReplaySendPayload {
                        request: request.clone(),
                        target,
                        source_transaction_id: tab.source_transaction_id,
                    },
                )
                .await?;

            let tab_mut = find_replay_tab_mut(&mut workspace.replay, &args.tab_id)?;
            tab_mut.response_record = Some(record.clone());
            tab_mut.notice.clear();
            tab_mut.history_entries.push(ReplayHistoryEntryState {
                request,
                request_text: tab_mut.request_text.clone(),
                response_record: Some(record.clone()),
                notice: String::new(),
                target_scheme: tab_mut.target_scheme.clone(),
                target_host: tab_mut.target_host.clone(),
                target_port: tab_mut.target_port.clone(),
            });
            tab_mut.history_index = Some(tab_mut.history_entries.len().saturating_sub(1));

            let _snapshot: WorkspaceStateSnapshot =
                api.post_json("/api/workspace-state", &workspace).await?;
            print_json(&record)
        }
    }
}

async fn handle_fuzzer(api: ApiClient, command: FuzzerCommand) -> Result<()> {
    match command {
        FuzzerCommand::SetTemplate(args) => {
            let mut workspace: WorkspaceStateSnapshot =
                api.get_json("/api/workspace-state").await?;
            let (base_request, source_transaction_id, request_text) =
                resolve_request_source(&api, args.transaction_id, args.request_file, args.stdin)
                    .await?;
            workspace.fuzzer.base_request = base_request;
            workspace.fuzzer.source_transaction_id = source_transaction_id;
            workspace.fuzzer.request_text = request_text;
            workspace.fuzzer.notice.clear();
            let snapshot: WorkspaceStateSnapshot =
                api.post_json("/api/workspace-state", &workspace).await?;
            print_json(&snapshot.fuzzer)
        }
        FuzzerCommand::SetPayloads(args) => {
            let mut workspace: WorkspaceStateSnapshot =
                api.get_json("/api/workspace-state").await?;
            workspace.fuzzer.payloads_text =
                read_payloads_input(args.payloads, args.file, args.stdin)?;
            workspace.fuzzer.notice.clear();
            let snapshot: WorkspaceStateSnapshot =
                api.post_json("/api/workspace-state", &workspace).await?;
            print_json(&snapshot.fuzzer)
        }
        FuzzerCommand::Run => {
            let mut workspace: WorkspaceStateSnapshot =
                api.get_json("/api/workspace-state").await?;
            let template = parse_editable_raw_request(
                &workspace.fuzzer.request_text,
                workspace.fuzzer.base_request.as_ref(),
            )?;
            let payloads = split_payload_lines(&workspace.fuzzer.payloads_text);
            if payloads.is_empty() {
                bail!("fuzzer payloads are empty");
            }
            let record: FuzzerAttackRecord = api
                .post_json(
                    "/api/fuzzer/attacks",
                    &FuzzerRunPayload {
                        template,
                        payloads,
                        source_transaction_id: workspace.fuzzer.source_transaction_id,
                    },
                )
                .await?;
            workspace.fuzzer.attack_record = Some(record.clone());
            workspace.fuzzer.notice.clear();
            let _snapshot: WorkspaceStateSnapshot =
                api.post_json("/api/workspace-state", &workspace).await?;
            print_json(&record)
        }
    }
}

async fn handle_intercept(api: ApiClient, command: InterceptCommand) -> Result<()> {
    match command {
        InterceptCommand::On => {
            let runtime: RuntimeSettingsSnapshot = api
                .post_json(
                    "/api/runtime",
                    &RuntimeUpdatePayload {
                        intercept_enabled: Some(true),
                        websocket_capture_enabled: None,
                        scope_patterns: None,
                    },
                )
                .await?;
            print_json(&runtime)
        }
        InterceptCommand::Off => {
            let runtime: RuntimeSettingsSnapshot = api
                .post_json(
                    "/api/runtime",
                    &RuntimeUpdatePayload {
                        intercept_enabled: Some(false),
                        websocket_capture_enabled: None,
                        scope_patterns: None,
                    },
                )
                .await?;
            print_json(&runtime)
        }
        InterceptCommand::List => {
            let intercepts: Vec<InterceptSummary> = api.get_json("/api/intercepts").await?;
            print_json(&intercepts)
        }
        InterceptCommand::Forward(args) => {
            let intercept: InterceptRecord = api
                .get_json(&format!("/api/intercepts/{}", args.id))
                .await?;
            let request = if args.request_file.is_some() || args.stdin {
                let request_text = read_text_input(args.request_file, args.stdin)?;
                parse_editable_raw_request(&request_text, Some(&intercept.request))?
            } else {
                intercept.request
            };
            api.post_status(
                &format!("/api/intercepts/{}/forward", args.id),
                &InterceptForwardPayload { request },
            )
            .await?;
            print_json(&InterceptActionResult {
                ok: true,
                action: "forward",
                id: args.id,
            })
        }
        InterceptCommand::Drop(args) => {
            api.post_status(&format!("/api/intercepts/{}/drop", args.id), &json!({}))
                .await?;
            print_json(&InterceptActionResult {
                ok: true,
                action: "drop",
                id: args.id,
            })
        }
    }
}

async fn handle_websocket(api: ApiClient, command: WebSocketCommand) -> Result<()> {
    match command {
        WebSocketCommand::List(args) => {
            let mut params = Vec::new();
            if let Some(limit) = args.limit {
                params.push(("limit".to_string(), limit.to_string()));
            }
            let query = encode_query(params);
            let path = if query.is_empty() {
                "/api/websockets".to_string()
            } else {
                format!("/api/websockets?{query}")
            };
            let websockets: Vec<WebSocketSessionSummary> = api.get_json(&path).await?;
            print_json(&websockets)
        }
        WebSocketCommand::Get(args) => {
            let websocket: WebSocketSessionRecord = api
                .get_json(&format!("/api/websockets/{}", args.id))
                .await?;
            print_json(&websocket)
        }
    }
}

async fn handle_auto_replace(api: ApiClient, command: AutoReplaceCommand) -> Result<()> {
    match command {
        AutoReplaceCommand::List => {
            let rules: Vec<MatchReplaceRule> = api.get_json("/api/match-replace").await?;
            print_json(&rules)
        }
        AutoReplaceCommand::Set(args) => {
            let raw = read_text_input(args.file, args.stdin)?;
            let parsed: AutoReplaceInput = serde_json::from_str(&raw).context(
                "failed to parse auto-replace JSON; expected either an array of rules or {\"rules\": [...]}",
            )?;
            let payload = match parsed {
                AutoReplaceInput::Rules(rules) => MatchReplaceRulesPayload { rules },
                AutoReplaceInput::Payload(payload) => payload,
            };
            let rules: Vec<MatchReplaceRule> =
                api.post_json("/api/match-replace", &payload).await?;
            print_json(&rules)
        }
    }
}

async fn open_replay_tab(
    api: &ApiClient,
    transaction_id: Option<Uuid>,
    request_file: Option<PathBuf>,
    stdin: bool,
    scheme: Option<String>,
    host: Option<String>,
    port: Option<String>,
) -> Result<ReplayTabState> {
    let mut workspace: WorkspaceStateSnapshot = api.get_json("/api/workspace-state").await?;
    let (base_request, source_transaction_id, request_text) =
        resolve_request_source(api, transaction_id, request_file, stdin).await?;
    let normalized = normalize_target_inputs(scheme, host, port, base_request.as_ref());
    let sequence = workspace.replay.tab_sequence + 1;
    let tab = ReplayTabState {
        id: Uuid::new_v4().to_string(),
        sequence,
        base_request,
        source_transaction_id,
        notice: String::new(),
        request_text,
        response_record: None,
        target_scheme: normalized.scheme,
        target_host: normalized.host,
        target_port: normalized.port,
        history_entries: Vec::new(),
        history_index: None,
    };
    workspace.replay.tab_sequence = sequence;
    workspace.replay.active_tab_id = Some(tab.id.clone());
    workspace.replay.tabs.push(tab.clone());
    let snapshot: WorkspaceStateSnapshot = api.post_json("/api/workspace-state", &workspace).await?;
    let tab = find_replay_tab(&snapshot.replay, &tab.id)?;
    Ok(tab.clone())
}

async fn resolve_request_source(
    api: &ApiClient,
    transaction_id: Option<Uuid>,
    request_file: Option<PathBuf>,
    stdin: bool,
) -> Result<(Option<EditableRequest>, Option<Uuid>, String)> {
    if let Some(transaction_id) = transaction_id {
        let record: TransactionRecord = api
            .get_json(&format!("/api/transactions/{}", transaction_id))
            .await?;
        let request = record.editable_request();
        let request_text = build_editable_raw_request(&request);
        return Ok((Some(request), Some(transaction_id), request_text));
    }

    if request_file.is_some() || stdin {
        let request_text = read_text_input(request_file, stdin)?;
        let request = parse_editable_raw_request(&request_text, None)?;
        return Ok((Some(request), None, request_text));
    }

    let request = default_editable_request();
    let request_text = build_editable_raw_request(&request);
    Ok((Some(request), None, request_text))
}

fn default_editable_request() -> EditableRequest {
    EditableRequest {
        scheme: "https".to_string(),
        host: "example.com".to_string(),
        method: "GET".to_string(),
        path: "/".to_string(),
        headers: vec![HeaderRecord {
            name: "host".to_string(),
            value: "example.com".to_string(),
        }],
        body: String::new(),
        body_encoding: BodyEncoding::Utf8,
        preview_truncated: false,
    }
}

fn normalize_target_inputs(
    scheme: Option<String>,
    host: Option<String>,
    port: Option<String>,
    fallback: Option<&EditableRequest>,
) -> NormalizedTarget {
    let fallback_scheme = fallback
        .map(|request| request.scheme.clone())
        .unwrap_or_else(|| "https".to_string());
    let fallback_host = fallback
        .map(|request| strip_host_port(&request.host).to_string())
        .unwrap_or_default();
    let fallback_port = fallback
        .and_then(|request| extract_port(&request.host))
        .unwrap_or_else(|| default_port_for_scheme(&fallback_scheme).to_string());

    let mut scheme = scheme
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback_scheme);
    let mut host = host
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback_host);
    let mut port = port
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback_port);

    if host.starts_with("http://") || host.starts_with("https://") {
        if let Ok(parsed) = Url::parse(&host) {
            scheme = parsed.scheme().to_ascii_lowercase();
            host = parsed.host_str().unwrap_or_default().to_string();
            if let Some(url_port) = parsed.port() {
                port = url_port.to_string();
            }
        }
    } else if let Some((parsed_host, parsed_port)) = split_host_port(&host.clone()) {
        host = parsed_host.to_string();
        port = parsed_port.to_string();
    }

    if port.is_empty() {
        port = default_port_for_scheme(&scheme).to_string();
    }

    NormalizedTarget { scheme, host, port }
}

fn build_target_override(scheme: &str, host: &str, port: &str) -> Option<RequestTargetOverride> {
    let host = host.trim();
    if host.is_empty() {
        return None;
    }

    Some(RequestTargetOverride {
        scheme: scheme.trim().to_ascii_lowercase(),
        host: host.to_string(),
        port: if port.trim().is_empty() {
            default_port_for_scheme(scheme).to_string()
        } else {
            port.trim().to_string()
        },
    })
}

fn split_payload_lines(payloads_text: &str) -> Vec<String> {
    payloads_text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn read_payloads_input(
    payloads: Vec<String>,
    file: Option<PathBuf>,
    stdin: bool,
) -> Result<String> {
    if !payloads.is_empty() {
        return Ok(payloads.join("\n"));
    }

    if file.is_some() || stdin {
        return read_text_input(file, stdin);
    }

    bail!("provide payloads with --payload, --file, or --stdin")
}

fn read_lines_input(
    patterns: Vec<String>,
    file: Option<PathBuf>,
    stdin: bool,
) -> Result<Vec<String>> {
    if !patterns.is_empty() {
        return Ok(patterns);
    }
    let text = if file.is_some() || stdin {
        read_text_input(file, stdin)?
    } else {
        String::new()
    };
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

fn read_text_input(file: Option<PathBuf>, stdin: bool) -> Result<String> {
    if let Some(file) = file {
        return fs::read_to_string(&file)
            .with_context(|| format!("failed to read {}", file.display()));
    }

    if stdin {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .context("failed to read stdin")?;
        return Ok(buf);
    }

    bail!("expected --file or --stdin")
}

fn discover_api_base_url(cli_api: Option<String>) -> Result<String> {
    if let Some(api) = cli_api {
        return Ok(normalize_api_base_url(&api));
    }

    if let Ok(api) = env::var("SNIPER_API_ADDR") {
        if !api.trim().is_empty() {
            return Ok(normalize_api_base_url(&api));
        }
    }

    let data_dir = default_data_dir();
    if let Some(runtime_state) = load_runtime_state(&data_dir)? {
        return Ok(runtime_state.api_base_url());
    }

    bail!("could not discover Sniper API address; pass --api or start sniper-desktop first")
}

fn normalize_api_base_url(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    }
}

fn build_editable_raw_request(request: &EditableRequest) -> String {
    let mut headers = request.headers.clone();
    let has_host = headers
        .iter()
        .any(|header| header.name.eq_ignore_ascii_case("host"));
    if !has_host && !request.host.trim().is_empty() {
        headers.insert(
            0,
            HeaderRecord {
                name: "host".to_string(),
                value: request.host.clone(),
            },
        );
    }

    let mut lines = Vec::with_capacity(headers.len() + 2);
    let path = if request.path.trim().is_empty() {
        "/"
    } else {
        request.path.as_str()
    };
    lines.push(format!(
        "{} {} HTTP/1.1",
        request.method.trim().to_ascii_uppercase(),
        path
    ));
    lines.extend(
        headers
            .iter()
            .map(|header| format!("{}: {}", header.name, header.value)),
    );
    let head = lines.join("\n");
    if request.body.is_empty() {
        head.trim_end().to_string()
    } else {
        format!("{}\n\n{}", head, request.body)
            .trim_end()
            .to_string()
    }
}

fn parse_editable_raw_request(
    text: &str,
    fallback: Option<&EditableRequest>,
) -> Result<EditableRequest> {
    let normalized = text.replace("\r\n", "\n");
    let (head, body) = match normalized.split_once("\n\n") {
        Some((head, body)) => (head, body.to_string()),
        None => (normalized.as_str(), String::new()),
    };

    let mut lines = head.lines();
    let fallback_start_line = fallback.map(|request| {
        format!(
            "{} {} HTTP/1.1",
            request.method,
            if request.path.trim().is_empty() {
                "/"
            } else {
                request.path.as_str()
            }
        )
    });
    let start_line = lines
        .next()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .or(fallback_start_line)
        .unwrap_or_else(|| "GET / HTTP/1.1".to_string());

    let mut start_parts = start_line.split_whitespace();
    let method = start_parts
        .next()
        .map(|value| value.to_ascii_uppercase())
        .unwrap_or_else(|| "GET".to_string());
    let target = start_parts.next().unwrap_or("/");

    let mut scheme = fallback
        .map(|request| request.scheme.clone())
        .unwrap_or_else(|| "https".to_string());
    let mut host = fallback
        .map(|request| request.host.clone())
        .unwrap_or_default();
    let mut path;

    if target.starts_with("http://") || target.starts_with("https://") {
        let parsed = Url::parse(target)
            .with_context(|| format!("request target is not a valid URL: {target}"))?;
        scheme = parsed.scheme().to_ascii_lowercase();
        host = parsed
            .host_str()
            .ok_or_else(|| anyhow!("request target is missing a host"))?
            .to_string();
        if let Some(port) = parsed.port() {
            host = format!("{host}:{port}");
        }
        path = format!(
            "{}{}",
            parsed.path(),
            parsed
                .query()
                .map(|value| format!("?{value}"))
                .unwrap_or_default()
        );
    } else {
        path = target.to_string();
    }

    let headers: Vec<HeaderRecord> = lines
        .filter_map(|line| {
            let line = line.trim_end();
            if line.is_empty() {
                return None;
            }
            line.split_once(':').map(|(name, value)| HeaderRecord {
                name: name.trim().to_string(),
                value: value.trim().to_string(),
            })
        })
        .collect();

    if let Some(host_header) = headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("host"))
    {
        host = host_header.value.clone();
    }

    if host.trim().is_empty() {
        bail!("request is missing a Host header");
    }

    if !path.starts_with('/') {
        path = format!("/{path}");
    }

    Ok(EditableRequest {
        scheme,
        host,
        method,
        path,
        headers,
        body,
        body_encoding: fallback
            .map(|request| request.body_encoding.clone())
            .unwrap_or(BodyEncoding::Utf8),
        preview_truncated: false,
    })
}

fn encode_query(params: Vec<(String, String)>) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in params {
        serializer.append_pair(&key, &value);
    }
    serializer.finish()
}

fn print_json<T: Serialize>(value: &T) -> Result<()> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, value).context("failed to encode JSON output")?;
    stdout.write_all(b"\n").context("failed to write stdout")
}

fn find_replay_tab<'a>(
    replay: &'a ReplayWorkspaceState,
    tab_id: &str,
) -> Result<&'a ReplayTabState> {
    replay
        .tabs
        .iter()
        .find(|tab| tab.id == tab_id)
        .ok_or_else(|| anyhow!("replay tab not found: {tab_id}"))
}

fn find_replay_tab_mut<'a>(
    replay: &'a mut ReplayWorkspaceState,
    tab_id: &str,
) -> Result<&'a mut ReplayTabState> {
    replay
        .tabs
        .iter_mut()
        .find(|tab| tab.id == tab_id)
        .ok_or_else(|| anyhow!("replay tab not found: {tab_id}"))
}

fn split_host_port(value: &str) -> Option<(&str, &str)> {
    if value.starts_with('[') {
        return None;
    }
    let (host, port) = value.rsplit_once(':')?;
    if port.chars().all(|char| char.is_ascii_digit()) {
        Some((host, port))
    } else {
        None
    }
}

fn strip_host_port(value: &str) -> &str {
    split_host_port(value)
        .map(|(host, _)| host)
        .unwrap_or(value)
}

fn extract_port(value: &str) -> Option<String> {
    split_host_port(value).map(|(_, port)| port.to_string())
}

fn default_port_for_scheme(scheme: &str) -> u16 {
    if scheme.eq_ignore_ascii_case("http") {
        80
    } else {
        443
    }
}

fn install_skills(args: SkillsInstallArgs) -> Result<SkillsInstallResult> {
    let install_codex = args.all || args.codex;
    let install_claude = args.all || args.claude;
    if !install_codex && !install_claude {
        bail!("select at least one destination with --codex, --claude, or --all");
    }

    let mut installed = Vec::new();
    if install_codex {
        let root = args
            .codex_dir
            .clone()
            .unwrap_or_else(default_codex_skills_dir);
        let path = install_skill_folder(&root, CODEX_SKILL_NAME, CODEX_SKILL_TEMPLATE)?;
        installed.push(InstalledSkill {
            agent: "codex",
            path: path.display().to_string(),
        });
    }
    if install_claude {
        let root = args
            .claude_dir
            .clone()
            .unwrap_or_else(default_claude_skills_dir);
        let path = install_skill_folder(&root, CLAUDE_SKILL_NAME, CLAUDE_SKILL_TEMPLATE)?;
        installed.push(InstalledSkill {
            agent: "claude",
            path: path.display().to_string(),
        });
    }

    Ok(SkillsInstallResult { installed })
}

fn install_skill_folder(root: &Path, name: &str, skill_md: &str) -> Result<PathBuf> {
    fs::create_dir_all(root)
        .with_context(|| format!("failed to create skills dir {}", root.display()))?;
    let skill_dir = root.join(name);
    if skill_dir.exists() {
        fs::remove_dir_all(&skill_dir)
            .with_context(|| format!("failed to replace {}", skill_dir.display()))?;
    }
    fs::create_dir_all(&skill_dir)
        .with_context(|| format!("failed to create {}", skill_dir.display()))?;
    fs::write(skill_dir.join("SKILL.md"), skill_md)
        .with_context(|| format!("failed to write {}", skill_dir.display()))?;
    Ok(skill_dir)
}

fn default_codex_skills_dir() -> PathBuf {
    if let Some(codex_home) = env::var_os("CODEX_HOME") {
        return PathBuf::from(codex_home).join("skills");
    }
    user_home_dir().join(".codex/skills")
}

fn default_claude_skills_dir() -> PathBuf {
    if let Some(claude_home) = env::var_os("CLAUDE_HOME") {
        return PathBuf::from(claude_home).join("skills");
    }
    user_home_dir().join(".claude/skills")
}

fn user_home_dir() -> PathBuf {
    env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("USERPROFILE").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."))
}

struct NormalizedTarget {
    scheme: String,
    host: String,
    port: String,
}

#[cfg(test)]
mod tests {
    use super::{
        build_editable_raw_request, default_claude_skills_dir, default_codex_skills_dir,
        install_skill_folder, normalize_api_base_url, parse_editable_raw_request,
    };
    use sniper::model::{BodyEncoding, EditableRequest, HeaderRecord};
    use std::{fs, path::PathBuf};
    use uuid::Uuid;

    #[test]
    fn parse_raw_request_respects_host_header() {
        let request = parse_editable_raw_request(
            "GET /hello HTTP/1.1\nHost: example.com\nUser-Agent: test\n\nbody",
            None,
        )
        .unwrap();
        assert_eq!(request.method, "GET");
        assert_eq!(request.host, "example.com");
        assert_eq!(request.path, "/hello");
        assert_eq!(request.body, "body");
    }

    #[test]
    fn build_raw_request_restores_host_header() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            method: "POST".to_string(),
            path: "/submit".to_string(),
            headers: vec![HeaderRecord {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            }],
            body: "{\"ok\":true}".to_string(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let text = build_editable_raw_request(&request);
        assert!(text.contains("Host:") || text.contains("host:"));
        assert!(text.starts_with("POST /submit HTTP/1.1"));
    }

    #[test]
    fn normalize_api_base_accepts_host_port() {
        assert_eq!(
            normalize_api_base_url("127.0.0.1:19081"),
            "http://127.0.0.1:19081"
        );
    }

    #[test]
    fn codex_default_skills_dir_uses_hidden_folder() {
        let path = default_codex_skills_dir();
        assert!(path.to_string_lossy().contains(".codex/skills") || path.ends_with("skills"));
    }

    #[test]
    fn claude_default_skills_dir_uses_hidden_folder() {
        let path = default_claude_skills_dir();
        assert!(path.to_string_lossy().contains(".claude/skills") || path.ends_with("skills"));
    }

    #[test]
    fn install_skill_folder_writes_skill_markdown() {
        let root = std::env::temp_dir().join(format!("sniper-skill-test-{}", Uuid::new_v4()));
        let skill_dir = install_skill_folder(&root, "sniper-operator", "# test skill\n").unwrap();
        let skill_md = fs::read_to_string(skill_dir.join("SKILL.md")).unwrap();
        assert_eq!(skill_md, "# test skill\n");
        fs::remove_dir_all(PathBuf::from(root)).unwrap();
    }
}
