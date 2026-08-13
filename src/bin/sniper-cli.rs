use std::{
    env, fmt, fs,
    io::{self, Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{ArgAction, ArgGroup, Args, Parser, Subcommand, ValueEnum};
use reqwest::{Method, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sniper::{
    fuzzer::FuzzerAttackRecord,
    intercept::{
        InterceptRecord, InterceptRule, InterceptSummary, ResponseInterceptRecord,
        ResponseInterceptSummary,
    },
    match_replace::{MatchReplaceRule, MatchReplaceRulesPayload},
    model::{
        BodyEncoding, EditableRequest, EditableResponse, HeaderRecord, RequestTargetOverride,
        TransactionRecord, TransactionSummary, WebSocketSessionRecord, WebSocketSessionSummary,
    },
    runtime::{
        RuntimeSettingsSnapshot, MAX_OAST_POLLING_INTERVAL_SECS, MIN_OAST_POLLING_INTERVAL_SECS,
    },
    runtime_state::{load_runtime_state, remove_runtime_state_if_matches, RuntimeStateSnapshot},
    sequence::{SequenceDefinition, SequenceRunRecord, SequenceRunSummary},
    session::SessionSummary,
    skills,
    workspace::{
        FuzzerWorkspaceState, ReplayHistoryEntryState, ReplayTabState, ReplayWorkspaceState,
        WorkspaceStateSnapshot,
    },
};
use url::Url;
use uuid::Uuid;

const CLI_REPEATER_HISTORY_LIMIT: usize = 30;
const DEFAULT_WEBSOCKET_DETAIL_FRAME_LIMIT: usize = 1_000;
const MAX_WEBSOCKET_DETAIL_FRAME_LIMIT: usize = 1_000;
const MAX_CLI_INPUT_BYTES: usize = 64 * 1024 * 1024;
const SNIPER_API_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
const SNIPER_API_PROBE_RETRY_DELAYS: [std::time::Duration; 2] = [
    std::time::Duration::from_millis(150),
    std::time::Duration::from_millis(400),
];
const CLI_API_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
const SNIPER_DATA_DIR_ENV: &str = "SNIPER_DATA_DIR";
const CLI_SCHEMA_VERSION: &str = "2026-06-22";

static CLI_OUTPUT_CONTEXT: OnceLock<CliOutputContext> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum OutputFormat {
    Pretty,
    Compact,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CliSideEffect {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum SchemaKind {
    Input,
    Output,
}

struct CliOutputContext {
    format: OutputFormat,
    operation: String,
    success_envelope: bool,
}

#[derive(Parser, Debug)]
#[command(name = "sniper-cli", version = env!("CARGO_PKG_VERSION"), about = "Operate a local Sniper proxy through its JSON API.")]
struct Cli {
    #[arg(long, global = true)]
    api: Option<String>,

    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Pretty)]
    output: OutputFormat,

    /// Preview the CLI/API plan without applying a write or sending traffic.
    #[arg(long, global = true, conflicts_with = "yes")]
    dry_run: bool,

    /// Confirm a side-effecting operation that can delete, forward, or send traffic.
    #[arg(long, global = true)]
    yes: bool,

    #[command(subcommand)]
    command: Command,
}

fn parse_nonzero_usize(value: &str) -> std::result::Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|error| format!("invalid limit: {error}"))?;
    if parsed == 0 {
        Err("limit must be greater than zero".to_string())
    } else {
        Ok(parsed)
    }
}

fn parse_oast_polling_interval(value: &str) -> std::result::Result<u64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|error| format!("invalid OAST polling interval: {error}"))?;
    if !(MIN_OAST_POLLING_INTERVAL_SECS..=MAX_OAST_POLLING_INTERVAL_SECS).contains(&parsed) {
        Err(format!(
            "OAST polling interval must be between {} and {} seconds",
            MIN_OAST_POLLING_INTERVAL_SECS, MAX_OAST_POLLING_INTERVAL_SECS
        ))
    } else {
        Ok(parsed)
    }
}

#[derive(Subcommand, Debug)]
enum Command {
    Manifest,
    Schema {
        #[arg(value_enum)]
        kind: SchemaKind,
        operation: String,
    },
    Examples {
        operation: String,
    },
    /// Invoke an operation by canonical manifest name.
    Call(CallArgs),
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
    Sequence {
        #[command(subcommand)]
        command: SequenceCommand,
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

#[derive(Args, Debug)]
struct CallArgs {
    operation: String,
    /// JSON object, @file path, or - for stdin. Omit for {}.
    #[arg(long)]
    input: Option<String>,
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
    #[command(name = "response-intercept")]
    ResponseIntercept {
        #[command(subcommand)]
        command: ResponseInterceptCommand,
    },
    #[command(name = "intercept-rule")]
    InterceptRule {
        #[command(subcommand)]
        command: InterceptRuleCommand,
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
    Oast {
        #[command(subcommand)]
        command: OastCommand,
    },
}

#[derive(Subcommand, Debug)]
enum SessionCommand {
    List,
    Create(CreateSessionArgs),
    Switch(SessionSwitchArgs),
    Delete(SessionDeleteArgs),
    Reveal(SessionRevealArgs),
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

#[derive(Args, Debug)]
struct SessionDeleteArgs {
    #[arg(long)]
    id: Uuid,
}

#[derive(Args, Debug)]
struct SessionRevealArgs {
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
    session_id: Option<Uuid>,
    #[arg(long)]
    query: Option<String>,
    #[arg(long)]
    method: Option<String>,
    #[arg(long, value_parser = parse_nonzero_usize)]
    limit: Option<usize>,
    /// Return rows after this zero-based offset. Uses the paged history API.
    #[arg(long, conflicts_with = "before_sequence")]
    offset: Option<usize>,
    /// Return rows older than this capture sequence. Uses stable cursor paging.
    #[arg(long, conflicts_with = "offset")]
    before_sequence: Option<u64>,
    /// Include pagination metadata instead of the legacy array-only output.
    #[arg(long)]
    page: bool,
    /// Filter by host (substring match)
    #[arg(long)]
    host: Option<String>,
    /// Filter by exact HTTP status code
    #[arg(long, value_parser = clap::value_parser!(u16).range(100..=599))]
    status: Option<u16>,
    /// Filter by status range, e.g. "4xx" or "200-299"
    #[arg(long)]
    status_range: Option<String>,
    /// Filter by time, e.g. "2024-01-01" or "1h" (relative)
    #[arg(long)]
    since: Option<String>,
    /// Filter by response MIME type (substring match), e.g. "json" or "text/html"
    #[arg(long)]
    mime: Option<String>,
    /// Sort key for paged history output, e.g. index, host, method, path, status, length, mime, notes, tls, started_at.
    #[arg(long, value_parser = ["index", "host", "method", "path", "status", "length", "mime", "notes", "tls", "edited", "started_at"])]
    sort_key: Option<String>,
    /// Sort direction for paged history output.
    #[arg(long, value_parser = ["asc", "desc"])]
    sort_direction: Option<String>,
}

#[derive(Args, Debug)]
struct HistoryGetArgs {
    #[arg(long)]
    id: Uuid,
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug, Default)]
struct HistoryReplayArgs {
    #[arg(long)]
    id: Uuid,
    #[arg(long)]
    session_id: Option<Uuid>,
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
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long)]
    scheme: Option<String>,
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    port: Option<String>,
}

#[derive(Args, Debug)]
struct HistoryAnnotateArgs {
    #[arg(long)]
    id: Uuid,
    #[arg(long)]
    session_id: Option<Uuid>,
    /// Set color tag (e.g. red, orange, yellow, green, blue, purple). Use --clear-color to remove.
    #[arg(long, conflicts_with = "clear_color")]
    color: Option<String>,
    /// Remove the color tag.
    #[arg(long, conflicts_with = "color")]
    clear_color: bool,
    /// Set a user note on the transaction.
    #[arg(long, conflicts_with = "clear_note")]
    note: Option<String>,
    /// Remove the user note.
    #[arg(long, conflicts_with = "note")]
    clear_note: bool,
}

#[derive(Subcommand, Debug)]
enum TargetCommand {
    GetScope(TargetSessionArgs),
    SetScope(TargetSetScopeArgs),
}

#[derive(Args, Debug, Default)]
struct TargetSessionArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug, Default)]
#[command(group(
    ArgGroup::new("scope_source")
        .args(["patterns", "file", "stdin", "clear"])
        .multiple(false)
        .required(true)
))]
struct TargetSetScopeArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    /// Clear all scope patterns.
    #[arg(long)]
    clear: bool,
    #[arg(long = "pattern", action = ArgAction::Append)]
    patterns: Vec<String>,
    #[arg(long)]
    file: Option<PathBuf>,
    #[arg(long)]
    stdin: bool,
}

#[derive(Subcommand, Debug)]
enum ReplayCommand {
    List(ReplayListArgs),
    Open(ReplayOpenArgs),
    Update(ReplayUpdateArgs),
    Send(ReplaySendArgs),
}

#[derive(Args, Debug, Default)]
struct ReplayListArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug, Default)]
#[command(group(
    ArgGroup::new("request_source")
        .args(["transaction_id", "request_file", "stdin"])
        .multiple(false)
))]
struct ReplayOpenArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
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
#[command(
    group(
        ArgGroup::new("request_source")
            .args(["request_file", "stdin"])
            .multiple(false)
    ),
    group(
        ArgGroup::new("target_update")
            .args(["scheme", "host", "port"])
            .multiple(true)
    ),
    group(
        ArgGroup::new("update_input")
            .args(["request_file", "stdin", "scheme", "host", "port"])
            .required(true)
            .multiple(true)
    )
)]
struct ReplayUpdateArgs {
    #[arg(long)]
    tab_id: String,
    #[arg(long)]
    session_id: Option<Uuid>,
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
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Subcommand, Debug)]
enum FuzzerCommand {
    SetTemplate(FuzzerSetTemplateArgs),
    SetPayloads(FuzzerSetPayloadsArgs),
    Run(FuzzerRunArgs),
    /// Show fuzzer attack status by ID
    Status(FuzzerStatusArgs),
    /// Show fuzzer attack results by ID
    Results(FuzzerResultsArgs),
    /// List past fuzzer attacks
    List(FuzzerListArgs),
}

#[derive(Args, Debug, Default)]
struct FuzzerRunArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    /// Mark async intent in output; the current Sniper API still returns after completion
    #[arg(long, alias = "async")]
    r#async: bool,
}

#[derive(Args, Debug)]
struct FuzzerStatusArgs {
    #[arg(long)]
    id: Uuid,
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug)]
struct FuzzerResultsArgs {
    #[arg(long)]
    id: Uuid,
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug, Default)]
struct FuzzerListArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long, value_parser = parse_nonzero_usize)]
    limit: Option<usize>,
}

#[derive(Args, Debug, Default)]
#[command(group(
    ArgGroup::new("request_source")
        .args(["transaction_id", "request_file", "stdin"])
        .required(true)
        .multiple(false)
))]
struct FuzzerSetTemplateArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
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
#[command(group(
    ArgGroup::new("payload_source")
        .args(["payloads", "file", "stdin"])
        .required(true)
        .multiple(false)
))]
struct FuzzerSetPayloadsArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long = "payload", action = ArgAction::Append)]
    payloads: Vec<String>,
    #[arg(long)]
    file: Option<PathBuf>,
    #[arg(long)]
    stdin: bool,
}

#[derive(Subcommand, Debug)]
enum InterceptCommand {
    On(InterceptSessionArgs),
    Off(InterceptSessionArgs),
    List(InterceptSessionArgs),
    Forward(InterceptForwardArgs),
    Drop(InterceptDropArgs),
    #[command(name = "forward-all")]
    ForwardAll(InterceptSessionArgs),
}

#[derive(Args, Debug, Default)]
struct InterceptSessionArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug, Default)]
#[command(group(
    ArgGroup::new("request_source")
        .args(["request_file", "stdin"])
        .multiple(false)
))]
struct InterceptForwardArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
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
    session_id: Option<Uuid>,
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
    List(AutoReplaceSessionArgs),
    Set(AutoReplaceSetArgs),
}

#[derive(Args, Debug, Default)]
struct AutoReplaceSessionArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Subcommand, Debug)]
enum OastCommand {
    /// Show OAST registration status and provider info
    Status(OastSessionArgs),
    /// List received OAST callbacks
    List(OastListArgs),
    /// Get full details of a specific callback
    Get(OastGetArgs),
    /// Generate a new OAST payload
    Generate(OastSessionArgs),
    /// Clear all OAST callbacks
    Clear(OastSessionArgs),
    /// Configure OAST provider settings
    Configure(OastConfigureArgs),
}

#[derive(Args, Debug, Default)]
struct OastSessionArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug, Default)]
struct OastListArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long, value_parser = parse_nonzero_usize)]
    limit: Option<usize>,
}

#[derive(Args, Debug)]
struct OastGetArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long)]
    id: Uuid,
}

#[derive(Args, Debug, Default)]
struct OastConfigureArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    /// Provider: interactsh, boast, or custom
    #[arg(long, value_parser = ["interactsh", "boast", "custom"])]
    provider: Option<String>,
    /// OAST server URL
    #[arg(long)]
    url: Option<String>,
    /// Deprecated unsafe token argv path. Use --token-stdin instead.
    #[arg(long, hide = true, conflicts_with = "token_stdin")]
    token: Option<String>,
    /// Read the authentication token from stdin.
    #[arg(long, conflicts_with = "token")]
    token_stdin: bool,
    /// Polling interval in seconds
    #[arg(long, value_parser = parse_oast_polling_interval)]
    interval: Option<u64>,
    /// Enable OAST
    #[arg(long, conflicts_with = "disable")]
    enable: bool,
    /// Disable OAST
    #[arg(long, conflicts_with = "enable")]
    disable: bool,
}

#[derive(Args, Debug, Default)]
struct WebSocketListArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long)]
    query: Option<String>,
    #[arg(long, value_parser = parse_nonzero_usize)]
    limit: Option<usize>,
    #[arg(long)]
    offset: Option<usize>,
    #[arg(long, value_parser = ["index", "host", "path", "status", "frame_count", "duration_ms", "started_at"])]
    sort_key: Option<String>,
    #[arg(long, value_parser = ["asc", "desc"])]
    sort_direction: Option<String>,
    #[arg(long)]
    in_scope_only: bool,
    #[arg(long)]
    live_only: bool,
    /// Include pagination metadata instead of printing the legacy array shape.
    #[arg(long)]
    page: bool,
}

#[derive(Args, Debug)]
struct WebSocketGetArgs {
    #[arg(long)]
    id: Uuid,
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long)]
    frame_limit: Option<usize>,
    #[arg(long)]
    before_index: Option<usize>,
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
#[command(group(
    ArgGroup::new("rules_source")
        .args(["file", "stdin"])
        .multiple(false)
        .required(true)
))]
struct AutoReplaceSetArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long)]
    file: Option<PathBuf>,
    #[arg(long)]
    stdin: bool,
}

#[derive(Subcommand, Debug)]
enum ResponseInterceptCommand {
    List(ResponseInterceptSessionArgs),
    Get(ResponseInterceptGetArgs),
    Forward(ResponseInterceptForwardArgs),
    Drop(ResponseInterceptDropArgs),
    #[command(name = "forward-all")]
    ForwardAll(ResponseInterceptSessionArgs),
}

#[derive(Args, Debug, Default)]
struct ResponseInterceptSessionArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug)]
struct ResponseInterceptGetArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long)]
    id: Uuid,
}

#[derive(Args, Debug)]
#[command(group(
    ArgGroup::new("response_source")
        .args(["response_file", "stdin"])
        .multiple(false)
))]
struct ResponseInterceptForwardArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long)]
    id: Uuid,
    #[arg(long)]
    response_file: Option<PathBuf>,
    #[arg(long)]
    stdin: bool,
}

#[derive(Args, Debug)]
struct ResponseInterceptDropArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long)]
    id: Uuid,
}

#[derive(Subcommand, Debug)]
enum InterceptRuleCommand {
    List(InterceptRuleSessionArgs),
    Create(InterceptRuleCreateArgs),
    Delete(InterceptRuleDeleteArgs),
}

#[derive(Args, Debug, Default)]
struct InterceptRuleSessionArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug)]
#[command(group(
    ArgGroup::new("matcher")
        .args(["host_pattern", "path_pattern", "method_filter", "all"])
        .multiple(true)
        .required(true)
))]
struct InterceptRuleCreateArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long, default_value = "both", value_parser = ["request", "response", "both"])]
    scope: String,
    /// Create a rule that matches all traffic. Required when no matcher is supplied.
    #[arg(long, conflicts_with_all = ["host_pattern", "path_pattern", "method_filter"])]
    all: bool,
    #[arg(long)]
    host_pattern: Option<String>,
    #[arg(long)]
    path_pattern: Option<String>,
    #[arg(long = "method", action = ArgAction::Append)]
    method_filter: Vec<String>,
    #[arg(long)]
    enabled: Option<bool>,
}

#[derive(Args, Debug)]
struct InterceptRuleDeleteArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long)]
    id: Uuid,
}

#[derive(Subcommand, Debug)]
enum SequenceCommand {
    List(SequenceListArgs),
    Get(SequenceGetArgs),
    Create(SequenceCreateArgs),
    Run(SequenceRunArgs),
    #[command(name = "run-get")]
    RunGet(SequenceRunGetArgs),
    Delete(SequenceDeleteArgs),
    Runs(SequenceRunsArgs),
}

#[derive(Args, Debug, Default)]
struct SequenceListArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug)]
struct SequenceGetArgs {
    #[arg(long)]
    id: Uuid,
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug)]
#[command(group(
    ArgGroup::new("sequence_source")
        .args(["file", "stdin"])
        .multiple(false)
        .required(true)
))]
struct SequenceCreateArgs {
    #[arg(long)]
    file: Option<PathBuf>,
    #[arg(long)]
    stdin: bool,
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug)]
struct SequenceRunArgs {
    #[arg(long)]
    id: Uuid,
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug)]
struct SequenceRunGetArgs {
    #[arg(long)]
    id: Uuid,
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug)]
struct SequenceDeleteArgs {
    #[arg(long)]
    id: Uuid,
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug, Default)]
struct SequenceRunsArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long, value_parser = parse_nonzero_usize)]
    limit: Option<usize>,
}

#[derive(Serialize)]
struct ResponseInterceptForwardPayload {
    response: EditableResponse,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AutoReplaceInput {
    Rules(Vec<MatchReplaceRule>),
    Payload(AutoReplaceRulesInput),
}

#[derive(Deserialize)]
struct AutoReplaceRulesInput {
    #[serde(default)]
    session_id: Option<Uuid>,
    rules: Vec<MatchReplaceRule>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum HistoryListResponse {
    Items(Vec<TransactionSummary>),
    Page {
        items: Vec<TransactionSummary>,
        #[serde(default)]
        total: Option<usize>,
        #[serde(default)]
        filtered_total: Option<usize>,
        #[serde(default)]
        hidden_connect_total: Option<usize>,
        #[serde(default)]
        offset: Option<usize>,
        #[serde(default)]
        limit: Option<usize>,
        #[serde(default)]
        has_more: Option<bool>,
    },
}

impl HistoryListResponse {
    fn into_cli_output(self, include_page: bool) -> serde_json::Value {
        match self {
            Self::Items(items) if include_page => serde_json::json!({
                "items": items,
                "total": null,
                "filtered_total": null,
                "hidden_connect_total": null,
                "offset": null,
                "limit": null,
                "has_more": null,
            }),
            Self::Items(items) => serde_json::json!(items),
            Self::Page {
                items,
                total,
                filtered_total,
                hidden_connect_total,
                offset,
                limit,
                has_more,
            } if include_page => serde_json::json!({
                "items": items,
                "total": total,
                "filtered_total": filtered_total,
                "hidden_connect_total": hidden_connect_total,
                "offset": offset,
                "limit": limit,
                "has_more": has_more,
            }),
            Self::Page { items, .. } => serde_json::json!(items),
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum WebSocketListResponse {
    Items(Vec<WebSocketSessionSummary>),
    Page {
        items: Vec<WebSocketSessionSummary>,
        #[serde(default)]
        total: Option<usize>,
        #[serde(default)]
        filtered_total: Option<usize>,
        #[serde(default)]
        limit: Option<usize>,
        #[serde(default)]
        offset: Option<usize>,
        #[serde(default)]
        has_more: Option<bool>,
    },
}

impl WebSocketListResponse {
    fn into_cli_output(self, include_page: bool) -> serde_json::Value {
        match self {
            Self::Items(items) if include_page => serde_json::json!({
                "items": items,
                "total": null,
                "filtered_total": null,
                "limit": null,
                "offset": null,
                "has_more": null,
            }),
            Self::Items(items) => serde_json::json!(items),
            Self::Page {
                items,
                total,
                filtered_total,
                limit,
                offset,
                has_more,
            } if include_page => serde_json::json!({
                "items": items,
                "total": total,
                "filtered_total": filtered_total,
                "limit": limit,
                "offset": offset,
                "has_more": has_more,
            }),
            Self::Page { items, .. } => serde_json::json!(items),
        }
    }
}

#[derive(Debug, Deserialize)]
struct StructuredApiErrorBody {
    error: Option<String>,
    session_id: Option<Uuid>,
    owner_session_id: Option<Uuid>,
}

fn api_failure_detail(status: StatusCode, message: String) -> String {
    if message.trim().is_empty() {
        return status.to_string();
    }
    if let Ok(body) = serde_json::from_str::<StructuredApiErrorBody>(&message) {
        if let Some(error) = body.error.filter(|value| !value.trim().is_empty()) {
            if let Some(owner_session_id) = body.owner_session_id {
                return format!("{error} (owner_session_id {owner_session_id})");
            }
            if let Some(session_id) = body.session_id {
                return format!("{error} (session_id {session_id})");
            }
            return error;
        }
    }
    message
}

#[derive(Clone)]
struct ApiClient {
    base_url: String,
    client: reqwest::Client,
    long_client: reqwest::Client,
}

impl ApiClient {
    async fn discover(cli_api: Option<String>) -> Result<Self> {
        let probe_client = reqwest::Client::builder()
            .no_proxy()
            .timeout(CLI_API_TIMEOUT)
            .build()
            .context("failed to build sniper-cli discovery HTTP client")?;
        let base_url = discover_api_base_url(cli_api, &probe_client).await?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(CLI_API_TIMEOUT)
            .build()
            .context("failed to build sniper-cli HTTP client")?;
        let long_client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .context("failed to build sniper-cli long-running HTTP client")?;
        Ok(Self {
            base_url,
            client,
            long_client,
        })
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

    async fn post_json_or_no_content<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<Option<T>> {
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
            let detail = api_failure_detail(status, message);
            bail!("request to {} failed ({}): {}", path, status, detail);
        }
        if status == StatusCode::NO_CONTENT {
            return Ok(None);
        }
        response
            .json::<T>()
            .await
            .map(Some)
            .with_context(|| format!("failed to decode JSON response from {}", path))
    }

    async fn post_json_long<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        self.request_json_with_client(&self.long_client, Method::POST, path, Some(body))
            .await
    }

    async fn send_replay(&self, payload: &ReplaySendPayload) -> Result<ReplaySendApiResult> {
        let path = "/api/replay/send";
        let response = self
            .long_client
            .post(self.url(path))
            .json(payload)
            .send()
            .await
            .with_context(|| format!("failed to POST {}", path))?;
        let status = response.status();
        if status.is_success() {
            return response
                .json::<TransactionRecord>()
                .await
                .map(ReplaySendApiResult::Success)
                .with_context(|| format!("failed to decode JSON response from {}", path));
        }
        if status == StatusCode::BAD_REQUEST {
            let message = response.text().await.unwrap_or_else(|_| String::new());
            let body = match serde_json::from_str::<ReplaySendErrorBody>(&message) {
                Ok(body) => body,
                Err(_) => {
                    let detail = api_failure_detail(status, message);
                    bail!("request to {} failed ({}): {}", path, status, detail);
                }
            };
            if body.record.is_some() {
                return Ok(ReplaySendApiResult::StoredError(body));
            }
            bail!("request to {} failed ({}): {}", path, status, body.error);
        }
        if status == StatusCode::CONFLICT {
            let message = response.text().await.unwrap_or_else(|_| String::new());
            bail!("{}", workspace_state_conflict_detail(path, status, message));
        }
        let message = response.text().await.unwrap_or_else(|_| String::new());
        let detail = api_failure_detail(status, message);
        bail!("request to {} failed ({}): {}", path, status, detail);
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
            let detail = api_failure_detail(status, message);
            bail!("request to {} failed ({}): {}", path, status, detail);
        }
        Ok(status)
    }

    async fn delete_status(&self, path: &str) -> Result<StatusCode> {
        let response = self
            .client
            .delete(self.url(path))
            .send()
            .await
            .with_context(|| format!("failed to DELETE {}", path))?;
        let status = response.status();
        if !status.is_success() {
            let message = response.text().await.unwrap_or_else(|_| String::new());
            let detail = api_failure_detail(status, message);
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
        self.send_json_request(request, method, path, body).await
    }

    async fn request_json_with_client<B: Serialize, T: DeserializeOwned>(
        &self,
        client: &reqwest::Client,
        method: Method,
        path: &str,
        body: Option<B>,
    ) -> Result<T> {
        let request = client.request(method.clone(), self.url(path));
        self.send_json_request(request, method, path, body).await
    }

    async fn send_json_request<B: Serialize, T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
        method: Method,
        path: &str,
        body: Option<B>,
    ) -> Result<T> {
        let response = match body {
            Some(body) => request.json(&body).send().await,
            None => request.send().await,
        }
        .with_context(|| format!("failed to {} {}", method, path))?;

        let status = response.status();
        if !status.is_success() {
            let message = response.text().await.unwrap_or_else(|_| String::new());
            let detail = api_failure_detail(status, message);
            bail!("request to {} failed ({}): {}", path, status, detail);
        }

        response
            .json::<T>()
            .await
            .with_context(|| format!("failed to decode JSON response from {}", path))
    }

    fn url(&self, path: &str) -> Url {
        api_url(&self.base_url, path).expect("API base URL should be normalized")
    }
}

const CLI_WORKSPACE_CLIENT_ID: &str = "sniper-cli";

async fn post_workspace_state(
    api: &ApiClient,
    workspace: &mut WorkspaceStateSnapshot,
    explicit_session_id: Option<Uuid>,
) -> Result<WorkspaceStateSnapshot> {
    const PATH: &str = "/api/workspace-state";
    prepare_cli_workspace_save(workspace, explicit_session_id);
    let response = api
        .client
        .post(api.url(PATH))
        .json(workspace)
        .send()
        .await
        .context("failed to POST workspace state")?;
    let status = response.status();
    if status == StatusCode::CONFLICT {
        let message = response.text().await.unwrap_or_else(|_| String::new());
        bail!("{}", workspace_state_conflict_detail(PATH, status, message));
    }
    if !status.is_success() {
        let message = response.text().await.unwrap_or_else(|_| String::new());
        let detail = if message.trim().is_empty() {
            status.to_string()
        } else {
            message
        };
        bail!("request to {} failed ({}): {}", PATH, status, detail);
    }
    response
        .json::<WorkspaceStateSnapshot>()
        .await
        .context("failed to decode JSON response from workspace state")
}

fn workspace_conflict_message(current: &WorkspaceStateSnapshot) -> String {
    let session = current
        .session_id
        .map(|id| id.to_string())
        .unwrap_or_else(|| "none".to_string());
    let client = current.client_id.as_deref().unwrap_or("none");
    format!(
        "workspace state revision conflict: current revision {}, session_id {}, client_id {}, client_version {}; reload workspace state and retry",
        current.revision, session, client, current.client_version,
    )
}

fn workspace_state_conflict_detail(path: &str, status: StatusCode, message: String) -> String {
    if let Ok(body) = serde_json::from_str::<StructuredApiErrorBody>(&message) {
        if body
            .error
            .as_deref()
            .is_some_and(|error| !error.trim().is_empty())
        {
            return format!(
                "request to {} failed ({}): {}",
                path,
                status,
                api_failure_detail(status, message)
            );
        }
    }
    if let Ok(current) = serde_json::from_str::<WorkspaceStateSnapshot>(&message) {
        return workspace_conflict_message(&current);
    }
    format!(
        "request to {} failed ({}): {}",
        path,
        status,
        api_failure_detail(status, message)
    )
}

async fn load_workspace_state(
    api: &ApiClient,
    explicit_session_id: Option<Uuid>,
) -> Result<WorkspaceStateSnapshot> {
    let session_id = resolve_session_id_arg(api, explicit_session_id).await?;
    api.get_json(&session_query_path("/api/workspace-state", session_id))
        .await
}

fn prepare_cli_workspace_save(
    workspace: &mut WorkspaceStateSnapshot,
    explicit_session_id: Option<Uuid>,
) {
    workspace.expected_active_session_id = if explicit_session_id.is_none() {
        workspace.session_id
    } else {
        None
    };
    workspace.client_id = Some(CLI_WORKSPACE_CLIENT_ID.to_string());
    workspace.client_version = workspace.client_version.saturating_add(1).max(1);
}

fn expected_active_session_for_implicit_write(
    workspace: &WorkspaceStateSnapshot,
    explicit_session_id: Option<Uuid>,
) -> Option<Uuid> {
    explicit_session_id
        .is_none()
        .then_some(workspace.session_id)
        .flatten()
}

async fn runtime_write_session_ids(
    api: &ApiClient,
    explicit_session_id: Option<Uuid>,
) -> Result<(Option<Uuid>, Option<Uuid>)> {
    if let Some(session_id) = explicit_session_id {
        return Ok((Some(session_id), None));
    }
    let active_session_id = active_session_id(api).await?;
    Ok((active_session_id, active_session_id))
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
    session_id: Option<Uuid>,
}

#[derive(Serialize)]
struct RuntimeUpdatePayload {
    session_id: Option<Uuid>,
    expected_active_session_id: Option<Uuid>,
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
    session_id: Option<Uuid>,
    expected_active_session_id: Option<Uuid>,
    expected_workspace_revision: Option<u64>,
    request: EditableRequest,
    target: Option<RequestTargetOverride>,
    source_transaction_id: Option<Uuid>,
    http_version: Option<String>,
}

enum ReplaySendApiResult {
    Success(TransactionRecord),
    StoredError(ReplaySendErrorBody),
}

#[derive(Deserialize)]
struct ReplaySendErrorBody {
    error: String,
    record: Option<TransactionRecord>,
}

#[derive(Serialize)]
struct FuzzerRunPayload {
    session_id: Option<Uuid>,
    expected_active_session_id: Option<Uuid>,
    expected_workspace_revision: Option<u64>,
    template: EditableRequest,
    payloads: Vec<String>,
    source_transaction_id: Option<Uuid>,
    http_version: Option<String>,
    target: Option<RequestTargetOverride>,
}

#[derive(Serialize)]
struct SequenceRunPayload {
    session_id: Option<Uuid>,
    expected_active_session_id: Option<Uuid>,
}

#[derive(Serialize)]
struct SequenceUpsertPayload<'a> {
    session_id: Option<Uuid>,
    expected_active_session_id: Option<Uuid>,
    #[serde(flatten)]
    definition: &'a SequenceDefinition,
}

#[derive(Deserialize)]
struct SequenceCreateInput {
    session_id: Option<Uuid>,
    #[serde(flatten)]
    definition: SequenceDefinition,
}

#[derive(Serialize)]
struct InterceptForwardPayload {
    request: EditableRequest,
}

#[derive(Clone, Debug, Serialize)]
struct CliOperationSpec {
    operation: &'static str,
    command: &'static str,
    description: &'static str,
    side_effect: CliSideEffect,
    requires_confirmation: bool,
    input_schema: Value,
    output_schema: Value,
    examples: Vec<Value>,
}

impl Command {
    fn operation_name(&self) -> &'static str {
        match self {
            Command::Manifest => "manifest",
            Command::Schema { .. } => "schema",
            Command::Examples { .. } => "examples",
            Command::Call { .. } => "call",
            Command::Session { command } => command.operation_name(),
            Command::Capture { command } => command.operation_name(),
            Command::Scope { command } => command.operation_name(),
            Command::Replay { command } => command.operation_name(),
            Command::Fuzzer { command } => command.operation_name(),
            Command::Sequence { command } => command.operation_name(),
            Command::Skills { command } => command.operation_name(),
            Command::History { command } => command.operation_name(),
            Command::Intercept { command } => command.operation_name(),
            Command::Websocket { command } => command.operation_name(),
            Command::AutoReplace { command } => command.operation_name(),
        }
    }

    fn requires_confirmation(&self) -> bool {
        operation_spec(self.operation_name())
            .map(|spec| spec.requires_confirmation)
            .unwrap_or(false)
    }

    fn output_operation_name(&self) -> String {
        match self {
            Command::Call(args) => args.operation.clone(),
            _ => self.operation_name().to_string(),
        }
    }
}

impl SessionCommand {
    fn operation_name(&self) -> &'static str {
        match self {
            SessionCommand::List => "session.list",
            SessionCommand::Create(_) => "session.create",
            SessionCommand::Switch(_) => "session.switch",
            SessionCommand::Delete(_) => "session.delete",
            SessionCommand::Reveal(_) => "session.reveal",
        }
    }
}

impl CaptureCommand {
    fn operation_name(&self) -> &'static str {
        match self {
            CaptureCommand::Http { command } => command.operation_name(),
            CaptureCommand::Intercept { command } => command.operation_name(),
            CaptureCommand::ResponseIntercept { command } => command.operation_name(),
            CaptureCommand::InterceptRule { command } => command.operation_name(),
            CaptureCommand::WebSocket { command } => command.operation_name(),
            CaptureCommand::AutoReplace { command } => command.operation_name(),
            CaptureCommand::Oast { command } => command.operation_name(),
        }
    }
}

impl HistoryCommand {
    fn operation_name(&self) -> &'static str {
        match self {
            HistoryCommand::List(_) => "capture.http.list",
            HistoryCommand::Get(_) => "capture.http.get",
            HistoryCommand::Replay(_) => "capture.http.replay",
            HistoryCommand::Fuzzer(_) => "capture.http.fuzzer",
            HistoryCommand::Annotate(_) => "capture.http.annotate",
        }
    }
}

impl TargetCommand {
    fn operation_name(&self) -> &'static str {
        match self {
            TargetCommand::GetScope(_) => "scope.get",
            TargetCommand::SetScope(_) => "scope.set",
        }
    }
}

impl ReplayCommand {
    fn operation_name(&self) -> &'static str {
        match self {
            ReplayCommand::List(_) => "replay.list",
            ReplayCommand::Open(_) => "replay.open",
            ReplayCommand::Update(_) => "replay.update",
            ReplayCommand::Send(_) => "replay.send",
        }
    }
}

impl FuzzerCommand {
    fn operation_name(&self) -> &'static str {
        match self {
            FuzzerCommand::SetTemplate(_) => "fuzzer.set_template",
            FuzzerCommand::SetPayloads(_) => "fuzzer.set_payloads",
            FuzzerCommand::Run(_) => "fuzzer.run",
            FuzzerCommand::Status(_) => "fuzzer.status",
            FuzzerCommand::Results(_) => "fuzzer.results",
            FuzzerCommand::List(_) => "fuzzer.list",
        }
    }
}

impl InterceptCommand {
    fn operation_name(&self) -> &'static str {
        match self {
            InterceptCommand::On(_) => "capture.intercept.on",
            InterceptCommand::Off(_) => "capture.intercept.off",
            InterceptCommand::List(_) => "capture.intercept.list",
            InterceptCommand::Forward(_) => "capture.intercept.forward",
            InterceptCommand::Drop(_) => "capture.intercept.drop",
            InterceptCommand::ForwardAll(_) => "capture.intercept.forward_all",
        }
    }
}

impl WebSocketCommand {
    fn operation_name(&self) -> &'static str {
        match self {
            WebSocketCommand::List(_) => "capture.websocket.list",
            WebSocketCommand::Get(_) => "capture.websocket.get",
        }
    }
}

impl AutoReplaceCommand {
    fn operation_name(&self) -> &'static str {
        match self {
            AutoReplaceCommand::List(_) => "capture.auto_replace.list",
            AutoReplaceCommand::Set(_) => "capture.auto_replace.set",
        }
    }
}

impl ResponseInterceptCommand {
    fn operation_name(&self) -> &'static str {
        match self {
            ResponseInterceptCommand::List(_) => "capture.response_intercept.list",
            ResponseInterceptCommand::Get(_) => "capture.response_intercept.get",
            ResponseInterceptCommand::Forward(_) => "capture.response_intercept.forward",
            ResponseInterceptCommand::Drop(_) => "capture.response_intercept.drop",
            ResponseInterceptCommand::ForwardAll(_) => "capture.response_intercept.forward_all",
        }
    }
}

impl InterceptRuleCommand {
    fn operation_name(&self) -> &'static str {
        match self {
            InterceptRuleCommand::List(_) => "capture.intercept_rule.list",
            InterceptRuleCommand::Create(_) => "capture.intercept_rule.create",
            InterceptRuleCommand::Delete(_) => "capture.intercept_rule.delete",
        }
    }
}

impl SequenceCommand {
    fn operation_name(&self) -> &'static str {
        match self {
            SequenceCommand::List(_) => "sequence.list",
            SequenceCommand::Get(_) => "sequence.get",
            SequenceCommand::Create(_) => "sequence.create",
            SequenceCommand::Run(_) => "sequence.run",
            SequenceCommand::RunGet(_) => "sequence.run_get",
            SequenceCommand::Delete(_) => "sequence.delete",
            SequenceCommand::Runs(_) => "sequence.runs",
        }
    }
}

impl OastCommand {
    fn operation_name(&self) -> &'static str {
        match self {
            OastCommand::Status(_) => "capture.oast.status",
            OastCommand::List(_) => "capture.oast.list",
            OastCommand::Get(_) => "capture.oast.get",
            OastCommand::Generate(_) => "capture.oast.generate",
            OastCommand::Clear(_) => "capture.oast.clear",
            OastCommand::Configure(_) => "capture.oast.configure",
        }
    }
}

impl SkillsCommand {
    fn operation_name(&self) -> &'static str {
        match self {
            SkillsCommand::Install(_) => "skills.install",
        }
    }
}

fn manifest_operations() -> Vec<CliOperationSpec> {
    use CliSideEffect::{Read, Write};
    vec![
        op(
            "manifest",
            "manifest",
            "Print the AI-readable Sniper CLI operation catalog.",
            Read,
            false,
            &[],
            vec![json!({})],
        ),
        op(
            "schema",
            "schema <input|output> <operation>",
            "Print the JSON schema for one Sniper CLI operation.",
            Read,
            false,
            &["kind", "operation"],
            vec![json!({"operation":"replay.send","kind":"input"})],
        ),
        op(
            "examples",
            "examples <operation>",
            "Print example inputs for one Sniper CLI operation.",
            Read,
            false,
            &["operation"],
            vec![json!({"operation":"capture.http.list"})],
        ),
        op(
            "skills.install",
            "skills install",
            "Install Sniper operator skills into Codex and/or Claude.",
            Write,
            false,
            &[],
            vec![json!({"all":true})],
        ),
        op(
            "session.list",
            "session list",
            "List Sniper sessions.",
            Read,
            false,
            &[],
            vec![json!({})],
        ),
        op(
            "session.create",
            "session create",
            "Create a Sniper session.",
            Write,
            false,
            &[],
            vec![json!({"name":"test session"})],
        ),
        op(
            "session.switch",
            "session switch --id <uuid>",
            "Switch the active Sniper session.",
            Write,
            false,
            &["id"],
            vec![json!({"id":"00000000-0000-0000-0000-000000000000"})],
        ),
        op(
            "session.delete",
            "session delete --id <uuid>",
            "Delete a Sniper session.",
            Write,
            true,
            &["id"],
            vec![json!({"id":"00000000-0000-0000-0000-000000000000"})],
        ),
        op(
            "session.reveal",
            "session reveal --id <uuid>",
            "Reveal a session folder in Finder.",
            Write,
            false,
            &["id"],
            vec![json!({"id":"00000000-0000-0000-0000-000000000000"})],
        ),
        op(
            "capture.http.list",
            "capture http list",
            "List captured HTTP transactions.",
            Read,
            false,
            &[],
            vec![json!({"limit":20,"page":true})],
        ),
        op(
            "capture.http.get",
            "capture http get --id <uuid>",
            "Get one captured HTTP transaction.",
            Read,
            false,
            &["id"],
            vec![json!({"id":"00000000-0000-0000-0000-000000000000"})],
        ),
        op(
            "capture.http.replay",
            "capture http replay --id <uuid>",
            "Open a captured HTTP transaction in Replay.",
            Write,
            false,
            &["id"],
            vec![json!({"id":"00000000-0000-0000-0000-000000000000"})],
        ),
        op(
            "capture.http.fuzzer",
            "capture http fuzzer --id <uuid>",
            "Seed the Fuzzer from a captured HTTP transaction.",
            Write,
            false,
            &["id"],
            vec![json!({"id":"00000000-0000-0000-0000-000000000000"})],
        ),
        op(
            "capture.http.annotate",
            "capture http annotate --id <uuid>",
            "Set or clear a transaction note/color.",
            Write,
            false,
            &["id"],
            vec![json!({"id":"00000000-0000-0000-0000-000000000000","note":"interesting"})],
        ),
        op(
            "scope.get",
            "scope get-scope",
            "Read the active scope patterns.",
            Read,
            false,
            &[],
            vec![json!({})],
        ),
        op(
            "scope.set",
            "scope set-scope",
            "Replace or clear active scope patterns.",
            Write,
            false,
            &[],
            vec![json!({"patterns":["*.example.com"]})],
        ),
        op(
            "replay.list",
            "replay list",
            "List Replay tabs.",
            Read,
            false,
            &[],
            vec![json!({})],
        ),
        op(
            "replay.open",
            "replay open",
            "Open a new Replay tab.",
            Write,
            false,
            &[],
            vec![json!({"transaction_id":"00000000-0000-0000-0000-000000000000"})],
        ),
        op(
            "replay.update",
            "replay update --tab-id <id>",
            "Update a Replay tab request or connection target.",
            Write,
            false,
            &["tab_id"],
            vec![json!({"tab_id":"tab-1","host":"example.com"})],
        ),
        op(
            "replay.send",
            "replay send --tab-id <id>",
            "Send a Replay tab request to the network.",
            Write,
            true,
            &["tab_id"],
            vec![json!({"tab_id":"tab-1"})],
        ),
        op(
            "fuzzer.set_template",
            "fuzzer set-template",
            "Set the Fuzzer request template.",
            Write,
            false,
            &[],
            vec![json!({"transaction_id":"00000000-0000-0000-0000-000000000000"})],
        ),
        op(
            "fuzzer.set_payloads",
            "fuzzer set-payloads",
            "Set Fuzzer payloads.",
            Write,
            false,
            &[],
            vec![json!({"payloads":["admin","test"]})],
        ),
        op(
            "fuzzer.run",
            "fuzzer run",
            "Run the Fuzzer, sending generated HTTP requests.",
            Write,
            true,
            &[],
            vec![json!({})],
        ),
        op(
            "fuzzer.status",
            "fuzzer status --id <uuid>",
            "Read Fuzzer attack status.",
            Read,
            false,
            &["id"],
            vec![json!({"id":"00000000-0000-0000-0000-000000000000"})],
        ),
        op(
            "fuzzer.results",
            "fuzzer results --id <uuid>",
            "Read Fuzzer attack results.",
            Read,
            false,
            &["id"],
            vec![json!({"id":"00000000-0000-0000-0000-000000000000"})],
        ),
        op(
            "fuzzer.list",
            "fuzzer list",
            "List Fuzzer attacks.",
            Read,
            false,
            &[],
            vec![json!({"limit":20})],
        ),
        op(
            "capture.intercept.on",
            "capture intercept on",
            "Enable request interception.",
            Write,
            false,
            &[],
            vec![json!({})],
        ),
        op(
            "capture.intercept.off",
            "capture intercept off",
            "Disable request interception.",
            Write,
            false,
            &[],
            vec![json!({})],
        ),
        op(
            "capture.intercept.list",
            "capture intercept list",
            "List held requests.",
            Read,
            false,
            &[],
            vec![json!({})],
        ),
        op(
            "capture.intercept.forward",
            "capture intercept forward --id <uuid>",
            "Forward one held request.",
            Write,
            true,
            &["id"],
            vec![json!({"id":"00000000-0000-0000-0000-000000000000"})],
        ),
        op(
            "capture.intercept.drop",
            "capture intercept drop --id <uuid>",
            "Drop one held request.",
            Write,
            true,
            &["id"],
            vec![json!({"id":"00000000-0000-0000-0000-000000000000"})],
        ),
        op(
            "capture.intercept.forward_all",
            "capture intercept forward-all",
            "Forward all held requests.",
            Write,
            true,
            &[],
            vec![json!({})],
        ),
        op(
            "capture.websocket.list",
            "capture web-socket list",
            "List captured WebSocket sessions.",
            Read,
            false,
            &[],
            vec![json!({"limit":20,"page":true})],
        ),
        op(
            "capture.websocket.get",
            "capture web-socket get --id <uuid>",
            "Get one WebSocket session and frames.",
            Read,
            false,
            &["id"],
            vec![json!({"id":"00000000-0000-0000-0000-000000000000"})],
        ),
        op(
            "capture.auto_replace.list",
            "capture auto-replace list",
            "List match/replace rules.",
            Read,
            false,
            &[],
            vec![json!({})],
        ),
        op(
            "capture.auto_replace.set",
            "capture auto-replace set",
            "Replace match/replace rules.",
            Write,
            false,
            &[],
            vec![json!({"stdin":true})],
        ),
        op(
            "capture.response_intercept.list",
            "capture response-intercept list",
            "List held responses.",
            Read,
            false,
            &[],
            vec![json!({})],
        ),
        op(
            "capture.response_intercept.get",
            "capture response-intercept get --id <uuid>",
            "Get one held response.",
            Read,
            false,
            &["id"],
            vec![json!({"id":"00000000-0000-0000-0000-000000000000"})],
        ),
        op(
            "capture.response_intercept.forward",
            "capture response-intercept forward --id <uuid>",
            "Forward one held response.",
            Write,
            true,
            &["id"],
            vec![json!({"id":"00000000-0000-0000-0000-000000000000"})],
        ),
        op(
            "capture.response_intercept.drop",
            "capture response-intercept drop --id <uuid>",
            "Drop one held response.",
            Write,
            true,
            &["id"],
            vec![json!({"id":"00000000-0000-0000-0000-000000000000"})],
        ),
        op(
            "capture.response_intercept.forward_all",
            "capture response-intercept forward-all",
            "Forward all held responses.",
            Write,
            true,
            &[],
            vec![json!({})],
        ),
        op(
            "capture.intercept_rule.list",
            "capture intercept-rule list",
            "List intercept rules.",
            Read,
            false,
            &[],
            vec![json!({})],
        ),
        op(
            "capture.intercept_rule.create",
            "capture intercept-rule create",
            "Create an intercept rule.",
            Write,
            false,
            &[],
            vec![json!({"all":true})],
        ),
        op(
            "capture.intercept_rule.delete",
            "capture intercept-rule delete --id <uuid>",
            "Delete an intercept rule.",
            Write,
            true,
            &["id"],
            vec![json!({"id":"00000000-0000-0000-0000-000000000000"})],
        ),
        op(
            "sequence.list",
            "sequence list",
            "List saved sequences.",
            Read,
            false,
            &[],
            vec![json!({})],
        ),
        op(
            "sequence.get",
            "sequence get --id <uuid>",
            "Get one saved sequence.",
            Read,
            false,
            &["id"],
            vec![json!({"id":"00000000-0000-0000-0000-000000000000"})],
        ),
        op(
            "sequence.create",
            "sequence create",
            "Create a saved sequence.",
            Write,
            false,
            &[],
            vec![json!({"file":"sequence.json"})],
        ),
        op(
            "sequence.run",
            "sequence run --id <uuid>",
            "Run a saved sequence, sending HTTP requests.",
            Write,
            true,
            &["id"],
            vec![json!({"id":"00000000-0000-0000-0000-000000000000"})],
        ),
        op(
            "sequence.run_get",
            "sequence run-get --id <uuid>",
            "Get one sequence run result.",
            Read,
            false,
            &["id"],
            vec![json!({"id":"00000000-0000-0000-0000-000000000000"})],
        ),
        op(
            "sequence.delete",
            "sequence delete --id <uuid>",
            "Delete a saved sequence.",
            Write,
            true,
            &["id"],
            vec![json!({"id":"00000000-0000-0000-0000-000000000000"})],
        ),
        op(
            "sequence.runs",
            "sequence runs",
            "List sequence runs.",
            Read,
            false,
            &[],
            vec![json!({"limit":20})],
        ),
        op(
            "capture.oast.status",
            "capture oast status",
            "Read OAST provider status.",
            Read,
            false,
            &[],
            vec![json!({})],
        ),
        op(
            "capture.oast.list",
            "capture oast list",
            "List OAST callbacks.",
            Read,
            false,
            &[],
            vec![json!({"limit":20})],
        ),
        op(
            "capture.oast.get",
            "capture oast get --id <uuid>",
            "Get one OAST callback.",
            Read,
            false,
            &["id"],
            vec![json!({"id":"00000000-0000-0000-0000-000000000000"})],
        ),
        op(
            "capture.oast.generate",
            "capture oast generate",
            "Generate a fresh OAST payload.",
            Write,
            false,
            &[],
            vec![json!({})],
        ),
        op(
            "capture.oast.clear",
            "capture oast clear",
            "Clear OAST callbacks.",
            Write,
            true,
            &[],
            vec![json!({})],
        ),
        op(
            "capture.oast.configure",
            "capture oast configure",
            "Configure the OAST provider.",
            Write,
            true,
            &[],
            vec![json!({"provider":"interactsh","url":"https://oast.example","token_stdin":true})],
        ),
    ]
}

fn op(
    operation: &'static str,
    command: &'static str,
    description: &'static str,
    side_effect: CliSideEffect,
    requires_confirmation: bool,
    required_fields: &[&'static str],
    examples: Vec<Value>,
) -> CliOperationSpec {
    CliOperationSpec {
        operation,
        command,
        description,
        side_effect,
        requires_confirmation: requires_confirmation || side_effect == CliSideEffect::Write,
        input_schema: input_schema(operation, required_fields),
        output_schema: json!({
            "type": "object",
            "additionalProperties": true,
            "description": "Returned in the envelope data field."
        }),
        examples,
    }
}

fn input_schema(operation: &str, required_fields: &[&'static str]) -> Value {
    let mut properties = serde_json::Map::new();
    let fields = call_allowed_fields(operation).unwrap_or(required_fields);
    for field in fields {
        properties.insert(
            (*field).to_string(),
            json!({
                "description": format!("CLI argument `{field}`"),
            }),
        );
    }
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": required_fields,
        "properties": properties,
    })
}

fn operation_spec(operation: &str) -> Option<CliOperationSpec> {
    manifest_operations()
        .into_iter()
        .find(|spec| spec.operation == operation)
}

fn call_allowed_fields(operation: &str) -> Option<&'static [&'static str]> {
    Some(match operation {
        "manifest" | "session.list" => &[],
        "schema" => &["kind", "operation"],
        "examples" => &["operation"],
        "skills.install" => &["codex", "claude", "all", "codex_dir", "claude_dir"],
        "session.create" => &["name"],
        "session.switch" | "session.delete" | "session.reveal" => &["id"],
        "capture.http.list" => &[
            "session_id",
            "query",
            "method",
            "limit",
            "offset",
            "before_sequence",
            "page",
            "host",
            "status",
            "status_range",
            "since",
            "mime",
            "sort_key",
            "sort_direction",
        ],
        "capture.http.get" => &["id", "session_id"],
        "capture.http.replay" | "capture.http.fuzzer" => {
            &["id", "session_id", "scheme", "host", "port"]
        }
        "capture.http.annotate" => &[
            "id",
            "session_id",
            "color",
            "clear_color",
            "note",
            "clear_note",
        ],
        "scope.get" => &["session_id"],
        "scope.set" => &[
            "session_id",
            "clear",
            "patterns",
            "pattern",
            "file",
            "stdin",
        ],
        "replay.list" => &["session_id"],
        "replay.open" | "fuzzer.set_template" => &[
            "session_id",
            "transaction_id",
            "request_file",
            "stdin",
            "scheme",
            "host",
            "port",
        ],
        "replay.update" => &[
            "tab_id",
            "session_id",
            "request_file",
            "stdin",
            "scheme",
            "host",
            "port",
        ],
        "replay.send" => &["tab_id", "session_id"],
        "fuzzer.set_payloads" => &["session_id", "payloads", "payload", "file", "stdin"],
        "fuzzer.run" => &["session_id", "async", "r#async"],
        "fuzzer.status" | "fuzzer.results" => &["id", "session_id"],
        "fuzzer.list" => &["session_id", "limit"],
        "capture.intercept.on"
        | "capture.intercept.off"
        | "capture.intercept.list"
        | "capture.intercept.forward_all"
        | "capture.auto_replace.list"
        | "capture.response_intercept.list"
        | "capture.response_intercept.forward_all"
        | "capture.intercept_rule.list"
        | "sequence.list"
        | "capture.oast.status"
        | "capture.oast.generate"
        | "capture.oast.clear" => &["session_id"],
        "capture.intercept.forward" => &["id", "session_id", "request_file", "stdin"],
        "capture.intercept.drop"
        | "capture.response_intercept.get"
        | "capture.response_intercept.drop"
        | "capture.intercept_rule.delete"
        | "sequence.get"
        | "sequence.run"
        | "sequence.run_get"
        | "sequence.delete"
        | "capture.oast.get" => &["id", "session_id"],
        "capture.websocket.list" => &[
            "session_id",
            "query",
            "limit",
            "offset",
            "sort_key",
            "sort_direction",
            "in_scope_only",
            "live_only",
            "page",
        ],
        "capture.websocket.get" => &["id", "session_id", "frame_limit", "before_index"],
        "capture.auto_replace.set" => &["session_id", "file", "stdin"],
        "capture.response_intercept.forward" => &["id", "session_id", "response_file", "stdin"],
        "capture.intercept_rule.create" => &[
            "session_id",
            "scope",
            "all",
            "host_pattern",
            "path_pattern",
            "method_filter",
            "method",
            "enabled",
        ],
        "sequence.create" => &["file", "stdin", "session_id"],
        "sequence.runs" | "capture.oast.list" => &["session_id", "limit"],
        "capture.oast.configure" => &[
            "session_id",
            "provider",
            "url",
            "token",
            "token_stdin",
            "interval",
            "enable",
            "disable",
        ],
        _ => return None,
    })
}

fn dry_run_command(command: &Command) -> Result<Value> {
    let operation = command.operation_name();
    let spec =
        operation_spec(operation).ok_or_else(|| anyhow!("unknown operation `{operation}`"))?;
    Ok(json!({
        "dry_run": true,
        "operation": operation,
        "command": spec.command,
        "side_effect": spec.side_effect,
        "requires_confirmation": spec.requires_confirmation,
        "input": command_input_preview(command),
        "api": command_api_preview(command)?,
        "notes": dry_run_notes(command),
    }))
}

fn command_input_preview(command: &Command) -> Value {
    match command {
        Command::Manifest => json!({}),
        Command::Schema { kind, operation } => json!({ "kind": kind, "operation": operation }),
        Command::Examples { operation } => json!({ "operation": operation }),
        Command::Call(args) => json!({ "operation": args.operation, "input": args.input }),
        Command::Session { command } => match command {
            SessionCommand::List => json!({}),
            SessionCommand::Create(args) => json!({ "name": args.name }),
            SessionCommand::Switch(args) => json!({ "id": args.id }),
            SessionCommand::Delete(args) => json!({ "id": args.id }),
            SessionCommand::Reveal(args) => json!({ "id": args.id }),
        },
        Command::Capture { command } => match command {
            CaptureCommand::Http { command } => history_input_preview(command),
            CaptureCommand::Intercept { command } => intercept_input_preview(command),
            CaptureCommand::ResponseIntercept { command } => {
                response_intercept_input_preview(command)
            }
            CaptureCommand::InterceptRule { command } => intercept_rule_input_preview(command),
            CaptureCommand::WebSocket { command } => websocket_input_preview(command),
            CaptureCommand::AutoReplace { command } => auto_replace_input_preview(command),
            CaptureCommand::Oast { command } => oast_input_preview(command),
        },
        Command::Scope { command } => match command {
            TargetCommand::GetScope(args) => json!({ "session_id": args.session_id }),
            TargetCommand::SetScope(args) => json!({
                "session_id": args.session_id,
                "clear": args.clear,
                "patterns": args.patterns,
                "file": args.file,
                "stdin": args.stdin,
            }),
        },
        Command::Replay { command } => replay_input_preview(command),
        Command::Fuzzer { command } => fuzzer_input_preview(command),
        Command::Sequence { command } => sequence_input_preview(command),
        Command::Skills { command } => match command {
            SkillsCommand::Install(args) => json!({
                "codex": args.codex,
                "claude": args.claude,
                "all": args.all,
                "codex_dir": args.codex_dir,
                "claude_dir": args.claude_dir,
            }),
        },
        Command::History { command } => history_input_preview(command),
        Command::Intercept { command } => intercept_input_preview(command),
        Command::Websocket { command } => websocket_input_preview(command),
        Command::AutoReplace { command } => auto_replace_input_preview(command),
    }
}

fn history_input_preview(command: &HistoryCommand) -> Value {
    match command {
        HistoryCommand::List(args) => json!({
            "session_id": args.session_id,
            "query": args.query,
            "method": args.method,
            "limit": args.limit,
            "offset": args.offset,
            "before_sequence": args.before_sequence,
            "page": args.page,
            "host": args.host,
            "status": args.status,
            "status_range": args.status_range,
            "since": args.since,
            "mime": args.mime,
            "sort_key": args.sort_key,
            "sort_direction": args.sort_direction,
        }),
        HistoryCommand::Get(args) => json!({ "id": args.id, "session_id": args.session_id }),
        HistoryCommand::Replay(args) => json!({
            "id": args.id,
            "session_id": args.session_id,
            "scheme": args.scheme,
            "host": args.host,
            "port": args.port,
        }),
        HistoryCommand::Fuzzer(args) => json!({
            "id": args.id,
            "session_id": args.session_id,
            "scheme": args.scheme,
            "host": args.host,
            "port": args.port,
        }),
        HistoryCommand::Annotate(args) => json!({
            "id": args.id,
            "session_id": args.session_id,
            "color": args.color,
            "clear_color": args.clear_color,
            "note": args.note,
            "clear_note": args.clear_note,
        }),
    }
}

fn replay_input_preview(command: &ReplayCommand) -> Value {
    match command {
        ReplayCommand::List(args) => json!({ "session_id": args.session_id }),
        ReplayCommand::Open(args) => json!({
            "session_id": args.session_id,
            "transaction_id": args.transaction_id,
            "request_file": args.request_file,
            "stdin": args.stdin,
            "scheme": args.scheme,
            "host": args.host,
            "port": args.port,
        }),
        ReplayCommand::Update(args) => json!({
            "tab_id": args.tab_id,
            "session_id": args.session_id,
            "request_file": args.request_file,
            "stdin": args.stdin,
            "scheme": args.scheme,
            "host": args.host,
            "port": args.port,
        }),
        ReplayCommand::Send(args) => {
            json!({ "tab_id": args.tab_id, "session_id": args.session_id })
        }
    }
}

fn fuzzer_input_preview(command: &FuzzerCommand) -> Value {
    match command {
        FuzzerCommand::SetTemplate(args) => json!({
            "session_id": args.session_id,
            "transaction_id": args.transaction_id,
            "request_file": args.request_file,
            "stdin": args.stdin,
            "scheme": args.scheme,
            "host": args.host,
            "port": args.port,
        }),
        FuzzerCommand::SetPayloads(args) => json!({
            "session_id": args.session_id,
            "payloads": args.payloads,
            "file": args.file,
            "stdin": args.stdin,
        }),
        FuzzerCommand::Run(args) => json!({ "session_id": args.session_id, "async": args.r#async }),
        FuzzerCommand::Status(args) => json!({ "id": args.id, "session_id": args.session_id }),
        FuzzerCommand::Results(args) => json!({ "id": args.id, "session_id": args.session_id }),
        FuzzerCommand::List(args) => json!({ "session_id": args.session_id, "limit": args.limit }),
    }
}

fn intercept_input_preview(command: &InterceptCommand) -> Value {
    match command {
        InterceptCommand::On(args)
        | InterceptCommand::Off(args)
        | InterceptCommand::List(args)
        | InterceptCommand::ForwardAll(args) => json!({ "session_id": args.session_id }),
        InterceptCommand::Forward(args) => json!({
            "id": args.id,
            "session_id": args.session_id,
            "request_file": args.request_file,
            "stdin": args.stdin,
        }),
        InterceptCommand::Drop(args) => json!({ "id": args.id, "session_id": args.session_id }),
    }
}

fn websocket_input_preview(command: &WebSocketCommand) -> Value {
    match command {
        WebSocketCommand::List(args) => json!({
            "session_id": args.session_id,
            "query": args.query,
            "limit": args.limit,
            "offset": args.offset,
            "sort_key": args.sort_key,
            "sort_direction": args.sort_direction,
            "in_scope_only": args.in_scope_only,
            "live_only": args.live_only,
            "page": args.page,
        }),
        WebSocketCommand::Get(args) => json!({
            "id": args.id,
            "session_id": args.session_id,
            "frame_limit": args.frame_limit,
            "before_index": args.before_index,
        }),
    }
}

fn auto_replace_input_preview(command: &AutoReplaceCommand) -> Value {
    match command {
        AutoReplaceCommand::List(args) => json!({ "session_id": args.session_id }),
        AutoReplaceCommand::Set(args) => json!({
            "session_id": args.session_id,
            "file": args.file,
            "stdin": args.stdin,
        }),
    }
}

fn response_intercept_input_preview(command: &ResponseInterceptCommand) -> Value {
    match command {
        ResponseInterceptCommand::List(args) | ResponseInterceptCommand::ForwardAll(args) => {
            json!({ "session_id": args.session_id })
        }
        ResponseInterceptCommand::Get(args) => {
            json!({ "id": args.id, "session_id": args.session_id })
        }
        ResponseInterceptCommand::Forward(args) => json!({
            "id": args.id,
            "session_id": args.session_id,
            "response_file": args.response_file,
            "stdin": args.stdin,
        }),
        ResponseInterceptCommand::Drop(args) => {
            json!({ "id": args.id, "session_id": args.session_id })
        }
    }
}

fn intercept_rule_input_preview(command: &InterceptRuleCommand) -> Value {
    match command {
        InterceptRuleCommand::List(args) => json!({ "session_id": args.session_id }),
        InterceptRuleCommand::Create(args) => json!({
            "session_id": args.session_id,
            "scope": args.scope,
            "all": args.all,
            "host_pattern": args.host_pattern,
            "path_pattern": args.path_pattern,
            "method_filter": args.method_filter,
            "enabled": args.enabled,
        }),
        InterceptRuleCommand::Delete(args) => {
            json!({ "id": args.id, "session_id": args.session_id })
        }
    }
}

fn sequence_input_preview(command: &SequenceCommand) -> Value {
    match command {
        SequenceCommand::List(args) => json!({ "session_id": args.session_id }),
        SequenceCommand::Get(args) => json!({ "id": args.id, "session_id": args.session_id }),
        SequenceCommand::Create(args) => json!({
            "file": args.file,
            "stdin": args.stdin,
            "session_id": args.session_id,
        }),
        SequenceCommand::Run(args) => json!({ "id": args.id, "session_id": args.session_id }),
        SequenceCommand::RunGet(args) => json!({ "id": args.id, "session_id": args.session_id }),
        SequenceCommand::Delete(args) => json!({ "id": args.id, "session_id": args.session_id }),
        SequenceCommand::Runs(args) => {
            json!({ "session_id": args.session_id, "limit": args.limit })
        }
    }
}

fn oast_input_preview(command: &OastCommand) -> Value {
    match command {
        OastCommand::Status(args) | OastCommand::Generate(args) | OastCommand::Clear(args) => {
            json!({ "session_id": args.session_id })
        }
        OastCommand::List(args) => json!({ "session_id": args.session_id, "limit": args.limit }),
        OastCommand::Get(args) => json!({ "id": args.id, "session_id": args.session_id }),
        OastCommand::Configure(args) => json!({
            "session_id": args.session_id,
            "provider": args.provider,
            "url": args.url,
            "token_stdin": args.token_stdin,
            "interval": args.interval,
            "enable": args.enable,
            "disable": args.disable,
        }),
    }
}

fn command_api_preview(command: &Command) -> Result<Value> {
    let api = match command {
        Command::Manifest | Command::Schema { .. } | Command::Examples { .. } => Value::Null,
        Command::Call { .. } => Value::Null,
        Command::Skills { .. } => json!({ "local": true }),
        Command::Session { command } => match command {
            SessionCommand::List => api_preview("GET", "/api/sessions", None),
            SessionCommand::Create(args) => {
                api_preview("POST", "/api/sessions", Some(json!({ "name": args.name })))
            }
            SessionCommand::Switch(args) => api_preview(
                "POST",
                format!("/api/sessions/{}/activate", args.id),
                Some(json!({})),
            ),
            SessionCommand::Delete(args) => {
                api_preview("DELETE", format!("/api/sessions/{}", args.id), None)
            }
            SessionCommand::Reveal(args) => api_preview(
                "POST",
                format!("/api/sessions/{}/reveal", args.id),
                Some(json!({})),
            ),
        },
        Command::Capture { command } => capture_api_preview(command)?,
        Command::Scope { command } => match command {
            TargetCommand::GetScope(args) => api_preview(
                "GET",
                session_query_path("/api/runtime", args.session_id),
                None,
            ),
            TargetCommand::SetScope(args) => api_preview(
                "POST",
                "/api/runtime",
                Some(json!({
                    "session_id": args.session_id,
                    "scope_patterns": if args.clear { Some(Vec::<String>::new()) } else { None },
                })),
            ),
        },
        Command::Replay { command } => replay_api_preview(command),
        Command::Fuzzer { command } => fuzzer_api_preview(command),
        Command::Sequence { command } => sequence_api_preview(command),
        Command::History { command } => history_api_preview(command)?,
        Command::Intercept { command } => intercept_api_preview(command),
        Command::Websocket { command } => websocket_api_preview(command),
        Command::AutoReplace { command } => auto_replace_api_preview(command),
    };
    Ok(api)
}

fn capture_api_preview(command: &CaptureCommand) -> Result<Value> {
    match command {
        CaptureCommand::Http { command } => history_api_preview(command),
        CaptureCommand::Intercept { command } => Ok(intercept_api_preview(command)),
        CaptureCommand::ResponseIntercept { command } => {
            Ok(response_intercept_api_preview(command))
        }
        CaptureCommand::InterceptRule { command } => Ok(intercept_rule_api_preview(command)),
        CaptureCommand::WebSocket { command } => Ok(websocket_api_preview(command)),
        CaptureCommand::AutoReplace { command } => Ok(auto_replace_api_preview(command)),
        CaptureCommand::Oast { command } => Ok(oast_api_preview(command)),
    }
}

fn history_api_preview(command: &HistoryCommand) -> Result<Value> {
    Ok(match command {
        HistoryCommand::List(args) => {
            api_preview("GET", history_list_path(args.session_id, args)?, None)
        }
        HistoryCommand::Get(args) => api_preview(
            "GET",
            transaction_detail_path(args.id, args.session_id),
            None,
        ),
        HistoryCommand::Replay(_) | HistoryCommand::Fuzzer(_) => api_preview(
            "POST",
            "/api/workspace-state",
            Some(json!({ "note": "loads transaction, then updates workspace state" })),
        ),
        HistoryCommand::Annotate(args) => api_preview(
            "PATCH",
            session_query_path(
                &format!("/api/transactions/{}/annotations", args.id),
                args.session_id,
            ),
            Some(json!({ "note": "annotation payload" })),
        ),
    })
}

fn replay_api_preview(command: &ReplayCommand) -> Value {
    match command {
        ReplayCommand::List(args) => api_preview(
            "GET",
            session_query_path("/api/workspace-state", args.session_id),
            None,
        ),
        ReplayCommand::Open(_) | ReplayCommand::Update(_) => api_preview(
            "POST",
            "/api/workspace-state",
            Some(json!({ "note": "updates Replay workspace state" })),
        ),
        ReplayCommand::Send(_) => api_preview(
            "POST",
            "/api/replay/send",
            Some(json!({ "note": "sends the selected Replay tab request" })),
        ),
    }
}

fn fuzzer_api_preview(command: &FuzzerCommand) -> Value {
    match command {
        FuzzerCommand::SetTemplate(_) | FuzzerCommand::SetPayloads(_) => api_preview(
            "POST",
            "/api/workspace-state",
            Some(json!({ "note": "updates Fuzzer workspace state" })),
        ),
        FuzzerCommand::Run(_) => api_preview(
            "POST",
            "/api/fuzzer/attacks",
            Some(json!({ "note": "runs payload-generated HTTP requests" })),
        ),
        FuzzerCommand::Status(args) => api_preview(
            "GET",
            session_query_path(&format!("/api/fuzzer/attacks/{}", args.id), args.session_id),
            None,
        ),
        FuzzerCommand::Results(args) => api_preview(
            "GET",
            session_query_path(
                &format!("/api/fuzzer/attacks/{}/results", args.id),
                args.session_id,
            ),
            None,
        ),
        FuzzerCommand::List(args) => api_preview(
            "GET",
            session_query_path("/api/fuzzer/attacks", args.session_id),
            None,
        ),
    }
}

fn intercept_api_preview(command: &InterceptCommand) -> Value {
    match command {
        InterceptCommand::On(args) | InterceptCommand::Off(args) => api_preview(
            "POST",
            "/api/runtime",
            Some(
                json!({ "session_id": args.session_id, "intercept_enabled": matches!(command, InterceptCommand::On(_)) }),
            ),
        ),
        InterceptCommand::List(args) => api_preview(
            "GET",
            session_query_path("/api/intercepts", args.session_id),
            None,
        ),
        InterceptCommand::Forward(args) => api_preview(
            "POST",
            session_query_path(
                &format!("/api/intercepts/{}/forward", args.id),
                args.session_id,
            ),
            Some(json!({ "note": "optional edited request" })),
        ),
        InterceptCommand::Drop(args) => api_preview(
            "POST",
            session_query_path(
                &format!("/api/intercepts/{}/drop", args.id),
                args.session_id,
            ),
            Some(json!({})),
        ),
        InterceptCommand::ForwardAll(args) => api_preview(
            "POST",
            session_query_path("/api/intercepts/forward-all", args.session_id),
            Some(json!({})),
        ),
    }
}

fn websocket_api_preview(command: &WebSocketCommand) -> Value {
    match command {
        WebSocketCommand::List(args) => {
            api_preview("GET", websocket_list_path(args.session_id, args), None)
        }
        WebSocketCommand::Get(args) => api_preview(
            "GET",
            websocket_detail_path(
                args.id,
                args.session_id,
                args.frame_limit,
                args.before_index,
            ),
            None,
        ),
    }
}

fn auto_replace_api_preview(command: &AutoReplaceCommand) -> Value {
    match command {
        AutoReplaceCommand::List(args) => api_preview(
            "GET",
            session_query_path("/api/match-replace", args.session_id),
            None,
        ),
        AutoReplaceCommand::Set(args) => api_preview(
            "POST",
            session_query_path("/api/match-replace", args.session_id),
            Some(json!({ "note": "replacement rules from file/stdin" })),
        ),
    }
}

fn response_intercept_api_preview(command: &ResponseInterceptCommand) -> Value {
    match command {
        ResponseInterceptCommand::List(args) => api_preview(
            "GET",
            session_query_path("/api/response-intercepts", args.session_id),
            None,
        ),
        ResponseInterceptCommand::Get(args) => api_preview(
            "GET",
            session_query_path(
                &format!("/api/response-intercepts/{}", args.id),
                args.session_id,
            ),
            None,
        ),
        ResponseInterceptCommand::Forward(args) => api_preview(
            "POST",
            session_query_path(
                &format!("/api/response-intercepts/{}/forward", args.id),
                args.session_id,
            ),
            Some(json!({ "note": "optional edited response" })),
        ),
        ResponseInterceptCommand::Drop(args) => api_preview(
            "POST",
            session_query_path(
                &format!("/api/response-intercepts/{}/drop", args.id),
                args.session_id,
            ),
            Some(json!({})),
        ),
        ResponseInterceptCommand::ForwardAll(args) => api_preview(
            "POST",
            session_query_path("/api/response-intercepts/forward-all", args.session_id),
            Some(json!({})),
        ),
    }
}

fn intercept_rule_api_preview(command: &InterceptRuleCommand) -> Value {
    match command {
        InterceptRuleCommand::List(args) => api_preview(
            "GET",
            session_query_path("/api/intercept-rules", args.session_id),
            None,
        ),
        InterceptRuleCommand::Create(args) => api_preview(
            "POST",
            session_query_path("/api/intercept-rules", args.session_id),
            Some(json!({ "scope": args.scope, "all": args.all })),
        ),
        InterceptRuleCommand::Delete(args) => api_preview(
            "DELETE",
            session_query_path(
                &format!("/api/intercept-rules/{}", args.id),
                args.session_id,
            ),
            None,
        ),
    }
}

fn sequence_api_preview(command: &SequenceCommand) -> Value {
    match command {
        SequenceCommand::List(args) => api_preview(
            "GET",
            session_query_path("/api/sequences", args.session_id),
            None,
        ),
        SequenceCommand::Get(args) => api_preview(
            "GET",
            session_query_path(&format!("/api/sequences/{}", args.id), args.session_id),
            None,
        ),
        SequenceCommand::Create(args) => api_preview(
            "POST",
            session_query_path("/api/sequences", args.session_id),
            Some(json!({ "note": "sequence definition from file/stdin" })),
        ),
        SequenceCommand::Run(args) => api_preview(
            "POST",
            session_query_path(&format!("/api/sequences/{}/run", args.id), args.session_id),
            Some(json!({})),
        ),
        SequenceCommand::RunGet(args) => api_preview(
            "GET",
            session_query_path(&format!("/api/sequence-runs/{}", args.id), args.session_id),
            None,
        ),
        SequenceCommand::Delete(args) => api_preview(
            "DELETE",
            session_query_path(&format!("/api/sequences/{}", args.id), args.session_id),
            None,
        ),
        SequenceCommand::Runs(args) => api_preview(
            "GET",
            session_query_path("/api/sequence-runs", args.session_id),
            None,
        ),
    }
}

fn oast_api_preview(command: &OastCommand) -> Value {
    match command {
        OastCommand::Status(args) => api_preview(
            "GET",
            session_query_path("/api/oast/status", args.session_id),
            None,
        ),
        OastCommand::List(args) => api_preview(
            "GET",
            session_query_path("/api/oast/callbacks", args.session_id),
            None,
        ),
        OastCommand::Get(args) => api_preview(
            "GET",
            session_query_path(&format!("/api/oast/callbacks/{}", args.id), args.session_id),
            None,
        ),
        OastCommand::Generate(args) => api_preview(
            "POST",
            session_query_path("/api/oast/generate", args.session_id),
            Some(json!({})),
        ),
        OastCommand::Clear(args) => api_preview(
            "POST",
            session_query_path("/api/oast/callbacks/clear", args.session_id),
            Some(json!({})),
        ),
        OastCommand::Configure(_) => api_preview(
            "POST",
            "/api/runtime",
            Some(
                json!({ "note": "updates OAST runtime settings; token value is read from stdin when token_stdin=true" }),
            ),
        ),
    }
}

fn api_preview(method: &str, path: impl Into<String>, body: Option<Value>) -> Value {
    json!({
        "method": method,
        "path": path.into(),
        "body": body,
    })
}

fn dry_run_notes(command: &Command) -> Vec<&'static str> {
    let mut notes = Vec::new();
    if command.requires_confirmation() {
        notes.push("Use --yes to apply this side-effecting operation after reviewing the dry-run.");
    }
    if matches!(
        command.operation_name(),
        "replay.send" | "fuzzer.run" | "sequence.run"
    ) {
        notes.push("This operation may send traffic; failed sends should not be retried blindly.");
    }
    notes
}

fn command_from_call_args(args: CallArgs) -> Result<Command> {
    let input_from_stdin = args.input.as_deref() == Some("-");
    let input = parse_call_input(args.input)?;
    let command = command_from_operation_input(&args.operation, &input)?;
    if input_from_stdin && command_uses_stdin(&command) {
        bail!("call --input - cannot be combined with operation stdin fields");
    }
    Ok(command)
}

fn parse_call_input(source: Option<String>) -> Result<Value> {
    let Some(source) = source else {
        return Ok(json!({}));
    };
    let raw = if source == "-" {
        read_text_input(None, true)?
    } else if let Some(path) = source.strip_prefix('@') {
        if path.is_empty() {
            bail!("call --input @ requires a file path");
        }
        read_text_input(Some(PathBuf::from(path)), false)?
    } else {
        source
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_str(trimmed).context("failed to parse call input JSON")
}

fn command_from_operation_input(operation: &str, input: &Value) -> Result<Command> {
    let Some(_) = operation_spec(operation) else {
        bail!("unknown operation `{operation}`");
    };
    validate_call_known_fields(operation, input)?;
    Ok(match operation {
        "manifest" => Command::Manifest,
        "schema" => Command::Schema {
            kind: call_schema_kind(operation, input)?,
            operation: call_required(operation, input, "operation")?,
        },
        "examples" => Command::Examples {
            operation: call_required(operation, input, "operation")?,
        },
        "skills.install" => Command::Skills {
            command: SkillsCommand::Install(SkillsInstallArgs {
                codex: call_bool(operation, input, "codex")?,
                claude: call_bool(operation, input, "claude")?,
                all: call_bool(operation, input, "all")?,
                codex_dir: call_optional_path(operation, input, "codex_dir")?,
                claude_dir: call_optional_path(operation, input, "claude_dir")?,
            }),
        },
        "session.list" => Command::Session {
            command: SessionCommand::List,
        },
        "session.create" => Command::Session {
            command: SessionCommand::Create(CreateSessionArgs {
                name: call_optional(operation, input, "name")?,
            }),
        },
        "session.switch" => Command::Session {
            command: SessionCommand::Switch(SessionSwitchArgs {
                id: call_required(operation, input, "id")?,
            }),
        },
        "session.delete" => Command::Session {
            command: SessionCommand::Delete(SessionDeleteArgs {
                id: call_required(operation, input, "id")?,
            }),
        },
        "session.reveal" => Command::Session {
            command: SessionCommand::Reveal(SessionRevealArgs {
                id: call_required(operation, input, "id")?,
            }),
        },
        "capture.http.list" => {
            let offset = call_optional(operation, input, "offset")?;
            let before_sequence = call_optional(operation, input, "before_sequence")?;
            validate_call_conflicts(
                operation,
                "offset",
                offset.is_some(),
                "before_sequence",
                before_sequence.is_some(),
            )?;
            Command::Capture {
                command: CaptureCommand::Http {
                    command: HistoryCommand::List(HistoryListArgs {
                        session_id: call_optional(operation, input, "session_id")?,
                        query: call_optional(operation, input, "query")?,
                        method: call_optional(operation, input, "method")?,
                        limit: call_optional_nonzero_usize(operation, input, "limit")?,
                        offset,
                        before_sequence,
                        page: call_bool(operation, input, "page")?,
                        host: call_optional(operation, input, "host")?,
                        status: call_optional_http_status(operation, input, "status")?,
                        status_range: call_optional(operation, input, "status_range")?,
                        since: call_optional(operation, input, "since")?,
                        mime: call_optional(operation, input, "mime")?,
                        sort_key: call_optional_enum_string(
                            operation,
                            input,
                            "sort_key",
                            &[
                                "index",
                                "host",
                                "method",
                                "path",
                                "status",
                                "length",
                                "mime",
                                "notes",
                                "tls",
                                "started_at",
                            ],
                        )?,
                        sort_direction: call_optional_enum_string(
                            operation,
                            input,
                            "sort_direction",
                            &["asc", "desc"],
                        )?,
                    }),
                },
            }
        }
        "capture.http.get" => Command::Capture {
            command: CaptureCommand::Http {
                command: HistoryCommand::Get(HistoryGetArgs {
                    id: call_required(operation, input, "id")?,
                    session_id: call_optional(operation, input, "session_id")?,
                }),
            },
        },
        "capture.http.replay" => Command::Capture {
            command: CaptureCommand::Http {
                command: HistoryCommand::Replay(HistoryReplayArgs {
                    id: call_required(operation, input, "id")?,
                    session_id: call_optional(operation, input, "session_id")?,
                    scheme: call_optional(operation, input, "scheme")?,
                    host: call_optional(operation, input, "host")?,
                    port: call_optional(operation, input, "port")?,
                }),
            },
        },
        "capture.http.fuzzer" => Command::Capture {
            command: CaptureCommand::Http {
                command: HistoryCommand::Fuzzer(HistoryFuzzerArgs {
                    id: call_required(operation, input, "id")?,
                    session_id: call_optional(operation, input, "session_id")?,
                    scheme: call_optional(operation, input, "scheme")?,
                    host: call_optional(operation, input, "host")?,
                    port: call_optional(operation, input, "port")?,
                }),
            },
        },
        "capture.http.annotate" => {
            let color = call_optional(operation, input, "color")?;
            let clear_color = call_bool(operation, input, "clear_color")?;
            let note = call_optional(operation, input, "note")?;
            let clear_note = call_bool(operation, input, "clear_note")?;
            validate_call_conflicts(
                operation,
                "color",
                color.is_some(),
                "clear_color",
                clear_color,
            )?;
            validate_call_conflicts(operation, "note", note.is_some(), "clear_note", clear_note)?;
            Command::Capture {
                command: CaptureCommand::Http {
                    command: HistoryCommand::Annotate(HistoryAnnotateArgs {
                        id: call_required(operation, input, "id")?,
                        session_id: call_optional(operation, input, "session_id")?,
                        color,
                        clear_color,
                        note,
                        clear_note,
                    }),
                },
            }
        }
        "scope.get" => Command::Scope {
            command: TargetCommand::GetScope(TargetSessionArgs {
                session_id: call_optional(operation, input, "session_id")?,
            }),
        },
        "scope.set" => {
            let clear = call_bool(operation, input, "clear")?;
            let patterns = call_string_list(operation, input, "patterns", "pattern")?;
            let file = call_optional_path(operation, input, "file")?;
            let stdin = call_bool(operation, input, "stdin")?;
            validate_call_exactly_one(
                operation,
                "scope_source",
                &[
                    ("clear", clear),
                    ("patterns", !patterns.is_empty()),
                    ("file", file.is_some()),
                    ("stdin", stdin),
                ],
            )?;
            Command::Scope {
                command: TargetCommand::SetScope(TargetSetScopeArgs {
                    session_id: call_optional(operation, input, "session_id")?,
                    clear,
                    patterns,
                    file,
                    stdin,
                }),
            }
        }
        "replay.list" => Command::Replay {
            command: ReplayCommand::List(ReplayListArgs {
                session_id: call_optional(operation, input, "session_id")?,
            }),
        },
        "replay.open" => {
            let transaction_id = call_optional(operation, input, "transaction_id")?;
            let request_file = call_optional_path(operation, input, "request_file")?;
            let stdin = call_bool(operation, input, "stdin")?;
            validate_call_at_most_one(
                operation,
                "request_source",
                &[
                    ("transaction_id", transaction_id.is_some()),
                    ("request_file", request_file.is_some()),
                    ("stdin", stdin),
                ],
            )?;
            Command::Replay {
                command: ReplayCommand::Open(ReplayOpenArgs {
                    session_id: call_optional(operation, input, "session_id")?,
                    transaction_id,
                    request_file,
                    stdin,
                    scheme: call_optional(operation, input, "scheme")?,
                    host: call_optional(operation, input, "host")?,
                    port: call_optional(operation, input, "port")?,
                }),
            }
        }
        "replay.update" => {
            let request_file = call_optional_path(operation, input, "request_file")?;
            let stdin = call_bool(operation, input, "stdin")?;
            let scheme = call_optional(operation, input, "scheme")?;
            let host = call_optional(operation, input, "host")?;
            let port = call_optional(operation, input, "port")?;
            validate_call_at_most_one(
                operation,
                "request_source",
                &[("request_file", request_file.is_some()), ("stdin", stdin)],
            )?;
            validate_call_at_least_one(
                operation,
                "update_input",
                &[
                    ("request_file", request_file.is_some()),
                    ("stdin", stdin),
                    ("scheme", scheme.is_some()),
                    ("host", host.is_some()),
                    ("port", port.is_some()),
                ],
            )?;
            Command::Replay {
                command: ReplayCommand::Update(ReplayUpdateArgs {
                    tab_id: call_required(operation, input, "tab_id")?,
                    session_id: call_optional(operation, input, "session_id")?,
                    request_file,
                    stdin,
                    scheme,
                    host,
                    port,
                }),
            }
        }
        "replay.send" => Command::Replay {
            command: ReplayCommand::Send(ReplaySendArgs {
                tab_id: call_required(operation, input, "tab_id")?,
                session_id: call_optional(operation, input, "session_id")?,
            }),
        },
        "fuzzer.set_template" => {
            let transaction_id = call_optional(operation, input, "transaction_id")?;
            let request_file = call_optional_path(operation, input, "request_file")?;
            let stdin = call_bool(operation, input, "stdin")?;
            validate_call_exactly_one(
                operation,
                "request_source",
                &[
                    ("transaction_id", transaction_id.is_some()),
                    ("request_file", request_file.is_some()),
                    ("stdin", stdin),
                ],
            )?;
            Command::Fuzzer {
                command: FuzzerCommand::SetTemplate(FuzzerSetTemplateArgs {
                    session_id: call_optional(operation, input, "session_id")?,
                    transaction_id,
                    request_file,
                    stdin,
                    scheme: call_optional(operation, input, "scheme")?,
                    host: call_optional(operation, input, "host")?,
                    port: call_optional(operation, input, "port")?,
                }),
            }
        }
        "fuzzer.set_payloads" => {
            let payloads = call_string_list(operation, input, "payloads", "payload")?;
            let file = call_optional_path(operation, input, "file")?;
            let stdin = call_bool(operation, input, "stdin")?;
            validate_call_exactly_one(
                operation,
                "payload_source",
                &[
                    ("payloads", !payloads.is_empty()),
                    ("file", file.is_some()),
                    ("stdin", stdin),
                ],
            )?;
            Command::Fuzzer {
                command: FuzzerCommand::SetPayloads(FuzzerSetPayloadsArgs {
                    session_id: call_optional(operation, input, "session_id")?,
                    payloads,
                    file,
                    stdin,
                }),
            }
        }
        "fuzzer.run" => Command::Fuzzer {
            command: FuzzerCommand::Run(FuzzerRunArgs {
                session_id: call_optional(operation, input, "session_id")?,
                r#async: call_bool_any(operation, input, &["async", "r#async"])?,
            }),
        },
        "fuzzer.status" => Command::Fuzzer {
            command: FuzzerCommand::Status(FuzzerStatusArgs {
                id: call_required(operation, input, "id")?,
                session_id: call_optional(operation, input, "session_id")?,
            }),
        },
        "fuzzer.results" => Command::Fuzzer {
            command: FuzzerCommand::Results(FuzzerResultsArgs {
                id: call_required(operation, input, "id")?,
                session_id: call_optional(operation, input, "session_id")?,
            }),
        },
        "fuzzer.list" => Command::Fuzzer {
            command: FuzzerCommand::List(FuzzerListArgs {
                session_id: call_optional(operation, input, "session_id")?,
                limit: call_optional_nonzero_usize(operation, input, "limit")?,
            }),
        },
        "capture.intercept.on" => Command::Capture {
            command: CaptureCommand::Intercept {
                command: InterceptCommand::On(InterceptSessionArgs {
                    session_id: call_optional(operation, input, "session_id")?,
                }),
            },
        },
        "capture.intercept.off" => Command::Capture {
            command: CaptureCommand::Intercept {
                command: InterceptCommand::Off(InterceptSessionArgs {
                    session_id: call_optional(operation, input, "session_id")?,
                }),
            },
        },
        "capture.intercept.list" => Command::Capture {
            command: CaptureCommand::Intercept {
                command: InterceptCommand::List(InterceptSessionArgs {
                    session_id: call_optional(operation, input, "session_id")?,
                }),
            },
        },
        "capture.intercept.forward" => {
            let request_file = call_optional_path(operation, input, "request_file")?;
            let stdin = call_bool(operation, input, "stdin")?;
            validate_call_at_most_one(
                operation,
                "request_source",
                &[("request_file", request_file.is_some()), ("stdin", stdin)],
            )?;
            Command::Capture {
                command: CaptureCommand::Intercept {
                    command: InterceptCommand::Forward(InterceptForwardArgs {
                        id: call_required(operation, input, "id")?,
                        session_id: call_optional(operation, input, "session_id")?,
                        request_file,
                        stdin,
                    }),
                },
            }
        }
        "capture.intercept.drop" => Command::Capture {
            command: CaptureCommand::Intercept {
                command: InterceptCommand::Drop(InterceptDropArgs {
                    id: call_required(operation, input, "id")?,
                    session_id: call_optional(operation, input, "session_id")?,
                }),
            },
        },
        "capture.intercept.forward_all" => Command::Capture {
            command: CaptureCommand::Intercept {
                command: InterceptCommand::ForwardAll(InterceptSessionArgs {
                    session_id: call_optional(operation, input, "session_id")?,
                }),
            },
        },
        "capture.websocket.list" => Command::Capture {
            command: CaptureCommand::WebSocket {
                command: WebSocketCommand::List(WebSocketListArgs {
                    session_id: call_optional(operation, input, "session_id")?,
                    query: call_optional(operation, input, "query")?,
                    limit: call_optional_nonzero_usize(operation, input, "limit")?,
                    offset: call_optional(operation, input, "offset")?,
                    sort_key: call_optional_enum_string(
                        operation,
                        input,
                        "sort_key",
                        &[
                            "index",
                            "host",
                            "path",
                            "status",
                            "frame_count",
                            "duration_ms",
                            "started_at",
                        ],
                    )?,
                    sort_direction: call_optional_enum_string(
                        operation,
                        input,
                        "sort_direction",
                        &["asc", "desc"],
                    )?,
                    in_scope_only: call_bool(operation, input, "in_scope_only")?,
                    live_only: call_bool(operation, input, "live_only")?,
                    page: call_bool(operation, input, "page")?,
                }),
            },
        },
        "capture.websocket.get" => Command::Capture {
            command: CaptureCommand::WebSocket {
                command: WebSocketCommand::Get(WebSocketGetArgs {
                    id: call_required(operation, input, "id")?,
                    session_id: call_optional(operation, input, "session_id")?,
                    frame_limit: call_optional(operation, input, "frame_limit")?,
                    before_index: call_optional(operation, input, "before_index")?,
                }),
            },
        },
        "capture.auto_replace.list" => Command::Capture {
            command: CaptureCommand::AutoReplace {
                command: AutoReplaceCommand::List(AutoReplaceSessionArgs {
                    session_id: call_optional(operation, input, "session_id")?,
                }),
            },
        },
        "capture.auto_replace.set" => {
            let file = call_optional_path(operation, input, "file")?;
            let stdin = call_bool(operation, input, "stdin")?;
            validate_call_exactly_one(
                operation,
                "rules_source",
                &[("file", file.is_some()), ("stdin", stdin)],
            )?;
            Command::Capture {
                command: CaptureCommand::AutoReplace {
                    command: AutoReplaceCommand::Set(AutoReplaceSetArgs {
                        session_id: call_optional(operation, input, "session_id")?,
                        file,
                        stdin,
                    }),
                },
            }
        }
        "capture.response_intercept.list" => Command::Capture {
            command: CaptureCommand::ResponseIntercept {
                command: ResponseInterceptCommand::List(ResponseInterceptSessionArgs {
                    session_id: call_optional(operation, input, "session_id")?,
                }),
            },
        },
        "capture.response_intercept.get" => Command::Capture {
            command: CaptureCommand::ResponseIntercept {
                command: ResponseInterceptCommand::Get(ResponseInterceptGetArgs {
                    id: call_required(operation, input, "id")?,
                    session_id: call_optional(operation, input, "session_id")?,
                }),
            },
        },
        "capture.response_intercept.forward" => {
            let response_file = call_optional_path(operation, input, "response_file")?;
            let stdin = call_bool(operation, input, "stdin")?;
            validate_call_at_most_one(
                operation,
                "response_source",
                &[("response_file", response_file.is_some()), ("stdin", stdin)],
            )?;
            Command::Capture {
                command: CaptureCommand::ResponseIntercept {
                    command: ResponseInterceptCommand::Forward(ResponseInterceptForwardArgs {
                        id: call_required(operation, input, "id")?,
                        session_id: call_optional(operation, input, "session_id")?,
                        response_file,
                        stdin,
                    }),
                },
            }
        }
        "capture.response_intercept.drop" => Command::Capture {
            command: CaptureCommand::ResponseIntercept {
                command: ResponseInterceptCommand::Drop(ResponseInterceptDropArgs {
                    id: call_required(operation, input, "id")?,
                    session_id: call_optional(operation, input, "session_id")?,
                }),
            },
        },
        "capture.response_intercept.forward_all" => Command::Capture {
            command: CaptureCommand::ResponseIntercept {
                command: ResponseInterceptCommand::ForwardAll(ResponseInterceptSessionArgs {
                    session_id: call_optional(operation, input, "session_id")?,
                }),
            },
        },
        "capture.intercept_rule.list" => Command::Capture {
            command: CaptureCommand::InterceptRule {
                command: InterceptRuleCommand::List(InterceptRuleSessionArgs {
                    session_id: call_optional(operation, input, "session_id")?,
                }),
            },
        },
        "capture.intercept_rule.create" => {
            let all = call_bool(operation, input, "all")?;
            let host_pattern = call_optional(operation, input, "host_pattern")?;
            let path_pattern = call_optional(operation, input, "path_pattern")?;
            let method_filter = call_string_list(operation, input, "method_filter", "method")?;
            if all
                && (host_pattern.is_some() || path_pattern.is_some() || !method_filter.is_empty())
            {
                bail!("field `all` conflicts with matcher fields for `{operation}`");
            }
            if !all && host_pattern.is_none() && path_pattern.is_none() && method_filter.is_empty()
            {
                bail!("provide at least one matcher field for `{operation}`");
            }
            Command::Capture {
                command: CaptureCommand::InterceptRule {
                    command: InterceptRuleCommand::Create(InterceptRuleCreateArgs {
                        session_id: call_optional(operation, input, "session_id")?,
                        scope: call_optional_enum_string(
                            operation,
                            input,
                            "scope",
                            &["request", "response", "both"],
                        )?
                        .unwrap_or_else(|| "both".to_string()),
                        all,
                        host_pattern,
                        path_pattern,
                        method_filter,
                        enabled: call_optional(operation, input, "enabled")?,
                    }),
                },
            }
        }
        "capture.intercept_rule.delete" => Command::Capture {
            command: CaptureCommand::InterceptRule {
                command: InterceptRuleCommand::Delete(InterceptRuleDeleteArgs {
                    id: call_required(operation, input, "id")?,
                    session_id: call_optional(operation, input, "session_id")?,
                }),
            },
        },
        "sequence.list" => Command::Sequence {
            command: SequenceCommand::List(SequenceListArgs {
                session_id: call_optional(operation, input, "session_id")?,
            }),
        },
        "sequence.get" => Command::Sequence {
            command: SequenceCommand::Get(SequenceGetArgs {
                id: call_required(operation, input, "id")?,
                session_id: call_optional(operation, input, "session_id")?,
            }),
        },
        "sequence.create" => {
            let file = call_optional_path(operation, input, "file")?;
            let stdin = call_bool(operation, input, "stdin")?;
            validate_call_exactly_one(
                operation,
                "sequence_source",
                &[("file", file.is_some()), ("stdin", stdin)],
            )?;
            Command::Sequence {
                command: SequenceCommand::Create(SequenceCreateArgs {
                    file,
                    stdin,
                    session_id: call_optional(operation, input, "session_id")?,
                }),
            }
        }
        "sequence.run" => Command::Sequence {
            command: SequenceCommand::Run(SequenceRunArgs {
                id: call_required(operation, input, "id")?,
                session_id: call_optional(operation, input, "session_id")?,
            }),
        },
        "sequence.run_get" => Command::Sequence {
            command: SequenceCommand::RunGet(SequenceRunGetArgs {
                id: call_required(operation, input, "id")?,
                session_id: call_optional(operation, input, "session_id")?,
            }),
        },
        "sequence.delete" => Command::Sequence {
            command: SequenceCommand::Delete(SequenceDeleteArgs {
                id: call_required(operation, input, "id")?,
                session_id: call_optional(operation, input, "session_id")?,
            }),
        },
        "sequence.runs" => Command::Sequence {
            command: SequenceCommand::Runs(SequenceRunsArgs {
                session_id: call_optional(operation, input, "session_id")?,
                limit: call_optional_nonzero_usize(operation, input, "limit")?,
            }),
        },
        "capture.oast.status" => Command::Capture {
            command: CaptureCommand::Oast {
                command: OastCommand::Status(OastSessionArgs {
                    session_id: call_optional(operation, input, "session_id")?,
                }),
            },
        },
        "capture.oast.list" => Command::Capture {
            command: CaptureCommand::Oast {
                command: OastCommand::List(OastListArgs {
                    session_id: call_optional(operation, input, "session_id")?,
                    limit: call_optional_nonzero_usize(operation, input, "limit")?,
                }),
            },
        },
        "capture.oast.get" => Command::Capture {
            command: CaptureCommand::Oast {
                command: OastCommand::Get(OastGetArgs {
                    id: call_required(operation, input, "id")?,
                    session_id: call_optional(operation, input, "session_id")?,
                }),
            },
        },
        "capture.oast.generate" => Command::Capture {
            command: CaptureCommand::Oast {
                command: OastCommand::Generate(OastSessionArgs {
                    session_id: call_optional(operation, input, "session_id")?,
                }),
            },
        },
        "capture.oast.clear" => Command::Capture {
            command: CaptureCommand::Oast {
                command: OastCommand::Clear(OastSessionArgs {
                    session_id: call_optional(operation, input, "session_id")?,
                }),
            },
        },
        "capture.oast.configure" => {
            let enable = call_bool(operation, input, "enable")?;
            let disable = call_bool(operation, input, "disable")?;
            if enable && disable {
                bail!("enable and disable conflicts for `{operation}`");
            }
            let token = call_optional(operation, input, "token")?;
            let token_stdin = call_bool(operation, input, "token_stdin")?;
            validate_call_conflicts(
                operation,
                "token",
                token.is_some(),
                "token_stdin",
                token_stdin,
            )?;
            Command::Capture {
                command: CaptureCommand::Oast {
                    command: OastCommand::Configure(OastConfigureArgs {
                        session_id: call_optional(operation, input, "session_id")?,
                        provider: call_optional_enum_string(
                            operation,
                            input,
                            "provider",
                            &["interactsh", "boast", "custom"],
                        )?,
                        url: call_optional(operation, input, "url")?,
                        token,
                        token_stdin,
                        interval: call_optional_oast_polling_interval(
                            operation, input, "interval",
                        )?,
                        enable,
                        disable,
                    }),
                },
            }
        }
        _ => bail!("unsupported call operation `{operation}`"),
    })
}

fn call_schema_kind(operation: &str, input: &Value) -> Result<SchemaKind> {
    let kind: String = call_required(operation, input, "kind")?;
    match kind.as_str() {
        "input" => Ok(SchemaKind::Input),
        "output" => Ok(SchemaKind::Output),
        _ => bail!("invalid schema kind `{kind}` for `{operation}`; expected input or output"),
    }
}

fn validate_call_known_fields(operation: &str, input: &Value) -> Result<()> {
    let allowed = call_allowed_fields(operation).unwrap_or(&[]);
    let Value::Object(map) = input else {
        bail!("call input for `{operation}` must be a JSON object");
    };
    for field in map.keys() {
        if !allowed.contains(&field.as_str()) {
            bail!("invalid field `{field}` for `{operation}`");
        }
    }
    Ok(())
}

fn call_required<T: DeserializeOwned>(operation: &str, input: &Value, field: &str) -> Result<T> {
    let value = call_field(operation, input, field)?
        .ok_or_else(|| anyhow!("missing required field `{field}` for `{operation}`"))?;
    serde_json::from_value(value.clone())
        .with_context(|| format!("invalid field `{field}` for `{operation}`"))
}

fn call_optional<T: DeserializeOwned>(
    operation: &str,
    input: &Value,
    field: &str,
) -> Result<Option<T>> {
    let Some(value) = call_field(operation, input, field)? else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    serde_json::from_value(value.clone())
        .map(Some)
        .with_context(|| format!("invalid field `{field}` for `{operation}`"))
}

fn call_optional_path(operation: &str, input: &Value, field: &str) -> Result<Option<PathBuf>> {
    Ok(call_optional::<String>(operation, input, field)?.map(PathBuf::from))
}

fn call_bool(operation: &str, input: &Value, field: &str) -> Result<bool> {
    Ok(call_optional::<bool>(operation, input, field)?.unwrap_or(false))
}

fn call_optional_nonzero_usize(
    operation: &str,
    input: &Value,
    field: &str,
) -> Result<Option<usize>> {
    let value = call_optional::<usize>(operation, input, field)?;
    if value == Some(0) {
        bail!("field `{field}` for `{operation}` must be greater than zero");
    }
    Ok(value)
}

fn call_optional_http_status(operation: &str, input: &Value, field: &str) -> Result<Option<u16>> {
    let value = call_optional::<u16>(operation, input, field)?;
    if let Some(status) = value {
        if !(100..=599).contains(&status) {
            bail!("field `{field}` for `{operation}` must be between 100 and 599");
        }
    }
    Ok(value)
}

fn call_optional_oast_polling_interval(
    operation: &str,
    input: &Value,
    field: &str,
) -> Result<Option<u64>> {
    let value = call_optional::<u64>(operation, input, field)?;
    if let Some(interval) = value {
        if !(MIN_OAST_POLLING_INTERVAL_SECS..=MAX_OAST_POLLING_INTERVAL_SECS).contains(&interval) {
            bail!(
                "field `{field}` for `{operation}` must be between {} and {} seconds",
                MIN_OAST_POLLING_INTERVAL_SECS,
                MAX_OAST_POLLING_INTERVAL_SECS
            );
        }
    }
    Ok(value)
}

fn call_optional_enum_string(
    operation: &str,
    input: &Value,
    field: &str,
    allowed: &[&str],
) -> Result<Option<String>> {
    let value = call_optional::<String>(operation, input, field)?;
    if let Some(value) = value.as_deref() {
        if !allowed.contains(&value) {
            bail!(
                "invalid field `{field}` for `{operation}`; expected one of: {}",
                allowed.join(", ")
            );
        }
    }
    Ok(value)
}

fn call_bool_any(operation: &str, input: &Value, fields: &[&str]) -> Result<bool> {
    for field in fields {
        if call_field(operation, input, field)?.is_some() {
            return call_bool(operation, input, field);
        }
    }
    Ok(false)
}

fn call_string_list(
    operation: &str,
    input: &Value,
    plural_field: &str,
    singular_field: &str,
) -> Result<Vec<String>> {
    let plural_present = call_field_present(operation, input, plural_field)?;
    let singular_present = call_field_present(operation, input, singular_field)?;
    if plural_present && singular_present {
        bail!("fields `{plural_field}` and `{singular_field}` have conflicts for `{operation}`");
    }
    if plural_present {
        let value = call_field(operation, input, plural_field)?.expect("present field exists");
        return parse_call_string_list(operation, plural_field, value);
    }
    if singular_present {
        let value = call_field(operation, input, singular_field)?.expect("present field exists");
        return parse_call_string_list(operation, singular_field, value);
    }
    Ok(Vec::new())
}

fn parse_call_string_list(operation: &str, field: &str, value: &Value) -> Result<Vec<String>> {
    if value.is_null() {
        return Ok(Vec::new());
    }
    if let Some(value) = value.as_str() {
        return Ok(vec![value.to_string()]);
    }
    serde_json::from_value::<Vec<String>>(value.clone())
        .with_context(|| format!("invalid field `{field}` for `{operation}`"))
}

fn call_field<'a>(operation: &str, input: &'a Value, field: &str) -> Result<Option<&'a Value>> {
    match input {
        Value::Object(map) => Ok(map.get(field)),
        _ => bail!("call input for `{operation}` must be a JSON object"),
    }
}

fn call_field_present(operation: &str, input: &Value, field: &str) -> Result<bool> {
    Ok(match call_field(operation, input, field)? {
        None | Some(Value::Null) => false,
        Some(Value::Bool(value)) => *value,
        Some(Value::Array(values)) => !values.is_empty(),
        Some(_) => true,
    })
}

fn validate_call_conflicts(
    operation: &str,
    left_name: &str,
    left_present: bool,
    right_name: &str,
    right_present: bool,
) -> Result<()> {
    if left_present && right_present {
        bail!("fields `{left_name}` and `{right_name}` have conflicts for `{operation}`");
    }
    Ok(())
}

fn validate_call_exactly_one(
    operation: &str,
    group_name: &str,
    fields: &[(&str, bool)],
) -> Result<()> {
    let present = present_call_fields(fields);
    if present.len() != 1 {
        bail!(
            "provide exactly one `{group_name}` field for `{operation}`: {}",
            field_names(fields)
        );
    }
    Ok(())
}

fn validate_call_at_most_one(
    operation: &str,
    group_name: &str,
    fields: &[(&str, bool)],
) -> Result<()> {
    let present = present_call_fields(fields);
    if present.len() > 1 {
        bail!(
            "fields have conflicts in `{group_name}` for `{operation}`: {}",
            present.join(", ")
        );
    }
    Ok(())
}

fn validate_call_at_least_one(
    operation: &str,
    group_name: &str,
    fields: &[(&str, bool)],
) -> Result<()> {
    if present_call_fields(fields).is_empty() {
        bail!(
            "provide at least one `{group_name}` field for `{operation}`: {}",
            field_names(fields)
        );
    }
    Ok(())
}

fn present_call_fields<'a>(fields: &'a [(&'a str, bool)]) -> Vec<&'a str> {
    fields
        .iter()
        .filter_map(|(field, present)| present.then_some(*field))
        .collect()
}

fn field_names(fields: &[(&str, bool)]) -> String {
    fields
        .iter()
        .map(|(field, _)| *field)
        .collect::<Vec<_>>()
        .join(", ")
}

fn command_uses_stdin(command: &Command) -> bool {
    match command {
        Command::Scope {
            command: TargetCommand::SetScope(args),
        } => args.stdin,
        Command::Replay {
            command: ReplayCommand::Open(args),
        } => args.stdin,
        Command::Replay {
            command: ReplayCommand::Update(args),
        } => args.stdin,
        Command::Fuzzer {
            command: FuzzerCommand::SetTemplate(args),
        } => args.stdin,
        Command::Fuzzer {
            command: FuzzerCommand::SetPayloads(args),
        } => args.stdin,
        Command::Capture {
            command:
                CaptureCommand::Intercept {
                    command: InterceptCommand::Forward(args),
                },
        } => args.stdin,
        Command::Capture {
            command:
                CaptureCommand::AutoReplace {
                    command: AutoReplaceCommand::Set(args),
                },
        } => args.stdin,
        Command::Capture {
            command:
                CaptureCommand::ResponseIntercept {
                    command: ResponseInterceptCommand::Forward(args),
                },
        } => args.stdin,
        Command::Sequence {
            command: SequenceCommand::Create(args),
        } => args.stdin,
        Command::Capture {
            command:
                CaptureCommand::Oast {
                    command: OastCommand::Configure(args),
                },
        } => args.token_stdin,
        _ => false,
    }
}

#[tokio::main]
async fn main() {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            error.exit();
        }
        Err(error) => {
            let raw_args: Vec<String> = env::args().skip(1).collect();
            let operation = cli_parse_error_operation(&raw_args);
            let _ = CLI_OUTPUT_CONTEXT.set(CliOutputContext {
                format: cli_output_format_from_raw_args(&raw_args),
                operation: operation.clone(),
                success_envelope: true,
            });
            let payload = clap_error_payload(&error);
            if let Err(write_error) = print_error_json(&operation, payload.exit_code, &payload) {
                eprintln!("sniper-cli: failed to write JSON error output: {write_error}");
                eprintln!("sniper-cli: original parse error: {error}");
                std::process::exit(1);
            }
            std::process::exit(payload.exit_code);
        }
    };
    let operation = cli.command.output_operation_name();
    let output_format = cli.output;
    let success_envelope = matches!(cli.command, Command::Call(_));
    let _ = CLI_OUTPUT_CONTEXT.set(CliOutputContext {
        format: output_format,
        operation: operation.clone(),
        success_envelope,
    });
    if let Err(error) = run(cli).await {
        let payload = cli_error_payload(&operation, &error);
        if let Err(write_error) = print_error_json(&operation, payload.exit_code, &payload) {
            eprintln!("sniper-cli: failed to write JSON error output: {write_error}");
            eprintln!("sniper-cli: original error: {error:#}");
            std::process::exit(1);
        }
        std::process::exit(payload.exit_code);
    }
}

async fn run(cli: Cli) -> Result<()> {
    let api_override = cli.api;
    let dry_run = cli.dry_run;
    let yes = cli.yes;
    let command = match cli.command {
        Command::Call(args) => command_from_call_args(args)?,
        command => command,
    };

    validate_command_preflight(&command)?;
    if dry_run {
        let plan = dry_run_command(&command)?;
        return print_json(&plan);
    }
    if command.requires_confirmation() && !yes {
        bail!(
            "operation `{}` requires --dry-run or --yes",
            command.operation_name()
        );
    }

    match command {
        Command::Manifest => print_json(&json!({ "operations": manifest_operations() })),
        Command::Schema { kind, operation } => {
            let spec = operation_spec(&operation)
                .ok_or_else(|| anyhow!("unknown operation `{operation}`"))?;
            let schema = match kind {
                SchemaKind::Input => spec.input_schema,
                SchemaKind::Output => spec.output_schema,
            };
            print_json(&json!({
                "operation": operation,
                "kind": kind,
                "schema": schema,
            }))
        }
        Command::Examples { operation } => {
            let spec = operation_spec(&operation)
                .ok_or_else(|| anyhow!("unknown operation `{operation}`"))?;
            print_json(&json!({
                "operation": operation,
                "examples": spec.examples,
            }))
        }
        Command::Skills {
            command: SkillsCommand::Install(args),
        } => {
            let result = install_skills(args)?;
            print_json(&result)
        }
        command => {
            let api = ApiClient::discover(api_override).await?;
            match command {
                Command::Session { command } => handle_session(api, command).await,
                Command::Capture { command } => match command {
                    CaptureCommand::Http { command } => handle_history(api, command).await,
                    CaptureCommand::Intercept { command } => handle_intercept(api, command).await,
                    CaptureCommand::WebSocket { command } => handle_websocket(api, command).await,
                    CaptureCommand::AutoReplace { command } => {
                        handle_auto_replace(api, command).await
                    }
                    CaptureCommand::ResponseIntercept { command } => {
                        handle_response_intercept(api, command).await
                    }
                    CaptureCommand::InterceptRule { command } => {
                        handle_intercept_rule(api, command).await
                    }
                    CaptureCommand::Oast { command } => handle_oast(api, command).await,
                },
                Command::Scope { command } => handle_target(api, command).await,
                Command::Replay { command } => handle_replay(api, command).await,
                Command::Fuzzer { command } => handle_fuzzer(api, command).await,
                Command::Sequence { command } => handle_sequence(api, command).await,
                Command::Skills { .. } => unreachable!(),
                Command::Manifest | Command::Schema { .. } | Command::Examples { .. } => {
                    unreachable!()
                }
                Command::Call { .. } => unreachable!(),
                Command::History { command } => handle_history(api, command).await,
                Command::Intercept { command } => handle_intercept(api, command).await,
                Command::Websocket { command } => handle_websocket(api, command).await,
                Command::AutoReplace { command } => handle_auto_replace(api, command).await,
            }
        }
    }
}

fn validate_command_preflight(command: &Command) -> Result<()> {
    if let Some(args) = oast_configure_args(command) {
        if args.token.is_some() {
            bail!("--token is unsafe because it can be stored in shell history; pipe the token with --token-stdin");
        }
        if args.provider.as_deref() == Some("boast") && args.token_stdin {
            bail!("BOAST provider does not use an OAST token");
        }
    }
    if let Some(args) = history_annotate_args(command) {
        if !args.clear_color && args.color.is_none() && !args.clear_note && args.note.is_none() {
            bail!("provide at least one of --color, --clear-color, --note, or --clear-note");
        }
    }
    Ok(())
}

fn oast_configure_args(command: &Command) -> Option<&OastConfigureArgs> {
    match command {
        Command::Capture {
            command:
                CaptureCommand::Oast {
                    command: OastCommand::Configure(args),
                },
        } => Some(args),
        _ => None,
    }
}

fn history_annotate_args(command: &Command) -> Option<&HistoryAnnotateArgs> {
    match command {
        Command::Capture {
            command:
                CaptureCommand::Http {
                    command: HistoryCommand::Annotate(args),
                },
        }
        | Command::History {
            command: HistoryCommand::Annotate(args),
        } => Some(args),
        _ => None,
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
        SessionCommand::Delete(args) => {
            api.delete_status(&format!("/api/sessions/{}", args.id))
                .await?;
            print_json(&json!({
                "ok": true,
                "id": args.id,
            }))
        }
        SessionCommand::Reveal(args) => {
            let result: serde_json::Value = api
                .post_json(&format!("/api/sessions/{}/reveal", args.id), &json!({}))
                .await?;
            print_json(&result)
        }
    }
}

async fn active_session_id(api: &ApiClient) -> Result<Option<Uuid>> {
    let sessions: Vec<SessionSummary> = api.get_json("/api/sessions").await?;
    active_session_id_from_summaries(&sessions)
}

fn active_session_id_from_summaries(sessions: &[SessionSummary]) -> Result<Option<Uuid>> {
    let active_sessions: Vec<_> = sessions.iter().filter(|session| session.active).collect();
    match active_sessions.as_slice() {
        [session] => Ok(Some(session.id)),
        [] if sessions.is_empty() => Ok(None),
        [] => bail!("no active session; pass --session-id to choose a session explicitly"),
        _ => bail!("multiple active sessions; pass --session-id to choose a session explicitly"),
    }
}

async fn resolve_session_id_arg(
    api: &ApiClient,
    explicit_session_id: Option<Uuid>,
) -> Result<Option<Uuid>> {
    let active_session_id = if explicit_session_id.is_some() {
        None
    } else {
        active_session_id(api).await?
    };
    Ok(explicit_or_active_session_id(
        explicit_session_id,
        active_session_id,
    ))
}

fn explicit_or_active_session_id(
    explicit_session_id: Option<Uuid>,
    active_session_id: Option<Uuid>,
) -> Option<Uuid> {
    explicit_session_id.or(active_session_id)
}

fn session_id_for_write_payload(explicit_session_id: Option<Uuid>) -> Option<Uuid> {
    explicit_session_id
}

fn sequence_write_session_id(
    cli_session_id: Option<Uuid>,
    input_session_id: Option<Uuid>,
    active_session_id: Option<Uuid>,
) -> Result<Option<Uuid>> {
    if let Some(input_session_id) = input_session_id {
        let Some(cli_session_id) = cli_session_id else {
            bail!("sequence JSON session_id requires matching --session-id");
        };
        if cli_session_id != input_session_id {
            bail!("sequence JSON session_id conflicts with --session-id");
        }
        return Ok(Some(cli_session_id));
    }
    Ok(explicit_or_active_session_id(
        session_id_for_write_payload(cli_session_id),
        active_session_id,
    ))
}

fn auto_replace_write_session_id(
    cli_session_id: Option<Uuid>,
    input_session_id: Option<Uuid>,
) -> Result<Option<Uuid>> {
    if let Some(input_session_id) = input_session_id {
        let Some(cli_session_id) = cli_session_id else {
            bail!("auto-replace JSON session_id requires matching --session-id");
        };
        if cli_session_id != input_session_id {
            bail!("auto-replace JSON session_id conflicts with --session-id");
        }
        return Ok(Some(cli_session_id));
    }
    Ok(session_id_for_write_payload(cli_session_id))
}

async fn handle_history(api: ApiClient, command: HistoryCommand) -> Result<()> {
    match command {
        HistoryCommand::List(args) => {
            let include_page = args.page;
            let session_id = match args.session_id {
                Some(session_id) => Some(session_id),
                None => active_session_id(&api).await?,
            };
            let path = history_list_path(session_id, &args)?;
            let history: HistoryListResponse = api.get_json(&path).await?;
            print_json(&history.into_cli_output(include_page))
        }
        HistoryCommand::Get(args) => {
            let session_id = match args.session_id {
                Some(session_id) => Some(session_id),
                None => active_session_id(&api).await?,
            };
            let record: TransactionRecord = api
                .get_json(&transaction_detail_path(args.id, session_id))
                .await?;
            print_json(&record)
        }
        HistoryCommand::Replay(args) => {
            let (session_id, tab) = open_replay_tab(
                &api,
                ReplayOpenInput {
                    session_id: args.session_id,
                    transaction_id: Some(args.id),
                    request_file: None,
                    stdin: false,
                    scheme: args.scheme,
                    host: args.host,
                    port: args.port,
                },
            )
            .await?;
            print_json_with_session(&tab, session_id)
        }
        HistoryCommand::Fuzzer(args) => {
            let mut workspace = load_workspace_state(&api, args.session_id).await?;
            let (base_request, source_transaction_id, request_text) =
                resolve_request_source(&api, workspace.session_id, Some(args.id), None, false)
                    .await?;
            let target = build_optional_target_override(
                args.scheme,
                args.host,
                args.port,
                base_request.as_ref(),
            )?;
            let target_request_authority = target
                .as_ref()
                .and(base_request.as_ref())
                .map(fuzzer_target_request_authority_for_request);
            workspace.fuzzer.base_request = base_request;
            workspace.fuzzer.source_transaction_id = source_transaction_id;
            workspace.fuzzer.target = target;
            workspace.fuzzer.target_request_authority = target_request_authority;
            workspace.fuzzer.request_text = request_text;
            workspace.fuzzer.notice.clear();
            workspace.fuzzer.clear_attack_record_reference();
            let snapshot = post_workspace_state(&api, &mut workspace, args.session_id).await?;
            print_json_with_session(&snapshot.fuzzer, workspace.session_id)
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
            let payload = build_annotations_payload(color_tag, user_note);
            let (session_id, expected_active_session_id) =
                runtime_write_session_ids(&api, args.session_id).await?;
            let path = session_query_path_with_expected_active(
                &format!("/api/transactions/{}/annotations", args.id),
                session_id,
                expected_active_session_id,
            );
            let summary: TransactionSummary = api
                .request_json(Method::PATCH, &path, Some(&payload))
                .await?;
            print_json_with_session(&summary, session_id)
        }
    }
}

fn build_annotations_payload(
    color_tag: Option<Option<String>>,
    user_note: Option<Option<String>>,
) -> Value {
    let mut payload = serde_json::Map::new();
    if let Some(value) = color_tag {
        payload.insert("color_tag".to_string(), json!(value));
    }
    if let Some(value) = user_note {
        payload.insert("user_note".to_string(), json!(value));
    }
    payload.insert(
        "client_id".to_string(),
        json!(next_cli_annotation_client_id()),
    );
    payload.insert(
        "client_version".to_string(),
        json!(next_cli_annotation_client_version()),
    );
    Value::Object(payload)
}

fn next_cli_annotation_client_version() -> u64 {
    1
}

fn next_cli_annotation_client_id() -> String {
    format!("{CLI_WORKSPACE_CLIENT_ID}:{}", Uuid::new_v4())
}

fn oast_fields_for_output(
    runtime: serde_json::Value,
) -> serde_json::Map<String, serde_json::Value> {
    let mut fields: serde_json::Map<String, serde_json::Value> = runtime
        .as_object()
        .map(|object| {
            object
                .iter()
                .filter(|(key, _)| key.starts_with("oast_") && key.as_str() != "oast_token")
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        })
        .unwrap_or_default();
    let token_configured = runtime
        .get("oast_token")
        .and_then(|value| value.as_str())
        .is_some_and(|value| !value.is_empty());
    fields.insert("oast_token_configured".to_string(), json!(token_configured));
    fields
}

async fn handle_target(api: ApiClient, command: TargetCommand) -> Result<()> {
    match command {
        TargetCommand::GetScope(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path = session_query_path("/api/runtime", session_id);
            let runtime: RuntimeSettingsSnapshot = api.get_json(&path).await?;
            print_json(&ScopeOutput {
                scope_patterns: runtime.scope_patterns,
            })
        }
        TargetCommand::SetScope(args) => {
            let (session_id, expected_active_session_id) =
                runtime_write_session_ids(&api, args.session_id).await?;
            let scope_patterns = if args.clear {
                Vec::new()
            } else {
                read_lines_input(args.patterns, args.file, args.stdin)?
            };
            let runtime: RuntimeSettingsSnapshot = api
                .post_json(
                    "/api/runtime",
                    &RuntimeUpdatePayload {
                        session_id,
                        expected_active_session_id,
                        intercept_enabled: None,
                        websocket_capture_enabled: None,
                        scope_patterns: Some(scope_patterns),
                    },
                )
                .await?;
            print_json_with_session(
                &ScopeOutput {
                    scope_patterns: runtime.scope_patterns,
                },
                session_id,
            )
        }
    }
}

async fn handle_replay(api: ApiClient, command: ReplayCommand) -> Result<()> {
    match command {
        ReplayCommand::List(args) => {
            let workspace = load_workspace_state(&api, args.session_id).await?;
            print_json(&workspace.replay)
        }
        ReplayCommand::Open(args) => {
            let (session_id, tab) = open_replay_tab(
                &api,
                ReplayOpenInput {
                    session_id: args.session_id,
                    transaction_id: args.transaction_id,
                    request_file: args.request_file,
                    stdin: args.stdin,
                    scheme: args.scheme,
                    host: args.host,
                    port: args.port,
                },
            )
            .await?;
            print_json_with_session(&tab, session_id)
        }
        ReplayCommand::Update(args) => {
            let mut workspace = load_workspace_state(&api, args.session_id).await?;
            let tab = find_replay_tab_mut(&mut workspace.replay, &args.tab_id)?;
            ensure_http_replay_tab(tab, &args.tab_id)?;
            let explicit_target_update =
                args.scheme.is_some() || args.host.is_some() || args.port.is_some();
            if args.request_file.is_some() || args.stdin {
                let (parsed_request, request_text) = read_raw_request_input(
                    args.request_file,
                    args.stdin,
                    tab.base_request.as_ref(),
                )?;
                if !request_text.trim().is_empty() {
                    tab.request_text = request_text;
                    tab.base_request = Some(parsed_request.request.clone());
                    tab.http_version_mode = parsed_request.http_version.unwrap_or_default();
                    tab.response_record = None;
                    tab.notice.clear();
                }
            }
            if explicit_target_update {
                let current_target_fallback = replay_tab_target_as_request(tab);
                let preserve_current_port = replay_update_should_preserve_current_port(
                    args.scheme.as_deref(),
                    args.host.as_deref(),
                    args.port.as_deref(),
                    tab.target_scheme.as_str(),
                    tab.target_port.as_str(),
                );
                let mut normalized = normalize_target_inputs(
                    args.scheme.clone(),
                    args.host.clone(),
                    args.port.clone(),
                    current_target_fallback
                        .as_ref()
                        .or(tab.base_request.as_ref()),
                )?;
                if preserve_current_port {
                    normalized.port = normalize_replay_port(&tab.target_port)?;
                }
                if !normalized.scheme.is_empty() {
                    tab.target_scheme = normalized.scheme;
                }
                if !normalized.host.is_empty() {
                    tab.target_host = normalized.host;
                }
                if !normalized.port.is_empty() {
                    tab.target_port = normalized.port;
                }
                tab.response_record = None;
            }
            let snapshot = post_workspace_state(&api, &mut workspace, args.session_id).await?;
            let tab = find_replay_tab(&snapshot.replay, &args.tab_id)?;
            print_json_with_session(tab, workspace.session_id)
        }
        ReplayCommand::Send(args) => {
            let mut workspace = load_workspace_state(&api, args.session_id).await?;
            let tab = find_replay_tab_mut(&mut workspace.replay, &args.tab_id)?.clone();
            ensure_http_replay_tab(&tab, &args.tab_id)?;
            let parsed_request = parse_editable_raw_request_with_version(
                &tab.request_text,
                tab.base_request.as_ref(),
            )?;
            let http_version = replay_send_http_version(&tab, &parsed_request);
            let request = parsed_request.request;
            let target = replay_send_target_for_tab(&tab, &request)?;
            let replay_result = api
                .send_replay(&ReplaySendPayload {
                    session_id: workspace.session_id,
                    expected_active_session_id: expected_active_session_for_implicit_write(
                        &workspace,
                        args.session_id,
                    ),
                    expected_workspace_revision: Some(workspace.revision),
                    request: request.clone(),
                    target: target.clone(),
                    source_transaction_id: tab.source_transaction_id,
                    http_version,
                })
                .await?;
            let (record, replay_error) = match replay_result {
                ReplaySendApiResult::Success(record) => (record, None),
                ReplaySendApiResult::StoredError(body) => {
                    let record = body
                        .record
                        .context("replay failed without a stored transaction record")?;
                    (record, Some(body.error))
                }
            };

            let tab_mut = find_replay_tab_mut(&mut workspace.replay, &args.tab_id)?;
            tab_mut.base_request = Some(request.clone());
            if let Some(target) = target.as_ref() {
                tab_mut.target_scheme = target.scheme.clone();
                tab_mut.target_host = target.host.clone();
                tab_mut.target_port = target.port.clone();
            }
            tab_mut.response_record = Some(record.clone());
            tab_mut.notice = replay_error.clone().unwrap_or_default();
            let history_entry = ReplayHistoryEntryState {
                request: Some(request),
                request_text: tab_mut.request_text.clone(),
                http_version_mode: tab_mut.http_version_mode.clone(),
                response_record: Some(record.clone()),
                notice: replay_error.clone().unwrap_or_default(),
                target_scheme: tab_mut.target_scheme.clone(),
                target_host: tab_mut.target_host.clone(),
                target_port: tab_mut.target_port.clone(),
            };
            push_replay_history_entry(tab_mut, history_entry);

            let workspace_save_error = post_workspace_state(&api, &mut workspace, args.session_id)
                .await
                .err();
            if let Some(error) = replay_error {
                let mut output = json!({
                    "error": error.clone(),
                    "record": record,
                    "session_id": workspace.session_id,
                });
                if let Some(save_error) = workspace_save_error {
                    attach_workspace_save_error(&mut output, &save_error);
                    return Err(cli_partial_apply_error(
                        format!(
                            "replay failed after storing transaction record: {error}; workspace state was not saved: {save_error}"
                        ),
                        output,
                    ));
                }
                Err(cli_partial_apply_error(
                    format!("replay failed after storing transaction record: {error}"),
                    output,
                ))
            } else {
                let output = json_value_with_session_and_workspace_save_error(
                    &record,
                    workspace.session_id,
                    workspace_save_error.as_ref(),
                )?;
                print_json(&output)?;
                Ok(())
            }
        }
    }
}

async fn handle_fuzzer(api: ApiClient, command: FuzzerCommand) -> Result<()> {
    match command {
        FuzzerCommand::SetTemplate(args) => {
            let mut workspace = load_workspace_state(&api, args.session_id).await?;
            let (base_request, source_transaction_id, request_text) = resolve_request_source(
                &api,
                workspace.session_id,
                args.transaction_id,
                args.request_file,
                args.stdin,
            )
            .await?;
            let target = build_optional_target_override(
                args.scheme,
                args.host,
                args.port,
                base_request.as_ref(),
            )?;
            let target_request_authority = target
                .as_ref()
                .and(base_request.as_ref())
                .map(fuzzer_target_request_authority_for_request);
            workspace.fuzzer.base_request = base_request;
            workspace.fuzzer.source_transaction_id = source_transaction_id;
            workspace.fuzzer.target = target;
            workspace.fuzzer.target_request_authority = target_request_authority;
            workspace.fuzzer.request_text = request_text;
            workspace.fuzzer.notice.clear();
            workspace.fuzzer.clear_attack_record_reference();
            let snapshot = post_workspace_state(&api, &mut workspace, args.session_id).await?;
            print_json_with_session(&snapshot.fuzzer, workspace.session_id)
        }
        FuzzerCommand::SetPayloads(args) => {
            let mut workspace = load_workspace_state(&api, args.session_id).await?;
            workspace.fuzzer.payloads_text =
                read_payloads_input(args.payloads, args.file, args.stdin)?;
            workspace.fuzzer.notice.clear();
            workspace.fuzzer.clear_attack_record_reference();
            let snapshot = post_workspace_state(&api, &mut workspace, args.session_id).await?;
            print_json_with_session(&snapshot.fuzzer, workspace.session_id)
        }
        FuzzerCommand::Run(args) => {
            let mut workspace = load_workspace_state(&api, args.session_id).await?;
            let parsed_template = parse_editable_raw_request_with_version(
                &workspace.fuzzer.request_text,
                workspace.fuzzer.base_request.as_ref(),
            )?;
            let target =
                fuzzer_active_target_for_request(&workspace.fuzzer, &parsed_template.request);
            let template = parsed_template.request;
            let payloads = split_payload_lines(&workspace.fuzzer.payloads_text);
            if payloads.is_empty() {
                bail!("fuzzer payloads are empty");
            }

            let record: FuzzerAttackRecord = api
                .post_json_long(
                    "/api/fuzzer/attacks",
                    &FuzzerRunPayload {
                        session_id: workspace.session_id,
                        expected_active_session_id: expected_active_session_for_implicit_write(
                            &workspace,
                            args.session_id,
                        ),
                        expected_workspace_revision: Some(workspace.revision),
                        template,
                        payloads,
                        source_transaction_id: workspace.fuzzer.source_transaction_id,
                        http_version: parsed_template.http_version,
                        target,
                    },
                )
                .await?;
            workspace.fuzzer.attack_record_id = Some(record.id);
            workspace.fuzzer.attack_record = None;
            workspace.fuzzer.notice.clear();
            let workspace_save_error = post_workspace_state(&api, &mut workspace, args.session_id)
                .await
                .err();

            let record_value =
                serde_json::to_value(&record).context("failed to inspect JSON status")?;
            if let Some(mut output) = failed_record_output("fuzzer attack", &record_value) {
                attach_session_id(&mut output, workspace.session_id);
                if let Some(save_error) = &workspace_save_error {
                    attach_workspace_save_error(&mut output, save_error);
                }
                if let Some(save_error) = workspace_save_error {
                    return Err(cli_partial_apply_error(
                        format!(
                            "fuzzer attack failed; workspace state was not saved: {save_error}"
                        ),
                        output,
                    ));
                }
                return Err(cli_partial_apply_error("fuzzer attack failed", output));
            }
            let record_output = json_value_with_session_and_workspace_save_error(
                &record,
                workspace.session_id,
                workspace_save_error.as_ref(),
            )?;
            if args.r#async {
                let mut async_output = json!({
                    "async_requested": true,
                    "session_id": workspace.session_id,
                    "message": "Fuzzer attack completed. The current Sniper API creates attacks synchronously, so the CLI waits until the server returns the attack record.",
                    "attack": record,
                });
                if let Some(save_error) = workspace_save_error.as_ref() {
                    attach_workspace_save_error(&mut async_output, save_error);
                }
                print_json(&async_output)?;
            } else {
                print_json(&record_output)?;
            }
            Ok(())
        }
        FuzzerCommand::Status(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let record: FuzzerAttackRecord = api
                .get_json(&session_query_path(
                    &format!("/api/fuzzer/attacks/{}", args.id),
                    session_id,
                ))
                .await?;
            print_json(&json!({
                "id": record.id,
                "status": record.status,
                "started_at": record.started_at,
                "completed_at": record.completed_at,
                "payload_count": record.payload_count,
                "result_count": record.results.len(),
                "marker_count": record.marker_count,
            }))
        }
        FuzzerCommand::Results(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let record: FuzzerAttackRecord = api
                .get_json(&session_query_path(
                    &format!("/api/fuzzer/attacks/{}", args.id),
                    session_id,
                ))
                .await?;
            print_json(&record)
        }
        FuzzerCommand::List(args) => {
            let mut params = Vec::new();
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            if let Some(session_id) = session_id {
                params.push(("session_id".to_string(), session_id.to_string()));
            }
            if let Some(limit) = args.limit {
                params.push(("limit".to_string(), limit.to_string()));
            }
            let query = encode_query(params);
            let path = if query.is_empty() {
                "/api/fuzzer/attacks".to_string()
            } else {
                format!("/api/fuzzer/attacks?{query}")
            };
            let attacks: Vec<serde_json::Value> = api.get_json(&path).await?;
            print_json(&attacks)
        }
    }
}

async fn handle_intercept(api: ApiClient, command: InterceptCommand) -> Result<()> {
    match command {
        InterceptCommand::On(args) => {
            let (session_id, expected_active_session_id) =
                runtime_write_session_ids(&api, args.session_id).await?;
            let runtime: RuntimeSettingsSnapshot = api
                .post_json(
                    "/api/runtime",
                    &RuntimeUpdatePayload {
                        session_id,
                        expected_active_session_id,
                        intercept_enabled: Some(true),
                        websocket_capture_enabled: None,
                        scope_patterns: None,
                    },
                )
                .await?;
            print_json_with_session(&runtime, session_id)
        }
        InterceptCommand::Off(args) => {
            let (session_id, expected_active_session_id) =
                runtime_write_session_ids(&api, args.session_id).await?;
            let runtime: RuntimeSettingsSnapshot = api
                .post_json(
                    "/api/runtime",
                    &RuntimeUpdatePayload {
                        session_id,
                        expected_active_session_id,
                        intercept_enabled: Some(false),
                        websocket_capture_enabled: None,
                        scope_patterns: None,
                    },
                )
                .await?;
            print_json_with_session(&runtime, session_id)
        }
        InterceptCommand::List(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path = session_query_path("/api/intercepts", session_id);
            let intercepts: Vec<InterceptSummary> = api.get_json(&path).await?;
            print_json(&intercepts)
        }
        InterceptCommand::Forward(args) => {
            let read_session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let expected_active_session_id = if args.session_id.is_none() {
                read_session_id
            } else {
                None
            };
            let detail_path =
                session_query_path(&format!("/api/intercepts/{}", args.id), read_session_id);
            let intercept: InterceptRecord = api.get_json(&detail_path).await?;
            let request = if args.request_file.is_some() || args.stdin {
                read_raw_request_input(args.request_file, args.stdin, Some(&intercept.request))?
                    .0
                    .request
            } else {
                intercept.request
            };
            let session_id = read_session_id;
            let action_path = session_query_path_with_expected_active(
                &format!("/api/intercepts/{}/forward", args.id),
                read_session_id,
                expected_active_session_id,
            );
            api.post_status(&action_path, &InterceptForwardPayload { request })
                .await?;
            print_json(&InterceptActionResult {
                ok: true,
                action: "forward",
                id: args.id,
                session_id,
            })
        }
        InterceptCommand::Drop(args) => {
            let (session_id, expected_active_session_id) =
                runtime_write_session_ids(&api, args.session_id).await?;
            let path = session_query_path_with_expected_active(
                &format!("/api/intercepts/{}/drop", args.id),
                session_id,
                expected_active_session_id,
            );
            api.post_status(&path, &json!({})).await?;
            print_json(&InterceptActionResult {
                ok: true,
                action: "drop",
                id: args.id,
                session_id,
            })
        }
        InterceptCommand::ForwardAll(args) => {
            let (session_id, expected_active_session_id) =
                runtime_write_session_ids(&api, args.session_id).await?;
            let path = session_query_path_with_expected_active(
                "/api/intercepts/forward-all",
                session_id,
                expected_active_session_id,
            );
            let mut result: serde_json::Value = api
                .post_json_or_no_content(&path, &json!({}))
                .await?
                .unwrap_or_else(|| {
                    json!({
                        "ok": true,
                        "action": "forward-all",
                    })
                });
            attach_session_id(&mut result, session_id);
            print_json(&result)
        }
    }
}

async fn handle_websocket(api: ApiClient, command: WebSocketCommand) -> Result<()> {
    match command {
        WebSocketCommand::List(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path = websocket_list_path(session_id, &args);
            let websockets: WebSocketListResponse = api.get_json(&path).await?;
            print_json(&websockets.into_cli_output(args.page))
        }
        WebSocketCommand::Get(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let websocket: WebSocketSessionRecord = api
                .get_json(&websocket_detail_path(
                    args.id,
                    session_id,
                    args.frame_limit,
                    args.before_index,
                ))
                .await?;
            print_json(&websocket)
        }
    }
}

async fn handle_auto_replace(api: ApiClient, command: AutoReplaceCommand) -> Result<()> {
    match command {
        AutoReplaceCommand::List(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path = session_query_path("/api/match-replace", session_id);
            let rules: Vec<MatchReplaceRule> = api.get_json(&path).await?;
            print_json(&rules)
        }
        AutoReplaceCommand::Set(args) => {
            let raw = read_text_input(args.file, args.stdin)?;
            let parsed: AutoReplaceInput = serde_json::from_str(&raw).context(
                "failed to parse auto-replace JSON; expected either an array of rules or {\"rules\": [...]}",
            )?;
            let (payload, input_session_id) = match parsed {
                AutoReplaceInput::Rules(rules) => (
                    MatchReplaceRulesPayload {
                        session_id: None,
                        rules,
                    },
                    None,
                ),
                AutoReplaceInput::Payload(payload) => (
                    MatchReplaceRulesPayload {
                        session_id: None,
                        rules: payload.rules,
                    },
                    payload.session_id,
                ),
            };
            let session_id = auto_replace_write_session_id(args.session_id, input_session_id)?;
            let expected_active_session_id = if session_id.is_none() {
                active_session_id(&api).await?
            } else {
                None
            };
            let path = session_query_path_with_expected_active(
                "/api/match-replace",
                session_id.or(expected_active_session_id),
                expected_active_session_id,
            );
            let rules: Vec<MatchReplaceRule> = api.post_json(&path, &payload).await?;
            print_json(&rules)
        }
    }
}

async fn handle_response_intercept(
    api: ApiClient,
    command: ResponseInterceptCommand,
) -> Result<()> {
    match command {
        ResponseInterceptCommand::List(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path = session_query_path("/api/response-intercepts", session_id);
            let items: Vec<ResponseInterceptSummary> = api.get_json(&path).await?;
            print_json(&items)
        }
        ResponseInterceptCommand::Get(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path =
                session_query_path(&format!("/api/response-intercepts/{}", args.id), session_id);
            let item: ResponseInterceptRecord = api.get_json(&path).await?;
            print_json(&item)
        }
        ResponseInterceptCommand::Forward(args) => {
            let read_session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let expected_active_session_id = if args.session_id.is_none() {
                read_session_id
            } else {
                None
            };
            let detail_path = session_query_path(
                &format!("/api/response-intercepts/{}", args.id),
                read_session_id,
            );
            let item: ResponseInterceptRecord = api.get_json(&detail_path).await?;
            let response = if args.response_file.is_some() || args.stdin {
                read_raw_response_input(
                    args.response_file,
                    args.stdin,
                    Some(&item.response),
                    &item.method,
                )?
            } else {
                item.response
            };
            let session_id = read_session_id;
            let action_path = session_query_path_with_expected_active(
                &format!("/api/response-intercepts/{}/forward", args.id),
                read_session_id,
                expected_active_session_id,
            );
            api.post_status(&action_path, &ResponseInterceptForwardPayload { response })
                .await?;
            print_json(&InterceptActionResult {
                ok: true,
                action: "forward",
                id: args.id,
                session_id,
            })
        }
        ResponseInterceptCommand::Drop(args) => {
            let (session_id, expected_active_session_id) =
                runtime_write_session_ids(&api, args.session_id).await?;
            let path = session_query_path_with_expected_active(
                &format!("/api/response-intercepts/{}/drop", args.id),
                session_id,
                expected_active_session_id,
            );
            api.post_status(&path, &json!({})).await?;
            print_json(&InterceptActionResult {
                ok: true,
                action: "drop",
                id: args.id,
                session_id,
            })
        }
        ResponseInterceptCommand::ForwardAll(args) => {
            let (session_id, expected_active_session_id) =
                runtime_write_session_ids(&api, args.session_id).await?;
            let path = session_query_path_with_expected_active(
                "/api/response-intercepts/forward-all",
                session_id,
                expected_active_session_id,
            );
            let mut result: serde_json::Value = api
                .post_json_or_no_content(&path, &json!({}))
                .await?
                .unwrap_or_else(|| {
                    json!({
                        "ok": true,
                        "action": "forward-all",
                    })
                });
            attach_session_id(&mut result, session_id);
            print_json(&result)
        }
    }
}

async fn handle_intercept_rule(api: ApiClient, command: InterceptRuleCommand) -> Result<()> {
    match command {
        InterceptRuleCommand::List(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path = session_query_path("/api/intercept-rules", session_id);
            let rules: Vec<InterceptRule> = api.get_json(&path).await?;
            print_json(&rules)
        }
        InterceptRuleCommand::Create(args) => {
            let (session_id, expected_active_session_id) =
                runtime_write_session_ids(&api, args.session_id).await?;
            let _explicit_all = args.all;
            let rule = json!({
                "id": Uuid::new_v4(),
                "enabled": args.enabled.unwrap_or(true),
                "scope": args.scope,
                "host_pattern": args.host_pattern.unwrap_or_default(),
                "path_pattern": args.path_pattern.unwrap_or_default(),
                "method_filter": if args.method_filter.is_empty() { vec![] } else { args.method_filter },
            });
            let path = session_query_path_with_expected_active(
                "/api/intercept-rules",
                session_id,
                expected_active_session_id,
            );
            api.post_status(&path, &rule).await?;
            print_json_with_session(&rule, session_id)
        }
        InterceptRuleCommand::Delete(args) => {
            let (session_id, expected_active_session_id) =
                runtime_write_session_ids(&api, args.session_id).await?;
            let path = session_query_path_with_expected_active(
                &format!("/api/intercept-rules/{}", args.id),
                session_id,
                expected_active_session_id,
            );
            api.delete_status(&path).await?;
            print_json(&json!({ "ok": true, "deleted": args.id, "session_id": session_id }))
        }
    }
}

async fn handle_sequence(api: ApiClient, command: SequenceCommand) -> Result<()> {
    match command {
        SequenceCommand::List(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path = session_query_path("/api/sequences", session_id);
            let defs: Vec<SequenceDefinition> = api.get_json(&path).await?;
            print_json(&defs)
        }
        SequenceCommand::Get(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path = session_query_path(&format!("/api/sequences/{}", args.id), session_id);
            let def: SequenceDefinition = api.get_json(&path).await?;
            print_json(&def)
        }
        SequenceCommand::Create(args) => {
            let SequenceCreateArgs {
                file,
                stdin,
                session_id,
            } = args;
            let raw = read_text_input(file, stdin)?;
            let input: SequenceCreateInput =
                serde_json::from_str(&raw).context("failed to parse sequence JSON")?;
            let active_session_id = if session_id.is_none() && input.session_id.is_none() {
                active_session_id(&api).await?
            } else {
                None
            };
            let session_id =
                sequence_write_session_id(session_id, input.session_id, active_session_id)?;
            let def = input.definition;
            let expected_active_session_id = active_session_id;
            api.post_status(
                "/api/sequences",
                &SequenceUpsertPayload {
                    session_id,
                    expected_active_session_id,
                    definition: &def,
                },
            )
            .await?;
            print_json_with_session(&def, session_id)
        }
        SequenceCommand::Run(args) => {
            let workspace = load_workspace_state(&api, args.session_id).await?;
            let session_id = workspace.session_id;
            let mut result: serde_json::Value = api
                .post_json_long(
                    &format!("/api/sequences/{}/run", args.id),
                    &SequenceRunPayload {
                        session_id,
                        expected_active_session_id: expected_active_session_for_implicit_write(
                            &workspace,
                            args.session_id,
                        ),
                    },
                )
                .await?;
            attach_session_id(&mut result, session_id);
            if let Some(mut output) = failed_record_output("sequence run", &result) {
                attach_session_id(&mut output, session_id);
                return Err(cli_partial_apply_error("sequence run failed", output));
            }
            print_json(&result)?;
            Ok(())
        }
        SequenceCommand::RunGet(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path = session_query_path(&format!("/api/sequence-runs/{}", args.id), session_id);
            let run: SequenceRunRecord = api.get_json(&path).await?;
            print_json(&run)
        }
        SequenceCommand::Delete(args) => {
            let expected_active_session_id = if args.session_id.is_none() {
                active_session_id(&api).await?
            } else {
                None
            };
            let session_id =
                explicit_or_active_session_id(args.session_id, expected_active_session_id);
            let path = session_query_path_with_expected_active(
                &format!("/api/sequences/{}", args.id),
                session_id,
                expected_active_session_id,
            );
            api.delete_status(&path).await?;
            print_json(&json!({ "ok": true, "deleted": args.id, "session_id": session_id }))
        }
        SequenceCommand::Runs(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let mut params = Vec::new();
            if let Some(limit) = args.limit {
                params.push(("limit".to_string(), limit.to_string()));
            }
            let query = encode_query(params);
            let base_path = if query.is_empty() {
                "/api/sequence-runs".to_string()
            } else {
                format!("/api/sequence-runs?{query}")
            };
            let path = session_query_path(&base_path, session_id);
            let runs: Vec<SequenceRunSummary> = api.get_json(&path).await?;
            print_json(&runs)
        }
    }
}

async fn handle_oast(api: ApiClient, command: OastCommand) -> Result<()> {
    match command {
        OastCommand::Status(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path = session_query_path("/api/oast/status", session_id);
            let status: serde_json::Value = api.get_json(&path).await?;
            print_json(&status)
        }
        OastCommand::List(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let mut params = Vec::new();
            if let Some(session_id) = session_id {
                params.push(("session_id".to_string(), session_id.to_string()));
            }
            if let Some(limit) = args.limit {
                params.push(("limit".to_string(), limit.to_string()));
            }
            let query = encode_query(params);
            let path = if query.is_empty() {
                "/api/oast/callbacks".to_string()
            } else {
                format!("/api/oast/callbacks?{query}")
            };
            let callbacks: Vec<serde_json::Value> = api.get_json(&path).await?;
            print_json(&callbacks)
        }
        OastCommand::Get(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path = session_query_path(&format!("/api/oast/callbacks/{}", args.id), session_id);
            let cb: serde_json::Value = api.get_json(&path).await?;
            print_json(&cb)
        }
        OastCommand::Generate(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path = session_query_path("/api/oast/generate", session_id);
            let result: serde_json::Value = api
                .request_json::<(), serde_json::Value>(reqwest::Method::POST, &path, None)
                .await?;
            print_json(&result)
        }
        OastCommand::Clear(args) => {
            let (session_id, expected_active_session_id) =
                runtime_write_session_ids(&api, args.session_id).await?;
            let path = session_query_path_with_expected_active(
                "/api/oast/callbacks/clear",
                session_id,
                expected_active_session_id,
            );
            api.post_status(&path, &serde_json::json!({})).await?;
            print_json(&serde_json::json!({"status": "cleared", "session_id": session_id}))
        }
        OastCommand::Configure(args) => {
            let (session_id, expected_active_session_id) =
                runtime_write_session_ids(&api, args.session_id).await?;
            if args.token.is_some() {
                bail!("--token is unsafe because it can be stored in shell history; pipe the token with --token-stdin");
            }
            if args.provider.as_deref() == Some("boast") && args.token_stdin {
                bail!("BOAST provider does not use an OAST token");
            }
            let stdin_token = if args.token_stdin {
                Some(read_secret_stdin("OAST token")?)
            } else {
                None
            };
            let update = build_oast_configure_update(
                &args,
                stdin_token.as_deref(),
                session_id,
                expected_active_session_id,
            );
            let identity_field_count = usize::from(session_id.is_some())
                + usize::from(expected_active_session_id.is_some());
            if update.len() == identity_field_count {
                // Just show current settings
                let path = session_query_path("/api/runtime", session_id);
                let runtime: serde_json::Value = api.get_json(&path).await?;
                let mut output = Value::Object(oast_fields_for_output(runtime));
                attach_session_id(&mut output, session_id);
                print_json(&output)
            } else {
                let result: serde_json::Value = api
                    .post_json("/api/runtime", &serde_json::Value::Object(update))
                    .await?;
                let mut output = Value::Object(oast_fields_for_output(result));
                attach_session_id(&mut output, session_id);
                print_json(&output)
            }
        }
    }
}

fn build_oast_configure_update(
    args: &OastConfigureArgs,
    stdin_token: Option<&str>,
    session_id: Option<Uuid>,
    expected_active_session_id: Option<Uuid>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut update = serde_json::Map::new();
    if let Some(session_id) = session_id {
        update.insert("session_id".into(), serde_json::json!(session_id));
    }
    if let Some(expected_active_session_id) = expected_active_session_id {
        update.insert(
            "expected_active_session_id".into(),
            serde_json::json!(expected_active_session_id),
        );
    }
    if let Some(provider) = args.provider.as_deref() {
        update.insert(
            "oast_provider".into(),
            serde_json::Value::String(provider.to_string()),
        );
    }
    if let Some(url) = args.url.as_deref() {
        update.insert(
            "oast_server_url".into(),
            serde_json::Value::String(url.to_string()),
        );
    }
    if let Some(token) = stdin_token {
        update.insert(
            "oast_token".into(),
            serde_json::Value::String(token.to_string()),
        );
    }
    if let Some(interval) = args.interval {
        update.insert(
            "oast_polling_interval_secs".into(),
            serde_json::json!(interval),
        );
    }
    if args.enable {
        update.insert("oast_enabled".into(), serde_json::Value::Bool(true));
    }
    if args.disable {
        update.insert("oast_enabled".into(), serde_json::Value::Bool(false));
    }
    update
}

struct ReplayOpenInput {
    session_id: Option<Uuid>,
    transaction_id: Option<Uuid>,
    request_file: Option<PathBuf>,
    stdin: bool,
    scheme: Option<String>,
    host: Option<String>,
    port: Option<String>,
}

async fn open_replay_tab(
    api: &ApiClient,
    input: ReplayOpenInput,
) -> Result<(Option<Uuid>, ReplayTabState)> {
    let ReplayOpenInput {
        session_id,
        transaction_id,
        request_file,
        stdin,
        scheme,
        host,
        port,
    } = input;
    let mut workspace = load_workspace_state(api, session_id).await?;
    let (base_request, source_transaction_id, request_text) = resolve_request_source(
        api,
        workspace.session_id,
        transaction_id,
        request_file,
        stdin,
    )
    .await?;
    let normalized = normalize_target_inputs(scheme, host, port, base_request.as_ref())?;
    let sequence = next_replay_tab_sequence(&workspace.replay)?;
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
        ..Default::default()
    };
    // Refuse before pushing: past the cap the server rejects every
    // workspace-state save, which strands the UI in a save-retry loop that
    // even deleting tabs cannot clear.
    if workspace.replay.tabs.len() >= sniper::workspace::MAX_WORKSPACE_REPLAY_TABS {
        bail!(
            "workspace already has {} replay tabs (limit {}); close some before opening more",
            workspace.replay.tabs.len(),
            sniper::workspace::MAX_WORKSPACE_REPLAY_TABS
        );
    }
    workspace.replay.tab_sequence = sequence;
    workspace.replay.active_tab_id = Some(tab.id.clone());
    workspace.replay.tabs.push(tab.clone());
    let snapshot = post_workspace_state(api, &mut workspace, session_id).await?;
    let tab = find_replay_tab(&snapshot.replay, &tab.id)?;
    Ok((workspace.session_id, tab.clone()))
}

fn next_replay_tab_sequence(replay: &ReplayWorkspaceState) -> Result<usize> {
    let current = replay
        .tabs
        .iter()
        .map(|tab| tab.sequence)
        .max()
        .unwrap_or(0)
        .max(replay.tab_sequence);
    current
        .checked_add(1)
        .context("replay tab sequence is too large; save the workspace from the app to repair it")
}

fn replay_tab_target_as_request(tab: &ReplayTabState) -> Option<EditableRequest> {
    let scheme = tab.target_scheme.trim();
    let host = tab.target_host.trim();
    let port = tab.target_port.trim();
    if scheme.is_empty() || host.is_empty() {
        return None;
    }
    let default_port = default_port_for_scheme(scheme).to_string();
    let host = if port.is_empty() || port == default_port {
        host.to_string()
    } else {
        let port = normalize_replay_port(port).ok()?.parse::<u16>().ok()?;
        format_request_authority(host, Some(port))
    };
    Some(EditableRequest {
        scheme: scheme.to_string(),
        host,
        method: "GET".to_string(),
        path: "/".to_string(),
        headers: Vec::new(),
        body: String::new(),
        body_encoding: BodyEncoding::Utf8,
        preview_truncated: false,
    })
}

fn push_replay_history_entry(tab: &mut ReplayTabState, entry: ReplayHistoryEntryState) {
    if let Some(index) = tab.history_index {
        if !tab.history_entries.is_empty() {
            let normalized_index = index.min(tab.history_entries.len() - 1);
            tab.history_entries.truncate(normalized_index + 1);
        }
    }
    tab.history_entries.push(entry);
    if tab.history_entries.len() > CLI_REPEATER_HISTORY_LIMIT {
        let overflow = tab.history_entries.len() - CLI_REPEATER_HISTORY_LIMIT;
        tab.history_entries.drain(0..overflow);
    }
    tab.history_index = tab.history_entries.len().checked_sub(1);
}

fn replay_update_should_preserve_current_port(
    scheme: Option<&str>,
    host: Option<&str>,
    port: Option<&str>,
    current_scheme: &str,
    current_port: &str,
) -> bool {
    if port.is_some_and(|value| !value.trim().is_empty()) || current_port.trim().is_empty() {
        return false;
    }
    if scheme.is_some_and(|value| !value.trim().is_empty()) {
        let Ok(current_port) = normalize_replay_port(current_port) else {
            return false;
        };
        if current_port == default_port_for_scheme(current_scheme).to_string() {
            return false;
        }
    }
    let Some(host) = host.map(str::trim).filter(|value| !value.is_empty()) else {
        return true;
    };
    if host.starts_with("http://") || host.starts_with("https://") {
        return false;
    }
    split_host_port(host).is_none()
}

async fn resolve_request_source(
    api: &ApiClient,
    session_id: Option<Uuid>,
    transaction_id: Option<Uuid>,
    request_file: Option<PathBuf>,
    stdin: bool,
) -> Result<(Option<EditableRequest>, Option<Uuid>, String)> {
    if let Some(transaction_id) = transaction_id {
        let record: TransactionRecord = api
            .get_json(&transaction_detail_path(transaction_id, session_id))
            .await?;
        let request = record.editable_request();
        let request_text =
            build_editable_raw_request_with_version(&request, record.http_version.as_deref());
        return Ok((Some(request), Some(transaction_id), request_text));
    }

    if request_file.is_some() || stdin {
        let (parsed, request_text) = read_raw_request_input(request_file, stdin, None)?;
        return Ok((Some(parsed.request), None, request_text));
    }

    let request = default_editable_request();
    let request_text = build_editable_raw_request(&request);
    Ok((Some(request), None, request_text))
}

fn transaction_detail_path(transaction_id: Uuid, session_id: Option<Uuid>) -> String {
    match session_id {
        Some(session_id) => {
            let query = encode_query(vec![("session_id".to_string(), session_id.to_string())]);
            format!("/api/transactions/{transaction_id}?{query}")
        }
        None => format!("/api/transactions/{transaction_id}"),
    }
}

fn history_list_path(session_id: Option<Uuid>, args: &HistoryListArgs) -> Result<String> {
    validate_history_cursor_options(args)?;
    let mut params = Vec::new();
    if let Some(session_id) = session_id {
        params.push(("session_id".to_string(), session_id.to_string()));
    }
    if let Some(query) = args
        .query
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        params.push(("q".to_string(), query.to_string()));
    }
    if let Some(method) = args
        .method
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        params.push(("method".to_string(), method.to_string()));
    }
    if let Some(limit) = args.limit {
        params.push(("limit".to_string(), limit.to_string()));
    }
    if let Some(offset) = args.offset {
        params.push(("offset".to_string(), offset.to_string()));
    }
    if let Some(before_sequence) = args.before_sequence {
        params.push(("before_sequence".to_string(), before_sequence.to_string()));
    }
    if let Some(host) = args
        .host
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        params.push(("host".to_string(), host.to_string()));
    }
    if let Some(status) = args.status {
        params.push(("status".to_string(), status.to_string()));
    }
    if let Some(status_range) = args
        .status_range
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        params.push(("status_range".to_string(), status_range.to_string()));
    }
    if let Some(since) = args
        .since
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        params.push(("since".to_string(), since.to_string()));
    }
    if let Some(mime) = args
        .mime
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        params.push(("mime".to_string(), mime.to_string()));
    }
    let sort_key = args
        .sort_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(sort_key) = sort_key {
        params.push(("sort_key".to_string(), sort_key.to_string()));
    } else if args.before_sequence.is_some() {
        params.push(("sort_key".to_string(), "index".to_string()));
    }
    let sort_direction = args
        .sort_direction
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(sort_direction) = sort_direction {
        params.push(("sort_direction".to_string(), sort_direction.to_string()));
    } else if args.before_sequence.is_some() {
        params.push(("sort_direction".to_string(), "desc".to_string()));
    }
    let endpoint = if args.page
        || args.offset.is_some()
        || args.before_sequence.is_some()
        || sort_key.is_some()
        || sort_direction.is_some()
    {
        "/api/transactions-page"
    } else {
        "/api/transactions"
    };
    let query = encode_query(params);
    Ok(if query.is_empty() {
        endpoint.to_string()
    } else {
        format!("{endpoint}?{query}")
    })
}

fn validate_history_cursor_options(args: &HistoryListArgs) -> Result<()> {
    if args.before_sequence.is_none() {
        return Ok(());
    }
    if args.offset.is_some() {
        bail!("--before-sequence cannot be combined with --offset");
    }

    let sort_key = args
        .sort_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("index");
    let sort_direction = args
        .sort_direction
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("desc");
    if sort_key != "index" || !sort_direction.eq_ignore_ascii_case("desc") {
        bail!("--before-sequence requires --sort-key index and --sort-direction desc");
    }
    Ok(())
}

fn websocket_list_path(session_id: Option<Uuid>, args: &WebSocketListArgs) -> String {
    let mut params = Vec::new();
    if let Some(session_id) = session_id {
        params.push(("session_id".to_string(), session_id.to_string()));
    }
    if let Some(query) = args
        .query
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        params.push(("q".to_string(), query.to_string()));
    }
    if let Some(limit) = args.limit {
        params.push(("limit".to_string(), limit.to_string()));
    }
    if let Some(offset) = args.offset {
        params.push(("offset".to_string(), offset.to_string()));
    }
    let sort_key = args
        .sort_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(sort_key) = sort_key {
        params.push(("sort_key".to_string(), sort_key.to_string()));
    }
    let sort_direction = args
        .sort_direction
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(sort_direction) = sort_direction {
        params.push(("sort_direction".to_string(), sort_direction.to_string()));
    }
    if args.in_scope_only {
        params.push(("in_scope_only".to_string(), "true".to_string()));
    }
    if args.live_only {
        params.push(("live_only".to_string(), "true".to_string()));
    }
    let endpoint = if args.page
        || args.offset.is_some()
        || sort_key.is_some()
        || sort_direction.is_some()
        || args.in_scope_only
        || args.live_only
    {
        "/api/websockets-page"
    } else {
        "/api/websockets"
    };
    let query = encode_query(params);
    if query.is_empty() {
        endpoint.to_string()
    } else {
        format!("{endpoint}?{query}")
    }
}

fn websocket_detail_path(
    websocket_id: Uuid,
    session_id: Option<Uuid>,
    frame_limit: Option<usize>,
    before_index: Option<usize>,
) -> String {
    let mut params = Vec::new();
    if let Some(session_id) = session_id {
        params.push(("session_id".to_string(), session_id.to_string()));
    }
    params.push((
        "frame_limit".to_string(),
        websocket_detail_frame_limit(frame_limit).to_string(),
    ));
    if let Some(before_index) = before_index {
        params.push(("before_index".to_string(), before_index.to_string()));
    }
    let query = encode_query(params);
    if query.is_empty() {
        format!("/api/websockets/{websocket_id}")
    } else {
        format!("/api/websockets/{websocket_id}?{query}")
    }
}

fn websocket_detail_frame_limit(frame_limit: Option<usize>) -> usize {
    frame_limit
        .unwrap_or(DEFAULT_WEBSOCKET_DETAIL_FRAME_LIMIT)
        .min(MAX_WEBSOCKET_DETAIL_FRAME_LIMIT)
}

fn session_query_path(path: &str, session_id: Option<Uuid>) -> String {
    session_query_path_with_expected_active(path, session_id, None)
}

fn session_query_path_with_expected_active(
    path: &str,
    session_id: Option<Uuid>,
    expected_active_session_id: Option<Uuid>,
) -> String {
    let mut params = Vec::new();
    if let Some(session_id) = session_id {
        params.push(("session_id".to_string(), session_id.to_string()));
    }
    if let Some(expected_active_session_id) = expected_active_session_id {
        params.push((
            "expected_active_session_id".to_string(),
            expected_active_session_id.to_string(),
        ));
    }
    if params.is_empty() {
        path.to_string()
    } else {
        let query = encode_query(params);
        let separator = if path.contains('?') { '&' } else { '?' };
        format!("{path}{separator}{query}")
    }
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
) -> Result<NormalizedTarget> {
    let requested_scheme = scheme
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty());
    let requested_host = host
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let requested_port = port
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|value| normalize_replay_port(&value))
        .transpose()?;
    let fallback_scheme = fallback
        .map(|request| request.scheme.clone())
        .unwrap_or_else(|| "https".to_string());
    let fallback_scheme = validate_replay_scheme(&fallback_scheme)?;
    let fallback_host = fallback
        .map(|request| strip_host_port(&request.host).to_string())
        .unwrap_or_default();
    let fallback_explicit_port = fallback
        .and_then(|request| extract_port(&request.host))
        .and_then(|port| normalize_replay_port(&port).ok());

    let mut scheme = requested_scheme
        .clone()
        .unwrap_or_else(|| fallback_scheme.clone());
    let mut host = requested_host.clone().unwrap_or(fallback_host);
    let mut parsed_host_port = None;
    let mut host_url_without_port = false;

    if is_absolute_http_url(&host) {
        let parsed =
            Url::parse(&host).with_context(|| format!("invalid replay target URL: {host}"))?;
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || (parsed.path() != "/" && !parsed.path().is_empty())
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            bail!("replay target URL must not include path, query, fragment, or credentials");
        }
        let url_scheme = parsed.scheme().to_ascii_lowercase();
        if let Some(requested_scheme) = requested_scheme.as_deref() {
            if requested_scheme != url_scheme {
                bail!(
                    "replay target URL scheme conflicts with --scheme: URL uses {url_scheme}, --scheme uses {requested_scheme}"
                );
            }
        }
        scheme = url_scheme;
        host = parsed
            .host_str()
            .ok_or_else(|| anyhow!("replay target URL is missing a host"))?
            .to_string();
        if let Some(url_port) = parsed.port() {
            parsed_host_port = Some(normalize_replay_port(&url_port.to_string())?);
        } else {
            host_url_without_port = true;
        }
    } else if let Some((parsed_host, parsed_port)) = split_host_port(&host.clone()) {
        host = parsed_host.to_string();
        parsed_host_port = Some(normalize_replay_port(parsed_port)?);
    }

    let scheme = validate_replay_scheme(&scheme)?;
    validate_replay_target_host(&host)?;
    let scheme_changed_from_fallback = requested_scheme.is_some() && scheme != fallback_scheme;
    if let (Some(requested_port), Some(parsed_host_port)) =
        (requested_port.as_deref(), parsed_host_port.as_deref())
    {
        if requested_port != parsed_host_port {
            bail!(
                "replay target URL port conflicts with --port: URL uses {parsed_host_port}, --port uses {requested_port}"
            );
        }
    }
    let port = requested_port
        .or(parsed_host_port)
        .or_else(|| {
            (!host_url_without_port && !scheme_changed_from_fallback)
                .then_some(fallback_explicit_port)
                .flatten()
        })
        .unwrap_or_else(|| default_port_for_scheme(&scheme).to_string());

    Ok(NormalizedTarget { scheme, host, port })
}

fn validate_replay_target_host(host: &str) -> Result<()> {
    let host = host.trim();
    if host.is_empty() {
        bail!("replay target host is required");
    }
    if host.chars().any(char::is_whitespace)
        || host.contains('/')
        || host.contains('\\')
        || host.contains('@')
        || host.contains('?')
        || host.contains('#')
    {
        bail!("invalid replay target host: {host}");
    }
    if host.starts_with('[') {
        let Some(end) = host.find(']') else {
            bail!("invalid replay target host: {host}");
        };
        if end != host.len() - 1 {
            bail!("replay target host must not include a port; use --port");
        }
        host[1..end]
            .parse::<IpAddr>()
            .with_context(|| format!("invalid replay target host: {host}"))?;
        return Ok(());
    }
    if host.contains(':') && host.parse::<IpAddr>().is_err() {
        bail!("replay target host must not include a port; use --port");
    }
    Ok(())
}

fn build_target_override(
    scheme: &str,
    host: &str,
    port: &str,
) -> Result<Option<RequestTargetOverride>> {
    let scheme = scheme.trim();
    let host = host.trim();
    let port = port.trim();
    if scheme.is_empty() && host.is_empty() && port.is_empty() {
        return Ok(None);
    }
    if host.is_empty() {
        return Ok(Some(RequestTargetOverride {
            scheme: if scheme.is_empty() {
                String::new()
            } else {
                validate_replay_scheme(scheme)?
            },
            host: String::new(),
            port: if port.is_empty() {
                String::new()
            } else {
                normalize_replay_port(port)?
            },
        }));
    }
    let port = if port.is_empty() {
        default_port_for_scheme(scheme).to_string()
    } else {
        normalize_replay_port(port)?
    };

    Ok(Some(RequestTargetOverride {
        scheme: validate_replay_scheme(scheme)?,
        host: host.to_string(),
        port,
    }))
}

fn replay_send_target_for_tab(
    tab: &ReplayTabState,
    request: &EditableRequest,
) -> Result<Option<RequestTargetOverride>> {
    let stored = build_target_override(&tab.target_scheme, &tab.target_host, &tab.target_port)?;
    if let Some(target) = stored.as_ref() {
        let stored_target = NormalizedTarget {
            scheme: target.scheme.clone(),
            host: target.host.clone(),
            port: target.port.clone(),
        };
        let request_target = normalize_target_inputs(None, None, None, Some(request))?;
        if normalized_targets_equivalent(&stored_target, &request_target) {
            return Ok(None);
        }
        if strip_ipv6_brackets(&request_target.host)
            .parse::<IpAddr>()
            .is_ok()
        {
            bail!("Replay target override is not supported when the request host is an IP address");
        }
    }
    Ok(stored)
}

fn normalized_targets_equivalent(left: &NormalizedTarget, right: &NormalizedTarget) -> bool {
    if !left.scheme.eq_ignore_ascii_case(&right.scheme) {
        return false;
    }
    request_authorities_equivalent(
        &target_authority(left),
        &target_authority(right),
        &left.scheme,
    )
}

fn target_authority(target: &NormalizedTarget) -> String {
    let port = target.port.parse::<u16>().ok();
    format_request_authority(&target.host, port)
}

fn fuzzer_active_target_for_request(
    fuzzer: &FuzzerWorkspaceState,
    request: &EditableRequest,
) -> Option<RequestTargetOverride> {
    let target = fuzzer.target.as_ref()?;
    if let Some(saved_authority) = fuzzer.target_request_authority.as_deref() {
        let (saved_scheme, saved_authority) = parse_saved_fuzzer_target_authority(saved_authority)?;
        if !saved_scheme.eq_ignore_ascii_case(&request.scheme) {
            return None;
        }
        if !request_authorities_equivalent(&saved_authority, &request.host, &request.scheme) {
            return None;
        }
    }
    let target_normalized = normalize_target_inputs(
        Some(target.scheme.clone()),
        Some(target.host.clone()),
        Some(target.port.clone()),
        Some(request),
    )
    .ok()?;
    let request_target = normalize_target_inputs(None, None, None, Some(request)).ok()?;
    if normalized_targets_equivalent(&target_normalized, &request_target) {
        return None;
    }
    Some(target.clone())
}

fn fuzzer_target_request_authority_for_request(request: &EditableRequest) -> String {
    format!("{}://{}", request.scheme, request.host.trim())
}

fn parse_saved_fuzzer_target_authority(value: &str) -> Option<(String, String)> {
    let parsed = Url::parse(value.trim()).ok()?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || (parsed.path() != "/" && !parsed.path().is_empty())
    {
        return None;
    }
    let host = parsed.host_str()?;
    Some((scheme, format_request_authority(host, parsed.port())))
}

fn validate_replay_scheme(scheme: &str) -> Result<String> {
    let normalized = scheme.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "http" | "https" => Ok(normalized),
        _ => bail!("unsupported replay target scheme: {scheme}"),
    }
}

fn build_optional_target_override(
    scheme: Option<String>,
    host: Option<String>,
    port: Option<String>,
    fallback: Option<&EditableRequest>,
) -> Result<Option<RequestTargetOverride>> {
    let has_override = [&scheme, &host, &port].iter().any(|value| {
        value
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
    });
    if !has_override {
        return Ok(None);
    }

    let normalized = normalize_target_inputs(scheme, host, port, fallback)?;
    build_target_override(&normalized.scheme, &normalized.host, &normalized.port)
}

fn normalize_replay_port(port: &str) -> Result<String> {
    let port = port.trim();
    let parsed = port
        .parse::<u16>()
        .with_context(|| format!("invalid replay target port: {port}"))?;
    if parsed == 0 {
        bail!("invalid replay target port: {port}");
    }
    Ok(parsed.to_string())
}

fn split_payload_lines(payloads_text: &str) -> Vec<String> {
    if payloads_text.is_empty() {
        return Vec::new();
    }
    let mut lines = payloads_text.split('\n').collect::<Vec<_>>();
    if payloads_text.ends_with('\n') {
        lines.pop();
    }
    lines
        .into_iter()
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .map(ToOwned::to_owned)
        .collect()
}

fn read_payloads_input(
    payloads: Vec<String>,
    file: Option<PathBuf>,
    stdin: bool,
) -> Result<String> {
    if !payloads.is_empty() {
        let mut text = payloads.join("\n");
        if payloads.last().is_some_and(|payload| payload.is_empty()) {
            text.push('\n');
        }
        return Ok(text);
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
    let bytes = read_bytes_input(file, stdin)?;
    String::from_utf8(bytes).context("input is not valid UTF-8")
}

fn read_secret_stdin(label: &str) -> Result<String> {
    let mut stdin = io::stdin();
    let bytes = read_limited_to_end(&mut stdin, "stdin", MAX_CLI_INPUT_BYTES)?;
    let token = String::from_utf8(bytes)
        .with_context(|| format!("{label} from stdin is not valid UTF-8"))?
        .trim()
        .to_string();
    if token.is_empty() {
        bail!("{label} from stdin is empty");
    }
    Ok(token)
}

fn read_bytes_input(file: Option<PathBuf>, stdin: bool) -> Result<Vec<u8>> {
    if let Some(file) = file {
        return read_file_bytes_limited(&file);
    }

    if stdin {
        let mut stdin = io::stdin();
        return read_limited_to_end(&mut stdin, "stdin", MAX_CLI_INPUT_BYTES);
    }

    bail!("expected --file or --stdin")
}

fn read_file_bytes_limited(file: &PathBuf) -> Result<Vec<u8>> {
    let metadata =
        fs::metadata(file).with_context(|| format!("failed to inspect {}", file.display()))?;
    if !metadata.is_file() {
        bail!("{} is not a regular file", file.display());
    }
    if metadata.len() > MAX_CLI_INPUT_BYTES as u64 {
        bail!(
            "{} cannot exceed {} bytes",
            file.display(),
            MAX_CLI_INPUT_BYTES
        );
    }
    let mut handle =
        fs::File::open(file).with_context(|| format!("failed to read {}", file.display()))?;
    read_limited_to_end(
        &mut handle,
        &format!("{}", file.display()),
        MAX_CLI_INPUT_BYTES,
    )
}

fn read_limited_to_end<R: Read>(reader: &mut R, label: &str, limit: usize) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    reader
        .take(limit.saturating_add(1) as u64)
        .read_to_end(&mut buf)
        .with_context(|| format!("failed to read {label}"))?;
    if buf.len() > limit {
        bail!("{label} cannot exceed {limit} bytes");
    }
    Ok(buf)
}

fn read_raw_request_input(
    file: Option<PathBuf>,
    stdin: bool,
    fallback: Option<&EditableRequest>,
) -> Result<(ParsedEditableRequest, String)> {
    let bytes = read_bytes_input(file, stdin)?;
    ensure_raw_http_input_not_empty(&bytes, "request")?;
    let parsed = parse_editable_raw_request_bytes_with_version(&bytes, fallback)?;
    let request_text = if parsed.request.body_encoding == BodyEncoding::Utf8 {
        String::from_utf8(bytes.clone()).unwrap_or_else(|_| {
            build_editable_raw_request_with_version(&parsed.request, parsed.http_version.as_deref())
        })
    } else {
        build_editable_raw_request_with_version(&parsed.request, parsed.http_version.as_deref())
    };
    Ok((parsed, request_text))
}

fn read_raw_response_input(
    file: Option<PathBuf>,
    stdin: bool,
    fallback: Option<&EditableResponse>,
    request_method: &str,
) -> Result<EditableResponse> {
    let bytes = read_bytes_input(file, stdin)?;
    ensure_raw_http_input_not_empty(&bytes, "response")?;
    parse_editable_raw_response_bytes_for_request_method(&bytes, fallback, request_method)
}

fn ensure_raw_http_input_not_empty(bytes: &[u8], label: &str) -> Result<()> {
    if bytes.is_empty() || bytes.iter().all(u8::is_ascii_whitespace) {
        bail!("{label} input is empty");
    }
    Ok(())
}

async fn discover_api_base_url(
    cli_api: Option<String>,
    client: &reqwest::Client,
) -> Result<String> {
    if let Some(api) = cli_api {
        let url = normalize_api_base_url(&api)?;
        probe_sniper_api_base_url(&url, client, None).await?;
        return Ok(url);
    }

    if let Ok(api) = env::var("SNIPER_API_ADDR") {
        if !api.trim().is_empty() {
            let url = normalize_api_base_url(&api)?;
            if let Err(error) = probe_sniper_api_base_url(&url, client, None).await {
                bail!("SNIPER_API_ADDR={url} did not point to a reachable Sniper API ({error})");
            }
            return Ok(url);
        }
    }

    discover_api_base_url_from_data_dir(client, cli_data_dir()).await
}

fn cli_data_dir() -> PathBuf {
    env::var_os(SNIPER_DATA_DIR_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(default_cli_data_dir)
}

fn default_cli_data_dir() -> PathBuf {
    env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".sniper"))
        .unwrap_or_else(|| PathBuf::from(".sniper"))
}

async fn discover_api_base_url_from_data_dir(
    client: &reqwest::Client,
    data_dir: PathBuf,
) -> Result<String> {
    let runtime_state = load_runtime_state(&data_dir).with_context(|| {
        format!(
            "failed to read Sniper runtime-state; it may be mid-update or stale at {}",
            data_dir.display()
        )
    })?;
    if let Some(runtime_state) = runtime_state {
        let url = runtime_state.api_base_url();
        let expected = SniperApiProbeExpectation {
            runtime_state: &runtime_state,
            data_dir: &data_dir,
        };
        let probe_failure =
            match probe_sniper_api_base_url_classified(&url, client, Some(expected)).await {
                Ok(()) => return Ok(url),
                Err(error) => error,
            };
        let probe_failure_kind = probe_failure.kind;
        let probe_failure_message = probe_failure.error.to_string();
        if probe_failure_kind == SniperApiProbeFailureKind::Unreachable {
            if let Some(owner_pid) = live_runtime_state_owner_pid(&runtime_state) {
                bail!(
                    "Sniper API at {} is not responding (runtime-state from {}, owner pid {} is still running). \
                     Leaving runtime-state intact; retry shortly, restart Sniper Desktop, or pass --api http://HOST:PORT explicitly.",
                    runtime_state.ui_addr,
                    runtime_state.updated_at.format("%Y-%m-%d %H:%M:%S"),
                    owner_pid
                );
            }
        }
        let stale_reason = match probe_failure_kind {
            SniperApiProbeFailureKind::Unreachable => "is not responding".to_string(),
            SniperApiProbeFailureKind::Rejected => {
                format!("did not match runtime-state ({probe_failure_message})")
            }
        };
        let remove_result = remove_runtime_state_if_matches(&data_dir, &runtime_state);
        // Probe failed — stale runtime-state
        let removed_stale = match remove_result {
            Ok(removed) => removed,
            Err(error) => {
                bail!(
                    "Sniper API at {} {} (stale runtime-state from {}), \
                     and failed to remove stale runtime-state: {error}. \
                     Either start Sniper Desktop or pass --api http://HOST:PORT explicitly.",
                    runtime_state.ui_addr,
                    stale_reason,
                    runtime_state.updated_at.format("%Y-%m-%d %H:%M:%S")
                );
            }
        };
        if !removed_stale {
            bail!(
                "Sniper API at {} {} (stale runtime-state from {}), \
                 but runtime-state changed before cleanup. \
                 Either start Sniper Desktop or pass --api http://HOST:PORT explicitly.",
                runtime_state.ui_addr,
                stale_reason,
                runtime_state.updated_at.format("%Y-%m-%d %H:%M:%S")
            );
        }
        bail!(
            "Sniper API at {} {} (stale runtime-state from {}). \
             Removed the stale runtime-state; start Sniper Desktop or pass --api http://HOST:PORT explicitly.",
            runtime_state.ui_addr,
            stale_reason,
            runtime_state.updated_at.format("%Y-%m-%d %H:%M:%S")
        )
    }

    bail!("could not discover Sniper API address; pass --api or start sniper-desktop first")
}

fn live_runtime_state_owner_pid(runtime_state: &RuntimeStateSnapshot) -> Option<u32> {
    let pid = runtime_state.pid?;
    let expected_process_path = runtime_state.process_path.as_deref()?;
    if runtime_state_owner_process_is_running(pid)
        && runtime_state_owner_process_path_matches(pid, expected_process_path)
    {
        Some(pid)
    } else {
        None
    }
}

#[cfg(unix)]
fn runtime_state_owner_process_is_running(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if result == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(not(unix))]
fn runtime_state_owner_process_is_running(_pid: u32) -> bool {
    false
}

#[cfg(target_os = "macos")]
fn runtime_state_owner_process_path_matches(pid: u32, expected_process_path: &str) -> bool {
    const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;
    let mut buffer = vec![0_u8; PROC_PIDPATHINFO_MAXSIZE];
    let length = unsafe {
        libc::proc_pidpath(
            pid as libc::c_int,
            buffer.as_mut_ptr() as *mut libc::c_void,
            buffer.len() as u32,
        )
    };
    if length <= 0 {
        return false;
    }
    let observed = String::from_utf8_lossy(&buffer[..length as usize]);
    process_path_strings_match(expected_process_path, observed.trim_end_matches('\0'))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn runtime_state_owner_process_path_matches(pid: u32, expected_process_path: &str) -> bool {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .is_some_and(|path| {
            process_path_strings_match(expected_process_path, &path.display().to_string())
        })
}

#[cfg(not(unix))]
fn runtime_state_owner_process_path_matches(_pid: u32, _expected_process_path: &str) -> bool {
    false
}

fn process_path_strings_match(expected_process_path: &str, observed_process_path: &str) -> bool {
    let observed_process_path = observed_process_path
        .strip_suffix(" (deleted)")
        .unwrap_or(observed_process_path);
    if expected_process_path == observed_process_path {
        return true;
    }
    paths_refer_to_same_location(
        Path::new(expected_process_path),
        Path::new(observed_process_path),
    )
}

fn data_dir_strings_match(response_data_dir: &str, expected_data_dir: &Path) -> bool {
    if Path::new(response_data_dir) == expected_data_dir {
        return true;
    }
    paths_refer_to_same_location(Path::new(response_data_dir), expected_data_dir)
}

fn paths_refer_to_same_location(left: &Path, right: &Path) -> bool {
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

#[derive(Clone, Copy)]
struct SniperApiProbeExpectation<'a> {
    runtime_state: &'a RuntimeStateSnapshot,
    data_dir: &'a Path,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SniperApiProbeFailureKind {
    Unreachable,
    Rejected,
}

#[derive(Debug)]
struct SniperApiProbeFailure {
    kind: SniperApiProbeFailureKind,
    error: anyhow::Error,
}

impl SniperApiProbeFailure {
    fn unreachable(error: anyhow::Error) -> Self {
        Self {
            kind: SniperApiProbeFailureKind::Unreachable,
            error,
        }
    }

    fn rejected(error: anyhow::Error) -> Self {
        Self {
            kind: SniperApiProbeFailureKind::Rejected,
            error,
        }
    }
}

async fn probe_sniper_api_base_url(
    url: &str,
    client: &reqwest::Client,
    expected: Option<SniperApiProbeExpectation<'_>>,
) -> Result<()> {
    probe_sniper_api_base_url_classified(url, client, expected)
        .await
        .map_err(|failure| failure.error)
}

async fn probe_sniper_api_base_url_classified(
    url: &str,
    client: &reqwest::Client,
    expected: Option<SniperApiProbeExpectation<'_>>,
) -> std::result::Result<(), SniperApiProbeFailure> {
    let mut last_error = None;
    for attempt in 0..=SNIPER_API_PROBE_RETRY_DELAYS.len() {
        if attempt > 0 {
            tokio::time::sleep(SNIPER_API_PROBE_RETRY_DELAYS[attempt - 1]).await;
        }
        match probe_sniper_api_base_url_once_classified(url, client, expected).await {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.expect("probe loop always runs at least once"))
}

async fn probe_sniper_api_base_url_once_classified(
    url: &str,
    client: &reqwest::Client,
    expected: Option<SniperApiProbeExpectation<'_>>,
) -> std::result::Result<(), SniperApiProbeFailure> {
    let settings_url = api_url(url, "/api/settings").map_err(SniperApiProbeFailure::rejected)?;
    let response = client
        .get(settings_url)
        .timeout(SNIPER_API_PROBE_TIMEOUT)
        .send()
        .await
        .map_err(|error| {
            SniperApiProbeFailure::unreachable(anyhow!(
                "failed to probe Sniper API at {url}: {error}"
            ))
        })?;
    let status = response.status();
    if !status.is_success() {
        return Err(SniperApiProbeFailure::rejected(anyhow!(
            "Sniper API probe returned {status}"
        )));
    }
    let payload: serde_json::Value = response.json().await.map_err(|error| {
        SniperApiProbeFailure::rejected(anyhow!("Sniper API probe response was not JSON: {error}"))
    })?;
    validate_sniper_settings_probe(&payload, expected).map_err(SniperApiProbeFailure::rejected)
}

fn validate_sniper_settings_probe(
    payload: &serde_json::Value,
    expected: Option<SniperApiProbeExpectation<'_>>,
) -> Result<()> {
    if !sniper_settings_probe_matches(payload) {
        bail!("Sniper API probe response did not match the expected /api/settings schema");
    }
    if let Some(expected) = expected {
        let response_instance_id =
            probe_string_field(payload, "runtime_instance_id").and_then(|value| {
                Uuid::parse_str(value).with_context(|| {
                    "Sniper API probe response had invalid runtime_instance_id".to_string()
                })
            })?;
        if response_instance_id != expected.runtime_state.instance_id {
            bail!(
                "Sniper API probe response did not match runtime-state instance \
                 (expected {}, got {})",
                expected.runtime_state.instance_id,
                response_instance_id
            );
        }

        let response_ui_addr = probe_string_field(payload, "ui_addr")?;
        if response_ui_addr != expected.runtime_state.ui_addr {
            bail!(
                "Sniper API probe response did not match runtime-state UI address \
                 (expected {}, got {})",
                expected.runtime_state.ui_addr,
                response_ui_addr
            );
        }

        let response_data_dir = probe_string_field(payload, "data_dir")?;
        let expected_data_dir = expected.data_dir.display().to_string();
        if !data_dir_strings_match(response_data_dir, expected.data_dir) {
            bail!(
                "Sniper API probe response did not match runtime-state data directory \
                 (expected {}, got {})",
                expected_data_dir,
                response_data_dir
            );
        }
    }
    Ok(())
}

fn probe_string_field<'a>(payload: &'a serde_json::Value, field: &str) -> Result<&'a str> {
    payload
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("Sniper API probe response missing string field {field}"))
}

fn sniper_settings_probe_matches(payload: &serde_json::Value) -> bool {
    let features = payload
        .get("features")
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    payload
        .get("runtime_instance_id")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| Uuid::parse_str(value).is_ok())
        && payload
            .get("proxy_addr")
            .is_some_and(serde_json::Value::is_string)
        && payload
            .get("ui_addr")
            .is_some_and(serde_json::Value::is_string)
        && payload
            .get("data_dir")
            .is_some_and(serde_json::Value::is_string)
        && payload
            .get("max_entries")
            .is_some_and(serde_json::Value::is_number)
        && features.contains(&"http_capture")
        && features.contains(&"session_storage")
        && features.contains(&"replay")
}

fn normalize_api_base_url(raw: &str) -> Result<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        bail!("Sniper API address is empty");
    }
    let with_scheme = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    };
    let mut url =
        Url::parse(&with_scheme).with_context(|| format!("invalid Sniper API address: {raw}"))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        bail!("Sniper API address must use http or https");
    }
    if url.host_str().is_none() {
        bail!("Sniper API address must include a host");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("Sniper API address must not include credentials");
    }
    if url.path() != "/" && !url.path().is_empty() {
        bail!("Sniper API address must not include a path");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("Sniper API address must not include a query string or fragment");
    }
    url.set_path("");
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.as_str().trim_end_matches('/').to_string())
}

fn api_url(base_url: &str, path: &str) -> Result<Url> {
    let base = Url::parse(&format!("{}/", base_url.trim_end_matches('/')))
        .with_context(|| format!("invalid normalized Sniper API address: {base_url}"))?;
    base.join(path.trim_start_matches('/'))
        .with_context(|| format!("failed to build Sniper API URL for {path}"))
}

fn build_editable_raw_request(request: &EditableRequest) -> String {
    build_editable_raw_request_with_version(request, None)
}

fn build_editable_raw_request_with_version(
    request: &EditableRequest,
    http_version: Option<&str>,
) -> String {
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
    if !request.body.is_empty() {
        let body_len = request
            .try_body_bytes()
            .map(|body| body.len())
            .unwrap_or_else(|_| request.body.len());
        normalize_content_length_for_raw_editor(&mut headers, body_len);
    }

    let mut lines = Vec::with_capacity(headers.len() + 2);
    let path = if request.path.trim().is_empty() {
        "/"
    } else {
        request.path.as_str()
    };
    let http_version = normalize_http_version(http_version).unwrap_or("HTTP/1.1");
    lines.push(format!(
        "{} {} {}",
        request.method.trim(),
        path,
        http_version
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
    }
}

fn normalize_content_length_for_raw_editor(headers: &mut Vec<HeaderRecord>, body_len: usize) {
    let mut updated = Vec::with_capacity(headers.len());
    let mut saw_content_length = false;
    for mut header in headers.drain(..) {
        if header.name.eq_ignore_ascii_case("content-length") {
            if saw_content_length {
                continue;
            }
            header.value = body_len.to_string();
            saw_content_length = true;
        }
        updated.push(header);
    }
    *headers = updated;
}

#[derive(Debug)]
struct ParsedEditableRequest {
    request: EditableRequest,
    http_version: Option<String>,
}

enum RawRequestBody {
    Text(String),
    Bytes(Vec<u8>),
}

impl RawRequestBody {
    fn wire_len(&self, body_encoding: Option<&BodyEncoding>, label: &str) -> Result<usize> {
        match self {
            Self::Bytes(value) => Ok(value.len()),
            Self::Text(value) if matches!(body_encoding, Some(BodyEncoding::Base64)) => STANDARD
                .decode(value)
                .map(|body| body.len())
                .with_context(|| format!("{label} body is not valid base64")),
            Self::Text(value) => Ok(value.len()),
        }
    }
}

#[cfg(test)]
fn parse_editable_raw_request(
    text: &str,
    fallback: Option<&EditableRequest>,
) -> Result<EditableRequest> {
    Ok(parse_editable_raw_request_with_version(text, fallback)?.request)
}

fn parse_editable_raw_request_with_version(
    text: &str,
    fallback: Option<&EditableRequest>,
) -> Result<ParsedEditableRequest> {
    let (head, body) = split_raw_http_message(text);
    parse_editable_raw_request_parts(head, RawRequestBody::Text(body), fallback)
}

fn parse_editable_raw_request_bytes_with_version(
    bytes: &[u8],
    fallback: Option<&EditableRequest>,
) -> Result<ParsedEditableRequest> {
    let (head, body) = split_raw_http_message_bytes(bytes)?;
    parse_editable_raw_request_parts(head, RawRequestBody::Bytes(body), fallback)
}

fn parse_editable_raw_request_parts(
    head: String,
    raw_body: RawRequestBody,
    fallback: Option<&EditableRequest>,
) -> Result<ParsedEditableRequest> {
    let mut lines = head.lines();
    let fallback_start_line = fallback.map(|request| {
        format!(
            "{} {}",
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
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| "GET".to_string());
    if !is_http_method_token(&method) {
        bail!("invalid HTTP method: {method}");
    }
    let target = start_parts.next().unwrap_or("/");
    let raw_http_version = start_parts.next();
    if start_parts.next().is_some() {
        bail!("invalid request line: too many fields");
    }
    let http_version = match raw_http_version {
        Some(value) => Some(
            normalize_http_version(Some(value))
                .map(str::to_string)
                .ok_or_else(|| anyhow!("unsupported HTTP version: {value}"))?,
        ),
        None => None,
    };

    let mut scheme = fallback
        .map(|request| request.scheme.clone())
        .unwrap_or_else(|| "https".to_string());
    let mut host = fallback
        .map(|request| request.host.clone())
        .unwrap_or_default();
    let mut absolute_target_authority: Option<String> = None;
    let mut path;
    let mut absolute_form = false;

    if is_absolute_http_url(target) {
        let parsed = Url::parse(target)
            .with_context(|| format!("request target is not a valid URL: {target}"))?;
        if !parsed.username().is_empty() || parsed.password().is_some() {
            bail!("absolute request target must not include credentials");
        }
        if parsed.fragment().is_some() {
            bail!("absolute request target must not include a fragment");
        }
        absolute_form = true;
        scheme = parsed.scheme().to_ascii_lowercase();
        let parsed_host = parsed
            .host_str()
            .ok_or_else(|| anyhow!("request target is missing a host"))?
            .to_string();
        let parsed_port = parsed.port();
        host = format_request_authority(&parsed_host, parsed_port);
        absolute_target_authority = Some(host.clone());
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
        .map(|line| {
            let line = line.trim_end();
            if line.is_empty() {
                return Ok(None);
            }
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| anyhow!("invalid request header line: {line}"))?;
            Ok(Some(HeaderRecord {
                name: name.trim().to_string(),
                value: value.trim().to_string(),
            }))
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();
    validate_raw_request_host_headers(&headers)?;
    let inferred_text_encoding = match &raw_body {
        RawRequestBody::Text(body) => infer_text_body_encoding(
            &headers,
            body,
            fallback.map(|request| &request.body_encoding),
        )?,
        RawRequestBody::Bytes(_) => None,
    };
    let body_len = raw_body.wire_len(inferred_text_encoding.as_ref(), "request")?;
    validate_raw_http_body_framing(&headers, body_len, false)?;

    let (body, body_encoding) = match raw_body {
        RawRequestBody::Text(body) => (body, inferred_text_encoding.unwrap_or(BodyEncoding::Utf8)),
        RawRequestBody::Bytes(body) => {
            let content_type = headers
                .iter()
                .find(|header| header.name.eq_ignore_ascii_case("content-type"))
                .map(|header| header.value.as_str());
            encode_raw_request_body(content_type, &body)
        }
    };

    if let Some(host_header) = headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("host"))
    {
        if absolute_form {
            let target_host = absolute_target_authority.as_deref().unwrap_or(host.trim());
            let header_host = host_header.value.trim();
            if !request_authorities_equivalent(target_host, header_host, &scheme) {
                bail!(
                    "absolute request target host {target_host} does not match Host header {header_host}"
                );
            }
        } else {
            host = host_header.value.clone();
        }
    }

    if host.trim().is_empty() {
        bail!("request is missing a Host header");
    }

    if method == "CONNECT" {
        bail!("CONNECT authority-form requests are not supported by Replay");
    }

    if path != "*" && !path.starts_with('/') {
        path = format!("/{path}");
    }

    let preview_truncated = fallback.is_some_and(|request| {
        request.preview_truncated && request.body == body && request.body_encoding == body_encoding
    });
    let request = EditableRequest {
        scheme,
        host,
        method,
        path,
        headers,
        body,
        body_encoding,
        preview_truncated,
    };
    request
        .try_body_bytes()
        .context("request body is not valid base64")?;
    Ok(ParsedEditableRequest {
        request,
        http_version,
    })
}

fn is_http_method_token(method: &str) -> bool {
    !method.trim().is_empty() && method.bytes().all(is_http_token_byte)
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn is_absolute_http_url(value: &str) -> bool {
    let value = value.trim_start();
    value
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
        || value
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
}

fn validate_raw_request_host_headers(headers: &[HeaderRecord]) -> Result<()> {
    let host_count = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("host"))
        .count();
    if host_count > 1 {
        bail!("raw request must not include multiple Host headers");
    }
    Ok(())
}

fn infer_text_body_encoding(
    headers: &[HeaderRecord],
    body: &str,
    fallback_encoding: Option<&BodyEncoding>,
) -> Result<Option<BodyEncoding>> {
    if matches!(fallback_encoding, Some(BodyEncoding::Base64)) {
        return Ok(Some(BodyEncoding::Base64));
    }

    let Some(expected_len) = declared_content_length(headers)? else {
        return Ok(fallback_encoding.cloned());
    };
    if expected_len == body.len() {
        return Ok(fallback_encoding.cloned());
    }
    if fallback_encoding.is_none() {
        if let Ok(decoded) = STANDARD.decode(body) {
            if decoded.len() == expected_len {
                return Ok(Some(BodyEncoding::Base64));
            }
        }
    }
    Ok(fallback_encoding.cloned())
}

fn validate_raw_http_body_framing(
    headers: &[HeaderRecord],
    body_len: usize,
    allow_representation_content_length: bool,
) -> Result<()> {
    if headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("transfer-encoding")
            && header
                .value
                .split(',')
                .any(|value| value.trim().eq_ignore_ascii_case("chunked"))
    }) {
        bail!("raw HTTP input with Transfer-Encoding: chunked is not supported");
    }

    if let Some(expected) = declared_content_length(headers)? {
        if expected != body_len && !(allow_representation_content_length && body_len == 0) {
            bail!("Content-Length {expected} does not match raw body length {body_len}");
        }
    }
    Ok(())
}

fn declared_content_length(headers: &[HeaderRecord]) -> Result<Option<usize>> {
    let mut content_length: Option<usize> = None;
    for header in headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("content-length"))
    {
        let parsed = header
            .value
            .trim()
            .parse::<usize>()
            .with_context(|| format!("invalid Content-Length: {}", header.value))?;
        if let Some(previous) = content_length {
            if previous != parsed {
                bail!("conflicting Content-Length headers");
            }
        }
        content_length = Some(parsed);
    }
    Ok(content_length)
}

fn split_raw_http_message(text: &str) -> (String, String) {
    if let Some(index) = text.find("\r\n\r\n") {
        return (
            text[..index].replace("\r\n", "\n"),
            text[index + 4..].to_string(),
        );
    }
    if let Some(index) = text.find("\n\n") {
        return (
            text[..index].replace("\r\n", "\n"),
            text[index + 2..].to_string(),
        );
    }
    (text.replace("\r\n", "\n"), String::new())
}

fn split_raw_http_message_bytes(bytes: &[u8]) -> Result<(String, Vec<u8>)> {
    let (head, body) =
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            (&bytes[..index], bytes[index + 4..].to_vec())
        } else if let Some(index) = bytes.windows(2).position(|window| window == b"\n\n") {
            (&bytes[..index], bytes[index + 2..].to_vec())
        } else {
            (bytes, Vec::new())
        };
    let head = std::str::from_utf8(head)
        .context("request headers are not valid UTF-8")?
        .replace("\r\n", "\n");
    Ok((head, body))
}

fn encode_raw_request_body(content_type: Option<&str>, body: &[u8]) -> (String, BodyEncoding) {
    if is_textual_raw_request_body(content_type, body) {
        (
            String::from_utf8(body.to_vec()).unwrap_or_default(),
            BodyEncoding::Utf8,
        )
    } else {
        (STANDARD.encode(body), BodyEncoding::Base64)
    }
}

fn is_textual_raw_request_body(content_type: Option<&str>, sample: &[u8]) -> bool {
    if sample.is_empty() {
        return true;
    }

    let valid_utf8 = std::str::from_utf8(sample).is_ok() && !sample.contains(&0);
    if let Some(content_type) = content_type {
        let normalized = content_type.to_ascii_lowercase();
        if normalized.starts_with("text/")
            || normalized.contains("json")
            || normalized.contains("xml")
            || normalized.contains("javascript")
            || normalized.contains("x-www-form-urlencoded")
            || normalized.contains("graphql")
            || normalized.contains("yaml")
        {
            return valid_utf8;
        }
    }

    valid_utf8
}

fn normalize_http_version(value: Option<&str>) -> Option<&'static str> {
    let normalized = value?.trim().to_ascii_uppercase();
    match normalized.as_str() {
        "HTTP/1.0" | "1.0" => Some("HTTP/1.0"),
        "HTTP/1.1" | "1.1" => Some("HTTP/1.1"),
        "HTTP/2" | "HTTP/2.0" | "2" | "2.0" => Some("HTTP/2"),
        _ => None,
    }
}

fn replay_send_http_version(
    tab: &ReplayTabState,
    parsed_request: &ParsedEditableRequest,
) -> Option<String> {
    parsed_request
        .http_version
        .clone()
        .or_else(|| normalize_http_version(Some(&tab.http_version_mode)).map(str::to_string))
}

fn encode_query(params: Vec<(String, String)>) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in params {
        serializer.append_pair(&key, &value);
    }
    serializer.finish()
}

#[derive(Debug)]
struct CliPartialApplyError {
    message: String,
    details: Value,
}

impl fmt::Display for CliPartialApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CliPartialApplyError {}

#[derive(Clone, Debug, Serialize)]
struct CliErrorPayload {
    code: &'static str,
    message: String,
    hint: Option<&'static str>,
    retryable: bool,
    details: Value,
    #[serde(skip)]
    exit_code: i32,
}

fn cli_output_format_from_raw_args(args: &[String]) -> OutputFormat {
    for (index, arg) in args.iter().enumerate() {
        if let Some(value) = arg.strip_prefix("--output=") {
            return output_format_from_raw_value(value).unwrap_or(OutputFormat::Pretty);
        }
        if arg == "--output" {
            if let Some(value) = args.get(index + 1) {
                return output_format_from_raw_value(value).unwrap_or(OutputFormat::Pretty);
            }
        }
    }
    OutputFormat::Pretty
}

fn output_format_from_raw_value(value: &str) -> Option<OutputFormat> {
    match value {
        "compact" => Some(OutputFormat::Compact),
        "pretty" => Some(OutputFormat::Pretty),
        _ => None,
    }
}

fn cli_parse_error_operation(args: &[String]) -> String {
    let mut tokens = Vec::new();
    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg == "--output" || arg == "--api" {
            skip_next = true;
            continue;
        }
        if arg.starts_with("--output=") || arg.starts_with("--api=") || arg.starts_with('-') {
            continue;
        }
        tokens.push(arg.as_str());
    }

    match tokens.as_slice() {
        ["session", action, ..] => format!("session.{action}"),
        ["scope" | "target", "get-scope", ..] => "scope.get".to_string(),
        ["scope" | "target", "set-scope", ..] => "scope.set".to_string(),
        ["replay" | "repeater", action, ..] => format!("replay.{action}"),
        ["fuzzer", action, ..] => format!("fuzzer.{}", action.replace('-', "_")),
        ["sequence", action, ..] => format!("sequence.{}", action.replace('-', "_")),
        ["skills", action, ..] => format!("skills.{action}"),
        ["capture", "http", action, ..] | ["http" | "history", action, ..] => {
            format!("capture.http.{}", action.replace('-', "_"))
        }
        ["capture", "intercept", action, ..] | ["intercept", action, ..] => {
            format!("capture.intercept.{}", action.replace('-', "_"))
        }
        ["capture", "response-intercept", action, ..] => {
            format!("capture.response_intercept.{}", action.replace('-', "_"))
        }
        ["capture", "intercept-rule", action, ..] => {
            format!("capture.intercept_rule.{}", action.replace('-', "_"))
        }
        ["capture", "web-socket", action, ..] | ["websocket", action, ..] => {
            format!("capture.websocket.{}", action.replace('-', "_"))
        }
        ["capture", "auto-replace", action, ..] | ["auto-replace", action, ..] => {
            format!("capture.auto_replace.{}", action.replace('-', "_"))
        }
        ["capture", "oast", action, ..] => format!("capture.oast.{}", action.replace('-', "_")),
        ["call", operation, ..] => (*operation).to_string(),
        ["manifest", ..] => "manifest".to_string(),
        ["schema", ..] => "schema".to_string(),
        ["examples", ..] => "examples".to_string(),
        [first, ..] => (*first).to_string(),
        [] => "parse".to_string(),
    }
}

fn cli_partial_apply_error(message: impl Into<String>, mut details: Value) -> anyhow::Error {
    if let Value::Object(map) = &mut details {
        map.insert("partial_apply".to_string(), json!(true));
        map.insert("idempotent".to_string(), json!(false));
    }
    anyhow!(CliPartialApplyError {
        message: message.into(),
        details,
    })
}

fn print_json<T: Serialize>(value: &T) -> Result<()> {
    let data = serde_json::to_value(value).context("failed to encode JSON output")?;
    let context = output_context();
    if !context.success_envelope {
        return write_json_envelope(&data, context.format);
    }
    let envelope = json!({
        "ok": true,
        "operation": context.operation,
        "schema_version": CLI_SCHEMA_VERSION,
        "data": data,
        "meta": {},
        "warnings": [],
    });
    write_json_envelope(&envelope, context.format)
}

fn print_error_json(operation: &str, exit_code: i32, payload: &CliErrorPayload) -> Result<()> {
    let context = output_context();
    let envelope = json!({
        "ok": false,
        "operation": operation,
        "schema_version": CLI_SCHEMA_VERSION,
        "error": payload,
        "meta": {},
        "warnings": [],
    });
    write_json_envelope(&envelope, context.format)
        .with_context(|| format!("failed to write error envelope with exit code {exit_code}"))
}

fn output_context() -> CliOutputContext {
    CLI_OUTPUT_CONTEXT
        .get()
        .map(|context| CliOutputContext {
            format: context.format,
            operation: context.operation.clone(),
            success_envelope: context.success_envelope,
        })
        .unwrap_or_else(|| CliOutputContext {
            format: OutputFormat::Pretty,
            operation: "unknown".to_string(),
            success_envelope: false,
        })
}

fn write_json_envelope(value: &Value, format: OutputFormat) -> Result<()> {
    let rendered = match format {
        OutputFormat::Pretty => {
            serde_json::to_string_pretty(value).context("failed to encode JSON output")?
        }
        OutputFormat::Compact => {
            serde_json::to_string(value).context("failed to encode JSON output")?
        }
    };
    let mut stdout = io::stdout().lock();
    write_stdout_bytes(&mut stdout, rendered.as_bytes())?;
    write_stdout_bytes(&mut stdout, b"\n")
}

fn write_stdout_bytes(stdout: &mut io::StdoutLock<'_>, bytes: &[u8]) -> Result<()> {
    match stdout.write_all(bytes) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => std::process::exit(0),
        Err(error) => Err(error).context("failed to write stdout"),
    }
}

fn clap_error_payload(error: &clap::Error) -> CliErrorPayload {
    CliErrorPayload {
        code: "INVALID_INPUT",
        message: error.to_string().trim().to_string(),
        hint: Some("Run the command with --help, or inspect `sniper-cli manifest`."),
        retryable: false,
        details: json!({ "kind": format!("{:?}", error.kind()) }),
        exit_code: error.exit_code(),
    }
}

fn cli_error_payload(operation: &str, error: &anyhow::Error) -> CliErrorPayload {
    if let Some(partial) = error.downcast_ref::<CliPartialApplyError>() {
        return CliErrorPayload {
            code: "PARTIAL_APPLY",
            message: partial.message.clone(),
            hint: Some(
                "This operation may have partially applied; inspect current state before retrying.",
            ),
            retryable: false,
            details: partial.details.clone(),
            exit_code: 5,
        };
    }

    let message = error.to_string();
    let mut payload = if message.contains("requires --dry-run or --yes") {
        CliErrorPayload {
            code: "CONFIRMATION_REQUIRED",
            message,
            hint: Some(
                "Run the same command with --dry-run to inspect the plan, then --yes to apply.",
            ),
            retryable: false,
            details: json!({ "operation": operation }),
            exit_code: 2,
        }
    } else if message.contains("unknown operation") {
        CliErrorPayload {
            code: "UNKNOWN_OPERATION",
            message,
            hint: Some("Run `sniper-cli manifest` to list known operations."),
            retryable: false,
            details: json!({ "operation": operation }),
            exit_code: 2,
        }
    } else if message.contains("could not discover Sniper API")
        || message.contains("did not point to a reachable Sniper API")
        || message.contains("is not responding")
        || message.contains("failed to probe Sniper API")
        || message.contains("Sniper API probe returned")
        || message.contains("Sniper API probe response was not JSON")
        || message.contains("Sniper API probe response did not match")
    {
        CliErrorPayload {
            code: "API_UNAVAILABLE",
            message,
            hint: Some("Start Sniper Desktop, or pass --api http://HOST:PORT explicitly."),
            retryable: true,
            details: json!({}),
            exit_code: 6,
        }
    } else if message.contains("workspace state revision conflict") {
        CliErrorPayload {
            code: "WORKSPACE_CONFLICT",
            message,
            hint: Some("Refresh workspace state and retry deliberately."),
            retryable: false,
            details: json!({}),
            exit_code: 5,
        }
    } else if let Some(status) = http_status_from_message(&message) {
        CliErrorPayload {
            code: "HTTP_STATUS_ERROR",
            message,
            hint: None,
            retryable: status >= 500,
            details: json!({ "status": status }),
            exit_code: if status < 500 { 5 } else { 6 },
        }
    } else if message.contains("invalid")
        || message.contains("must ")
        || message.contains("provide ")
        || message.contains("expected ")
        || message.contains("cannot ")
        || message.contains("conflicts")
        || message.contains(" is unsafe")
        || message.contains("does not use an OAST token")
        || message.contains("input is empty")
        || message.contains("failed to parse ")
        || message.contains("missing required field")
        || message.contains(" not found")
        || message.contains("no active session")
        || message.contains("multiple active sessions")
    {
        CliErrorPayload {
            code: "INVALID_INPUT",
            message,
            hint: Some(
                "Check `sniper-cli schema input <operation>` or run the command with --help.",
            ),
            retryable: false,
            details: json!({ "operation": operation }),
            exit_code: 2,
        }
    } else {
        CliErrorPayload {
            code: "CLI_ERROR",
            message,
            hint: None,
            retryable: false,
            details: json!({}),
            exit_code: 1,
        }
    };

    let write_may_have_been_sent = payload.code == "HTTP_STATUS_ERROR"
        || (payload.code == "CLI_ERROR"
            && (payload.message.contains("failed to POST")
                || payload.message.contains("failed to DELETE")));
    if operation_spec(operation)
        .is_some_and(|spec| spec.side_effect == CliSideEffect::Write && spec.requires_confirmation)
        && write_may_have_been_sent
    {
        payload.retryable = false;
        payload.hint = Some(
            "This operation may have partially applied; inspect current state before retrying.",
        );
        if let Some(details) = payload.details.as_object_mut() {
            details.insert("idempotent".to_string(), json!(false));
        }
    }
    payload
}

fn http_status_from_message(message: &str) -> Option<u16> {
    let marker = "failed (";
    let start = message.find(marker)? + marker.len();
    let status = message.get(start..start + 3)?;
    status.parse::<u16>().ok()
}

fn print_json_with_session<T: Serialize>(value: &T, session_id: Option<Uuid>) -> Result<()> {
    let output = json_value_with_session(value, session_id)?;
    print_json(&output)
}

fn json_value_with_session<T: Serialize>(value: &T, session_id: Option<Uuid>) -> Result<Value> {
    let mut output = serde_json::to_value(value).context("failed to encode JSON output")?;
    attach_session_id(&mut output, session_id);
    Ok(output)
}

fn json_value_with_session_and_workspace_save_error<T: Serialize>(
    value: &T,
    session_id: Option<Uuid>,
    workspace_save_error: Option<&anyhow::Error>,
) -> Result<Value> {
    let mut output = json_value_with_session(value, session_id)?;
    if let Some(error) = workspace_save_error {
        attach_workspace_save_error(&mut output, error);
    }
    Ok(output)
}

fn attach_session_id(output: &mut Value, session_id: Option<Uuid>) {
    if let Some(session_id) = session_id {
        if let Value::Object(map) = output {
            map.insert("session_id".to_string(), json!(session_id));
        }
    }
}

fn failed_record_output(label: &str, value: &Value) -> Option<Value> {
    if value.get("status").and_then(Value::as_str) == Some("failed") {
        Some(json!({
            "error": format!("{label} failed"),
            "record": value,
        }))
    } else {
        None
    }
}

fn attach_workspace_save_error(output: &mut Value, error: &anyhow::Error) {
    if let Value::Object(map) = output {
        map.insert(
            "workspace_save_error".to_string(),
            Value::String(error.to_string()),
        );
    }
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

fn ensure_http_replay_tab(tab: &ReplayTabState, tab_id: &str) -> Result<()> {
    if tab.tab_type == "websocket" {
        bail!("replay tab {tab_id} is a WebSocket replay tab");
    }
    Ok(())
}

fn split_host_port(value: &str) -> Option<(&str, &str)> {
    if value.starts_with('[') {
        let end = value.find(']')?;
        let remainder = value.get(end + 1..)?;
        let port = remainder.strip_prefix(':')?;
        return port
            .chars()
            .all(|char| char.is_ascii_digit())
            .then_some((&value[1..end], port));
    }
    if value.matches(':').count() != 1 {
        return None;
    }
    let (host, port) = value.rsplit_once(':')?;
    if !host.is_empty() && port.chars().all(|char| char.is_ascii_digit()) {
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

fn format_request_authority(host: &str, port: Option<u16>) -> String {
    let needs_brackets = host.contains(':') && !host.starts_with('[') && !host.ends_with(']');
    let authority_host = if needs_brackets {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    match port {
        Some(port) => format!("{authority_host}:{port}"),
        None => authority_host,
    }
}

fn request_authorities_equivalent(left: &str, right: &str, scheme: &str) -> bool {
    let Some((left_host, left_port)) = normalize_request_authority(left, scheme) else {
        return left.trim().eq_ignore_ascii_case(right.trim());
    };
    let Some((right_host, right_port)) = normalize_request_authority(right, scheme) else {
        return false;
    };
    left_host.eq_ignore_ascii_case(&right_host) && left_port == right_port
}

fn normalize_request_authority(authority: &str, scheme: &str) -> Option<(String, u16)> {
    let authority = authority.trim();
    if authority.is_empty() {
        return None;
    }
    if let Some((host, port)) = split_host_port(authority) {
        let port = port.parse::<u16>().ok()?;
        return Some((strip_ipv6_brackets(host).to_string(), port));
    }
    Some((
        strip_ipv6_brackets(authority).to_string(),
        default_port_for_scheme(scheme),
    ))
}

fn strip_ipv6_brackets(value: &str) -> &str {
    value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(value)
}

fn default_port_for_scheme(scheme: &str) -> u16 {
    if scheme.eq_ignore_ascii_case("http") {
        80
    } else {
        443
    }
}

fn install_skills(args: SkillsInstallArgs) -> Result<skills::SkillsInstallResult> {
    let install_codex = args.all || args.codex;
    let install_claude = args.all || args.claude;
    if !install_codex && !install_claude {
        bail!("select at least one destination with --codex, --claude, or --all");
    }

    let codex_root = install_codex.then(|| {
        args.codex_dir
            .clone()
            .or_else(skills::default_codex_skills_dir)
            .context("could not determine Codex skills directory; set HOME or pass --codex-dir")
    });
    let claude_root = install_claude.then(|| {
        args.claude_dir
            .clone()
            .or_else(skills::default_claude_skills_dir)
            .context("could not determine Claude skills directory; set HOME or pass --claude-dir")
    });
    let codex_root = codex_root.transpose()?;
    let claude_root = claude_root.transpose()?;
    if let (Some(codex_root), Some(claude_root)) = (&codex_root, &claude_root) {
        skills::ensure_distinct_skill_install_targets(codex_root, claude_root)?;
    }

    let mut installed = Vec::new();
    if let Some(root) = codex_root {
        let path =
            skills::install_skill_folder(&root, skills::SKILL_NAME, skills::CODEX_SKILL_TEMPLATE)?;
        installed.push(skills::InstalledSkill {
            agent: "codex",
            path: path.display().to_string(),
        });
    }
    if let Some(root) = claude_root {
        let path =
            skills::install_skill_folder(&root, skills::SKILL_NAME, skills::CLAUDE_SKILL_TEMPLATE)?;
        installed.push(skills::InstalledSkill {
            agent: "claude",
            path: path.display().to_string(),
        });
    }

    Ok(skills::SkillsInstallResult { installed })
}

struct NormalizedTarget {
    scheme: String,
    host: String,
    port: String,
}

#[cfg(test)]
fn parse_editable_raw_response(
    text: &str,
    fallback: Option<&EditableResponse>,
) -> Result<EditableResponse> {
    parse_editable_raw_response_for_request_method(text, fallback, "GET")
}

#[cfg(test)]
fn parse_editable_raw_response_for_request_method(
    text: &str,
    fallback: Option<&EditableResponse>,
    request_method: &str,
) -> Result<EditableResponse> {
    let (head, body) = split_raw_http_message(text);
    parse_editable_raw_response_parts(head, RawRequestBody::Text(body), fallback, request_method)
}

#[cfg(test)]
fn parse_editable_raw_response_bytes(
    bytes: &[u8],
    fallback: Option<&EditableResponse>,
) -> Result<EditableResponse> {
    parse_editable_raw_response_bytes_for_request_method(bytes, fallback, "GET")
}

fn parse_editable_raw_response_bytes_for_request_method(
    bytes: &[u8],
    fallback: Option<&EditableResponse>,
    request_method: &str,
) -> Result<EditableResponse> {
    let (head, body) = split_raw_http_message_bytes(bytes)?;
    parse_editable_raw_response_parts(head, RawRequestBody::Bytes(body), fallback, request_method)
}

fn parse_editable_raw_response_parts(
    head: String,
    raw_body: RawRequestBody,
    fallback: Option<&EditableResponse>,
    request_method: &str,
) -> Result<EditableResponse> {
    let mut lines = head.lines();
    let first_line = lines.next();
    let (status, header_lines): (u16, Vec<&str>) = match first_line {
        Some(line) if line.trim().is_empty() => (
            fallback.map(|f| f.status).unwrap_or(200),
            lines.collect::<Vec<_>>(),
        ),
        Some(line) if line.trim_start().starts_with("HTTP/") => {
            let status = parse_response_status_line(line)?;
            (status, lines.collect::<Vec<_>>())
        }
        Some(line) if line.contains(':') => {
            let mut header_lines = Vec::new();
            header_lines.push(line);
            header_lines.extend(lines);
            (fallback.map(|f| f.status).unwrap_or(200), header_lines)
        }
        Some(line) => bail!("invalid response status line: {line}"),
        None => (fallback.map(|f| f.status).unwrap_or(200), Vec::new()),
    };
    let headers: Vec<HeaderRecord> = header_lines
        .into_iter()
        .map(|line| {
            let idx = line
                .find(':')
                .ok_or_else(|| anyhow!("invalid response header line: {line}"))?;
            Ok(HeaderRecord {
                name: line[..idx].trim().to_string(),
                value: line[idx + 1..].trim().to_string(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let inferred_text_encoding = match &raw_body {
        RawRequestBody::Text(body) => infer_text_body_encoding(
            &headers,
            body,
            fallback.map(|response| &response.body_encoding),
        )?,
        RawRequestBody::Bytes(_) => None,
    };
    let body_len = raw_body.wire_len(inferred_text_encoding.as_ref(), "response")?;
    if response_must_not_include_body(status, request_method) && body_len != 0 {
        bail!("response status {status} must not include a body");
    }
    validate_raw_http_body_framing(
        &headers,
        body_len,
        response_content_length_may_describe_representation(status, request_method),
    )?;
    let (body, body_encoding) = match raw_body {
        RawRequestBody::Text(body) => (body, inferred_text_encoding.unwrap_or(BodyEncoding::Utf8)),
        RawRequestBody::Bytes(body) => {
            let content_type = headers
                .iter()
                .find(|header| header.name.eq_ignore_ascii_case("content-type"))
                .map(|header| header.value.as_str());
            encode_raw_request_body(content_type, &body)
        }
    };
    let response = EditableResponse {
        status,
        headers,
        body,
        body_encoding,
    };
    response
        .try_body_bytes()
        .context("response body is not valid base64")?;
    Ok(response)
}

fn response_status_must_not_include_body(status: u16) -> bool {
    status < 200 || status == 204 || status == 205 || status == 304
}

fn response_must_not_include_body(status: u16, request_method: &str) -> bool {
    response_status_must_not_include_body(status) || request_method.eq_ignore_ascii_case("HEAD")
}

fn response_content_length_may_describe_representation(status: u16, request_method: &str) -> bool {
    status == 304
        || (request_method.eq_ignore_ascii_case("HEAD") && !matches!(status, 100..=199 | 204 | 205))
}

fn parse_response_status_line(status_line: &str) -> Result<u16> {
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        bail!("invalid response status line: {status_line}");
    }
    let status = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing response status code"))?
        .parse::<u16>()
        .with_context(|| format!("invalid response status code in line: {status_line}"))?;
    if !(100..=599).contains(&status) {
        bail!("response status code out of range: {status}");
    }
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::{
        active_session_id_from_summaries, api_failure_detail, api_url, attach_session_id,
        attach_workspace_save_error, auto_replace_write_session_id, build_annotations_payload,
        build_editable_raw_request, build_editable_raw_request_with_version,
        build_oast_configure_update, clap_error_payload, cli_data_dir, cli_error_payload,
        cli_output_format_from_raw_args, cli_parse_error_operation, cli_partial_apply_error,
        command_from_call_args, command_from_operation_input, data_dir_strings_match,
        default_cli_data_dir, default_editable_request, discover_api_base_url,
        discover_api_base_url_from_data_dir, dry_run_command, ensure_http_replay_tab,
        explicit_or_active_session_id, failed_record_output, fuzzer_active_target_for_request,
        fuzzer_target_request_authority_for_request, history_list_path, install_skills,
        json_value_with_session_and_workspace_save_error, manifest_operations,
        next_replay_tab_sequence, normalize_api_base_url, normalize_replay_port,
        normalize_target_inputs, oast_fields_for_output, operation_spec,
        parse_editable_raw_request, parse_editable_raw_request_bytes_with_version,
        parse_editable_raw_request_with_version, parse_editable_raw_response,
        parse_editable_raw_response_bytes, parse_editable_raw_response_for_request_method,
        prepare_cli_workspace_save, process_path_strings_match, push_replay_history_entry,
        read_limited_to_end, read_payloads_input, read_raw_request_input, read_raw_response_input,
        read_text_input, replay_send_http_version, replay_send_target_for_tab,
        replay_tab_target_as_request, replay_update_should_preserve_current_port,
        sequence_write_session_id, session_id_for_write_payload, session_query_path,
        session_query_path_with_expected_active, sniper_settings_probe_matches, split_host_port,
        split_payload_lines, strip_host_port, transaction_detail_path, validate_command_preflight,
        validate_sniper_settings_probe, websocket_detail_path, websocket_list_path,
        workspace_conflict_message, workspace_state_conflict_detail, CaptureCommand, Cli,
        CliSideEffect, Command, FuzzerCommand, HistoryCommand, HistoryListArgs,
        HistoryListResponse, InterceptRuleCommand, OastCommand, OastConfigureArgs, OutputFormat,
        ReplayCommand, RuntimeUpdatePayload, SequenceCommand, SequenceCreateInput, SessionCommand,
        SkillsInstallArgs, SniperApiProbeExpectation, TargetCommand, WebSocketListArgs,
        WebSocketListResponse, CLI_REPEATER_HISTORY_LIMIT, CLI_WORKSPACE_CLIENT_ID,
        MAX_CLI_INPUT_BYTES, MAX_OAST_POLLING_INTERVAL_SECS, SNIPER_API_PROBE_RETRY_DELAYS,
        SNIPER_DATA_DIR_ENV,
    };
    use chrono::Utc;
    use clap::Parser;
    use serde_json::{json, Value};
    use sniper::model::{
        BodyEncoding, EditableRequest, EditableResponse, HeaderRecord, RequestTargetOverride,
    };
    use sniper::runtime_state::{persist_runtime_state, runtime_state_path, RuntimeStateSnapshot};
    use sniper::session::SessionSummary;
    use sniper::skills;
    use sniper::workspace::{
        FuzzerWorkspaceState, ReplayHistoryEntryState, ReplayTabState, ReplayWorkspaceState,
        WorkspaceStateSnapshot,
    };
    use std::fs;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use uuid::Uuid;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set<K: Into<std::ffi::OsString>>(key: &'static str, value: K) -> Self {
            let guard = Self {
                key,
                previous: std::env::var_os(key),
            };
            std::env::set_var(key, value.into());
            guard
        }

        fn remove(key: &'static str) -> Self {
            let guard = Self {
                key,
                previous: std::env::var_os(key),
            };
            std::env::remove_var(key);
            guard
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

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
    fn transaction_detail_path_pins_session_when_available() {
        let transaction_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let session_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();

        assert_eq!(
            transaction_detail_path(transaction_id, Some(session_id)),
            "/api/transactions/11111111-1111-1111-1111-111111111111?session_id=22222222-2222-2222-2222-222222222222"
        );
        assert_eq!(
            transaction_detail_path(transaction_id, None),
            "/api/transactions/11111111-1111-1111-1111-111111111111"
        );
    }

    #[test]
    fn history_list_path_uses_page_endpoint_for_sorting() {
        let session_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();

        let sorted_args = HistoryListArgs {
            limit: Some(1),
            sort_key: Some("host".to_string()),
            sort_direction: Some("asc".to_string()),
            ..HistoryListArgs::default()
        };
        assert_eq!(
            history_list_path(Some(session_id), &sorted_args).unwrap(),
            "/api/transactions-page?session_id=22222222-2222-2222-2222-222222222222&limit=1&sort_key=host&sort_direction=asc"
        );

        let legacy_args = HistoryListArgs {
            limit: Some(1),
            sort_key: Some("   ".to_string()),
            ..HistoryListArgs::default()
        };
        assert_eq!(
            history_list_path(Some(session_id), &legacy_args).unwrap(),
            "/api/transactions?session_id=22222222-2222-2222-2222-222222222222&limit=1"
        );

        let cursor_args = HistoryListArgs {
            limit: Some(50),
            before_sequence: Some(1234),
            ..HistoryListArgs::default()
        };
        assert_eq!(
            history_list_path(Some(session_id), &cursor_args).unwrap(),
            "/api/transactions-page?session_id=22222222-2222-2222-2222-222222222222&limit=50&before_sequence=1234&sort_key=index&sort_direction=desc"
        );
    }

    #[test]
    fn history_cursor_path_rejects_incompatible_sort_options() {
        let session_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();

        let invalid_sort_key = HistoryListArgs {
            before_sequence: Some(1234),
            sort_key: Some("host".to_string()),
            sort_direction: Some("asc".to_string()),
            ..HistoryListArgs::default()
        };
        let error = history_list_path(Some(session_id), &invalid_sort_key).unwrap_err();
        assert!(error.to_string().contains("--before-sequence requires"));

        let invalid_sort_direction = HistoryListArgs {
            before_sequence: Some(1234),
            sort_key: Some("index".to_string()),
            sort_direction: Some("asc".to_string()),
            ..HistoryListArgs::default()
        };
        let error = history_list_path(Some(session_id), &invalid_sort_direction).unwrap_err();
        assert!(error.to_string().contains("--before-sequence requires"));
    }

    #[test]
    fn websocket_list_path_uses_page_endpoint_when_requested() {
        let session_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();

        let page_args = WebSocketListArgs {
            limit: Some(1),
            page: true,
            ..WebSocketListArgs::default()
        };
        assert_eq!(
            websocket_list_path(Some(session_id), &page_args),
            "/api/websockets-page?session_id=22222222-2222-2222-2222-222222222222&limit=1"
        );
        let legacy_args = WebSocketListArgs {
            limit: Some(1),
            ..WebSocketListArgs::default()
        };
        assert_eq!(
            websocket_list_path(Some(session_id), &legacy_args),
            "/api/websockets?session_id=22222222-2222-2222-2222-222222222222&limit=1"
        );
        let offset_args = WebSocketListArgs {
            limit: Some(1),
            offset: Some(100),
            ..WebSocketListArgs::default()
        };
        assert_eq!(
            websocket_list_path(Some(session_id), &offset_args),
            "/api/websockets-page?session_id=22222222-2222-2222-2222-222222222222&limit=1&offset=100"
        );
        let sorted_args = WebSocketListArgs {
            limit: Some(1),
            sort_key: Some("host".to_string()),
            sort_direction: Some("asc".to_string()),
            ..WebSocketListArgs::default()
        };
        assert_eq!(
            websocket_list_path(Some(session_id), &sorted_args),
            "/api/websockets-page?session_id=22222222-2222-2222-2222-222222222222&limit=1&sort_key=host&sort_direction=asc"
        );
        let in_scope_args = WebSocketListArgs {
            limit: Some(1),
            in_scope_only: true,
            ..WebSocketListArgs::default()
        };
        assert_eq!(
            websocket_list_path(Some(session_id), &in_scope_args),
            "/api/websockets-page?session_id=22222222-2222-2222-2222-222222222222&limit=1&in_scope_only=true"
        );
        let filtered_args = WebSocketListArgs {
            query: Some("chat socket".to_string()),
            limit: Some(1),
            offset: Some(100),
            sort_key: Some("host".to_string()),
            sort_direction: Some("asc".to_string()),
            in_scope_only: true,
            live_only: true,
            page: true,
            ..WebSocketListArgs::default()
        };
        assert_eq!(
            websocket_list_path(Some(session_id), &filtered_args),
            "/api/websockets-page?session_id=22222222-2222-2222-2222-222222222222&q=chat+socket&limit=1&offset=100&sort_key=host&sort_direction=asc&in_scope_only=true&live_only=true"
        );
    }

    #[test]
    fn websocket_detail_path_includes_frame_limit_and_allows_zero() {
        let websocket_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let session_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();

        assert_eq!(
            websocket_detail_path(websocket_id, Some(session_id), Some(0), None),
            "/api/websockets/11111111-1111-1111-1111-111111111111?session_id=22222222-2222-2222-2222-222222222222&frame_limit=0"
        );
        assert_eq!(
            websocket_detail_path(websocket_id, None, Some(2), Some(1000)),
            "/api/websockets/11111111-1111-1111-1111-111111111111?frame_limit=2&before_index=1000"
        );
        assert_eq!(
            websocket_detail_path(websocket_id, None, Some(2), None),
            "/api/websockets/11111111-1111-1111-1111-111111111111?frame_limit=2"
        );
        assert_eq!(
            websocket_detail_path(websocket_id, Some(session_id), None, None),
            "/api/websockets/11111111-1111-1111-1111-111111111111?session_id=22222222-2222-2222-2222-222222222222&frame_limit=1000"
        );
        assert_eq!(
            websocket_detail_path(websocket_id, None, Some(50_000), None),
            "/api/websockets/11111111-1111-1111-1111-111111111111?frame_limit=1000"
        );
    }

    fn test_session_summary(id: Uuid, active: bool) -> SessionSummary {
        SessionSummary {
            id,
            name: "session".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_opened_at: Utc::now(),
            request_count: 0,
            websocket_count: 0,
            event_count: 0,
            fuzzer_count: 0,
            rule_count: 0,
            storage_path: String::new(),
            active,
        }
    }

    #[test]
    fn active_session_id_prefers_active_session_without_workspace_state() {
        let first = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let active = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        let sessions = vec![
            test_session_summary(first, false),
            test_session_summary(active, true),
        ];

        assert_eq!(
            active_session_id_from_summaries(&sessions).unwrap(),
            Some(active)
        );
    }

    #[test]
    fn read_text_input_rejects_oversized_regular_file() {
        let dir = std::env::temp_dir().join(format!("sniper-cli-input-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("large.txt");
        let file = fs::File::create(&path).unwrap();
        file.set_len((MAX_CLI_INPUT_BYTES + 1) as u64).unwrap();

        let error = read_text_input(Some(path), false).unwrap_err();

        assert!(error.to_string().contains("cannot exceed"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn read_text_input_rejects_non_regular_file() {
        let dir =
            std::env::temp_dir().join(format!("sniper-cli-input-dir-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();

        let error = read_text_input(Some(dir.clone()), false).unwrap_err();

        assert!(error.to_string().contains("not a regular file"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn read_limited_to_end_rejects_streams_over_limit() {
        let mut reader = std::io::Cursor::new(vec![1, 2, 3, 4]);

        let error = read_limited_to_end(&mut reader, "fixture", 3).unwrap_err();

        assert!(error.to_string().contains("cannot exceed 3 bytes"));
    }

    #[test]
    fn active_session_id_requires_exactly_one_active_session() {
        let first = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let sessions = vec![test_session_summary(first, false)];

        let error = active_session_id_from_summaries(&sessions).unwrap_err();
        assert!(error
            .to_string()
            .contains("no active session; pass --session-id"));
        assert_eq!(active_session_id_from_summaries(&[]).unwrap(), None);
    }

    #[test]
    fn active_session_id_rejects_multiple_active_sessions() {
        let first = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let second = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        let sessions = vec![
            test_session_summary(first, true),
            test_session_summary(second, true),
        ];

        let error = active_session_id_from_summaries(&sessions).unwrap_err();
        assert!(error
            .to_string()
            .contains("multiple active sessions; pass --session-id"));
    }

    #[test]
    fn explicit_session_id_overrides_active_session_id() {
        let explicit = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let active = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();

        assert_eq!(
            explicit_or_active_session_id(Some(explicit), Some(active)),
            Some(explicit)
        );
        assert_eq!(
            explicit_or_active_session_id(None, Some(active)),
            Some(active)
        );
        assert_eq!(explicit_or_active_session_id(None, None), None);
    }

    #[test]
    fn implicit_write_payload_does_not_pin_active_session() {
        let active = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();

        assert_eq!(
            explicit_or_active_session_id(None, Some(active)),
            Some(active)
        );
        assert_eq!(session_id_for_write_payload(None), None);
        assert_eq!(session_id_for_write_payload(Some(active)), Some(active));
    }

    #[test]
    fn session_query_path_with_expected_active_adds_write_guard() {
        let session_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();

        assert_eq!(
            session_query_path_with_expected_active(
                "/api/match-replace",
                Some(session_id),
                Some(session_id),
            ),
            "/api/match-replace?session_id=22222222-2222-2222-2222-222222222222&expected_active_session_id=22222222-2222-2222-2222-222222222222"
        );
    }

    #[test]
    fn sequence_write_session_id_only_uses_explicit_sources() {
        let cli_session_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let input_session_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();

        assert_eq!(
            sequence_write_session_id(None, None, Some(cli_session_id)).unwrap(),
            Some(cli_session_id)
        );
        assert_eq!(sequence_write_session_id(None, None, None).unwrap(), None);
        assert_eq!(
            sequence_write_session_id(Some(cli_session_id), None, Some(input_session_id)).unwrap(),
            Some(cli_session_id)
        );
        let error = sequence_write_session_id(None, Some(input_session_id), Some(cli_session_id))
            .expect_err("sequence JSON session_id without --session-id should fail");
        assert!(error
            .to_string()
            .contains("sequence JSON session_id requires matching --session-id"));
        assert_eq!(
            sequence_write_session_id(Some(input_session_id), Some(input_session_id), None)
                .unwrap(),
            Some(input_session_id)
        );

        let error = sequence_write_session_id(Some(cli_session_id), Some(input_session_id), None)
            .expect_err("conflicting explicit sequence session ids should fail");
        assert!(error
            .to_string()
            .contains("sequence JSON session_id conflicts with --session-id"));
    }

    #[test]
    fn auto_replace_write_session_id_rejects_json_only_or_conflicting_session_id() {
        let cli_session_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let input_session_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();

        assert_eq!(auto_replace_write_session_id(None, None).unwrap(), None);
        assert_eq!(
            auto_replace_write_session_id(Some(cli_session_id), None).unwrap(),
            Some(cli_session_id)
        );

        let error = auto_replace_write_session_id(None, Some(input_session_id))
            .expect_err("auto-replace JSON session_id without --session-id should fail");
        assert!(error
            .to_string()
            .contains("auto-replace JSON session_id requires matching --session-id"));

        assert_eq!(
            auto_replace_write_session_id(Some(input_session_id), Some(input_session_id)).unwrap(),
            Some(input_session_id)
        );

        let error = auto_replace_write_session_id(Some(cli_session_id), Some(input_session_id))
            .expect_err("conflicting explicit auto-replace session ids should fail");
        assert!(error
            .to_string()
            .contains("auto-replace JSON session_id conflicts with --session-id"));
    }

    #[test]
    fn session_query_path_appends_encoded_session_id() {
        let session_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();

        assert_eq!(
            session_query_path("/api/sequences/abc", Some(session_id)),
            "/api/sequences/abc?session_id=22222222-2222-2222-2222-222222222222"
        );
        assert_eq!(
            session_query_path("/api/sequences/abc?force=true", Some(session_id)),
            "/api/sequences/abc?force=true&session_id=22222222-2222-2222-2222-222222222222"
        );
        assert_eq!(
            session_query_path("/api/sequences/abc", None),
            "/api/sequences/abc"
        );
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
    fn raw_request_parser_and_builder_preserve_method_case() {
        let parsed = parse_editable_raw_request_with_version(
            "gEt-Custom /case HTTP/1.1\nHost: example.com\n\n",
            None,
        )
        .unwrap();

        assert_eq!(parsed.request.method, "gEt-Custom");
        let text = build_editable_raw_request_with_version(
            &parsed.request,
            parsed.http_version.as_deref(),
        );
        assert!(text.starts_with("gEt-Custom /case HTTP/1.1"));
    }

    #[test]
    fn annotation_payload_only_includes_requested_fields() {
        let color_payload = build_annotations_payload(Some(Some("red".to_string())), None);
        assert_eq!(
            color_payload.get("color_tag"),
            Some(&serde_json::json!("red"))
        );
        assert!(!color_payload.as_object().unwrap().contains_key("user_note"));

        let note_payload = build_annotations_payload(None, Some(None));
        assert_eq!(
            note_payload.get("user_note"),
            Some(&serde_json::json!(null))
        );
        assert!(!note_payload.as_object().unwrap().contains_key("color_tag"));
    }

    #[test]
    fn oast_output_redacts_token_and_reports_configured_state() {
        let fields = oast_fields_for_output(serde_json::json!({
            "oast_enabled": true,
            "oast_token": "secret-token",
            "oast_provider": "custom"
        }));

        assert_eq!(fields.get("oast_token"), None);
        assert_eq!(
            fields.get("oast_token_configured"),
            Some(&serde_json::json!(true))
        );
        assert_eq!(
            fields.get("oast_provider"),
            Some(&serde_json::json!("custom"))
        );
    }

    #[test]
    fn oast_configure_provider_change_leaves_token_policy_to_runtime() {
        let update = build_oast_configure_update(
            &OastConfigureArgs {
                provider: Some("interactsh".to_string()),
                ..Default::default()
            },
            None,
            None,
            None,
        );

        assert_eq!(
            update.get("oast_provider"),
            Some(&serde_json::json!("interactsh"))
        );
        assert!(update.get("oast_token").is_none());
    }

    #[test]
    fn oast_configure_boast_without_token_sets_provider_only() {
        let update = build_oast_configure_update(
            &OastConfigureArgs {
                provider: Some("boast".to_string()),
                ..Default::default()
            },
            None,
            None,
            None,
        );

        assert_eq!(
            update.get("oast_provider"),
            Some(&serde_json::json!("boast"))
        );
        assert!(update.get("oast_token").is_none());
    }

    #[test]
    fn runtime_update_payload_serializes_expected_active_session_guard() {
        let session_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let payload = RuntimeUpdatePayload {
            session_id: Some(session_id),
            expected_active_session_id: Some(session_id),
            intercept_enabled: Some(true),
            websocket_capture_enabled: None,
            scope_patterns: None,
        };

        let value = serde_json::to_value(payload).unwrap();
        assert_eq!(
            value.get("session_id"),
            Some(&serde_json::json!("11111111-1111-1111-1111-111111111111"))
        );
        assert_eq!(
            value.get("expected_active_session_id"),
            Some(&serde_json::json!("11111111-1111-1111-1111-111111111111"))
        );
    }

    #[test]
    fn oast_configure_update_includes_expected_active_session_guard() {
        let session_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let update = build_oast_configure_update(
            &OastConfigureArgs {
                enable: true,
                ..Default::default()
            },
            None,
            Some(session_id),
            Some(session_id),
        );

        assert_eq!(
            update.get("session_id"),
            Some(&serde_json::json!("11111111-1111-1111-1111-111111111111"))
        );
        assert_eq!(
            update.get("expected_active_session_id"),
            Some(&serde_json::json!("11111111-1111-1111-1111-111111111111"))
        );
        assert_eq!(update.get("oast_enabled"), Some(&serde_json::json!(true)));
    }

    #[test]
    fn raw_request_parser_preserves_http_version() {
        let parsed = parse_editable_raw_request_with_version(
            "GET /hello HTTP/2\nHost: example.com\n\n",
            None,
        )
        .unwrap();
        assert_eq!(parsed.request.host, "example.com");
        assert_eq!(parsed.http_version.as_deref(), Some("HTTP/2"));
    }

    #[test]
    fn replay_send_prefers_request_line_http_version() {
        let parsed = parse_editable_raw_request_with_version(
            "GET /hello HTTP/1.1\nHost: example.com\n\n",
            None,
        )
        .unwrap();
        let tab = ReplayTabState {
            http_version_mode: "http/2".to_string(),
            ..Default::default()
        };

        assert_eq!(
            replay_send_http_version(&tab, &parsed).as_deref(),
            Some("HTTP/1.1")
        );
    }

    #[test]
    fn replay_send_uses_tab_http_version_when_request_line_is_synthesized() {
        let fallback = EditableRequest {
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            method: "POST".to_string(),
            path: "/fallback".to_string(),
            headers: vec![HeaderRecord {
                name: "host".to_string(),
                value: "example.com".to_string(),
            }],
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let parsed = parse_editable_raw_request_with_version("", Some(&fallback)).unwrap();
        let tab = ReplayTabState {
            http_version_mode: "HTTP/2".to_string(),
            ..Default::default()
        };

        assert_eq!(parsed.request.method, "POST");
        assert_eq!(parsed.request.path, "/fallback");
        assert_eq!(parsed.http_version, None);
        assert_eq!(
            replay_send_http_version(&tab, &parsed).as_deref(),
            Some("HTTP/2")
        );
    }

    #[test]
    fn cli_status_helper_wraps_failed_records_for_json_output() {
        assert!(failed_record_output(
            "sequence run",
            &serde_json::json!({ "status": "completed" }),
        )
        .is_none());
        let mut output = failed_record_output(
            "sequence run",
            &serde_json::json!({ "id": "run-1", "status": "failed" }),
        )
        .expect("failed record should produce an error payload");
        assert_eq!(output["error"], "sequence run failed");
        assert_eq!(output["record"]["id"], "run-1");
        assert_eq!(output["record"]["status"], "failed");

        let session_id = Uuid::new_v4();
        attach_session_id(&mut output, Some(session_id));
        assert_eq!(output["session_id"], serde_json::json!(session_id));

        attach_workspace_save_error(&mut output, &anyhow::anyhow!("workspace conflict"));
        assert_eq!(output["workspace_save_error"], "workspace conflict");

        let replay_output = json_value_with_session_and_workspace_save_error(
            &serde_json::json!({ "status": "sent" }),
            Some(session_id),
            Some(&anyhow::anyhow!("workspace conflict")),
        )
        .unwrap();
        assert_eq!(replay_output["status"], "sent");
        assert_eq!(replay_output["session_id"], serde_json::json!(session_id));
        assert_eq!(replay_output["workspace_save_error"], "workspace conflict");
    }

    #[test]
    fn sequence_create_input_preserves_api_session_id() {
        let session_id = Uuid::new_v4();
        let sequence_id = Uuid::new_v4();
        let input: SequenceCreateInput = serde_json::from_value(serde_json::json!({
            "session_id": session_id,
            "id": sequence_id,
            "name": "demo",
            "steps": [],
        }))
        .unwrap();

        assert_eq!(input.session_id, Some(session_id));
        assert_eq!(input.definition.id, sequence_id);
    }

    #[test]
    fn raw_request_input_rejects_empty_explicit_source() {
        let path =
            std::env::temp_dir().join(format!("sniper-cli-empty-request-{}.http", Uuid::new_v4()));
        fs::write(&path, b" \n\t").unwrap();
        let fallback = default_editable_request();

        let error = read_raw_request_input(Some(path.clone()), false, Some(&fallback))
            .unwrap_err()
            .to_string();
        let _ = fs::remove_file(path);

        assert!(error.contains("request input is empty"));
    }

    #[test]
    fn raw_response_input_rejects_empty_explicit_source() {
        let path =
            std::env::temp_dir().join(format!("sniper-cli-empty-response-{}.http", Uuid::new_v4()));
        fs::write(&path, b"").unwrap();
        let fallback = EditableResponse {
            status: 200,
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
        };

        let error = read_raw_response_input(Some(path.clone()), false, Some(&fallback), "GET")
            .unwrap_err()
            .to_string();
        let _ = fs::remove_file(path);

        assert!(error.contains("response input is empty"));
    }

    #[test]
    fn raw_request_parser_preserves_fallback_truncated_preview_state() {
        let fallback = EditableRequest {
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            method: "POST".to_string(),
            path: "/upload".to_string(),
            headers: vec![HeaderRecord {
                name: "host".to_string(),
                value: "example.com".to_string(),
            }],
            body: "prefix-$payload$".to_string(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: true,
        };

        let parsed = parse_editable_raw_request_with_version(
            "POST /upload HTTP/1.1\nHost: example.com\n\nprefix-$payload$",
            Some(&fallback),
        )
        .unwrap();

        assert!(parsed.request.preview_truncated);
    }

    #[test]
    fn raw_request_parser_preserves_absolute_form_authority() {
        let request = parse_editable_raw_request(
            "GET http://target.example:8080/admin HTTP/1.1\nHost: target.example:8080\n\n",
            None,
        )
        .unwrap();

        assert_eq!(request.scheme, "http");
        assert_eq!(request.host, "target.example:8080");
        assert_eq!(request.path, "/admin");
    }

    #[test]
    fn raw_request_parser_accepts_mixed_case_absolute_form_url() {
        let request = parse_editable_raw_request(
            "GET HtTpS://target.example/admin HTTP/1.1\nHost: target.example\n\n",
            None,
        )
        .unwrap();

        assert_eq!(request.scheme, "https");
        assert_eq!(request.host, "target.example");
        assert_eq!(request.path, "/admin");
    }

    #[test]
    fn raw_request_parser_accepts_absolute_form_default_port_equivalence() {
        let request = parse_editable_raw_request(
            "GET http://target.example/admin HTTP/1.1\nHost: target.example:80\n\n",
            None,
        )
        .unwrap();

        assert_eq!(request.scheme, "http");
        assert_eq!(request.host, "target.example");
        assert_eq!(request.path, "/admin");
    }

    #[test]
    fn raw_request_parser_preserves_ipv6_absolute_form_authority() {
        let request = parse_editable_raw_request(
            "GET http://[::1]:8080/admin HTTP/1.1\nHost: [::1]:8080\n\n",
            None,
        )
        .unwrap();

        assert_eq!(request.scheme, "http");
        assert_eq!(request.host, "[::1]:8080");
        assert_eq!(request.path, "/admin");
    }

    #[test]
    fn raw_request_parser_rejects_conflicting_absolute_form_host() {
        let error = parse_editable_raw_request(
            "GET http://target.example:8080/admin HTTP/1.1\nHost: attacker.example\n\n",
            None,
        )
        .unwrap_err();

        assert!(error.to_string().contains("does not match Host header"));
    }

    #[test]
    fn raw_request_parser_rejects_duplicate_host_headers() {
        let error = parse_editable_raw_request(
            "GET /dup HTTP/1.1\nHost: first.example\nHost: second.example\n\n",
            None,
        )
        .unwrap_err();

        assert!(error.to_string().contains("multiple Host headers"));
    }

    #[test]
    fn raw_request_parser_rejects_absolute_form_credentials_and_fragments() {
        let credentials = parse_editable_raw_request(
            "GET http://user:pass@target.example/admin HTTP/1.1\nHost: target.example\n\n",
            None,
        )
        .unwrap_err();
        assert!(credentials.to_string().contains("credentials"));

        let fragment = parse_editable_raw_request(
            "GET http://target.example/admin#frag HTTP/1.1\nHost: target.example\n\n",
            None,
        )
        .unwrap_err();
        assert!(fragment.to_string().contains("fragment"));
    }

    #[test]
    fn raw_http_parser_rejects_unsupported_framing() {
        let chunked = parse_editable_raw_request(
            "POST /upload HTTP/1.1\nHost: example.com\nTransfer-Encoding: chunked\n\n4\nbody\n0\n\n",
            None,
        )
        .unwrap_err();
        assert!(chunked.to_string().contains("Transfer-Encoding: chunked"));

        let bad_length = parse_editable_raw_request(
            "POST /upload HTTP/1.1\nHost: example.com\nContent-Length: 2\n\nbody",
            None,
        )
        .unwrap_err();
        assert!(bad_length
            .to_string()
            .contains("does not match raw body length"));

        let chunked_response = parse_editable_raw_response(
            "HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n4\nbody\n0\n\n",
            None,
        )
        .unwrap_err();
        assert!(chunked_response
            .to_string()
            .contains("Transfer-Encoding: chunked"));
    }

    #[test]
    fn fuzzer_target_is_cleared_when_saved_authority_is_stale() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "current.example".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let fuzzer = FuzzerWorkspaceState {
            target: Some(RequestTargetOverride {
                scheme: "https".to_string(),
                host: "override.example".to_string(),
                port: "443".to_string(),
            }),
            target_request_authority: Some("https://old.example".to_string()),
            ..Default::default()
        };

        assert!(fuzzer_active_target_for_request(&fuzzer, &request).is_none());
    }

    #[test]
    fn fuzzer_target_survives_matching_saved_authority() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "current.example:443".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let fuzzer = FuzzerWorkspaceState {
            target: Some(RequestTargetOverride {
                scheme: "https".to_string(),
                host: "override.example".to_string(),
                port: "443".to_string(),
            }),
            target_request_authority: Some("https://current.example".to_string()),
            ..Default::default()
        };

        let target = fuzzer_active_target_for_request(&fuzzer, &request).unwrap();
        assert_eq!(target.host, "override.example");
    }

    #[test]
    fn fuzzer_target_survives_missing_saved_authority_for_legacy_workspace() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "current.example".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let fuzzer = FuzzerWorkspaceState {
            target: Some(RequestTargetOverride {
                scheme: "https".to_string(),
                host: "override.example".to_string(),
                port: "443".to_string(),
            }),
            target_request_authority: None,
            ..Default::default()
        };

        let target = fuzzer_active_target_for_request(&fuzzer, &request).unwrap();
        assert_eq!(target.host, "override.example");
    }

    #[test]
    fn fuzzer_target_with_missing_saved_authority_still_skips_equivalent_target() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "current.example:443".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let fuzzer = FuzzerWorkspaceState {
            target: Some(RequestTargetOverride {
                scheme: "https".to_string(),
                host: "current.example".to_string(),
                port: "443".to_string(),
            }),
            target_request_authority: None,
            ..Default::default()
        };

        assert!(fuzzer_active_target_for_request(&fuzzer, &request).is_none());
    }

    #[test]
    fn fuzzer_target_is_cleared_when_saved_authority_is_invalid() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "current.example".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let fuzzer = FuzzerWorkspaceState {
            target: Some(RequestTargetOverride {
                scheme: "https".to_string(),
                host: "override.example".to_string(),
                port: "443".to_string(),
            }),
            target_request_authority: Some("not a url".to_string()),
            ..Default::default()
        };

        assert!(fuzzer_active_target_for_request(&fuzzer, &request).is_none());
    }

    #[test]
    fn fuzzer_target_authority_persistence_uses_request_authority() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "current.example:8443".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };

        assert_eq!(
            fuzzer_target_request_authority_for_request(&request),
            "https://current.example:8443"
        );
    }

    #[test]
    fn raw_request_parser_preserves_asterisk_form_target() {
        let request =
            parse_editable_raw_request("OPTIONS * HTTP/1.1\nHost: example.com\n\n", None).unwrap();

        assert_eq!(request.method, "OPTIONS");
        assert_eq!(request.path, "*");
    }

    #[test]
    fn raw_request_parser_rejects_connect_authority_form() {
        let error = parse_editable_raw_request(
            "CONNECT example.com:443 HTTP/1.1\nHost: example.com:443\n\n",
            None,
        )
        .unwrap_err();

        assert!(error.to_string().contains("CONNECT authority-form"));
    }

    #[test]
    fn raw_request_parser_rejects_extra_request_line_tokens() {
        let error =
            parse_editable_raw_request("GET / HTTP/1.1 trailing\nHost: example.com\n\n", None)
                .unwrap_err();

        assert!(error.to_string().contains("too many fields"));
    }

    #[test]
    fn raw_request_parser_rejects_malformed_header_lines() {
        let error =
            parse_editable_raw_request("GET / HTTP/1.1\nNot-A-Header\n\n", None).unwrap_err();

        assert!(error.to_string().contains("invalid request header line"));
    }

    #[test]
    fn raw_request_parser_rejects_invalid_method_tokens() {
        let error =
            parse_editable_raw_request("GE/T / HTTP/1.1\nHost: example.com\n\n", None).unwrap_err();

        assert!(error.to_string().contains("invalid HTTP method"));
    }

    #[test]
    fn raw_request_parser_preserves_body_crlf() {
        let request = parse_editable_raw_request(
            "POST /hello HTTP/1.1\r\nHost: example.com\r\n\r\na\r\nb",
            None,
        )
        .unwrap();
        assert_eq!(request.body, "a\r\nb");
    }

    #[test]
    fn raw_request_byte_parser_encodes_binary_body_as_base64() {
        let parsed = parse_editable_raw_request_bytes_with_version(
          b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/octet-stream\r\n\r\n\xff\x00",
            None,
        )
        .unwrap();

        assert_eq!(parsed.request.host, "example.com");
        assert_eq!(parsed.request.body_encoding, BodyEncoding::Base64);
        assert_eq!(parsed.request.body, "/wA=");
        assert_eq!(parsed.request.try_body_bytes().unwrap(), vec![0xff, 0x00]);
    }

    #[test]
    fn binary_raw_request_rebuild_updates_content_length_for_editor_body() {
        let parsed = parse_editable_raw_request_bytes_with_version(
            b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/octet-stream\r\nContent-Length: 2\r\n\r\n\xff\x00",
            None,
        )
        .unwrap();

        let text = build_editable_raw_request_with_version(
            &parsed.request,
            parsed.http_version.as_deref(),
        );
        assert!(text.contains("Content-Length: 2"));
        let reparsed = parse_editable_raw_request_with_version(&text, None)
            .expect("rebuilt binary request should parse without hidden fallback state");

        assert_eq!(reparsed.request.body_encoding, BodyEncoding::Base64);
        assert_eq!(reparsed.request.try_body_bytes().unwrap(), vec![0xff, 0x00]);
    }

    #[test]
    fn binary_raw_request_parser_rejects_encoded_content_length() {
        let fallback = EditableRequest {
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            method: "POST".to_string(),
            path: "/upload".to_string(),
            headers: Vec::new(),
            body: "/wA=".to_string(),
            body_encoding: BodyEncoding::Base64,
            preview_truncated: false,
        };

        let error = parse_editable_raw_request_with_version(
            "POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\n/wA=",
            Some(&fallback),
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("does not match raw body length 2"));
    }

    #[test]
    fn raw_response_parser_preserves_body_crlf() {
        let response = parse_editable_raw_response(
            "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n\r\na\r\nb",
            None,
        )
        .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, "a\r\nb");
    }

    #[test]
    fn raw_response_byte_parser_encodes_binary_body_as_base64() {
        let response = parse_editable_raw_response_bytes(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n\xff\x00",
            None,
        )
        .unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.body_encoding, BodyEncoding::Base64);
        assert_eq!(response.body, "/wA=");
        assert_eq!(response.try_body_bytes().unwrap(), vec![0xff, 0x00]);
    }

    #[test]
    fn raw_response_parser_rejects_body_for_no_body_status() {
        let text_error =
            parse_editable_raw_response("HTTP/1.1 204 No Content\r\n\r\nbody", None).unwrap_err();
        assert!(text_error.to_string().contains("must not include a body"));

        let binary_error =
            parse_editable_raw_response_bytes(b"HTTP/1.1 304 Not Modified\r\n\r\n\x00", None)
                .unwrap_err();
        assert!(binary_error.to_string().contains("must not include a body"));
    }

    #[test]
    fn raw_response_parser_allows_304_representation_content_length() {
        let response = parse_editable_raw_response(
            "HTTP/1.1 304 Not Modified\r\nContent-Length: 55\r\n\r\n",
            None,
        )
        .unwrap();

        assert_eq!(response.status, 304);
        assert_eq!(response.body, "");
    }

    #[test]
    fn raw_response_parser_allows_head_representation_content_length() {
        let response = parse_editable_raw_response_for_request_method(
            "HTTP/1.1 200 OK\r\nContent-Length: 55\r\n\r\n",
            None,
            "HEAD",
        )
        .unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.body, "");
    }

    #[test]
    fn raw_response_parser_rejects_head_response_body() {
        let error = parse_editable_raw_response_for_request_method(
            "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody",
            None,
            "HEAD",
        )
        .unwrap_err();

        assert!(error.to_string().contains("must not include a body"));
    }

    #[test]
    fn raw_response_parser_rejects_get_empty_body_content_length_mismatch() {
        let error =
            parse_editable_raw_response("HTTP/1.1 200 OK\r\nContent-Length: 55\r\n\r\n", None)
                .unwrap_err();

        assert!(error
            .to_string()
            .contains("Content-Length 55 does not match raw body length 0"));
    }

    #[test]
    fn binary_raw_response_parser_infers_base64_from_content_length() {
        let response = parse_editable_raw_response(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 2\r\n\r\n/wA=",
            None,
        )
        .unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.body_encoding, BodyEncoding::Base64);
        assert_eq!(response.try_body_bytes().unwrap(), vec![0xff, 0x00]);
    }

    #[test]
    fn build_raw_request_uses_supplied_http_version() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            method: "POST".to_string(),
            path: "/submit".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let text = build_editable_raw_request_with_version(&request, Some("HTTP/2"));
        assert!(text.starts_with("POST /submit HTTP/2"));
    }

    #[test]
    fn build_raw_request_preserves_trailing_body_bytes() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            method: "POST".to_string(),
            path: "/submit".to_string(),
            headers: Vec::new(),
            body: "abc \n\t".to_string(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };

        let text = build_editable_raw_request(&request);
        assert!(text.ends_with("abc \n\t"));
    }

    #[test]
    fn normalize_target_defaults_port_from_final_scheme() {
        let fallback = EditableRequest {
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };

        let target =
            normalize_target_inputs(Some("http".to_string()), None, None, Some(&fallback)).unwrap();
        assert_eq!(target.scheme, "http");
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, "80");

        let fallback_with_port = EditableRequest {
            host: "example.com:443".to_string(),
            ..fallback.clone()
        };
        let target = normalize_target_inputs(
            Some("http".to_string()),
            None,
            None,
            Some(&fallback_with_port),
        )
        .unwrap();
        assert_eq!(target.scheme, "http");
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, "80");

        let target = normalize_target_inputs(
            None,
            Some("http://other.example".to_string()),
            None,
            Some(&fallback),
        )
        .unwrap();
        assert_eq!(target.scheme, "http");
        assert_eq!(target.host, "other.example");
        assert_eq!(target.port, "80");

        let target = normalize_target_inputs(
            None,
            Some("HtTpS://mixed.example:9443".to_string()),
            None,
            Some(&fallback),
        )
        .unwrap();
        assert_eq!(target.scheme, "https");
        assert_eq!(target.host, "mixed.example");
        assert_eq!(target.port, "9443");
    }

    #[test]
    fn replay_update_partial_target_uses_current_tab_target_as_fallback() {
        let tab = ReplayTabState {
            target_scheme: "https".to_string(),
            target_host: "override.example".to_string(),
            target_port: "9443".to_string(),
            ..Default::default()
        };
        let fallback = replay_tab_target_as_request(&tab).unwrap();

        let mut target =
            normalize_target_inputs(Some("http".to_string()), None, None, Some(&fallback)).unwrap();
        if replay_update_should_preserve_current_port(
            Some("http"),
            None,
            None,
            tab.target_scheme.as_str(),
            tab.target_port.as_str(),
        ) {
            target.port = normalize_replay_port(&tab.target_port).unwrap();
        }

        assert_eq!(target.scheme, "http");
        assert_eq!(target.host, "override.example");
        assert_eq!(target.port, "9443");
    }

    #[test]
    fn replay_update_plain_host_preserves_current_tab_port() {
        let tab = ReplayTabState {
            target_scheme: "https".to_string(),
            target_host: "override.example".to_string(),
            target_port: "9443".to_string(),
            ..Default::default()
        };
        let fallback = replay_tab_target_as_request(&tab).unwrap();

        let mut target =
            normalize_target_inputs(None, Some("new.example".to_string()), None, Some(&fallback))
                .unwrap();
        if replay_update_should_preserve_current_port(
            None,
            Some("new.example"),
            None,
            tab.target_scheme.as_str(),
            tab.target_port.as_str(),
        ) {
            target.port = normalize_replay_port(&tab.target_port).unwrap();
        }

        assert_eq!(target.scheme, "https");
        assert_eq!(target.host, "new.example");
        assert_eq!(target.port, "9443");
    }

    #[test]
    fn replay_update_scheme_only_does_not_preserve_previous_default_port() {
        let tab = ReplayTabState {
            target_scheme: "https".to_string(),
            target_host: "example.com".to_string(),
            target_port: "443".to_string(),
            ..Default::default()
        };
        let fallback = replay_tab_target_as_request(&tab).unwrap();

        let mut target =
            normalize_target_inputs(Some("http".to_string()), None, None, Some(&fallback)).unwrap();
        if replay_update_should_preserve_current_port(
            Some("http"),
            None,
            None,
            tab.target_scheme.as_str(),
            tab.target_port.as_str(),
        ) {
            target.port = normalize_replay_port(&tab.target_port).unwrap();
        }

        assert_eq!(target.scheme, "http");
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, "80");
    }

    #[test]
    fn replay_update_url_target_updates_scheme_host_and_port_together() {
        let tab = ReplayTabState {
            target_scheme: "https".to_string(),
            target_host: "override.example".to_string(),
            target_port: "9443".to_string(),
            ..Default::default()
        };
        let fallback = replay_tab_target_as_request(&tab).unwrap();

        let target = normalize_target_inputs(
            None,
            Some("https://new.example:8443".to_string()),
            None,
            Some(&fallback),
        )
        .unwrap();

        assert_eq!(target.scheme, "https");
        assert_eq!(target.host, "new.example");
        assert_eq!(target.port, "8443");
    }

    #[test]
    fn cli_replay_history_is_capped_like_browser_history() {
        fn entry(path: &str) -> ReplayHistoryEntryState {
            ReplayHistoryEntryState {
                request: Some(EditableRequest {
                    path: path.to_string(),
                    ..default_editable_request()
                }),
                request_text: format!("GET {path} HTTP/1.1\nHost: example.com"),
                ..Default::default()
            }
        }

        let mut tab = ReplayTabState::default();
        for index in 0..(CLI_REPEATER_HISTORY_LIMIT + 1) {
            push_replay_history_entry(&mut tab, entry(&format!("/{index}")));
        }

        assert_eq!(tab.history_entries.len(), CLI_REPEATER_HISTORY_LIMIT);
        assert_eq!(tab.history_index, Some(CLI_REPEATER_HISTORY_LIMIT - 1));
        assert_eq!(
            tab.history_entries
                .first()
                .and_then(|entry| entry.request.as_ref())
                .map(|request| request.path.as_str()),
            Some("/1")
        );
    }

    #[test]
    fn cli_replay_history_drops_forward_entries_before_append() {
        fn entry(path: &str) -> ReplayHistoryEntryState {
            ReplayHistoryEntryState {
                request: Some(EditableRequest {
                    path: path.to_string(),
                    ..default_editable_request()
                }),
                request_text: format!("GET {path} HTTP/1.1\nHost: example.com"),
                ..Default::default()
            }
        }

        let mut tab = ReplayTabState {
            history_entries: vec![entry("/old-0"), entry("/old-1"), entry("/old-2")],
            history_index: Some(0),
            ..Default::default()
        };

        push_replay_history_entry(&mut tab, entry("/new"));

        assert_eq!(tab.history_entries.len(), 2);
        assert_eq!(tab.history_index, Some(1));
        assert_eq!(
            tab.history_entries
                .last()
                .and_then(|entry| entry.request.as_ref())
                .map(|request| request.path.as_str()),
            Some("/new")
        );
    }

    #[test]
    fn normalize_target_rejects_url_components_and_host_ports() {
        assert!(normalize_target_inputs(
            None,
            Some("https://victim.test@127.0.0.1".to_string()),
            None,
            None,
        )
        .is_err());
        assert!(normalize_target_inputs(
            None,
            Some("https://example.test/path".to_string()),
            None,
            None,
        )
        .is_err());
        assert!(normalize_target_inputs(
            None,
            Some("example.test:notaport".to_string()),
            None,
            None,
        )
        .is_err());
        assert!(normalize_target_inputs(
            Some("http".to_string()),
            Some("https://example.test".to_string()),
            None,
            None,
        )
        .is_err());
    }

    #[test]
    fn normalize_target_rejects_invalid_user_supplied_ports() {
        assert!(
            normalize_target_inputs(None, Some("example.com:70000".to_string()), None, None,)
                .is_err()
        );
        assert!(normalize_target_inputs(
            None,
            Some("example.com".to_string()),
            Some("0".to_string()),
            None,
        )
        .is_err());
        assert!(normalize_target_inputs(
            None,
            Some("https://example.com:70000/".to_string()),
            None,
            None,
        )
        .is_err());
    }

    #[test]
    fn normalize_target_rejects_conflicting_host_and_explicit_ports() {
        assert!(normalize_target_inputs(
            None,
            Some("https://example.com:9443".to_string()),
            Some("443".to_string()),
            None,
        )
        .is_err());
        assert!(normalize_target_inputs(
            None,
            Some("example.com:9443".to_string()),
            Some("443".to_string()),
            None,
        )
        .is_err());
        let target = normalize_target_inputs(
            None,
            Some("https://example.com:9443".to_string()),
            Some("9443".to_string()),
            None,
        )
        .unwrap();
        assert_eq!(target.port, "9443");
    }

    #[test]
    fn normalize_target_rejects_invalid_user_supplied_scheme() {
        assert!(normalize_target_inputs(
            Some("ftp".to_string()),
            Some("example.com".to_string()),
            None,
            None,
        )
        .is_err());
    }

    #[test]
    fn replay_target_stays_independent_when_raw_request_host_changes() {
        let old_request = default_editable_request();
        let new_request = EditableRequest {
            host: "new.example.com".to_string(),
            headers: vec![HeaderRecord {
                name: "host".to_string(),
                value: "new.example.com".to_string(),
            }],
            ..old_request.clone()
        };
        let tab = ReplayTabState {
            base_request: Some(old_request.clone()),
            target_scheme: "https".to_string(),
            target_host: "example.com".to_string(),
            target_port: "443".to_string(),
            ..Default::default()
        };

        let target = replay_send_target_for_tab(&tab, &new_request)
            .unwrap()
            .expect("changed request host must not absorb the existing target");

        assert_eq!(target.scheme, "https");
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, "443");
    }

    #[test]
    fn replay_send_keeps_existing_target_after_base_request_changes() {
        let old_request = default_editable_request();
        let new_request = EditableRequest {
            host: "new.example.com".to_string(),
            headers: vec![HeaderRecord {
                name: "host".to_string(),
                value: "new.example.com".to_string(),
            }],
            ..old_request.clone()
        };
        let mut tab = ReplayTabState {
            base_request: Some(old_request),
            target_scheme: "https".to_string(),
            target_host: "example.com".to_string(),
            target_port: "443".to_string(),
            ..Default::default()
        };

        let target = replay_send_target_for_tab(&tab, &new_request)
            .unwrap()
            .expect("existing target must stay explicit when request host changes");
        assert_eq!(target.host, "example.com");

        tab.base_request = Some(new_request.clone());

        assert_eq!(tab.target_host, "example.com");
        assert_eq!(tab.target_port, "443");
        assert!(
            replay_send_target_for_tab(&tab, tab.base_request.as_ref().unwrap())
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn replay_send_target_preserves_empty_host_port_override() {
        let request = EditableRequest {
            scheme: "http".to_string(),
            host: "example.com:80".to_string(),
            headers: vec![HeaderRecord {
                name: "host".to_string(),
                value: "example.com:80".to_string(),
            }],
            ..default_editable_request()
        };
        let tab = ReplayTabState {
            target_scheme: String::new(),
            target_host: String::new(),
            target_port: "8081".to_string(),
            ..Default::default()
        };

        let target = replay_send_target_for_tab(&tab, &request)
            .unwrap()
            .expect("port-only target should be preserved");
        assert_eq!(target.scheme, "");
        assert_eq!(target.host, "");
        assert_eq!(target.port, "8081");
    }

    #[test]
    fn replay_send_target_rejects_ip_literal_request_host_override() {
        let request = EditableRequest {
            host: "127.0.0.1".to_string(),
            headers: vec![HeaderRecord {
                name: "host".to_string(),
                value: "127.0.0.1".to_string(),
            }],
            ..default_editable_request()
        };
        let tab = ReplayTabState {
            target_scheme: "http".to_string(),
            target_host: String::new(),
            target_port: String::new(),
            ..Default::default()
        };

        let error = replay_send_target_for_tab(&tab, &request).unwrap_err();
        assert!(error.to_string().contains("request host is an IP address"));
    }

    #[test]
    fn replay_http_commands_reject_websocket_tabs() {
        let tab = ReplayTabState {
            id: uuid::Uuid::new_v4().to_string(),
            tab_type: "websocket".to_string(),
            ..ReplayTabState::default()
        };

        let error = ensure_http_replay_tab(&tab, &tab.id).unwrap_err();

        assert!(error.to_string().contains("WebSocket replay tab"));
    }

    #[test]
    fn replay_send_target_allows_equivalent_ip_literal_request_host() {
        let request = EditableRequest {
            host: "127.0.0.1:443".to_string(),
            headers: vec![HeaderRecord {
                name: "host".to_string(),
                value: "127.0.0.1:443".to_string(),
            }],
            ..default_editable_request()
        };
        let tab = ReplayTabState {
            target_scheme: "https".to_string(),
            target_host: "127.0.0.1".to_string(),
            target_port: "443".to_string(),
            ..Default::default()
        };

        assert!(replay_send_target_for_tab(&tab, &request)
            .unwrap()
            .is_none());
    }

    #[test]
    fn cli_workspace_save_rewrites_browser_client_identity() {
        let mut workspace = WorkspaceStateSnapshot {
            revision: 7,
            session_id: Some(uuid::Uuid::new_v4()),
            client_id: Some("browser-client".to_string()),
            client_version: 41,
            ..Default::default()
        };
        let session_id = workspace.session_id;

        prepare_cli_workspace_save(&mut workspace, None);

        assert_eq!(workspace.revision, 7);
        assert_eq!(workspace.session_id, session_id);
        assert_eq!(workspace.expected_active_session_id, session_id);
        assert_eq!(workspace.client_id.as_deref(), Some("sniper-cli"));
        assert_eq!(workspace.client_version, 42);

        prepare_cli_workspace_save(&mut workspace, session_id);

        assert_eq!(workspace.revision, 7);
        assert_eq!(workspace.session_id, session_id);
        assert_eq!(workspace.expected_active_session_id, None);
        assert_eq!(workspace.client_id.as_deref(), Some("sniper-cli"));
        assert_eq!(workspace.client_version, 43);
    }

    #[test]
    fn replay_tab_sequence_reports_overflow() {
        let replay = ReplayWorkspaceState {
            tab_sequence: 41,
            ..ReplayWorkspaceState::default()
        };
        assert_eq!(next_replay_tab_sequence(&replay).unwrap(), 42);

        let replay = ReplayWorkspaceState {
            tab_sequence: 1,
            tabs: vec![ReplayTabState {
                sequence: 42,
                ..ReplayTabState::default()
            }],
            ..ReplayWorkspaceState::default()
        };
        assert_eq!(next_replay_tab_sequence(&replay).unwrap(), 43);

        let replay = ReplayWorkspaceState {
            tab_sequence: usize::MAX,
            ..ReplayWorkspaceState::default()
        };
        let error = next_replay_tab_sequence(&replay).unwrap_err();
        assert!(error
            .to_string()
            .contains("replay tab sequence is too large"));

        let replay = ReplayWorkspaceState {
            tab_sequence: 1,
            tabs: vec![ReplayTabState {
                sequence: usize::MAX,
                ..ReplayTabState::default()
            }],
            ..ReplayWorkspaceState::default()
        };
        let error = next_replay_tab_sequence(&replay).unwrap_err();
        assert!(error
            .to_string()
            .contains("replay tab sequence is too large"));
    }

    #[test]
    fn cli_workspace_conflict_message_includes_current_snapshot_identity() {
        let session_id = uuid::Uuid::new_v4();
        let workspace = WorkspaceStateSnapshot {
            revision: 9,
            session_id: Some(session_id),
            client_id: Some("browser-client".to_string()),
            client_version: 77,
            ..Default::default()
        };

        let message = workspace_conflict_message(&workspace);

        assert!(message.contains("current revision 9"));
        assert!(message.contains(&session_id.to_string()));
        assert!(message.contains("client_id browser-client"));
        assert!(message.contains("client_version 77"));
    }

    #[test]
    fn cli_workspace_conflict_detail_prefers_structured_errors() {
        let session_id = uuid::Uuid::new_v4();

        let message = workspace_state_conflict_detail(
            "/api/workspace-state",
            reqwest::StatusCode::CONFLICT,
            serde_json::json!({
                "error": "active session changed",
                "session_id": session_id,
            })
            .to_string(),
        );

        assert!(message.contains("active session changed"));
        assert!(message.contains(&session_id.to_string()));
        assert!(!message.contains("workspace state revision conflict"));
    }

    #[test]
    fn cli_api_failure_detail_formats_session_conflict_json() {
        let session_id = Uuid::new_v4();
        let detail = api_failure_detail(
            reqwest::StatusCode::CONFLICT,
            serde_json::json!({
                "error": "active session changed",
                "session_id": session_id,
            })
            .to_string(),
        );

        assert_eq!(
            detail,
            format!("active session changed (session_id {session_id})")
        );

        let owner_session_id = Uuid::new_v4();
        let detail = api_failure_detail(
            reqwest::StatusCode::CONFLICT,
            serde_json::json!({
                "error": "websocket replay connection belongs to another session",
                "owner_session_id": owner_session_id,
            })
            .to_string(),
        );

        assert_eq!(
            detail,
            format!(
                "websocket replay connection belongs to another session (owner_session_id {owner_session_id})"
            )
        );
    }

    #[test]
    fn cli_api_failure_detail_preserves_plain_text_and_empty_bodies() {
        assert_eq!(
            api_failure_detail(
                reqwest::StatusCode::BAD_REQUEST,
                "plain failure".to_string()
            ),
            "plain failure"
        );
        assert_eq!(
            api_failure_detail(reqwest::StatusCode::NOT_FOUND, String::new()),
            "404 Not Found"
        );
    }

    #[test]
    fn session_delete_and_reveal_parse_ids() {
        let delete_id = Uuid::new_v4();
        let delete_id_arg = delete_id.to_string();
        let parsed = Cli::try_parse_from([
            "sniper-cli",
            "session",
            "delete",
            "--id",
            delete_id_arg.as_str(),
        ])
        .unwrap();
        let Command::Session {
            command: SessionCommand::Delete(args),
        } = parsed.command
        else {
            panic!("expected session delete");
        };
        assert_eq!(args.id, delete_id);

        let reveal_id = Uuid::new_v4();
        let reveal_id_arg = reveal_id.to_string();
        let parsed = Cli::try_parse_from([
            "sniper-cli",
            "session",
            "reveal",
            "--id",
            reveal_id_arg.as_str(),
        ])
        .unwrap();
        let Command::Session {
            command: SessionCommand::Reveal(args),
        } = parsed.command
        else {
            panic!("expected session reveal");
        };
        assert_eq!(args.id, reveal_id);
    }

    #[test]
    fn oast_configure_rejects_enable_disable_conflict() {
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "capture",
            "oast",
            "configure",
            "--enable",
            "--disable",
        ])
        .is_err());
    }

    #[test]
    fn oast_configure_parses_supported_capture_path() {
        assert!(
            Cli::try_parse_from(["sniper-cli", "capture", "oast", "configure", "--enable",])
                .is_ok()
        );
    }

    #[test]
    fn cli_output_contract_parses_compact_and_manifest() {
        let parsed =
            Cli::try_parse_from(["sniper-cli", "--output", "compact", "manifest"]).unwrap();
        assert_eq!(parsed.output, OutputFormat::Compact);
        assert_eq!(parsed.command.operation_name(), "manifest");

        let spec = operation_spec("replay.send").expect("manifest should include replay.send");
        assert_eq!(spec.side_effect, CliSideEffect::Write);
        assert!(spec.requires_confirmation);
    }

    #[test]
    fn manifest_requires_confirmation_for_every_write_operation() {
        let unguarded_writes = manifest_operations()
            .into_iter()
            .filter(|spec| spec.side_effect == CliSideEffect::Write && !spec.requires_confirmation)
            .map(|spec| spec.operation)
            .collect::<Vec<_>>();
        assert!(
            unguarded_writes.is_empty(),
            "write operations must require --dry-run or --yes: {unguarded_writes:?}"
        );
    }

    #[test]
    fn call_maps_json_input_to_existing_history_command() {
        let parsed = Cli::try_parse_from([
            "sniper-cli",
            "call",
            "capture.http.list",
            "--input",
            "{\"limit\":5,\"page\":true,\"host\":\"example.com\"}",
            "--dry-run",
        ])
        .unwrap();
        assert!(parsed.dry_run);
        assert_eq!(parsed.command.output_operation_name(), "capture.http.list");
        let Command::Call(args) = parsed.command else {
            panic!("expected call command");
        };
        let command = command_from_call_args(args).unwrap();
        let Command::Capture {
            command:
                CaptureCommand::Http {
                    command: HistoryCommand::List(args),
                },
        } = command
        else {
            panic!("expected capture.http.list command");
        };
        assert_eq!(args.limit, Some(5));
        assert!(args.page);
        assert_eq!(args.host.as_deref(), Some("example.com"));
    }

    #[test]
    fn call_write_operations_use_existing_confirmation_contract() {
        let parsed = Cli::try_parse_from([
            "sniper-cli",
            "call",
            "session.switch",
            "--input",
            "{\"id\":\"00000000-0000-0000-0000-000000000000\"}",
        ])
        .unwrap();
        let Command::Call(args) = parsed.command else {
            panic!("expected call command");
        };
        let command = command_from_call_args(args).unwrap();
        assert_eq!(command.operation_name(), "session.switch");
        assert!(command.requires_confirmation());
    }

    #[test]
    fn call_input_can_be_loaded_from_at_file() {
        let dir = std::env::temp_dir().join(format!("sniper_call_input_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("input.json");
        std::fs::write(&path, "{\"tab_id\":\"tab-1\"}").unwrap();
        let parsed = Cli::try_parse_from([
            "sniper-cli",
            "call",
            "replay.send",
            "--input",
            &format!("@{}", path.display()),
            "--dry-run",
        ])
        .unwrap();
        let Command::Call(args) = parsed.command else {
            panic!("expected call command");
        };
        let command = command_from_call_args(args).unwrap();
        let Command::Replay {
            command: ReplayCommand::Send(args),
        } = command
        else {
            panic!("expected replay.send command");
        };
        assert_eq!(args.tab_id, "tab-1");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn clap_parse_errors_are_json_classified() {
        let error = Cli::try_parse_from(["sniper-cli", "replay", "send"]).unwrap_err();
        let payload = clap_error_payload(&error);
        assert_eq!(payload.code, "INVALID_INPUT");
        assert_eq!(payload.exit_code, 2);
        assert!(payload.message.contains("--tab-id"));

        let raw_args = vec![
            "--output".to_string(),
            "compact".to_string(),
            "replay".to_string(),
            "send".to_string(),
        ];
        assert_eq!(
            cli_output_format_from_raw_args(&raw_args),
            OutputFormat::Compact
        );
        assert_eq!(cli_parse_error_operation(&raw_args), "replay.send");
    }

    #[test]
    fn api_probe_rejections_are_api_unavailable() {
        let payload = cli_error_payload(
            "session.list",
            &anyhow::anyhow!("Sniper API probe returned 404 Not Found"),
        );
        assert_eq!(payload.code, "API_UNAVAILABLE");
        assert_eq!(payload.exit_code, 6);
        assert!(payload.retryable);
        assert!(payload.hint.unwrap().contains("Start Sniper Desktop"));
    }

    #[test]
    fn missing_call_required_fields_are_invalid_input() {
        let payload = cli_error_payload(
            "capture.http.get",
            &anyhow::anyhow!("missing required field `id` for `capture.http.get`"),
        );
        assert_eq!(payload.code, "INVALID_INPUT");
        assert_eq!(payload.exit_code, 2);
    }

    #[test]
    fn call_rejects_unknown_json_fields() {
        for (operation, input) in [
            ("capture.http.list", json!({"limt": 1})),
            (
                "session.switch",
                json!({"idd": "00000000-0000-0000-0000-000000000000"}),
            ),
            (
                "capture.oast.configure",
                json!({"provider": "custom", "tokn": "secret"}),
            ),
        ] {
            let error = command_from_operation_input(operation, &input)
                .expect_err("call should reject unknown JSON fields");
            let payload = cli_error_payload(operation, &error);
            assert_eq!(payload.code, "INVALID_INPUT", "{operation}: {error}");
        }
    }

    #[test]
    fn call_rejects_json_null_input() {
        let error = command_from_operation_input("fuzzer.run", &Value::Null)
            .expect_err("call input must match object-only schemas");
        let payload = cli_error_payload("fuzzer.run", &error);
        assert_eq!(payload.code, "INVALID_INPUT");
    }

    #[test]
    fn manifest_examples_are_accepted_by_call_mapper() {
        for spec in manifest_operations() {
            for example in spec.examples {
                let command = command_from_operation_input(spec.operation, &example)
                    .unwrap_or_else(|error| {
                        panic!(
                            "manifest example for {} must map to a command: {error}",
                            spec.operation
                        )
                    });
                assert_eq!(command.operation_name(), spec.operation);
            }
        }
    }

    #[test]
    fn schema_operation_requires_kind_in_manifest_schema() {
        let schema_spec = operation_spec("schema").expect("schema operation should exist");
        assert_eq!(
            schema_spec.input_schema["required"],
            json!(["kind", "operation"])
        );
        assert_eq!(
            schema_spec.input_schema["additionalProperties"],
            json!(false)
        );
        assert!(schema_spec.input_schema["properties"].get("kind").is_some());
    }

    #[test]
    fn annotate_noop_is_rejected_before_dry_run_plan() {
        let command = command_from_operation_input(
            "capture.http.annotate",
            &json!({"id":"00000000-0000-0000-0000-000000000000"}),
        )
        .unwrap();
        let error = validate_command_preflight(&command)
            .expect_err("annotation without fields must not dry-run as a valid patch");
        let payload = cli_error_payload(command.operation_name(), &error);
        assert_eq!(payload.code, "INVALID_INPUT");
    }

    #[test]
    fn call_rejects_legacy_required_source_group_omissions() {
        for (operation, input) in [
            ("scope.set", json!({})),
            ("fuzzer.set_template", json!({})),
            ("fuzzer.set_payloads", json!({})),
            ("capture.auto_replace.set", json!({})),
            ("sequence.create", json!({})),
        ] {
            let error = command_from_operation_input(operation, &input)
                .expect_err("call should preserve required source groups");
            let payload = cli_error_payload(operation, &error);
            assert_eq!(payload.code, "INVALID_INPUT", "{operation}: {error}");
        }
    }

    #[test]
    fn call_rejects_legacy_conflicting_groups() {
        let id = "00000000-0000-0000-0000-000000000000";
        for (operation, input) in [
            (
                "scope.set",
                json!({"clear": true, "pattern": "*.example.com"}),
            ),
            ("replay.open", json!({"transaction_id": id, "stdin": true})),
            (
                "replay.update",
                json!({"tab_id": "tab-1", "request_file": "req.txt", "stdin": true}),
            ),
            (
                "capture.intercept.forward",
                json!({"id": id, "request_file": "req.txt", "stdin": true}),
            ),
            (
                "capture.response_intercept.forward",
                json!({"id": id, "response_file": "res.txt", "stdin": true}),
            ),
            (
                "capture.intercept_rule.create",
                json!({"all": true, "host_pattern": "*.example.com"}),
            ),
            (
                "capture.oast.configure",
                json!({"enable": true, "disable": true}),
            ),
            (
                "capture.oast.configure",
                json!({"token": "secret", "token_stdin": true}),
            ),
            (
                "capture.http.annotate",
                json!({"id": id, "color": "red", "clear_color": true}),
            ),
            (
                "capture.http.annotate",
                json!({"id": id, "note": "keep", "clear_note": true}),
            ),
            (
                "capture.http.list",
                json!({"offset": 1, "before_sequence": 99}),
            ),
        ] {
            let error = command_from_operation_input(operation, &input)
                .expect_err("call should preserve conflicting groups");
            let payload = cli_error_payload(operation, &error);
            assert_eq!(payload.code, "INVALID_INPUT", "{operation}: {error}");
        }
    }

    #[test]
    fn call_rejects_legacy_value_parser_violations() {
        let too_large_oast_interval = MAX_OAST_POLLING_INTERVAL_SECS + 1;
        for (operation, input) in [
            ("capture.http.list", json!({"limit": 0})),
            ("capture.http.list", json!({"status": 99})),
            ("capture.http.list", json!({"sort_key": "hst"})),
            ("capture.http.list", json!({"sort_direction": "up"})),
            ("capture.websocket.list", json!({"limit": 0})),
            ("capture.websocket.list", json!({"sort_key": "hst"})),
            ("capture.websocket.list", json!({"sort_direction": "up"})),
            ("fuzzer.list", json!({"limit": 0})),
            ("capture.oast.list", json!({"limit": 0})),
            ("sequence.runs", json!({"limit": 0})),
            ("capture.oast.configure", json!({"provider": "interact"})),
            ("capture.oast.configure", json!({"interval": 0})),
            (
                "capture.oast.configure",
                json!({"interval": too_large_oast_interval}),
            ),
            (
                "capture.intercept_rule.create",
                json!({"all": true, "scope": "req"}),
            ),
        ] {
            let error = command_from_operation_input(operation, &input)
                .expect_err("call should preserve finite value parsers");
            let payload = cli_error_payload(operation, &error);
            assert_eq!(payload.code, "INVALID_INPUT", "{operation}: {error}");
        }
    }

    #[test]
    fn call_accepts_valid_legacy_group_inputs() {
        assert!(matches!(
            command_from_operation_input("scope.set", &json!({"clear": true})).unwrap(),
            Command::Scope {
                command: TargetCommand::SetScope(_),
            }
        ));
        assert!(matches!(
            command_from_operation_input(
                "replay.update",
                &json!({"tab_id": "tab-1", "scheme": "https"})
            )
            .unwrap(),
            Command::Replay {
                command: ReplayCommand::Update(_),
            }
        ));
        assert!(matches!(
            command_from_operation_input(
                "fuzzer.set_template",
                &json!({"transaction_id": "00000000-0000-0000-0000-000000000000"})
            )
            .unwrap(),
            Command::Fuzzer {
                command: FuzzerCommand::SetTemplate(_),
            }
        ));
        assert!(matches!(
            command_from_operation_input(
                "capture.intercept_rule.create",
                &json!({"all": true, "scope": "both"})
            )
            .unwrap(),
            Command::Capture {
                command: CaptureCommand::InterceptRule {
                    command: InterceptRuleCommand::Create(_),
                },
            }
        ));
    }

    #[test]
    fn partial_apply_errors_preserve_structured_details() {
        let error = cli_partial_apply_error(
            "fuzzer attack failed",
            serde_json::json!({
                "record": {
                    "id": "attack-1",
                    "status": "failed"
                }
            }),
        );
        let payload = cli_error_payload("fuzzer.run", &error);

        assert_eq!(payload.code, "PARTIAL_APPLY");
        assert_eq!(payload.exit_code, 5);
        assert!(!payload.retryable);
        assert_eq!(payload.details["partial_apply"], serde_json::json!(true));
        assert_eq!(payload.details["idempotent"], serde_json::json!(false));
        assert_eq!(payload.details["record"]["status"], "failed");
    }

    #[test]
    fn dry_run_preview_reports_risky_replay_send_plan() {
        let parsed = Cli::try_parse_from([
            "sniper-cli",
            "--dry-run",
            "replay",
            "send",
            "--tab-id",
            "tab-1",
        ])
        .unwrap();
        let plan = dry_run_command(&parsed.command).unwrap();
        assert_eq!(plan["dry_run"], serde_json::json!(true));
        assert_eq!(plan["operation"], "replay.send");
        assert_eq!(plan["requires_confirmation"], serde_json::json!(true));
        assert_eq!(plan["api"]["method"], "POST");
        assert_eq!(plan["api"]["path"], "/api/replay/send");
    }

    #[test]
    fn confirmation_errors_are_json_classified() {
        let payload = cli_error_payload(
            "replay.send",
            &anyhow::anyhow!("operation `replay.send` requires --dry-run or --yes"),
        );
        assert_eq!(payload.code, "CONFIRMATION_REQUIRED");
        assert_eq!(payload.exit_code, 2);
        assert!(!payload.retryable);
    }

    #[test]
    fn oast_configure_accepts_token_stdin_and_rejects_token_conflict() {
        let parsed = Cli::try_parse_from([
            "sniper-cli",
            "capture",
            "oast",
            "configure",
            "--provider",
            "custom",
            "--token-stdin",
        ])
        .unwrap();
        let Command::Capture {
            command:
                CaptureCommand::Oast {
                    command: OastCommand::Configure(args),
                },
        } = parsed.command
        else {
            panic!("expected oast configure");
        };
        assert!(args.token_stdin);
        assert!(args.token.is_none());
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "capture",
            "oast",
            "configure",
            "--token",
            "secret",
            "--token-stdin",
        ])
        .is_err());
    }

    #[test]
    fn oast_configure_rejects_unsafe_token_before_api_discovery() {
        let parsed = Cli::try_parse_from([
            "sniper-cli",
            "capture",
            "oast",
            "configure",
            "--provider",
            "custom",
            "--token",
            "secret",
            "--yes",
        ])
        .unwrap();
        let error = validate_command_preflight(&parsed.command).unwrap_err();
        assert!(error.to_string().contains("--token is unsafe"));
    }

    #[test]
    fn history_annotate_rejects_set_and_clear_conflicts() {
        let id = Uuid::new_v4().to_string();
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "history",
            "annotate",
            "--id",
            &id,
            "--color",
            "red",
            "--clear-color",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "history",
            "annotate",
            "--id",
            &id,
            "--note",
            "hello",
            "--clear-note",
        ])
        .is_err());
    }

    #[test]
    fn history_annotate_payload_includes_client_clock() {
        let payload = build_annotations_payload(Some(Some("red".to_string())), None);
        let client_id = payload
            .get("client_id")
            .and_then(|value| value.as_str())
            .expect("annotation payload should include client id");
        assert!(client_id.starts_with(&format!("{CLI_WORKSPACE_CLIENT_ID}:")));
        assert_eq!(
            payload
                .get("client_version")
                .and_then(|value| value.as_u64()),
            Some(1)
        );
    }

    #[test]
    fn history_list_supports_paged_and_legacy_array_shapes() {
        let item = serde_json::json!({
            "id": Uuid::new_v4(),
            "started_at": Utc::now(),
            "kind": "http",
            "sequence": 42,
            "method": "GET",
            "scheme": "https",
            "host": "history.example.test",
            "path": "/search",
            "status": 200,
            "duration_ms": 17,
            "request_bytes": 100,
            "response_bytes": 200,
            "note_count": 0,
            "has_response": true,
            "content_type": "application/json",
            "is_websocket": false,
            "has_match_replace": false,
            "has_user_note": false
        });
        let page: HistoryListResponse = serde_json::from_value(serde_json::json!({
            "items": [item.clone()],
            "total": 12,
            "filtered_total": 8,
            "hidden_connect_total": 1,
            "offset": 5,
            "limit": 1,
            "has_more": true
        }))
        .unwrap();
        let legacy_page_output = page.into_cli_output(false);
        assert_eq!(legacy_page_output[0]["host"], "history.example.test");

        let page: HistoryListResponse = serde_json::from_value(serde_json::json!({
            "items": [item.clone()],
            "total": 12,
            "filtered_total": 8,
            "hidden_connect_total": 1,
            "offset": 5,
            "limit": 1,
            "has_more": true
        }))
        .unwrap();
        let page_output = page.into_cli_output(true);
        assert_eq!(page_output["items"][0]["path"], "/search");
        assert_eq!(page_output["total"], 12);
        assert_eq!(page_output["filtered_total"], 8);
        assert_eq!(page_output["hidden_connect_total"], 1);
        assert_eq!(page_output["offset"], 5);
        assert_eq!(page_output["limit"], 1);
        assert_eq!(page_output["has_more"], true);

        let legacy: HistoryListResponse =
            serde_json::from_value(serde_json::json!([item])).unwrap();
        let legacy_output = legacy.into_cli_output(false);
        assert_eq!(legacy_output[0]["sequence"], 42);
    }

    #[test]
    fn history_list_accepts_offset_and_page_flags() {
        let parsed = Cli::try_parse_from([
            "sniper-cli",
            "history",
            "list",
            "--limit",
            "50",
            "--offset",
            "100",
            "--sort-key",
            "host",
            "--sort-direction",
            "asc",
            "--page",
        ])
        .unwrap();
        let Command::History {
            command: HistoryCommand::List(args),
        } = parsed.command
        else {
            panic!("expected history list");
        };
        assert_eq!(args.limit, Some(50));
        assert_eq!(args.offset, Some(100));
        assert_eq!(args.sort_key.as_deref(), Some("host"));
        assert_eq!(args.sort_direction.as_deref(), Some("asc"));
        assert!(args.page);

        let parsed = Cli::try_parse_from([
            "sniper-cli",
            "history",
            "list",
            "--limit",
            "50",
            "--before-sequence",
            "99",
        ])
        .unwrap();
        let Command::History {
            command: HistoryCommand::List(args),
        } = parsed.command
        else {
            panic!("expected history list");
        };
        assert_eq!(args.before_sequence, Some(99));
        assert!(args.offset.is_none());
    }

    fn parse_sequence_command(args: &[&str]) -> SequenceCommand {
        let parsed = Cli::try_parse_from(args).unwrap();
        let Command::Sequence { command } = parsed.command else {
            panic!("expected sequence command");
        };
        command
    }

    #[test]
    fn sequence_commands_accept_explicit_session_id() {
        let sequence_id = "11111111-1111-1111-1111-111111111111";
        let session_id = "22222222-2222-2222-2222-222222222222";
        let expected_session_id = Uuid::parse_str(session_id).unwrap();

        match parse_sequence_command(&[
            "sniper-cli",
            "sequence",
            "list",
            "--session-id",
            session_id,
        ]) {
            SequenceCommand::List(args) => assert_eq!(args.session_id, Some(expected_session_id)),
            _ => panic!("expected sequence list"),
        }

        match parse_sequence_command(&[
            "sniper-cli",
            "sequence",
            "get",
            "--id",
            sequence_id,
            "--session-id",
            session_id,
        ]) {
            SequenceCommand::Get(args) => assert_eq!(args.session_id, Some(expected_session_id)),
            _ => panic!("expected sequence get"),
        }

        match parse_sequence_command(&[
            "sniper-cli",
            "sequence",
            "create",
            "--stdin",
            "--session-id",
            session_id,
        ]) {
            SequenceCommand::Create(args) => assert_eq!(args.session_id, Some(expected_session_id)),
            _ => panic!("expected sequence create"),
        }

        match parse_sequence_command(&[
            "sniper-cli",
            "sequence",
            "run",
            "--id",
            sequence_id,
            "--session-id",
            session_id,
        ]) {
            SequenceCommand::Run(args) => assert_eq!(args.session_id, Some(expected_session_id)),
            _ => panic!("expected sequence run"),
        }

        match parse_sequence_command(&[
            "sniper-cli",
            "sequence",
            "delete",
            "--id",
            sequence_id,
            "--session-id",
            session_id,
        ]) {
            SequenceCommand::Delete(args) => assert_eq!(args.session_id, Some(expected_session_id)),
            _ => panic!("expected sequence delete"),
        }

        match parse_sequence_command(&[
            "sniper-cli",
            "sequence",
            "runs",
            "--session-id",
            session_id,
            "--limit",
            "10",
        ]) {
            SequenceCommand::Runs(args) => {
                assert_eq!(args.session_id, Some(expected_session_id));
                assert_eq!(args.limit, Some(10));
            }
            _ => panic!("expected sequence runs"),
        }
    }

    #[test]
    fn cli_rejects_ambiguous_input_sources() {
        let id = Uuid::new_v4().to_string();
        assert!(
            Cli::try_parse_from(["sniper-cli", "replay", "update", "--tab-id", "tab-1"]).is_err()
        );
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "replay",
            "open",
            "--transaction-id",
            &id,
            "--request-file",
            "request.http",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "fuzzer",
            "set-template",
            "--request-file",
            "request.http",
            "--stdin",
        ])
        .is_err());
        assert!(Cli::try_parse_from(["sniper-cli", "fuzzer", "set-template"]).is_err());
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "fuzzer",
            "set-payloads",
            "--payload",
            "admin",
            "--file",
            "payloads.txt",
        ])
        .is_err());
        assert!(Cli::try_parse_from(["sniper-cli", "fuzzer", "set-payloads"]).is_err());
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "capture",
            "intercept",
            "forward",
            "--id",
            &id,
            "--request-file",
            "request.http",
            "--stdin",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "auto-replace",
            "set",
            "--file",
            "rules.json",
            "--stdin",
        ])
        .is_err());
        assert!(Cli::try_parse_from(["sniper-cli", "auto-replace", "set"]).is_err());
        assert!(Cli::try_parse_from(["sniper-cli", "sequence", "create"]).is_err());
    }

    #[test]
    fn cli_requires_scope_source_for_set_scope() {
        assert!(Cli::try_parse_from(["sniper-cli", "scope", "set-scope"]).is_err());
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "scope",
            "set-scope",
            "--pattern",
            "*.example.com",
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["sniper-cli", "scope", "set-scope", "--clear"]).is_ok());
    }

    #[test]
    fn cli_requires_explicit_matcher_for_intercept_rule_create() {
        assert!(
            Cli::try_parse_from(["sniper-cli", "capture", "intercept-rule", "create",]).is_err()
        );
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "capture",
            "intercept-rule",
            "create",
            "--host-pattern",
            "*.example.com",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "capture",
            "intercept-rule",
            "create",
            "--all",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "capture",
            "intercept-rule",
            "create",
            "--all",
            "--host-pattern",
            "*.example.com",
        ])
        .is_err());
    }

    #[test]
    fn cli_rejects_invalid_finite_option_values() {
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "capture",
            "intercept-rule",
            "create",
            "--scope",
            "req",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "capture",
            "oast",
            "configure",
            "--provider",
            "interact",
        ])
        .is_err());
        assert!(Cli::try_parse_from(["sniper-cli", "history", "list", "--limit", "0"]).is_err());
        assert!(
            Cli::try_parse_from(["sniper-cli", "history", "list", "--sort-direction", "up",])
                .is_err()
        );
        assert!(
            Cli::try_parse_from(["sniper-cli", "history", "list", "--sort-key", "hst",]).is_err()
        );
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "history",
            "list",
            "--offset",
            "1",
            "--before-sequence",
            "99",
        ])
        .is_err());
        assert!(Cli::try_parse_from(["sniper-cli", "fuzzer", "list", "--limit", "0"]).is_err());
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "capture",
            "websocket",
            "list",
            "--limit",
            "0",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "capture",
            "websocket",
            "list",
            "--sort-key",
            "hst",
        ])
        .is_err());
        assert!(
            Cli::try_parse_from(["sniper-cli", "capture", "oast", "list", "--limit", "0",])
                .is_err()
        );
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "capture",
            "oast",
            "configure",
            "--interval",
            "0",
        ])
        .is_err());
        let too_large_oast_interval = (MAX_OAST_POLLING_INTERVAL_SECS + 1).to_string();
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "capture",
            "oast",
            "configure",
            "--interval",
            too_large_oast_interval.as_str(),
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "capture",
            "oast",
            "configure",
            "--interval",
            MAX_OAST_POLLING_INTERVAL_SECS.to_string().as_str(),
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["sniper-cli", "sequence", "runs", "--limit", "0"]).is_err());
    }

    #[test]
    fn split_payload_lines_preserves_significant_whitespace() {
        assert_eq!(
            split_payload_lines(" admin \n\r\n\t\nvalue\r\n"),
            vec![
                " admin ".to_string(),
                "".to_string(),
                "\t".to_string(),
                "value".to_string()
            ]
        );
    }

    #[test]
    fn split_payload_lines_preserves_explicit_empty_payloads() {
        assert_eq!(split_payload_lines(""), Vec::<String>::new());
        assert_eq!(split_payload_lines("\n"), vec!["".to_string()]);
        assert_eq!(split_payload_lines("value\n"), vec!["value".to_string()]);
        assert_eq!(
            split_payload_lines("value\n\n"),
            vec!["value".to_string(), "".to_string()]
        );
    }

    #[test]
    fn read_payloads_input_encodes_trailing_empty_cli_payloads() {
        let text =
            read_payloads_input(vec!["value".to_string(), "".to_string()], None, false).unwrap();
        assert_eq!(
            split_payload_lines(&text),
            vec!["value".to_string(), "".to_string()]
        );
    }

    #[test]
    fn websocket_list_response_accepts_page_and_legacy_array_shapes() {
        let item = serde_json::json!({
            "id": Uuid::new_v4(),
            "started_at": Utc::now(),
            "closed_at": null,
            "duration_ms": null,
            "scheme": "wss",
            "host": "ws.example.test",
            "path": "/socket",
            "status": 101,
            "frame_count": 2,
            "note_count": 0
        });
        let page: WebSocketListResponse = serde_json::from_value(serde_json::json!({
            "items": [item.clone()],
            "total": 1,
            "filtered_total": 1,
            "limit": 5000,
            "offset": 25,
            "has_more": false
        }))
        .unwrap();
        let legacy_page_output = page.into_cli_output(false);
        assert_eq!(legacy_page_output[0]["host"], "ws.example.test");

        let legacy: WebSocketListResponse =
            serde_json::from_value(serde_json::json!([item])).unwrap();
        let legacy_output = legacy.into_cli_output(false);
        assert_eq!(legacy_output[0]["path"], "/socket");

        let page: WebSocketListResponse = serde_json::from_value(serde_json::json!({
            "items": [item.clone()],
            "total": 1,
            "filtered_total": 1,
            "limit": 5000,
            "offset": 25,
            "has_more": false
        }))
        .unwrap();
        let page_output = page.into_cli_output(true);
        assert_eq!(page_output["items"][0]["host"], "ws.example.test");
        assert_eq!(page_output["total"], 1);
        assert_eq!(page_output["filtered_total"], 1);
        assert_eq!(page_output["limit"], 5000);
        assert_eq!(page_output["offset"], 25);
        assert_eq!(page_output["has_more"], false);
    }

    #[test]
    fn host_port_splitter_handles_ipv6_addresses() {
        assert_eq!(
            split_host_port("example.com:8443"),
            Some(("example.com", "8443"))
        );
        assert_eq!(split_host_port("[::1]:8443"), Some(("::1", "8443")));
        assert_eq!(split_host_port("::1"), None);
        assert_eq!(strip_host_port("::1"), "::1");
        assert_eq!(strip_host_port("[::1]:8443"), "::1");
    }

    #[test]
    fn parse_raw_request_rejects_invalid_base64_body() {
        let fallback = EditableRequest {
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            method: "POST".to_string(),
            path: "/submit".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Base64,
            preview_truncated: false,
        };
        let error = parse_editable_raw_request(
            "POST /submit HTTP/1.1\nHost: example.com\n\nnot base64!",
            Some(&fallback),
        )
        .unwrap_err();
        assert!(error.to_string().contains("not valid base64"));
    }

    #[test]
    fn parse_raw_response_rejects_invalid_status_line() {
        let fallback = EditableResponse {
            status: 204,
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
        };

        let error =
            parse_editable_raw_response("HTTP/1.1 nope\ncontent-type: text/plain", Some(&fallback))
                .unwrap_err();
        assert!(error.to_string().contains("invalid response status code"));
    }

    #[test]
    fn raw_response_parser_rejects_malformed_header_lines() {
        let error =
            parse_editable_raw_response("HTTP/1.1 200 OK\nNot-A-Header\n\n", None).unwrap_err();

        assert!(error.to_string().contains("invalid response header line"));
    }

    #[test]
    fn normalize_api_base_accepts_host_port() {
        assert_eq!(
            normalize_api_base_url("127.0.0.1:19081").unwrap(),
            "http://127.0.0.1:19081"
        );
    }

    #[test]
    fn normalize_api_base_rejects_path_query_and_credentials() {
        assert!(normalize_api_base_url("http://127.0.0.1:19081/foo").is_err());
        assert!(normalize_api_base_url("http://127.0.0.1:19081?x=1").is_err());
        assert!(normalize_api_base_url("http://user@127.0.0.1:19081").is_err());
    }

    #[test]
    fn api_url_joins_paths_under_normalized_base() {
        let url = api_url("http://127.0.0.1:19081", "/api/settings").unwrap();
        assert_eq!(url.as_str(), "http://127.0.0.1:19081/api/settings");
    }

    #[test]
    fn sniper_settings_probe_requires_sniper_markers() {
        let valid = serde_json::json!({
            "runtime_instance_id": Uuid::new_v4().to_string(),
            "proxy_addr": "127.0.0.1:18080",
            "ui_addr": "127.0.0.1:19090",
            "data_dir": "/tmp/sniper",
            "max_entries": 5000,
            "features": ["http_capture", "session_storage", "replay"]
        });
        assert!(sniper_settings_probe_matches(&valid));

        let wrong_service = serde_json::json!({
            "proxy_addr": "127.0.0.1:18080",
            "ui_addr": "127.0.0.1:19090",
            "data_dir": "/tmp/other",
            "max_entries": 5000,
            "features": ["health"]
        });
        assert!(!sniper_settings_probe_matches(&wrong_service));
    }

    #[test]
    #[cfg(unix)]
    fn sniper_settings_probe_accepts_canonicalized_data_dir_alias() {
        let root =
            std::env::temp_dir().join(format!("sniper-cli-data-dir-alias-{}", Uuid::new_v4()));
        let real = root.join("real");
        let alias = root.join("alias");
        fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        let snapshot = RuntimeStateSnapshot::with_proxy_status(
            "127.0.0.1:18080".parse().unwrap(),
            "127.0.0.1:19090".parse().unwrap(),
            true,
        );
        let payload = serde_json::json!({
            "runtime_instance_id": snapshot.instance_id.to_string(),
            "proxy_addr": "127.0.0.1:18080",
            "ui_addr": snapshot.ui_addr.to_string(),
            "data_dir": alias.display().to_string(),
            "max_entries": 5000,
            "features": ["http_capture", "session_storage", "replay"]
        });

        assert!(data_dir_strings_match(&alias.display().to_string(), &real));
        validate_sniper_settings_probe(
            &payload,
            Some(SniperApiProbeExpectation {
                runtime_state: &snapshot,
                data_dir: &real,
            }),
        )
        .unwrap();

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[cfg(unix)]
    fn process_path_matching_accepts_canonicalized_alias_and_linux_deleted_suffix() {
        let root =
            std::env::temp_dir().join(format!("sniper-cli-process-path-alias-{}", Uuid::new_v4()));
        let real = root.join("sniper");
        let alias = root.join("sniper-alias");
        fs::create_dir_all(&root).unwrap();
        fs::write(&real, b"test binary").unwrap();
        std::os::unix::fs::symlink(&real, &alias).unwrap();

        assert!(process_path_strings_match(
            &real.display().to_string(),
            &alias.display().to_string()
        ));
        assert!(process_path_strings_match(
            &real.display().to_string(),
            &format!("{} (deleted)", real.display())
        ));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cli_data_dir_honors_sniper_data_dir_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        let root = std::env::temp_dir().join(format!("sniper-cli-env-dir-{}", Uuid::new_v4()));

        let _data_dir_guard = EnvVarGuard::set(SNIPER_DATA_DIR_ENV, root.clone().into_os_string());
        assert_eq!(cli_data_dir(), root);
    }

    #[test]
    fn cli_data_dir_ignores_empty_sniper_data_dir_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        let _data_dir_guard = EnvVarGuard::set(SNIPER_DATA_DIR_ENV, "");

        assert_eq!(cli_data_dir(), default_cli_data_dir());
    }

    #[tokio::test]
    async fn discovery_removes_stale_runtime_state_after_probe_failure() {
        let root =
            std::env::temp_dir().join(format!("sniper-cli-stale-runtime-{}", Uuid::new_v4()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_ui_addr = listener.local_addr().unwrap();
        drop(listener);
        let mut snapshot = RuntimeStateSnapshot::with_proxy_status(
            "127.0.0.1:18080".parse().unwrap(),
            closed_ui_addr,
            true,
        );
        snapshot.pid = None;
        persist_runtime_state(&root, &snapshot).unwrap();

        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_millis(200))
            .build()
            .unwrap();
        let error = discover_api_base_url_from_data_dir(&client, root.clone())
            .await
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("Removed the stale runtime-state"));
        assert!(!runtime_state_path(&root).exists());
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn discovery_preserves_runtime_state_when_owner_process_is_alive() {
        let root = std::env::temp_dir().join(format!("sniper-cli-live-runtime-{}", Uuid::new_v4()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_ui_addr = listener.local_addr().unwrap();
        drop(listener);
        let snapshot = RuntimeStateSnapshot::with_proxy_status(
            "127.0.0.1:18080".parse().unwrap(),
            closed_ui_addr,
            true,
        );
        persist_runtime_state(&root, &snapshot).unwrap();

        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_millis(200))
            .build()
            .unwrap();
        let error = discover_api_base_url_from_data_dir(&client, root.clone())
            .await
            .unwrap_err();

        assert!(error.to_string().contains("owner pid"));
        assert!(runtime_state_path(&root).exists());
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn discovery_removes_runtime_state_when_live_pid_has_wrong_process_path() {
        let root =
            std::env::temp_dir().join(format!("sniper-cli-pid-reuse-runtime-{}", Uuid::new_v4()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_ui_addr = listener.local_addr().unwrap();
        drop(listener);
        let mut snapshot = RuntimeStateSnapshot::with_proxy_status(
            "127.0.0.1:18080".parse().unwrap(),
            closed_ui_addr,
            true,
        );
        snapshot.process_path = Some("/tmp/not-the-sniper-owner".to_string());
        persist_runtime_state(&root, &snapshot).unwrap();

        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_millis(200))
            .build()
            .unwrap();
        let error = discover_api_base_url_from_data_dir(&client, root.clone())
            .await
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("Removed the stale runtime-state"));
        assert!(!runtime_state_path(&root).exists());
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn discovery_removes_legacy_stale_runtime_state_missing_metadata() {
        let root =
            std::env::temp_dir().join(format!("sniper-cli-legacy-runtime-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            runtime_state_path(&root),
            br#"{"proxy_addr":"127.0.0.1:18080","ui_addr":"127.0.0.1:9"}"#,
        )
        .unwrap();

        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_millis(200))
            .build()
            .unwrap();
        let error = discover_api_base_url_from_data_dir(&client, root.clone())
            .await
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("Removed the stale runtime-state"));
        assert!(!runtime_state_path(&root).exists());
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn discovery_retries_runtime_state_probe_before_cleanup() {
        let root = std::env::temp_dir().join(format!("sniper-cli-probe-retry-{}", Uuid::new_v4()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ui_addr = listener.local_addr().unwrap();
        let snapshot = RuntimeStateSnapshot::with_proxy_status(
            "127.0.0.1:18080".parse().unwrap(),
            ui_addr,
            true,
        );
        let runtime_instance_id = snapshot.instance_id;
        let attempts = Arc::new(AtomicUsize::new(0));
        let server_attempts = attempts.clone();
        let server_root = root.clone();
        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buffer = [0_u8; 1024];
                let _ = stream.read(&mut buffer).await.unwrap();
                let attempt = server_attempts.fetch_add(1, Ordering::SeqCst);
                let (status, body) = if attempt < 2 {
                    ("503 Service Unavailable", "{}".to_string())
                } else {
                    (
                        "200 OK",
                        serde_json::json!({
                            "runtime_instance_id": runtime_instance_id.to_string(),
                            "proxy_addr": "127.0.0.1:18080",
                            "ui_addr": ui_addr.to_string(),
                            "data_dir": server_root.display().to_string(),
                            "max_entries": 5000,
                            "features": ["http_capture", "session_storage", "replay"]
                        })
                        .to_string(),
                    )
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        persist_runtime_state(&root, &snapshot).unwrap();

        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let url = discover_api_base_url_from_data_dir(&client, root.clone())
            .await
            .unwrap();

        assert_eq!(url, format!("http://{ui_addr}"));
        assert!(runtime_state_path(&root).exists());
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        server.await.unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn env_api_addr_is_authoritative_when_runtime_identity_mismatches() {
        let _guard = ENV_LOCK.lock().unwrap();
        let root = std::env::temp_dir().join(format!("sniper-cli-env-mismatch-{}", Uuid::new_v4()));
        let wrong_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let wrong_ui_addr = wrong_listener.local_addr().unwrap();
        let snapshot = RuntimeStateSnapshot::with_proxy_status(
            "127.0.0.1:18080".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            true,
        );
        persist_runtime_state(&root, &snapshot).unwrap();

        let wrong_root = root.join("wrong");
        let wrong_server = tokio::spawn(async move {
            let (mut stream, _) = wrong_listener.accept().await.unwrap();
            let mut buffer = [0_u8; 1024];
            let _ = stream.read(&mut buffer).await.unwrap();
            let body = serde_json::json!({
                "runtime_instance_id": Uuid::new_v4().to_string(),
                "proxy_addr": "127.0.0.1:18080",
                "ui_addr": wrong_ui_addr.to_string(),
                "data_dir": wrong_root.display().to_string(),
                "max_entries": 5000,
                "features": ["http_capture", "session_storage", "replay"]
            })
            .to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        let _api_guard = EnvVarGuard::set("SNIPER_API_ADDR", format!("http://{wrong_ui_addr}"));
        let _data_dir_guard = EnvVarGuard::set("SNIPER_DATA_DIR", root.clone().into_os_string());
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let discovered = discover_api_base_url(None, &client).await.unwrap();

        assert_eq!(discovered, format!("http://{wrong_ui_addr}"));
        wrong_server.await.unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn discovery_removes_runtime_state_when_probe_instance_mismatches() {
        let root =
            std::env::temp_dir().join(format!("sniper-cli-instance-mismatch-{}", Uuid::new_v4()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ui_addr = listener.local_addr().unwrap();
        let mut snapshot = RuntimeStateSnapshot::with_proxy_status(
            "127.0.0.1:18080".parse().unwrap(),
            ui_addr,
            true,
        );
        snapshot.pid = None;
        let mut response_instance_id = Uuid::new_v4();
        while response_instance_id == snapshot.instance_id {
            response_instance_id = Uuid::new_v4();
        }
        let server_root = root.clone();
        let server = tokio::spawn(async move {
            for _ in 0..=SNIPER_API_PROBE_RETRY_DELAYS.len() {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buffer = [0_u8; 1024];
                let _ = stream.read(&mut buffer).await.unwrap();
                let body = serde_json::json!({
                    "runtime_instance_id": response_instance_id.to_string(),
                    "proxy_addr": "127.0.0.1:18080",
                    "ui_addr": ui_addr.to_string(),
                    "data_dir": server_root.display().to_string(),
                    "max_entries": 5000,
                    "features": ["http_capture", "session_storage", "replay"]
                })
                .to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        persist_runtime_state(&root, &snapshot).unwrap();

        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let error = discover_api_base_url_from_data_dir(&client, root.clone())
            .await
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("Removed the stale runtime-state"));
        assert!(!runtime_state_path(&root).exists());
        server.await.unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn discovery_removes_runtime_state_when_live_owner_probe_identity_mismatches() {
        let root = std::env::temp_dir().join(format!(
            "sniper-cli-live-owner-instance-mismatch-{}",
            Uuid::new_v4()
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ui_addr = listener.local_addr().unwrap();
        let snapshot = RuntimeStateSnapshot::with_proxy_status(
            "127.0.0.1:18080".parse().unwrap(),
            ui_addr,
            true,
        );
        let mut response_instance_id = Uuid::new_v4();
        while response_instance_id == snapshot.instance_id {
            response_instance_id = Uuid::new_v4();
        }
        let server_root = root.clone();
        let server = tokio::spawn(async move {
            for _ in 0..=SNIPER_API_PROBE_RETRY_DELAYS.len() {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buffer = [0_u8; 1024];
                let _ = stream.read(&mut buffer).await.unwrap();
                let body = serde_json::json!({
                    "runtime_instance_id": response_instance_id.to_string(),
                    "proxy_addr": "127.0.0.1:18080",
                    "ui_addr": ui_addr.to_string(),
                    "data_dir": server_root.display().to_string(),
                    "max_entries": 5000,
                    "features": ["http_capture", "session_storage", "replay"]
                })
                .to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        persist_runtime_state(&root, &snapshot).unwrap();

        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let error = discover_api_base_url_from_data_dir(&client, root.clone())
            .await
            .unwrap_err();

        let message = error.to_string();
        assert!(message.contains("did not match runtime-state"));
        assert!(message.contains("Removed the stale runtime-state"));
        assert!(!runtime_state_path(&root).exists());
        server.await.unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn codex_default_skills_dir_uses_hidden_folder() {
        let path = skills::default_codex_skills_dir().unwrap();
        assert!(path.to_string_lossy().contains(".codex/skills") || path.ends_with("skills"));
    }

    #[test]
    fn claude_default_skills_dir_uses_hidden_folder() {
        let path = skills::default_claude_skills_dir().unwrap();
        assert!(path.to_string_lossy().contains(".claude/skills") || path.ends_with("skills"));
    }

    #[test]
    fn install_skill_folder_writes_skill_markdown() {
        let root = std::env::temp_dir().join(format!("sniper-skill-test-{}", Uuid::new_v4()));
        let skill_dir =
            skills::install_skill_folder(&root, "sniper-operator", "# test skill\n").unwrap();
        fs::write(skill_dir.join("notes.md"), "keep me").unwrap();
        skills::install_skill_folder(&root, "sniper-operator", "# updated skill\n").unwrap();
        let skill_md = fs::read_to_string(skill_dir.join("SKILL.md")).unwrap();
        assert_eq!(skill_md, "# updated skill\n");
        assert_eq!(
            fs::read_to_string(skill_dir.join("notes.md")).unwrap(),
            "keep me"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn skills_install_all_rejects_same_destination() {
        let root = std::env::temp_dir().join(format!("sniper-skill-same-{}", Uuid::new_v4()));
        let error = install_skills(SkillsInstallArgs {
            all: true,
            codex_dir: Some(root.clone()),
            claude_dir: Some(root.clone()),
            ..SkillsInstallArgs::default()
        })
        .unwrap_err();

        assert!(error.to_string().contains("same SKILL.md path"));
        assert!(!root.join(skills::SKILL_NAME).join("SKILL.md").exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn skills_install_all_errors_when_default_home_is_unavailable() {
        let _guard = ENV_LOCK.lock().unwrap();
        let _home = EnvVarGuard::remove("HOME");
        let _userprofile = EnvVarGuard::remove("USERPROFILE");
        let _codex_home = EnvVarGuard::remove("CODEX_HOME");
        let _claude_home = EnvVarGuard::remove("CLAUDE_HOME");

        let error = install_skills(SkillsInstallArgs {
            all: true,
            ..SkillsInstallArgs::default()
        })
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("could not determine Codex skills directory"));
    }
}
