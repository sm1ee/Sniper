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
    event_log::EventLogEntry,
    fuzzer::FuzzerAttackRecord,
    history_selection::HistorySelection,
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
    scanner::{
        scanner_config_token, validate_custom_rule, validate_scanner_config, CustomRule,
        FindingSummary, ScannerConfigSnapshot, ScannerFinding, Severity, BUILTIN_RULES,
        MAX_SCANNER_FIELD_BYTES,
    },
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

const DEFAULT_READ_LIST_LIMIT: usize = 100;
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
    /// Example inputs for one operation, or for every operation when none is named.
    Examples {
        operation: Option<String>,
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
    /// Read stored passive findings; list summaries before opening sensitive evidence.
    Findings {
        #[command(subcommand)]
        command: FindingsCommand,
    },
    /// Manage session-scoped passive regex rules for captured response previews and headers.
    Scanner {
        #[command(subcommand)]
        command: ScannerCommand,
    },
    /// Read stored session event messages.
    #[command(name = "event-log")]
    EventLog {
        #[command(subcommand)]
        command: EventLogCommand,
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
    /// Read proxy chain settings, or replace them with JSON from stdin.
    Proxy(ProxyChainArgs),
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
    /// Open a browser that already sends its traffic through this Sniper.
    Browser {
        #[command(subcommand)]
        command: BrowserCommand,
    },
}

#[derive(Subcommand, Debug)]
enum FindingsCommand {
    /// List newest stored summaries, without detail, evidence, or captured bodies.
    List(SessionReadListArgs),
    /// Read one stored finding, including potentially sensitive detail and evidence.
    Get(FindingGetArgs),
    /// Count all findings currently retained in the session.
    Count(SessionReadArgs),
}

#[derive(Subcommand, Debug)]
enum ScannerCommand {
    Config {
        #[command(subcommand)]
        command: ScannerConfigCommand,
    },
    Builtin {
        #[command(subcommand)]
        command: ScannerBuiltinCommand,
    },
    Custom {
        #[command(subcommand)]
        command: ScannerCustomCommand,
    },
}

#[derive(Subcommand, Debug)]
enum ScannerConfigCommand {
    Get(SessionReadArgs),
    SetEnabled(ScannerEnabledArgs),
}

#[derive(Subcommand, Debug)]
enum ScannerBuiltinCommand {
    SetEnabled(ScannerBuiltinEnabledArgs),
}

#[derive(Subcommand, Debug)]
enum ScannerCustomCommand {
    List(SessionReadArgs),
    Get(ScannerRuleIdArgs),
    Create(ScannerCreateArgs),
    Update(ScannerUpdateArgs),
    Delete(ScannerRuleIdArgs),
}

#[derive(Args, Debug)]
struct ScannerEnabledArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long, action = ArgAction::Set, required = true)]
    enabled: bool,
}

#[derive(Args, Debug)]
struct ScannerBuiltinEnabledArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long)]
    id: String,
    #[arg(long, action = ArgAction::Set, required = true)]
    enabled: bool,
}

#[derive(Args, Debug)]
struct ScannerRuleIdArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    /// Exact, stable custom rule ID; names and partial IDs are not accepted.
    #[arg(long)]
    id: String,
}

#[derive(Args, Debug)]
#[command(group(ArgGroup::new("rule_source").required(true).args(["file", "stdin"])))]
struct ScannerCreateArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    /// Complete CustomRule JSON, including its stable id.
    #[arg(long)]
    file: Option<PathBuf>,
    #[arg(long)]
    stdin: bool,
    #[arg(skip)]
    rule: Option<CustomRule>,
}

#[derive(Args, Debug)]
#[command(group(ArgGroup::new("patch_source").required(true).args(["file", "stdin"])))]
struct ScannerUpdateArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long)]
    id: String,
    /// Partial CustomRule JSON. Omitted fields are preserved; id cannot be changed.
    #[arg(long)]
    file: Option<PathBuf>,
    #[arg(long)]
    stdin: bool,
    #[arg(skip)]
    patch: Option<ScannerRulePatch>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScannerRulePatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    header_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<Severity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

impl ScannerRulePatch {
    fn apply(&self, rule: &mut CustomRule) {
        macro_rules! apply_fields {
            ($($field:ident),+) => { $(
                if let Some(value) = &self.$field {
                    rule.$field = value.clone();
                }
            )+ };
        }
        apply_fields!(
            name,
            enabled,
            target,
            header_name,
            pattern,
            severity,
            category,
            description
        );
    }
}

#[derive(Subcommand, Debug)]
enum EventLogCommand {
    /// List newest stored event messages; messages can contain sensitive metadata.
    List(SessionReadListArgs),
}

#[derive(Args, Debug)]
struct SessionReadArgs {
    /// Read this session without switching it; otherwise pin the active session.
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug)]
struct SessionReadListArgs {
    /// Read this session without switching it; otherwise pin the active session.
    #[arg(long)]
    session_id: Option<Uuid>,
    /// Maximum newest entries to return. No offset or cursor pagination is available.
    #[arg(long, default_value_t = DEFAULT_READ_LIST_LIMIT, value_parser = parse_nonzero_usize)]
    limit: usize,
}

#[derive(Args, Debug)]
struct FindingGetArgs {
    #[arg(long)]
    id: Uuid,
    /// Read this session without switching it; otherwise pin the active session.
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Debug, Deserialize, Serialize)]
struct FindingsCount {
    count: usize,
}

#[derive(Subcommand, Debug)]
enum BrowserCommand {
    /// List every browser Sniper knows on this platform, installed or not, with its
    /// driver, what that driver offers, and what is missing.
    List,
    /// Open a browser wired to this Sniper: proxy set, CA trusted, nothing to configure.
    Open(BrowserOpenArgs),
    /// Choose which browser opens when none is named. `auto` clears the choice.
    Prefer(BrowserPreferArgs),
}

#[derive(Args, Debug)]
struct BrowserPreferArgs {
    /// The browser to open when none is named, from `capture browser list`; `auto` clears
    /// the saved choice.
    #[arg(long, value_parser = clap::builder::PossibleValuesParser::new(browser_choices()))]
    browser: String,
}

#[derive(Args, Debug, Default)]
struct BrowserOpenArgs {
    /// auto opens the saved default, or ego, Aside or BrowserOS neo, when installed,
    /// then the first of Chrome, Edge, Brave and Chromium that is.
    #[arg(long, value_parser = clap::builder::PossibleValuesParser::new(browser_choices()))]
    browser: Option<String>,
    /// http(s) page to open. Default: about:blank.
    #[arg(long)]
    url: Option<String>,
    /// Use a throwaway profile instead of the persistent Sniper one.
    #[arg(long)]
    fresh: bool,
    /// Open a DevTools port so an agent can drive a Chromium-family browser, or
    /// BrowserOS neo's MCP server; the result's `control` carries its endpoint. ego
    /// and Aside are driven through their own command and always return it in
    /// `control`, so this changes nothing for them.
    #[arg(long)]
    agent: bool,
}

impl BrowserCommand {
    fn operation_name(&self) -> &'static str {
        match self {
            BrowserCommand::List => "capture.browser.list",
            BrowserCommand::Open(_) => "capture.browser.open",
            BrowserCommand::Prefer(_) => "capture.browser.prefer",
        }
    }
}

#[derive(Args, Debug)]
struct ProxyChainArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    /// Replace settings using {enabled, url, username, password, bypass_hosts}
    /// from stdin. Leaving out bypass_hosts keeps the saved list.
    #[arg(long)]
    stdin: bool,
}

#[derive(Subcommand, Debug)]
enum SessionCommand {
    List,
    Create(CreateSessionArgs),
    Switch(SessionSwitchArgs),
    Delete(SessionDeleteArgs),
    Rename(SessionRenameArgs),
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
struct SessionRenameArgs {
    #[arg(long)]
    id: Uuid,
    #[arg(long)]
    name: String,
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
    /// Find a literal value in URLs, headers and bodies. Says what it scanned,
    /// so an empty result can be told apart from a search that stopped early.
    Search(HistorySearchArgs),
    /// Preview a session-pinned ID or filter selection without changing saved data.
    Select(HistorySelectionArgs),
    /// Delete explicitly selected saved records; filters require a reviewed selection token.
    Delete(HistorySelectionArgs),
    /// Delete every saved HTTP record in the selected session.
    Clear(InterceptSessionArgs),
    Replay(HistoryReplayArgs),
    Fuzzer(HistoryFuzzerArgs),
    Annotate(HistoryAnnotateArgs),
}

#[derive(Args, Debug)]
struct HistorySelectionArgs {
    #[arg(long)]
    session_id: Uuid,
    /// Repeat --id or comma-separate UUIDs; cannot be combined with filters.
    #[arg(long = "id", value_delimiter = ',')]
    ids: Vec<Uuid>,
    #[arg(long)]
    query: Option<String>,
    #[arg(long)]
    method: Option<String>,
    #[arg(long)]
    host: Option<String>,
    #[arg(long, value_parser = clap::value_parser!(u16).range(100..=599))]
    status: Option<u16>,
    #[arg(long)]
    status_range: Option<String>,
    #[arg(long)]
    since: Option<String>,
    #[arg(long)]
    mime: Option<String>,
    /// Token returned by capture http select. Required for filtered deletion.
    #[arg(long)]
    selection_token: Option<String>,
}

impl HistorySelectionArgs {
    fn payload(&self) -> HistorySelection {
        HistorySelection {
            session_id: self.session_id,
            ids: self.ids.clone(),
            query: self.query.clone(),
            method: self.method.clone(),
            host: self.host.clone(),
            status: self.status,
            status_range: self.status_range.clone(),
            since: self.since.clone(),
            mime: self.mime.clone(),
            selection_token: self.selection_token.clone(),
        }
    }
}

#[derive(Args, Debug, Default)]
struct HistoryListArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    /// Filter by request metadata: method, host, path, status, MIME or id.
    /// Headers and bodies are not searched — use `capture http search`.
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

#[derive(Args, Debug, Default)]
struct HistorySearchArgs {
    /// Literal text to find. Case-insensitive unless --case-sensitive.
    #[arg(long)]
    value: String,
    #[arg(long)]
    session_id: Option<Uuid>,
    /// Where to look. Repeat or comma-separate. Default: all four.
    #[arg(long, value_delimiter = ',', value_parser = ["url", "request-body", "response-body", "headers"])]
    side: Vec<String>,
    #[arg(long)]
    case_sensitive: bool,
    /// Stop after this many matches (server default 200).
    #[arg(long, value_parser = parse_nonzero_usize)]
    max_matches: Option<usize>,
    /// Stop after reading this many body bytes (server default 128 MiB).
    #[arg(long)]
    byte_budget: Option<u64>,
    /// Bytes of surrounding text to return either side of each match (default 40).
    #[arg(long)]
    context: Option<usize>,
    /// Narrow the records searched by request metadata, as `list --query` does.
    #[arg(long)]
    query: Option<String>,
    #[arg(long)]
    method: Option<String>,
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
    /// Filter by response MIME type (substring match), e.g. "json"
    #[arg(long)]
    mime: Option<String>,
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
    /// Close one saved HTTP tab and its saved replay history without sending traffic.
    Close(ReplaySavedTabArgs),
    /// Clone one saved HTTP tab without sending traffic or changing the active tab.
    Duplicate(ReplaySavedTabArgs),
    /// Set saved HTTP tab pin state without sending traffic or changing focus.
    SetPinned(ReplaySetPinnedArgs),
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
    /// Tab name shown in the Replay tab strip
    #[arg(long)]
    label: Option<String>,
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
            .args(["request_file", "stdin", "scheme", "host", "port", "label"])
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
    /// Tab name shown in the Replay tab strip; an empty value clears it
    #[arg(long)]
    label: Option<String>,
}

#[derive(Args, Debug)]
struct ReplaySavedTabArgs {
    /// Exact saved tab ID; never interpreted as a label or normalized.
    #[arg(long)]
    tab_id: String,
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug)]
struct ReplaySetPinnedArgs {
    #[command(flatten)]
    tab: ReplaySavedTabArgs,
    /// Desired pin state; repeated values never toggle it.
    #[arg(long, required = true, action = ArgAction::Set)]
    pinned: bool,
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
    Get(InterceptGetArgs),
    Wait(InterceptWaitArgs),
    Forward(InterceptForwardArgs),
    Drop(InterceptDropArgs),
    #[command(name = "forward-all")]
    ForwardAll(InterceptSessionArgs),
}

#[derive(Args, Debug, Default)]
struct InterceptGetArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long)]
    id: Uuid,
}

/// `list` only reports summaries, so an agent that wants to edit a held request
/// has to poll for one and then fetch it. `wait` does both: it blocks until the
/// queue has something and prints that record in full, ready to edit and forward.
#[derive(Args, Debug)]
struct InterceptWaitArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    /// Give up after this many seconds.
    #[arg(long, default_value_t = 30)]
    timeout: u64,
    /// How often to re-check the queue, in milliseconds.
    #[arg(long, default_value_t = 200)]
    poll_interval: u64,
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
    /// Inspect installed skill hashes on this CLI host without changing files.
    Status(SkillsInstallArgs),
    /// Experimental: record local enrollment for one installed, exact bundled skill.
    Enroll(SingleSkillArgs),
    /// Compare local files and enrollment with this CLI's bundle; never writes.
    UpdatePreview(SkillsInstallArgs),
    /// Experimental: stage a bundled candidate in a new directory without activating it.
    StageUpdate(SkillsStageArgs),
}

#[derive(Args, Debug, Default)]
#[command(group(ArgGroup::new("skill_agent").args(["codex", "claude"]).required(true)))]
struct SingleSkillArgs {
    #[arg(long)]
    codex: bool,
    #[arg(long)]
    claude: bool,
    #[arg(long)]
    codex_dir: Option<PathBuf>,
    #[arg(long)]
    claude_dir: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct SkillsStageArgs {
    #[command(flatten)]
    target: SingleSkillArgs,
    /// New local directory for candidate and staging receipt; it must not exist.
    #[arg(long)]
    staging_dir: PathBuf,
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
    Wait(InterceptWaitArgs),
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
                "items": with_labels(&items, transaction_label),
                "total": null,
                "filtered_total": null,
                "hidden_connect_total": null,
                "offset": null,
                "limit": null,
                "has_more": null,
            }),
            Self::Items(items) => with_labels(&items, transaction_label),
            Self::Page {
                items,
                total,
                filtered_total,
                hidden_connect_total,
                offset,
                limit,
                has_more,
            } if include_page => serde_json::json!({
                "items": with_labels(&items, transaction_label),
                "total": total,
                "filtered_total": filtered_total,
                "hidden_connect_total": hidden_connect_total,
                "offset": offset,
                "limit": limit,
                "has_more": has_more,
            }),
            Self::Page { items, .. } => with_labels(&items, transaction_label),
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

    async fn delete_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.request_json_with_client::<(), T>(&self.client, Method::DELETE, path, None)
            .await
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
            Command::Call(args) => saved_operation_name(&args.operation).unwrap_or("call"),
            Command::Session { command } => command.operation_name(),
            Command::Capture { command } => command.operation_name(),
            Command::Findings { command } => command.operation_name(),
            Command::Scanner { command } => command.operation_name(),
            Command::EventLog { command } => command.operation_name(),
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

impl FindingsCommand {
    fn operation_name(&self) -> &'static str {
        match self {
            Self::List(_) => "findings.list",
            Self::Get(_) => "findings.get",
            Self::Count(_) => "findings.count",
        }
    }
}

impl ScannerCommand {
    fn operation_name(&self) -> &'static str {
        match self {
            Self::Config {
                command: ScannerConfigCommand::Get(_),
            } => "scanner.config.get",
            Self::Config {
                command: ScannerConfigCommand::SetEnabled(_),
            } => "scanner.config.set_enabled",
            Self::Builtin {
                command: ScannerBuiltinCommand::SetEnabled(_),
            } => "scanner.builtin.set_enabled",
            Self::Custom { command } => match command {
                ScannerCustomCommand::List(_) => "scanner.custom.list",
                ScannerCustomCommand::Get(_) => "scanner.custom.get",
                ScannerCustomCommand::Create(_) => "scanner.custom.create",
                ScannerCustomCommand::Update(_) => "scanner.custom.update",
                ScannerCustomCommand::Delete(_) => "scanner.custom.delete",
            },
        }
    }

    fn session_id(&self) -> Option<Uuid> {
        match self {
            Self::Config {
                command: ScannerConfigCommand::Get(args),
            }
            | Self::Custom {
                command: ScannerCustomCommand::List(args),
            } => args.session_id,
            Self::Config {
                command: ScannerConfigCommand::SetEnabled(args),
            } => args.session_id,
            Self::Builtin {
                command: ScannerBuiltinCommand::SetEnabled(args),
            } => args.session_id,
            Self::Custom {
                command: ScannerCustomCommand::Get(args) | ScannerCustomCommand::Delete(args),
            } => args.session_id,
            Self::Custom {
                command: ScannerCustomCommand::Create(args),
            } => args.session_id,
            Self::Custom {
                command: ScannerCustomCommand::Update(args),
            } => args.session_id,
        }
    }

    fn is_write(&self) -> bool {
        !matches!(
            self,
            Self::Config {
                command: ScannerConfigCommand::Get(_)
            } | Self::Custom {
                command: ScannerCustomCommand::List(_) | ScannerCustomCommand::Get(_)
            }
        )
    }
}

impl EventLogCommand {
    fn operation_name(&self) -> &'static str {
        match self {
            Self::List(_) => "event_log.list",
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
            SessionCommand::Rename(_) => "session.rename",
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
            CaptureCommand::Proxy(args) => {
                if args.stdin {
                    "capture.proxy.configure"
                } else {
                    "capture.proxy.get"
                }
            }
            CaptureCommand::Oast { command } => command.operation_name(),
            CaptureCommand::Browser { command } => command.operation_name(),
        }
    }
}

impl HistoryCommand {
    fn operation_name(&self) -> &'static str {
        match self {
            HistoryCommand::List(_) => "capture.http.list",
            HistoryCommand::Get(_) => "capture.http.get",
            HistoryCommand::Search(_) => "capture.http.search",
            HistoryCommand::Clear(_) => "capture.http.clear",
            HistoryCommand::Select(_) => "capture.http.select",
            HistoryCommand::Delete(_) => "capture.http.delete",
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
            ReplayCommand::Close(_) => "replay.close",
            ReplayCommand::Duplicate(_) => "replay.duplicate",
            ReplayCommand::SetPinned(_) => "replay.set_pinned",
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
            InterceptCommand::Get(_) => "capture.intercept.get",
            InterceptCommand::Wait(_) => "capture.intercept.wait",
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
            ResponseInterceptCommand::Wait(_) => "capture.response_intercept.wait",
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
            SkillsCommand::Status(_) => "skills.status",
            SkillsCommand::Enroll(_) => "skills.enroll",
            SkillsCommand::UpdatePreview(_) => "skills.update_preview",
            SkillsCommand::StageUpdate(_) => "skills.stage_update",
        }
    }
}

fn manifest_operations() -> Vec<CliOperationSpec> {
    use CliSideEffect::{Read, Write};
    let mut operations = vec![
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
            "examples [operation]",
            "Print example inputs for one Sniper CLI operation, or all operations when omitted.",
            Read,
            false,
            &[],
            vec![json!({}), json!({"operation":"capture.http.list"})],
        ),
        op(
            "skills.status",
            "skills status",
            "Inspect local CLI-host skill hashes without installing or updating files.",
            Read,
            false,
            &[],
            vec![json!({"all":true}), json!({"codex":true,"codex_dir":"/tmp/example-skills"})],
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
            "skills.enroll",
            "skills enroll <--codex|--claude>",
            "Experimental: record explicit local enrollment of one exact bundled skill. Does not permit automatic updates or change SKILL.md.",
            Write,
            true,
            &[],
            vec![json!({"codex":true,"codex_dir":"/tmp/example-skills"})],
        ),
        op(
            "skills.update_preview",
            "skills update-preview",
            "Compare local skills and enrollment against this CLI's bundle without changing files. Unmanaged files remain unmanaged.",
            Read,
            false,
            &[],
            vec![json!({"all":true}), json!({"codex":true,"codex_dir":"/tmp/example-skills"})],
        ),
        op(
            "skills.stage_update",
            "skills stage-update <--codex|--claude> --staging-dir <new-directory>",
            "Experimental: stage one enrolled, unchanged skill's bundled update and receipt in a new local directory. Does not activate it or replace the active SKILL.md.",
            Write,
            true,
            &["staging_dir"],
            vec![json!({"codex":true,"codex_dir":"/tmp/example-skills","staging_dir":"/tmp/example-skill-candidate"})],
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
            "session.rename", "session rename --id <uuid> --name <name>",
            "Rename a session without changing its ID, storage or active state.", Write, false,
            &["id", "name"], vec![json!({"id":"00000000-0000-0000-0000-000000000000","name":"Review archive"})],
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
            "findings.list", "findings list",
            "List newest stored finding summaries without detail, evidence or captured bodies. Defaults to 100; limit-only, not cursor pagination. Omitted session_id pins the active session.",
            Read, false, &[], vec![json!({"limit":20})],
        ),
        op(
            "findings.get", "findings get --id <uuid>",
            "Read one stored finding, including potentially sensitive detail and evidence. Does not fetch its linked captured transaction or send traffic. Omitted session_id pins the active session.",
            Read, false, &["id"], vec![json!({"id":"00000000-0000-0000-0000-000000000000"})],
        ),
        op(
            "findings.count", "findings count",
            "Count findings currently retained in one session. Omitted session_id pins the active session.",
            Read, false, &[], vec![json!({})],
        ),
        op(
            "event_log.list", "event-log list",
            "List newest stored session event messages, which can contain sensitive metadata. Defaults to 100; limit-only, not cursor pagination. Omitted session_id pins the active session.",
            Read, false, &[], vec![json!({"limit":20})],
        ),
        op(
            "capture.browser.list",
            "capture browser list",
            "List the browsers Sniper knows on this platform: whether each is installed, how an agent drives it, what that driver offers, and what is missing. `default` marks the one that opens when none is named; `preferred` marks the one the user saved; `install_url` is where to download one that is missing.",
            Read,
            false,
            &[],
            vec![json!({})],
        ),
        op(
            "capture.browser.open",
            "capture browser open",
            "Open a browser already wired to this Sniper: proxy set, CA trusted, persistent Sniper profile. With no browser named it opens the saved default, else ego, Aside or BrowserOS neo when installed, else Chrome or another Chromium-family browser, so read `control` rather than assume a DevTools endpoint. Pass agent to get a `control` an agent can drive it with.",
            Write,
            false,
            &[],
            vec![json!({"browser":"auto","agent":true})],
        ),
        op(
            "capture.browser.prefer",
            "capture browser prefer --browser <name|auto>",
            "Choose which browser opens when none is named, saved for this user. `auto` clears it. Refused for a browser that is not installed.",
            Write,
            false,
            &["browser"],
            vec![json!({"browser":"chrome"})],
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
            "capture.http.search",
            "capture http search --value <text>",
            "Find a literal value in captured URLs, headers and bodies. Check `complete` before treating no matches as absence.",
            Read,
            false,
            &["value"],
            vec![json!({"value":"access_token","side":["response-body"]})],
        ),
        op(
            "capture.http.select", "capture http select --session-id <uuid> [--id <uuid>|filters]",
            "Preview exactly which saved HTTP records match IDs or nonempty metadata filters. Returns count, IDs and a session-bound selection_token; writes nothing.",
            Read, false, &["session_id"], vec![json!({"session_id":"00000000-0000-0000-0000-000000000000","host":"example.com"})],
        ),
        op(
            "capture.http.delete", "capture http delete --session-id <uuid> [--id <uuid>|filters --selection-token <token>]",
            "Delete selected saved HTTP records. IDs and filters are exclusive; filtered deletion requires a reviewed selection_token from capture.http.select. Missing IDs or a changed selection delete nothing.",
            Write, true, &["session_id"], vec![json!({"session_id":"00000000-0000-0000-0000-000000000000","ids":["11111111-1111-1111-1111-111111111111"]})],
        ),
        op(
            "capture.http.clear", "capture http clear [--session-id <uuid>]",
            "Delete every saved HTTP transaction in one session. Omitted session_id pins the active session; filters and IDs are not accepted. WebSockets, findings and workspace tabs are retained.",
            Write, true, &[], vec![json!({"session_id":"00000000-0000-0000-0000-000000000000"})],
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
            "replay.close",
            "replay close --tab-id <exact-id> [--session-id <uuid>]",
            "Close one saved HTTP Replay tab and its saved history using one revision-checked write. No traffic is sent; conflicts and lost responses are never retried.",
            Write,
            true,
            &["tab_id"],
            vec![json!({"tab_id":"tab-1"})],
        ),
        op(
            "replay.duplicate",
            "replay duplicate --tab-id <exact-id> [--session-id <uuid>]",
            "Duplicate one saved HTTP Replay tab unchanged with a new UUID, unpinned and without changing focus. No traffic is sent; conflicts and lost responses are never retried.",
            Write,
            true,
            &["tab_id"],
            vec![json!({"tab_id":"tab-1"})],
        ),
        op(
            "replay.set_pinned",
            "replay set-pinned --tab-id <exact-id> --pinned <true|false> [--session-id <uuid>]",
            "Set one saved HTTP tab's pin state using one revision-checked write. Focus and saved array order are preserved; no traffic is sent.",
            Write,
            true,
            &["tab_id", "pinned"],
            vec![json!({"tab_id":"tab-1","pinned":true})],
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
            "capture.proxy.get",
            "capture proxy",
            "Read proxy chain settings, with a masked password and the hosts that bypass the chain.",
            Read,
            false,
            &[],
            vec![json!({})],
        ),
        op(
            "capture.proxy.configure",
            "capture proxy --stdin",
            "Replace proxy chain settings, and optionally its bypass hosts, from stdin JSON.",
            Write,
            true,
            &[],
            vec![json!({})],
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
    ];
    operations.extend(scanner_manifest_operations());
    operations.extend(saved_manifest_operations());
    operations
}

fn scanner_manifest_operations() -> Vec<CliOperationSpec> {
    use CliSideEffect::{Read, Write};
    vec![
        op("scanner.config.get", "scanner config get", "Read one session's passive scanner configuration and builtin metadata.", Read, false, &[], vec![json!({})]),
        op("scanner.config.set_enabled", "scanner config set-enabled --enabled <true|false>", "Set the session's passive scanner switch with optimistic concurrency. Does not rescan saved traffic.", Write, true, &["enabled"], vec![json!({"enabled":false})]),
        op("scanner.builtin.set_enabled", "scanner builtin set-enabled --id <rule-id> --enabled <true|false>", "Set one known builtin rule toggle, preserving all other configuration.", Write, true, &["id","enabled"], vec![json!({"id":"header","enabled":false})]),
        op("scanner.custom.list", "scanner custom list", "List stored custom passive regex rules in saved order.", Read, false, &[], vec![json!({})]),
        op("scanner.custom.get", "scanner custom get --id <rule-id>", "Read one custom passive rule by exact stable ID.", Read, false, &["id"], vec![json!({"id":"example-header"})]),
        op("scanner.custom.create", "scanner custom create --file <rule.json>", "Append one complete custom passive rule with an explicit stable ID. Accepts rule, file or stdin as exactly one source.", Write, true, &[], vec![json!({"rule":{"id":"example-header","name":"Example header marker","enabled":true,"target":"response_header","header_name":"X-Example","pattern":"example-marker","severity":"info","category":"example","description":"Synthetic passive marker."}})]),
        op("scanner.custom.update", "scanner custom update --id <rule-id> --file <patch.json>", "Patch one custom passive rule by exact ID. Omitted fields remain unchanged; accepts patch, file or stdin as exactly one source.", Write, true, &["id"], vec![json!({"id":"example-header","patch":{"enabled":false,"description":""}})]),
        op("scanner.custom.delete", "scanner custom delete --id <rule-id>", "Delete one custom passive rule by exact ID without clearing existing findings.", Write, true, &["id"], vec![json!({"id":"example-header"})]),
    ]
}

fn saved_operation_name(operation: &str) -> Option<&'static str> {
    sniper::saved_contract::OPERATIONS
        .iter()
        .copied()
        .find(|name| *name == operation)
}

fn saved_manifest_operations() -> Vec<CliOperationSpec> {
    let session_id = "00000000-0000-0000-0000-000000000000";
    let operation_id = "22222222-2222-2222-2222-222222222222";
    [
        ("saved.v1.http.list", "Read saved HTTP summaries in bounded, session-pinned pages; default 50, maximum 200.", json!({"limit":20})),
        ("saved.v1.http.select", "Preview a saved HTTP selection without changing data.", json!({"session_id":session_id,"host":"example.com"})),
        ("saved.v1.http.delete", "Delete a reviewed saved HTTP selection once per operation UUID; repeated IDs never execute again.", json!({"session_id":session_id,"operation_id":operation_id,"ids":["11111111-1111-1111-1111-111111111111"]})),
        ("saved.v1.http.clear", "Clear saved HTTP rows once per operation UUID. Reusing the ID never clears newer rows.", json!({"session_id":session_id,"operation_id":operation_id})),
        ("saved.v1.session.list", "List saved sessions in bounded UUID-ordered pages.", json!({"limit":20})),
        ("saved.v1.session.rename", "Rename a saved session with a durable operation receipt.", json!({"session_id":session_id,"operation_id":operation_id,"name":"Archive"})),
        ("saved.v1.operation.get", "Read a durable mutation receipt after response loss. Unknown is not permission to retry.", json!({"operation_id":operation_id})),
    ].into_iter().map(|(operation, description, example)| {
        let write = sniper::saved_data::is_write(operation);
        CliOperationSpec {
            operation,
            command: "call <saved.v1.operation> --input <json>",
            description,
            side_effect: if write { CliSideEffect::Write } else { CliSideEffect::Read },
            requires_confirmation: write,
            input_schema: sniper::saved_contract::input_schema(operation).expect("saved input schema"),
            output_schema: sniper::saved_contract::output_schema(operation).expect("saved output schema"),
            examples: vec![example],
        }
    }).collect()
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
        output_schema: replay_saved_tab_output_schema(operation)
            .or_else(|| scanner_output_schema(operation))
            .or_else(|| session_list_output_schema(operation))
            .or_else(|| session_read_output_schema(operation))
            .or_else(|| skills_status_output_schema(operation))
            .or_else(|| skills_managed_output_schema(operation))
            .unwrap_or_else(|| {
                json!({
                    "type": "object",
                    "additionalProperties": true,
                    "description": "Returned in the envelope data field."
                })
            }),
        examples,
    }
}

fn replay_saved_tab_output_schema(operation: &str) -> Option<Value> {
    if !matches!(
        operation,
        "replay.close" | "replay.duplicate" | "replay.set_pinned"
    ) {
        return None;
    }
    let mut schema = json!({
        "type":"object", "additionalProperties":false,
        "required":["session_id","revision","active_tab_id"],
        "properties":{
            "session_id":{"type":"string","format":"uuid"},
            "revision":{"type":"integer","minimum":1},
            "active_tab_id":{"type":["string","null"]}
        }
    });
    let fields: &[&str] = if operation == "replay.close" {
        &["closed_tab_id"]
    } else if operation == "replay.duplicate" {
        &["source_tab_id", "new_tab_id"]
    } else {
        &["tab_id"]
    };
    for field in fields {
        schema["required"].as_array_mut()?.push(json!(field));
        schema["properties"][field] = json!({"type":"string","minLength":1});
    }
    if operation == "replay.duplicate" {
        schema["properties"]["new_tab_id"]["format"] = json!("uuid");
    } else if operation == "replay.set_pinned" {
        schema["required"].as_array_mut()?.push(json!("pinned"));
        schema["properties"]["pinned"] = json!({"type":"boolean"});
    }
    Some(schema)
}

fn session_list_output_schema(operation: &str) -> Option<Value> {
    if operation != "session.list" {
        return None;
    }
    Some(json!({
        "type":"array",
        "description":"Session summaries returned in the envelope data field.",
        "items":sniper::saved_contract::session_summary_schema()
    }))
}

fn session_read_output_schema(operation: &str) -> Option<Value> {
    if !matches!(
        operation,
        "findings.list" | "findings.get" | "findings.count" | "event_log.list"
    ) {
        return None;
    }
    let mut finding = json!({
        "type":"object",
        "required":["id","record_id","found_at","severity","category","title","host","path"],
        "properties":{
            "id":{"type":"string","format":"uuid"},
            "record_id":{"type":"string","format":"uuid"},
            "found_at":{"type":"string","format":"date-time"},
            "rule_id":{"type":"string"},
            "severity":{"type":"string","enum":["info","low","medium","high","critical"]},
            "category":{"type":"string"}, "title":{"type":"string"},
            "host":{"type":"string"}, "path":{"type":"string"},
            "location":{
                "type":"object","required":["side"],
                "properties":{
                    "side":{"type":"string"}, "section":{"type":"string"},
                    "line":{"type":"integer","minimum":0}
                }
            }
        }
    });
    Some(match operation {
        "findings.list" => json!({"type":"array","items":finding}),
        "findings.get" => {
            finding["required"]
                .as_array_mut()?
                .extend([json!("detail"), json!("evidence")]);
            finding["properties"]["detail"] = json!({"type":"string"});
            finding["properties"]["evidence"] = json!({"type":"string"});
            finding
        }
        "findings.count" => json!({
            "type":"object","required":["count"],
            "properties":{"count":{"type":"integer","minimum":0}}
        }),
        "event_log.list" => json!({
            "type":"array","items":{
                "type":"object","required":["id","captured_at","level","source","title","message"],
                "properties":{
                    "id":{"type":"string","format":"uuid"},
                    "captured_at":{"type":"string","format":"date-time"},
                    "level":{"type":"string","enum":["info","warn","error"]},
                    "source":{"type":"string"}, "title":{"type":"string"},
                    "message":{"type":"string"}
                }
            }
        }),
        _ => return None,
    })
}

fn skills_status_output_schema(operation: &str) -> Option<Value> {
    if operation != "skills.status" {
        return None;
    }
    Some(json!({
        "type":"object","additionalProperties":false,
        "required":["scope","bundled_version","entries"],
        "properties":{
            "scope":{"type":"string","const":"cli_host"},
            "bundled_version":{"type":"string","description":"Version of this CLI's bundled templates; installed version is unknown."},
            "entries":{"type":"array","minItems":1,"maxItems":2,"items":{
                "type":"object","additionalProperties":false,
                "required":["agent","path","bundled_sha256","installed_sha256","status"],
                "properties":{
                    "agent":{"type":"string","enum":["codex","claude"]},
                    "path":{"type":"string","description":"Absolute local SKILL.md path; no source text is returned."},
                    "bundled_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},
                    "installed_sha256":{"type":["string","null"],"pattern":"^[0-9a-f]{64}$"},
                    "status":{"type":"string","enum":["missing","current","modified_or_outdated","unreadable","unsupported"],"description":"Current means exact byte hash equality. A different hash cannot distinguish user edits from an older template."},
                    "error_code":{"type":"string","enum":["symlink","reparse_point","non_regular_file","file_too_large","platform_unsupported","permission_denied","io_error","changed_during_read"]}
                }
            }}
        }
    }))
}

fn skills_managed_output_schema(operation: &str) -> Option<Value> {
    let string = json!({"type":"string"});
    let hash = json!({"type":"string","pattern":"^[0-9a-f]{64}$"});
    let mut entry = json!({
        "type":"object", "additionalProperties":false,
        "required":["agent","path","receipt_path"],
        "properties":{
            "agent":{"type":"string","enum":["codex","claude"]},
            "path":{"type":"string","description":"Absolute active local SKILL.md path; source text is never returned."},
            "receipt_path":{"type":"string"}
        }
    });
    let (required, properties) = match operation {
        "skills.update_preview" => (
            json!([
                "installed_sha256",
                "bundled_sha256",
                "bundled_version",
                "enrolled_sha256",
                "enrolled_version",
                "state",
                "stage_eligible"
            ]),
            json!({
                "installed_sha256":{"type":["string","null"],"pattern":"^[0-9a-f]{64}$"},
                "bundled_sha256":hash,
                "bundled_version":string,
                "enrolled_sha256":{"type":["string","null"],"pattern":"^[0-9a-f]{64}$"},
                "enrolled_version":{"type":["string","null"],"description":"Recorded enrollment version, not inferred provenance."},
                "state":{"type":"string","enum":["unmanaged","current","update_available","modified","missing","error"],"description":"Unmanaged files are never adopted by preview. Update availability requires enrolled bytes still matching the active file."},
                "stage_eligible":{"type":"boolean"},
                "error_code":{"type":"string","description":"Stable local inspection error code; no file contents."}
            }),
        ),
        "skills.enroll" => (
            json!([
                "enrolled_sha256",
                "enrolled_version",
                "allows_automatic_updates"
            ]),
            json!({
                "enrolled_sha256":hash,
                "enrolled_version":string,
                "allows_automatic_updates":{"type":"boolean","const":false}
            }),
        ),
        "skills.stage_update" => (
            json!([
                "staging_dir",
                "candidate_path",
                "installed_sha256",
                "bundled_sha256",
                "bundled_version",
                "activated"
            ]),
            json!({
                "staging_dir":string,
                "candidate_path":{"type":"string","description":"Staged candidate only; active SKILL.md remains unchanged."},
                "installed_sha256":hash,
                "bundled_sha256":hash,
                "bundled_version":string,
                "activated":{"type":"boolean","const":false}
            }),
        ),
        _ => return None,
    };
    entry["required"]
        .as_array_mut()?
        .extend(required.as_array()?.iter().cloned());
    entry["properties"].as_object_mut()?.extend(
        properties
            .as_object()?
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );
    if operation == "skills.update_preview" {
        Some(json!({
            "type":"object","additionalProperties":false,
            "required":["scope","bundled_version","entries"],
            "properties":{
                "scope":{"type":"string","const":"cli_host"},
                "bundled_version":string,
                "entries":{"type":"array","minItems":1,"maxItems":2,"items":entry}
            }
        }))
    } else {
        Some(entry)
    }
}

fn input_schema(operation: &str, required_fields: &[&'static str]) -> Value {
    if matches!(operation, "skills.status" | "skills.update_preview") {
        return json!({
            "type":"object", "additionalProperties":false, "required":[],
            "properties":{
                "codex":{"type":["boolean","null"],"default":false},
                "claude":{"type":["boolean","null"],"default":false},
                "all":{"type":["boolean","null"],"default":false},
                "codex_dir":{"type":["string","null"],"minLength":1,"pattern":"^[^\\u0000]*$","description":"Codex skills root on the CLI host; omission or null uses the install default."},
                "claude_dir":{"type":["string","null"],"minLength":1,"pattern":"^[^\\u0000]*$","description":"Claude skills root on the CLI host; omission or null uses the install default."}
            },
            "anyOf":[
                {"required":["codex"],"properties":{"codex":{"const":true}}},
                {"required":["claude"],"properties":{"claude":{"const":true}}},
                {"required":["all"],"properties":{"all":{"const":true}}}
            ]
        });
    }
    if matches!(operation, "skills.enroll" | "skills.stage_update") {
        let mut schema = json!({
            "type":"object", "additionalProperties":false, "required":[],
            "properties":{
                "codex":{"type":["boolean","null"],"default":false},
                "claude":{"type":["boolean","null"],"default":false},
                "codex_dir":{"type":["string","null"],"minLength":1,"pattern":"^[^\\u0000]*$","description":"Codex skills root on the CLI host; omission or null uses the install default."},
                "claude_dir":{"type":["string","null"],"minLength":1,"pattern":"^[^\\u0000]*$","description":"Claude skills root on the CLI host; omission or null uses the install default."}
            },
            "oneOf":[
                {"required":["codex"],"properties":{"codex":{"const":true},"claude":{"enum":[false,null]}}},
                {"required":["claude"],"properties":{"claude":{"const":true},"codex":{"enum":[false,null]}}}
            ]
        });
        if operation == "skills.stage_update" {
            schema["required"] = json!(["staging_dir"]);
            schema["properties"]["staging_dir"] = json!({"type":"string","minLength":1,"pattern":"^[^\\u0000]*$","description":"Explicit new local staging directory, which must not exist. The active SKILL.md is never replaced."});
        }
        return schema;
    }
    if matches!(
        operation,
        "replay.close" | "replay.duplicate" | "replay.set_pinned"
    ) {
        let mut schema = json!({
            "type":"object", "additionalProperties":false, "required":["tab_id"],
            "properties":{
                "tab_id":{"type":"string","minLength":1,"maxLength":128,"pattern":"\\S","description":"Exact saved HTTP tab ID; nonblank, at most 128 UTF-8 bytes, never trimmed or treated as a label."},
                "session_id":{"type":"string","format":"uuid","description":"Selected saved session, including inactive sessions. Omission pins the active session once."}
            }
        });
        if operation == "replay.set_pinned" {
            schema["required"]
                .as_array_mut()
                .unwrap()
                .push(json!("pinned"));
            schema["properties"]["pinned"] = json!({"type":"boolean"});
        }
        return schema;
    }
    if let Some(schema) = scanner_input_schema(operation, required_fields) {
        return schema;
    }
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
    if operation == "examples" {
        properties.insert("operation".into(), json!({
            "type":["string","null"],
            "description":"Operation to show examples for; omitted or null lists all operations."
        }));
    }
    if session_read_output_schema(operation).is_some() {
        properties.insert("session_id".into(), json!({
            "type":["string","null"],"format":"uuid",
            "description":"Read this session without switching it; omitted or null pins the active session."
        }));
        if properties.contains_key("id") {
            properties.insert("id".into(), json!({"type":"string","format":"uuid"}));
        }
        if properties.contains_key("limit") {
            properties.insert("limit".into(), json!({
                "type":["integer","null"],"minimum":1,"default":DEFAULT_READ_LIST_LIMIT,
                "description":"Maximum newest retained entries. Null uses the default. No offset or cursor pagination."
            }));
        }
    }
    if matches!(
        operation,
        "capture.http.select" | "capture.http.delete" | "capture.http.clear" | "session.rename"
    ) {
        for (field, schema) in [
            ("id", json!({"type":"string","format":"uuid"})),
            ("session_id", json!({"type":"string","format":"uuid"})),
            (
                "ids",
                json!({"type":"array","items":{"type":"string","format":"uuid"},"description":"Explicit transaction UUIDs; repeat --id in the legacy command. Cannot be combined with filters."}),
            ),
            (
                "name",
                json!({"type":"string","minLength":1,"description":"Trimmed nonblank session name, at most 256 UTF-8 bytes, no control characters."}),
            ),
            (
                "status",
                json!({"type":"integer","minimum":100,"maximum":599}),
            ),
            (
                "selection_token",
                json!({"type":"string","pattern":"^[0-9a-f]{64}$","description":"Returned by capture.http.select; required for filtered deletion. Any changed match rejects the entire deletion."}),
            ),
        ] {
            if properties.contains_key(field) {
                properties.insert(field.to_string(), schema);
            }
        }
        for field in ["query", "method", "host", "status_range", "since", "mime"] {
            if properties.contains_key(field) {
                properties.insert(field.into(), json!({"type":"string","minLength":1,"pattern":"\\S","description":"Nonblank metadata filter. All supplied filters must match; invalid filters are rejected."}));
            }
        }
    }
    let mut schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": required_fields,
        "properties": properties,
    });
    if matches!(operation, "capture.http.select" | "capture.http.delete") {
        let filters = json!([{"required":["query"]},{"required":["method"]},{"required":["host"]},{"required":["status"]},{"required":["status_range"]},{"required":["since"]},{"required":["mime"]}]);
        let mut filtered = json!({"anyOf":filters,"properties":{"ids":{"maxItems":0}}});
        if operation == "capture.http.delete" {
            filtered["required"] = json!(["selection_token"]);
        }
        schema["allOf"] = json!([{"not":{"required":["status","status_range"]}}]);
        schema["oneOf"] = json!([
            {"required":["ids"],"properties":{"ids":{"minItems":1}},"not":{"anyOf":filters}},
            filtered
        ]);
    }
    schema
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
        "skills.install" | "skills.status" | "skills.update_preview" => {
            &["codex", "claude", "all", "codex_dir", "claude_dir"]
        }
        "skills.enroll" => &["codex", "claude", "codex_dir", "claude_dir"],
        "skills.stage_update" => &["codex", "claude", "codex_dir", "claude_dir", "staging_dir"],
        "session.create" => &["name"],
        "session.rename" => &["id", "name"],
        "findings.list" | "event_log.list" => &["session_id", "limit"],
        "findings.get" => &["id", "session_id"],
        "findings.count" => &["session_id"],
        "scanner.config.get" | "scanner.custom.list" => &["session_id"],
        "scanner.config.set_enabled" => &["session_id", "enabled"],
        "scanner.builtin.set_enabled" => &["session_id", "id", "enabled"],
        "scanner.custom.get" | "scanner.custom.delete" => &["session_id", "id"],
        "scanner.custom.create" => &["session_id", "rule", "file", "stdin"],
        "scanner.custom.update" => &["session_id", "id", "patch", "file", "stdin"],
        "capture.http.clear" => &["session_id"],
        "capture.http.select" | "capture.http.delete" => &[
            "session_id",
            "ids",
            "query",
            "method",
            "host",
            "status",
            "status_range",
            "since",
            "mime",
            "selection_token",
        ],
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
        "capture.browser.list" => &[],
        "capture.browser.open" => &["browser", "url", "fresh", "agent"],
        "capture.browser.prefer" => &["browser"],
        "capture.http.get" => &["id", "session_id"],
        "capture.http.search" => &[
            "value",
            "session_id",
            "side",
            "case_sensitive",
            "max_matches",
            "byte_budget",
            "context",
            "query",
            "method",
            "host",
            "status",
            "status_range",
            "since",
            "mime",
        ],
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
        "replay.close" | "replay.duplicate" => &["tab_id", "session_id"],
        "replay.set_pinned" => &["tab_id", "session_id", "pinned"],
        "replay.open" => &[
            "session_id",
            "transaction_id",
            "request_file",
            "stdin",
            "scheme",
            "host",
            "port",
            "label",
        ],
        "fuzzer.set_template" => &[
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
            "label",
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
        "capture.proxy.get" | "capture.proxy.configure" => &["session_id"],
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
            SessionCommand::Rename(args) => json!({ "id": args.id, "name": args.name }),
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
            CaptureCommand::Proxy(args) => json!({"session_id": args.session_id}),
            CaptureCommand::Oast { command } => oast_input_preview(command),
            CaptureCommand::Browser { command } => match command {
                BrowserCommand::List => json!({}),
                BrowserCommand::Open(args) => browser_open_body(args),
                BrowserCommand::Prefer(args) => json!({ "browser": args.browser }),
            },
        },
        Command::Scanner { command } => scanner_input_preview(command),
        Command::Findings { command } => match command {
            FindingsCommand::List(args) => json!({"session_id":args.session_id,"limit":args.limit}),
            FindingsCommand::Get(args) => json!({"session_id":args.session_id,"id":args.id}),
            FindingsCommand::Count(args) => json!({"session_id":args.session_id}),
        },
        Command::EventLog {
            command: EventLogCommand::List(args),
        } => {
            json!({"session_id":args.session_id,"limit":args.limit})
        }
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
            SkillsCommand::Install(args)
            | SkillsCommand::Status(args)
            | SkillsCommand::UpdatePreview(args) => json!({
                "codex": args.codex,
                "claude": args.claude,
                "all": args.all,
                "codex_dir": args.codex_dir,
                "claude_dir": args.claude_dir,
            }),
            SkillsCommand::Enroll(args) => single_skill_input_preview(args),
            SkillsCommand::StageUpdate(args) => {
                let mut input = single_skill_input_preview(&args.target);
                input["staging_dir"] = json!(args.staging_dir);
                input
            }
        },
        Command::History { command } => history_input_preview(command),
        Command::Intercept { command } => intercept_input_preview(command),
        Command::Websocket { command } => websocket_input_preview(command),
        Command::AutoReplace { command } => auto_replace_input_preview(command),
    }
}

fn single_skill_input_preview(args: &SingleSkillArgs) -> Value {
    json!({"codex":args.codex,"claude":args.claude,"codex_dir":args.codex_dir,"claude_dir":args.claude_dir})
}

fn history_input_preview(command: &HistoryCommand) -> Value {
    match command {
        HistoryCommand::Clear(args) => json!({ "session_id": args.session_id }),
        HistoryCommand::Select(args) | HistoryCommand::Delete(args) => {
            serde_json::to_value(args.payload()).expect("selection serializes")
        }
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
        HistoryCommand::Search(args) => json!({
            "value": args.value,
            "session_id": args.session_id,
            "side": args.side,
            "case_sensitive": args.case_sensitive,
            "max_matches": args.max_matches,
            "byte_budget": args.byte_budget,
            "context": args.context,
            "query": args.query,
            "method": args.method,
            "host": args.host,
            "status": args.status,
            "status_range": args.status_range,
            "since": args.since,
            "mime": args.mime,
        }),
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
            "label": args.label,
        }),
        ReplayCommand::Update(args) => json!({
            "tab_id": args.tab_id,
            "session_id": args.session_id,
            "request_file": args.request_file,
            "stdin": args.stdin,
            "scheme": args.scheme,
            "host": args.host,
            "port": args.port,
            "label": args.label,
        }),
        ReplayCommand::Close(args) | ReplayCommand::Duplicate(args) => {
            let mut input = json!({"tab_id":args.tab_id});
            if let Some(session_id) = args.session_id {
                input["session_id"] = json!(session_id);
            }
            input
        }
        ReplayCommand::SetPinned(args) => {
            let mut input = json!({"tab_id":args.tab.tab_id,"pinned":args.pinned});
            if let Some(session_id) = args.tab.session_id {
                input["session_id"] = json!(session_id);
            }
            input
        }
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
        InterceptCommand::Get(args) => json!({ "id": args.id, "session_id": args.session_id }),
        InterceptCommand::Wait(args) => {
            json!({ "session_id": args.session_id, "timeout": args.timeout })
        }
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
        ResponseInterceptCommand::Wait(args) => {
            json!({ "session_id": args.session_id, "timeout": args.timeout })
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
            SessionCommand::Rename(args) => api_preview(
                "PATCH",
                format!("/api/sessions/{}", args.id),
                Some(json!({"name": args.name})),
            ),
            SessionCommand::Reveal(args) => api_preview(
                "POST",
                format!("/api/sessions/{}/reveal", args.id),
                Some(json!({})),
            ),
        },
        Command::Scanner { command } => scanner_api_preview(command),
        Command::Findings { command } => findings_api_preview(command),
        Command::EventLog {
            command: EventLogCommand::List(args),
        } => api_preview(
            "GET",
            session_read_list_path("/api/event-log", args.session_id, args.limit),
            None,
        ),
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
        CaptureCommand::Browser { command } => Ok(match command {
            BrowserCommand::List => api_preview("GET", "/api/browser/list", None),
            BrowserCommand::Open(args) => {
                api_preview("POST", "/api/browser/launch", Some(browser_open_body(args)))
            }
            BrowserCommand::Prefer(args) => api_preview(
                "POST",
                "/api/browser/preference",
                Some(json!({ "browser": args.browser })),
            ),
        }),
        CaptureCommand::Proxy(args) => Ok(if args.stdin {
            api_preview(
                "POST",
                "/api/runtime",
                Some(
                    json!({"session_id": args.session_id, "note": "proxy settings read from stdin"}),
                ),
            )
        } else {
            api_preview(
                "GET",
                session_query_path("/api/runtime", args.session_id),
                None,
            )
        }),
        CaptureCommand::Oast { command } => Ok(oast_api_preview(command)),
    }
}

fn history_api_preview(command: &HistoryCommand) -> Result<Value> {
    Ok(match command {
        HistoryCommand::Select(args) => api_preview(
            "POST",
            "/api/transactions/select",
            Some(serde_json::to_value(args.payload())?),
        ),
        HistoryCommand::Delete(args) => api_preview(
            "DELETE",
            "/api/transactions/selected",
            Some(serde_json::to_value(args.payload())?),
        ),
        HistoryCommand::Clear(args) => api_preview(
            "DELETE",
            session_query_path("/api/transactions", args.session_id),
            None,
        ),
        HistoryCommand::List(args) => {
            api_preview("GET", history_list_path(args.session_id, args)?, None)
        }
        HistoryCommand::Get(args) => api_preview(
            "GET",
            transaction_detail_path(args.id, args.session_id),
            None,
        ),
        HistoryCommand::Search(args) => {
            api_preview("GET", history_search_path(args.session_id, args), None)
        }
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
        ReplayCommand::Close(args) | ReplayCommand::Duplicate(args) => {
            let mut body = json!({
                "tab_id":args.tab_id,
                "session_id":args.session_id.map(|id| json!(id)).unwrap_or_else(|| json!("<resolved active session ID>")),
                "expected_workspace_revision":"<fetched saved workspace revision>"
            });
            if args.session_id.is_none() {
                body["expected_active_session_id"] = json!("<resolved active session ID>");
            }
            api_preview(
                "POST",
                replay_saved_tab_path(if matches!(command, ReplayCommand::Duplicate(_)) {
                    SavedReplayTabAction::Duplicate
                } else {
                    SavedReplayTabAction::Close
                }),
                Some(body),
            )
        }
        ReplayCommand::SetPinned(args) => {
            let mut preview = replay_api_preview(&ReplayCommand::Close(ReplaySavedTabArgs {
                tab_id: args.tab.tab_id.clone(),
                session_id: args.tab.session_id,
            }));
            preview["path"] = json!(replay_saved_tab_path(SavedReplayTabAction::SetPinned(
                args.pinned
            )));
            preview["body"]["pinned"] = json!(args.pinned);
            preview
        }
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
        InterceptCommand::Get(args) => api_preview(
            "GET",
            session_query_path(&format!("/api/intercepts/{}", args.id), args.session_id),
            None,
        ),
        InterceptCommand::Wait(args) => api_preview(
            "GET",
            session_query_path("/api/intercepts", args.session_id),
            Some(json!({ "note": "polls until a request is held" })),
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
        ResponseInterceptCommand::Wait(args) => api_preview(
            "GET",
            session_query_path("/api/response-intercepts", args.session_id),
            Some(json!({ "note": "polls until a response is held" })),
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

fn session_read_list_path(base: &str, session_id: Option<Uuid>, limit: usize) -> String {
    session_query_path(&format!("{base}?limit={limit}"), session_id)
}

fn findings_api_preview(command: &FindingsCommand) -> Value {
    let path = match command {
        FindingsCommand::List(args) => {
            session_read_list_path("/api/findings", args.session_id, args.limit)
        }
        FindingsCommand::Get(args) => {
            session_query_path(&format!("/api/findings/{}", args.id), args.session_id)
        }
        FindingsCommand::Count(args) => session_query_path("/api/findings/count", args.session_id),
    };
    api_preview("GET", path, None)
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
        "replay.close" | "replay.duplicate" | "replay.set_pinned"
    ) {
        notes.push("Dry-run is fully offline: it does not discover Sniper, resolve a session, read saved tabs or check whether the exact tab ID exists.");
        notes.push("Execution pins one session, reads its saved workspace revision, and posts only IDs, revision and any requested pin state to the dedicated endpoint once. An inferred session also guards against an active-session switch. Conflicts, redirects and ambiguous responses are not retried.");
        notes.push("Saved HTTP tabs only, including legacy empty types. No request parsing, body hydration, Replay send, WebSocket connection or full workspace replacement occurs. Success returns only acknowledgement metadata.");
    }
    if matches!(
        command,
        Command::Skills {
            command: SkillsCommand::Enroll(_)
                | SkillsCommand::UpdatePreview(_)
                | SkillsCommand::StageUpdate(_)
        }
    ) {
        notes.push("CLI-host local only; no Sniper API discovery or contact. Dry-run validates arguments and describes the plan without reading skill files or checking eligibility.");
        notes.push("Enrollment records explicit local opt-in only and does not enable startup or automatic updates. Preview never implies ownership of unmanaged files.");
        notes.push("Staging requires an unchanged enrolled skill with different bundled bytes and a new output directory. It writes a candidate and receipt only; the active SKILL.md remains unchanged and nothing is activated.");
    }
    if matches!(command, Command::Scanner { .. }) {
        notes.push("Dry-run is offline and validates supplied rule JSON before API discovery. It does not resolve sessions, fetch configuration, apply writes or inspect traffic.");
        notes.push("An omitted session_id is resolved once and pinned; writes also guard expected_active_session_id. Writes fetch a config_token and compare-and-swap once, preserving unrelated fields and custom rule order. Conflicts are not retried.");
        notes.push("Passive configuration only: regexes inspect captured response body previews or headers. Configuration changes do not send probes or rescan stored traffic.");
    }
    if matches!(command, Command::Findings { .. } | Command::EventLog { .. }) {
        notes.push("Dry-run is offline. An omitted session_id is resolved once and pinned before the read; call output includes it in meta.session_id.");
    }
    if matches!(
        command.operation_name(),
        "capture.http.select" | "capture.http.delete" | "capture.http.clear"
    ) {
        notes.push("Dry-run validates and describes the request only; it does not contact Sniper or resolve matching records. Use capture.http.select to review count, IDs and selection_token.");
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
    if saved_operation_name(operation).is_some() {
        sniper::saved_contract::validate_input(operation, input).map_err(|_| {
            saved_cli_error(
                "INVALID_INPUT",
                "Input does not satisfy the saved-data schema",
                "not_applied",
                input,
            )
        })?;
        return Ok(Command::Call(CallArgs {
            operation: operation.to_owned(),
            input: Some(input.to_string()),
        }));
    }
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
            operation: call_optional(operation, input, "operation")?,
        },
        "skills.status" | "skills.update_preview" => {
            let args = SkillsInstallArgs {
                codex: call_bool(operation, input, "codex")?,
                claude: call_bool(operation, input, "claude")?,
                all: call_bool(operation, input, "all")?,
                codex_dir: call_optional_path(operation, input, "codex_dir")?,
                claude_dir: call_optional_path(operation, input, "claude_dir")?,
            };
            Command::Skills {
                command: if operation == "skills.status" {
                    SkillsCommand::Status(args)
                } else {
                    SkillsCommand::UpdatePreview(args)
                },
            }
        }
        "skills.enroll" | "skills.stage_update" => {
            let target = SingleSkillArgs {
                codex: call_bool(operation, input, "codex")?,
                claude: call_bool(operation, input, "claude")?,
                codex_dir: call_optional_path(operation, input, "codex_dir")?,
                claude_dir: call_optional_path(operation, input, "claude_dir")?,
            };
            Command::Skills {
                command: if operation == "skills.enroll" {
                    SkillsCommand::Enroll(target)
                } else {
                    SkillsCommand::StageUpdate(SkillsStageArgs {
                        target,
                        staging_dir: PathBuf::from(call_required::<String>(
                            operation,
                            input,
                            "staging_dir",
                        )?),
                    })
                },
            }
        }
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
        "session.rename" => Command::Session {
            command: SessionCommand::Rename(SessionRenameArgs {
                id: call_required(operation, input, "id")?,
                name: call_required(operation, input, "name")?,
            }),
        },
        "capture.http.clear" => Command::Capture {
            command: CaptureCommand::Http {
                command: HistoryCommand::Clear(InterceptSessionArgs {
                    session_id: call_optional(operation, input, "session_id")?,
                }),
            },
        },
        "capture.http.select" | "capture.http.delete" => {
            let args = HistorySelectionArgs {
                session_id: call_required(operation, input, "session_id")?,
                ids: call_optional(operation, input, "ids")?.unwrap_or_default(),
                query: call_optional(operation, input, "query")?,
                method: call_optional(operation, input, "method")?,
                host: call_optional(operation, input, "host")?,
                status: call_optional_http_status(operation, input, "status")?,
                status_range: call_optional(operation, input, "status_range")?,
                since: call_optional(operation, input, "since")?,
                mime: call_optional(operation, input, "mime")?,
                selection_token: call_optional(operation, input, "selection_token")?,
            };
            args.payload()
                .validate(operation == "capture.http.delete")
                .map_err(|error| anyhow!(error))?;
            Command::Capture {
                command: CaptureCommand::Http {
                    command: if operation == "capture.http.select" {
                        HistoryCommand::Select(args)
                    } else {
                        HistoryCommand::Delete(args)
                    },
                },
            }
        }
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
        "capture.browser.list" => Command::Capture {
            command: CaptureCommand::Browser {
                command: BrowserCommand::List,
            },
        },
        "capture.browser.prefer" => Command::Capture {
            command: CaptureCommand::Browser {
                command: BrowserCommand::Prefer(BrowserPreferArgs {
                    browser: call_required_enum_string(
                        operation,
                        input,
                        "browser",
                        &browser_choices(),
                    )?,
                }),
            },
        },
        "capture.browser.open" => Command::Capture {
            command: CaptureCommand::Browser {
                command: BrowserCommand::Open(BrowserOpenArgs {
                    browser: call_optional_enum_string(
                        operation,
                        input,
                        "browser",
                        &browser_choices(),
                    )?,
                    url: call_optional(operation, input, "url")?,
                    fresh: call_bool(operation, input, "fresh")?,
                    agent: call_bool(operation, input, "agent")?,
                }),
            },
        },
        "capture.http.search" => Command::Capture {
            command: CaptureCommand::Http {
                command: HistoryCommand::Search(HistorySearchArgs {
                    value: call_required(operation, input, "value")?,
                    session_id: call_optional(operation, input, "session_id")?,
                    side: call_optional(operation, input, "side")?.unwrap_or_default(),
                    case_sensitive: call_bool(operation, input, "case_sensitive")?,
                    max_matches: call_optional_nonzero_usize(operation, input, "max_matches")?,
                    byte_budget: call_optional(operation, input, "byte_budget")?,
                    context: call_optional(operation, input, "context")?,
                    query: call_optional(operation, input, "query")?,
                    method: call_optional(operation, input, "method")?,
                    host: call_optional(operation, input, "host")?,
                    status: call_optional_http_status(operation, input, "status")?,
                    status_range: call_optional(operation, input, "status_range")?,
                    since: call_optional(operation, input, "since")?,
                    mime: call_optional(operation, input, "mime")?,
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
        operation if operation.starts_with("scanner.") => Command::Scanner {
            command: scanner_command_from_input(operation, input)?,
        },
        "findings.list" => Command::Findings {
            command: FindingsCommand::List(SessionReadListArgs {
                session_id: call_optional(operation, input, "session_id")?,
                limit: call_optional_nonzero_usize(operation, input, "limit")?
                    .unwrap_or(DEFAULT_READ_LIST_LIMIT),
            }),
        },
        "findings.get" => Command::Findings {
            command: FindingsCommand::Get(FindingGetArgs {
                id: call_required(operation, input, "id")?,
                session_id: call_optional(operation, input, "session_id")?,
            }),
        },
        "findings.count" => Command::Findings {
            command: FindingsCommand::Count(SessionReadArgs {
                session_id: call_optional(operation, input, "session_id")?,
            }),
        },
        "event_log.list" => Command::EventLog {
            command: EventLogCommand::List(SessionReadListArgs {
                session_id: call_optional(operation, input, "session_id")?,
                limit: call_optional_nonzero_usize(operation, input, "limit")?
                    .unwrap_or(DEFAULT_READ_LIST_LIMIT),
            }),
        },
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
                    label: call_optional(operation, input, "label")?,
                }),
            }
        }
        "replay.update" => {
            let request_file = call_optional_path(operation, input, "request_file")?;
            let stdin = call_bool(operation, input, "stdin")?;
            let scheme = call_optional(operation, input, "scheme")?;
            let host = call_optional(operation, input, "host")?;
            let port = call_optional(operation, input, "port")?;
            let label = call_optional(operation, input, "label")?;
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
                    ("label", label.is_some()),
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
                    label,
                }),
            }
        }
        "replay.close" | "replay.duplicate" | "replay.set_pinned" => {
            let args = ReplaySavedTabArgs {
                tab_id: call_required(operation, input, "tab_id")?,
                session_id: if input.get("session_id").is_some() {
                    Some(call_required(operation, input, "session_id")?)
                } else {
                    None
                },
            };
            Command::Replay {
                command: if operation == "replay.close" {
                    ReplayCommand::Close(args)
                } else if operation == "replay.duplicate" {
                    ReplayCommand::Duplicate(args)
                } else {
                    ReplayCommand::SetPinned(ReplaySetPinnedArgs {
                        tab: args,
                        pinned: call_required(operation, input, "pinned")?,
                    })
                },
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
        "capture.proxy.get" | "capture.proxy.configure" => Command::Capture {
            command: CaptureCommand::Proxy(ProxyChainArgs {
                session_id: call_optional(operation, input, "session_id")?,
                stdin: operation == "capture.proxy.configure",
            }),
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

fn call_required_enum_string(
    operation: &str,
    input: &Value,
    field: &str,
    allowed: &[&str],
) -> Result<String> {
    call_optional_enum_string(operation, input, field, allowed)?
        .ok_or_else(|| anyhow!("missing required field `{field}` for `{operation}`"))
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
        Command::Scanner {
            command:
                ScannerCommand::Custom {
                    command: ScannerCustomCommand::Create(args),
                },
        } => args.stdin,
        Command::Scanner {
            command:
                ScannerCommand::Custom {
                    command: ScannerCustomCommand::Update(args),
                },
        } => args.stdin,
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
        Command::Capture {
            command: CaptureCommand::Proxy(args),
        } => args.stdin,
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
    let mut command = match cli.command {
        Command::Call(args) if args.operation.starts_with("saved.v1.") => {
            return run_saved_call(api_override, args, dry_run, yes).await;
        }
        Command::Call(args) => command_from_call_args(args)?,
        command => command,
    };

    prepare_scanner_command(&mut command)?;
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
        Command::Examples {
            operation: Some(operation),
        } => {
            let spec = operation_spec(&operation)
                .ok_or_else(|| anyhow!("unknown operation `{operation}`"))?;
            print_json(&json!({
                "operation": operation,
                "examples": spec.examples,
            }))
        }
        // Bare `examples` is how an agent asks "what can I do"; an error there
        // costs a round trip for no information.
        Command::Examples { operation: None } => print_json(
            &manifest_operations()
                .into_iter()
                .map(|spec| {
                    json!({
                        "operation": spec.operation,
                        "command": spec.command,
                        "examples": spec.examples,
                    })
                })
                .collect::<Vec<_>>(),
        ),
        Command::Skills {
            command: SkillsCommand::Status(args),
        } => print_json(&skills_status(args)?),
        Command::Skills {
            command: SkillsCommand::Install(args),
        } => {
            let result = install_skills(args)?;
            print_json(&result)
        }
        Command::Skills {
            command: SkillsCommand::UpdatePreview(args),
        } => print_json(&skills_update_preview(args)?),
        Command::Skills {
            command: SkillsCommand::Enroll(args),
        } => {
            let (agent, root, bundled) = single_skill_target(args)?;
            print_json(&sniper::skill_managed::enroll_skill(
                agent,
                &root,
                bundled,
                env!("CARGO_PKG_VERSION"),
            )?)
        }
        Command::Skills {
            command: SkillsCommand::StageUpdate(args),
        } => {
            let (agent, root, bundled) = single_skill_target(args.target)?;
            print_json(&sniper::skill_managed::stage_skill_update(
                agent,
                &root,
                bundled,
                env!("CARGO_PKG_VERSION"),
                &args.staging_dir,
            )?)
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
                    CaptureCommand::Proxy(args) => handle_proxy_chain(api, args).await,
                    CaptureCommand::Oast { command } => handle_oast(api, command).await,
                    CaptureCommand::Browser { command } => handle_browser(api, command).await,
                },
                Command::Scanner { command } => handle_scanner(api, command).await,
                Command::Findings { command } => handle_findings(api, command).await,
                Command::EventLog { command } => handle_event_log(api, command).await,
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
    if let Command::Skills {
        command: SkillsCommand::Status(args) | SkillsCommand::UpdatePreview(args),
    } = command
    {
        if !(args.codex || args.claude || args.all) {
            bail!("must select at least one destination with --codex, --claude, or --all");
        }
        for path in [&args.codex_dir, &args.claude_dir].into_iter().flatten() {
            if path.as_os_str().is_empty() || path.to_string_lossy().contains('\0') {
                bail!("skill directory must be nonempty and contain no NUL characters");
            }
        }
    }

    if let Command::Skills {
        command:
            SkillsCommand::Enroll(args)
            | SkillsCommand::StageUpdate(SkillsStageArgs { target: args, .. }),
    } = command
    {
        if args.codex == args.claude {
            bail!("must select exactly one destination with --codex or --claude");
        }
        for path in [&args.codex_dir, &args.claude_dir].into_iter().flatten() {
            validate_skill_cli_path(path)?;
        }
    }
    if let Command::Skills {
        command: SkillsCommand::StageUpdate(args),
    } = command
    {
        validate_skill_cli_path(&args.staging_dir)?;
    }

    if let Command::Replay {
        command:
            ReplayCommand::Close(args)
            | ReplayCommand::Duplicate(args)
            | ReplayCommand::SetPinned(ReplaySetPinnedArgs { tab: args, .. }),
    } = command
    {
        if args.tab_id.trim().is_empty() || args.tab_id.len() > 128 {
            bail!("tab_id must be nonblank and at most 128 UTF-8 bytes; exact ID is never trimmed");
        }
    }
    if let Command::Session {
        command: SessionCommand::Rename(args),
    } = command
    {
        let name = args.name.trim();
        if name.is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
            bail!(
                "name must be nonblank, at most 256 UTF-8 bytes and contain no control characters"
            );
        }
    }
    if let Command::Capture {
        command: CaptureCommand::Http { command: history },
    }
    | Command::History { command: history } = command
    {
        match history {
            HistoryCommand::Select(args) => args
                .payload()
                .validate(false)
                .map_err(|error| anyhow!(error))?,
            HistoryCommand::Delete(args) => args
                .payload()
                .validate(true)
                .map_err(|error| anyhow!(error))?,
            _ => (),
        }
    }
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

/// `auto` and every browser Sniper knows, from the one list in `BrowserKind`, so a
/// browser added there is accepted here without anyone remembering this place.
fn browser_choices() -> Vec<&'static str> {
    std::iter::once("auto")
        .chain(sniper::browser::BrowserKind::names())
        .collect()
}

fn browser_open_body(args: &BrowserOpenArgs) -> Value {
    json!({
        "browser": args.browser,
        "url": args.url,
        "fresh": args.fresh,
        "agent": args.agent,
    })
}

async fn handle_browser(api: ApiClient, command: BrowserCommand) -> Result<()> {
    match command {
        BrowserCommand::List => {
            let browsers: Value = api.get_json("/api/browser/list").await?;
            print_json(&browsers)
        }
        BrowserCommand::Open(args) => {
            let launched: Value = api
                .post_json("/api/browser/launch", &browser_open_body(&args))
                .await?;
            print_json(&launched)
        }
        BrowserCommand::Prefer(args) => {
            let saved: Value = api
                .post_json(
                    "/api/browser/preference",
                    &json!({ "browser": args.browser }),
                )
                .await?;
            print_json(&saved)
        }
    }
}

async fn handle_proxy_chain(api: ApiClient, args: ProxyChainArgs) -> Result<()> {
    let runtime: Value = if args.stdin {
        let raw = read_text_input(None, true)?;
        let (proxy, bypass_hosts) = parse_proxy_chain_input(&raw)?;
        proxy.validate()?;
        let (session_id, expected_active_session_id) =
            runtime_write_session_ids(&api, args.session_id).await?;
        let mut body = json!({"session_id":session_id, "expected_active_session_id":expected_active_session_id, "upstream_proxy":proxy});
        if let Some(bypass_hosts) = bypass_hosts {
            body["upstream_bypass_hosts"] = json!(bypass_hosts);
        }
        api.post_json("/api/runtime", &body).await?
    } else {
        api.get_json(&session_query_path("/api/runtime", args.session_id))
            .await?
    };
    print_json_with_session(&proxy_chain_output(&runtime), args.session_id)
}

/// The API keeps the bypass list beside the proxy (`upstream_bypass_hosts`) so that
/// replacing the proxy cannot wipe it. The CLI reads and writes the two as one
/// object, which is how people think of a chain and its exceptions.
fn parse_proxy_chain_input(
    raw: &str,
) -> Result<(sniper::upstream_proxy::UpstreamProxy, Option<Vec<String>>)> {
    let invalid = || {
        anyhow!("Expected proxy settings JSON with enabled, url, username, password and optional bypass_hosts")
    };
    let mut value: Value = serde_json::from_str(raw).map_err(|_| invalid())?;
    let bypass_hosts = value
        .as_object_mut()
        .and_then(|object| object.remove("bypass_hosts"))
        .map(|hosts| serde_json::from_value(hosts).map_err(|_| invalid()))
        .transpose()?;
    let proxy = serde_json::from_value(value).map_err(|_| invalid())?;
    Ok((proxy, bypass_hosts))
}

fn proxy_chain_output(runtime: &Value) -> Value {
    let mut chain = runtime["upstream_proxy"].clone();
    if let Some(object) = chain.as_object_mut() {
        let bypass_hosts = runtime
            .get("upstream_bypass_hosts")
            .cloned()
            .unwrap_or_else(|| json!([]));
        object.insert("bypass_hosts".to_string(), bypass_hosts);
    }
    chain
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
        SessionCommand::Rename(args) => {
            let session: SessionSummary = api
                .request_json(
                    Method::PATCH,
                    &format!("/api/sessions/{}", args.id),
                    Some(json!({"name": args.name})),
                )
                .await?;
            print_json(&session)
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
        HistoryCommand::Select(args) => {
            let result: Value = api
                .post_json("/api/transactions/select", &args.payload())
                .await?;
            print_json(&result)
        }
        HistoryCommand::Delete(args) => {
            let result: Value = api
                .request_json(
                    Method::DELETE,
                    "/api/transactions/selected",
                    Some(args.payload()),
                )
                .await?;
            print_json(&result)
        }
        HistoryCommand::Clear(args) => {
            let (session_id, expected_active_session_id) =
                runtime_write_session_ids(&api, args.session_id).await?;
            let path = session_query_path_with_expected_active(
                "/api/transactions",
                session_id,
                expected_active_session_id,
            );
            let result: Value = api.delete_json(&path).await?;
            print_json_with_session(&result, session_id)
        }
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
        HistoryCommand::Search(args) => {
            let session_id = match args.session_id {
                Some(session_id) => Some(session_id),
                None => active_session_id(&api).await?,
            };
            let result: Value = api
                .get_json(&history_search_path(session_id, &args))
                .await?;
            print_json(&result)
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
                    label: None,
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
            let mut replay = serde_json::to_value(&workspace.replay)?;
            if let Some(object) = replay.as_object_mut() {
                object.insert(
                    "tabs".to_string(),
                    with_labels(&workspace.replay.tabs, replay_tab_label),
                );
            }
            print_json(&replay)
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
                    label: args.label,
                },
            )
            .await?;
            print_json_with_session(&tab, session_id)
        }
        ReplayCommand::Update(args) => {
            let mut workspace = load_workspace_state(&api, args.session_id).await?;
            let tab = find_replay_tab_mut(&mut workspace.replay, &args.tab_id)?;
            ensure_http_replay_tab(tab, &args.tab_id)?;
            if let Some(label) = args.label.as_deref() {
                tab.custom_label = normalize_replay_tab_label(label);
            }
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
        ReplayCommand::Close(args) => {
            handle_saved_replay_tab(&api, args, SavedReplayTabAction::Close).await
        }
        ReplayCommand::Duplicate(args) => {
            handle_saved_replay_tab(&api, args, SavedReplayTabAction::Duplicate).await
        }
        ReplayCommand::SetPinned(args) => {
            handle_saved_replay_tab(&api, args.tab, SavedReplayTabAction::SetPinned(args.pinned))
                .await
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

// Only metadata is decoded here. Saved request text, responses and history never
// become editable requests or a replacement workspace in these operations.
#[derive(Deserialize)]
struct SavedReplayTabMetadata {
    id: String,
    #[serde(rename = "type", default)]
    tab_type: String,
    #[serde(default)]
    pinned: bool,
}

struct SavedReplayTabSnapshot {
    revision: u64,
    tabs: Vec<SavedReplayTabMetadata>,
    active_tab_id: Option<String>,
}

#[derive(Debug)]
struct ReplayTabCliError {
    code: &'static str,
    message: &'static str,
    outcome: &'static str,
    session_id: Option<Uuid>,
}

impl fmt::Display for ReplayTabCliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for ReplayTabCliError {}

fn replay_tab_error(
    code: &'static str,
    message: &'static str,
    outcome: &'static str,
    session_id: Option<Uuid>,
) -> anyhow::Error {
    anyhow!(ReplayTabCliError {
        code,
        message,
        outcome,
        session_id
    })
}

#[derive(Clone, Copy)]
enum SavedReplayTabAction {
    Close,
    Duplicate,
    SetPinned(bool),
}

fn replay_saved_tab_path(action: SavedReplayTabAction) -> &'static str {
    match action {
        SavedReplayTabAction::Close => "/api/replay/tabs/close",
        SavedReplayTabAction::Duplicate => "/api/replay/tabs/duplicate",
        SavedReplayTabAction::SetPinned(_) => "/api/replay/tabs/set-pinned",
    }
}

async fn saved_replay_response_json(
    mut response: reqwest::Response,
    limit: usize,
) -> std::result::Result<Value, ()> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(());
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| ())
}

async fn saved_replay_get(
    api: &ApiClient,
    client: &reqwest::Client,
    path: &str,
    session_id: Option<Uuid>,
) -> Result<Value> {
    let response = client.get(api.url(path)).send().await.map_err(|_| {
        replay_tab_error(
            "TRANSPORT_ERROR",
            "Saved tab read failed; no mutation was sent",
            "not_applied",
            session_id,
        )
    })?;
    if !response.status().is_success() {
        return Err(replay_tab_error(
            "HTTP_STATUS_ERROR",
            "Saved tab read was rejected; no mutation was sent",
            "not_applied",
            session_id,
        ));
    }
    saved_replay_response_json(response, MAX_CLI_INPUT_BYTES)
        .await
        .map_err(|_| {
            replay_tab_error(
                "INVALID_RESPONSE",
                "Saved tab read was malformed or too large; no mutation was sent",
                "not_applied",
                session_id,
            )
        })
}

fn checked_saved_replay_snapshot(
    mut value: Value,
    session_id: Uuid,
) -> Result<SavedReplayTabSnapshot> {
    let invalid = || {
        replay_tab_error(
            "INVALID_RESPONSE",
            "Saved workspace metadata is invalid; no mutation was sent",
            "not_applied",
            Some(session_id),
        )
    };
    if value
        .get("session_id")
        .and_then(Value::as_str)
        .and_then(|id| Uuid::parse_str(id).ok())
        != Some(session_id)
    {
        return Err(invalid());
    }
    let revision = value
        .get("revision")
        .and_then(Value::as_u64)
        .filter(|revision| *revision < u64::MAX)
        .ok_or_else(invalid)?;
    let replay = value
        .get_mut("replay")
        .and_then(Value::as_object_mut)
        .ok_or_else(invalid)?;
    let active = replay.get("active_tab_id").ok_or_else(invalid)?;
    let active_tab_id = if active.is_null() {
        None
    } else {
        Some(active.as_str().ok_or_else(invalid)?.to_owned())
    };
    let tabs: Vec<SavedReplayTabMetadata> =
        serde_json::from_value(replay.remove("tabs").ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
    let mut ids = std::collections::HashSet::new();
    if tabs.len() > sniper::workspace::MAX_WORKSPACE_REPLAY_TABS
        || tabs.iter().any(|tab| {
            tab.id.trim().is_empty() || tab.id.len() > 128 || !ids.insert(tab.id.as_str())
        })
        || active_tab_id
            .as_ref()
            .is_some_and(|id| id.len() > 128 || (!id.is_empty() && !ids.contains(id.as_str())))
    {
        return Err(invalid());
    }
    Ok(SavedReplayTabSnapshot {
        revision,
        tabs,
        active_tab_id,
    })
}

fn saved_replay_expected_active(
    snapshot: &SavedReplayTabSnapshot,
    tab_id: &str,
    duplicate: bool,
) -> Option<String> {
    if !duplicate && snapshot.tabs.len() == 1 {
        return None;
    }
    if duplicate || snapshot.active_tab_id.as_deref() != Some(tab_id) {
        return snapshot.active_tab_id.clone();
    }
    let mut visual: Vec<_> = snapshot.tabs.iter().collect();
    visual.sort_by_key(|tab| !tab.pinned);
    let index = visual.iter().position(|tab| tab.id == tab_id)?;
    index
        .checked_sub(1)
        .and_then(|previous| visual.get(previous))
        .or_else(|| visual.get(index + 1))
        .map(|tab| tab.id.clone())
}

fn checked_saved_replay_ack(
    value: Value,
    snapshot: &SavedReplayTabSnapshot,
    session_id: Uuid,
    tab_id: &str,
    action: SavedReplayTabAction,
) -> Result<Value> {
    let invalid = || {
        replay_tab_error("INVALID_RESPONSE", "Saved tab acknowledgement did not match this operation; inspect saved tabs before any further action", "unknown", Some(session_id))
    };
    let expected_fields: &[&str] = if matches!(action, SavedReplayTabAction::Duplicate) {
        &[
            "session_id",
            "revision",
            "source_tab_id",
            "new_tab_id",
            "active_tab_id",
        ]
    } else if matches!(action, SavedReplayTabAction::Close) {
        &["session_id", "revision", "closed_tab_id", "active_tab_id"]
    } else {
        &[
            "session_id",
            "revision",
            "tab_id",
            "pinned",
            "active_tab_id",
        ]
    };
    let object = value.as_object().ok_or_else(invalid)?;
    if object.len() != expected_fields.len()
        || expected_fields.iter().any(|key| !object.contains_key(*key))
    {
        return Err(invalid());
    }
    let target_key = match action {
        SavedReplayTabAction::Close => "closed_tab_id",
        SavedReplayTabAction::Duplicate => "source_tab_id",
        SavedReplayTabAction::SetPinned(_) => "tab_id",
    };
    if value["session_id"]
        .as_str()
        .and_then(|id| Uuid::parse_str(id).ok())
        != Some(session_id)
        || value["revision"].as_u64() != snapshot.revision.checked_add(1)
        || value[target_key].as_str() != Some(tab_id)
        || value["active_tab_id"]
            != json!(saved_replay_expected_active(
                snapshot,
                tab_id,
                !matches!(action, SavedReplayTabAction::Close)
            ))
    {
        return Err(invalid());
    }
    if matches!(action, SavedReplayTabAction::Duplicate) {
        let new_id = value["new_tab_id"].as_str().ok_or_else(invalid)?;
        let uuid = Uuid::parse_str(new_id).map_err(|_| invalid())?;
        if snapshot
            .tabs
            .iter()
            .any(|tab| tab.id == new_id || Uuid::parse_str(&tab.id).ok() == Some(uuid))
        {
            return Err(invalid());
        }
    }
    if let SavedReplayTabAction::SetPinned(pinned) = action {
        if value["pinned"].as_bool() != Some(pinned) {
            return Err(invalid());
        }
    }
    Ok(value)
}

async fn handle_saved_replay_tab(
    api: &ApiClient,
    args: ReplaySavedTabArgs,
    action: SavedReplayTabAction,
) -> Result<()> {
    // Do not inherit redirect or protocol retry behavior from legacy clients:
    // an acknowledgement loss must never create a second duplicate or close.
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(CLI_API_TIMEOUT)
        .build()
        .map_err(|_| {
            replay_tab_error(
                "TRANSPORT_ERROR",
                "Could not prepare saved tab client; no mutation was sent",
                "not_applied",
                args.session_id,
            )
        })?;
    let session_id = if let Some(session_id) = args.session_id {
        session_id
    } else {
        let value = saved_replay_get(api, &client, "/api/sessions", None).await?;
        let sessions: Vec<SessionSummary> = serde_json::from_value(value).map_err(|_| {
            replay_tab_error(
                "INVALID_RESPONSE",
                "Session metadata is invalid; no mutation was sent",
                "not_applied",
                None,
            )
        })?;
        active_session_id_from_summaries(&sessions)
            .ok()
            .flatten()
            .ok_or_else(|| {
                replay_tab_error(
                    "INVALID_RESPONSE",
                    "Expected exactly one active saved session; pass --session-id explicitly",
                    "not_applied",
                    None,
                )
            })?
    };
    let value = saved_replay_get(
        api,
        &client,
        &session_query_path("/api/workspace-state", Some(session_id)),
        Some(session_id),
    )
    .await?;
    let snapshot = checked_saved_replay_snapshot(value, session_id)?;
    let tab = snapshot
        .tabs
        .iter()
        .find(|tab| tab.id == args.tab_id)
        .ok_or_else(|| {
            replay_tab_error(
                "TAB_NOT_FOUND",
                "Exact saved tab ID was not found in the selected session; no mutation was sent",
                "not_applied",
                Some(session_id),
            )
        })?;
    if !matches!(tab.tab_type.as_str(), "" | "http") {
        return Err(replay_tab_error(
            "INVALID_INPUT",
            "Saved tab operations require an HTTP tab; no mutation was sent",
            "not_applied",
            Some(session_id),
        ));
    }
    let mut body = json!({"session_id":session_id,"tab_id":args.tab_id,"expected_workspace_revision":snapshot.revision});
    if args.session_id.is_none() {
        body["expected_active_session_id"] = json!(session_id);
    }
    if let SavedReplayTabAction::SetPinned(pinned) = action {
        body["pinned"] = json!(pinned);
    }
    let response = client
        .post(api.url(replay_saved_tab_path(action)))
        .json(&body)
        .send()
        .await
        .map_err(|_| {
            replay_tab_error(
                "TRANSPORT_ERROR",
                "Saved tab response was lost; inspect saved tabs before any further action",
                "unknown",
                Some(session_id),
            )
        })?;
    let status = response.status();
    if status.is_redirection() {
        return Err(replay_tab_error(
            "REDIRECT_REFUSED",
            "Saved tab mutation redirect refused; inspect saved tabs before any further action",
            "unknown",
            Some(session_id),
        ));
    }
    if !status.is_success() {
        // Never print an error body: older servers may attach whole workspaces.
        let (code, outcome) = match status {
            StatusCode::CONFLICT => ("WORKSPACE_CONFLICT", "not_applied"),
            StatusCode::PRECONDITION_REQUIRED => ("PRECONDITION_REQUIRED", "not_applied"),
            StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND | StatusCode::UNPROCESSABLE_ENTITY => {
                ("HTTP_STATUS_ERROR", "not_applied")
            }
            _ => ("HTTP_STATUS_ERROR", "unknown"),
        };
        return Err(replay_tab_error(
            code,
            "Saved tab mutation was rejected; inspect saved tabs before any further action",
            outcome,
            Some(session_id),
        ));
    }
    let value = saved_replay_response_json(response, 4096).await.map_err(|_| replay_tab_error("INVALID_RESPONSE", "Saved tab acknowledgement was missing, malformed or too large; inspect saved tabs before any further action", "unknown", Some(session_id)))?;
    let acknowledgement =
        checked_saved_replay_ack(value, &snapshot, session_id, &args.tab_id, action)?;
    print_session_read_json(&acknowledgement, session_id)
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

/// Block until the queue at `list_path` holds something, and return the first
/// entry.
///
/// The event stream carries transactions, findings and workspace saves but not
/// intercepts, so there is nothing to subscribe to — this polls. An intercept
/// holds a live client connection open the whole time it waits, so the interval
/// is the operator's latency budget, not just ours.
async fn wait_for_first_intercept<T: DeserializeOwned>(
    api: &ApiClient,
    list_path: &str,
    timeout_secs: u64,
    poll_interval_ms: u64,
    _id_of: impl Fn(&T) -> Uuid,
) -> Result<Option<T>> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let interval = std::time::Duration::from_millis(poll_interval_ms.max(25));
    loop {
        let mut queued: Vec<T> = api.get_json(list_path).await?;
        if !queued.is_empty() {
            return Ok(Some(queued.remove(0)));
        }
        if std::time::Instant::now() >= deadline {
            return Ok(None);
        }
        tokio::time::sleep(interval).await;
    }
}

/// The identifier a person actually sees on a Replay tab.
///
/// The UI composes this from `sequence`, the request line and the target, and
/// never stores it — the tab is persisted, so a derived label written next to it
/// would go stale the moment either part changed. An agent reporting on a tab
/// has only the UUID otherwise, which nobody can match against their screen, so
/// the CLI composes the same string on the way out. Keep in step with
/// `replayTabAutoLabel` in web/app.js.
fn replay_tab_label(tab: &ReplayTabState) -> String {
    if !tab.custom_label.trim().is_empty() {
        return tab.custom_label.clone();
    }
    if tab.tab_type == "websocket" {
        let host = if tab.ws_host.trim().is_empty() {
            "draft"
        } else {
            tab.ws_host.trim()
        };
        return format!("{}. WS {host}", tab.sequence);
    }
    let method = tab
        .base_request
        .as_ref()
        .map(|request| request.method.as_str())
        .filter(|method| !method.trim().is_empty())
        .unwrap_or("GET");
    let authority = replay_tab_authority(tab);
    format!("{}. {method} {authority}", tab.sequence)
}

fn replay_tab_authority(tab: &ReplayTabState) -> String {
    let host = if tab.target_host.trim().is_empty() {
        tab.base_request
            .as_ref()
            .map(|request| request.host.trim().to_string())
            .unwrap_or_default()
    } else {
        tab.target_host.trim().to_string()
    };
    if host.is_empty() {
        return "draft".to_string();
    }
    // The host already carries a port when it came off a captured request, so
    // only an explicit override adds one.
    if tab.target_port.trim().is_empty() || host.contains(':') {
        host
    } else {
        format!("{host}:{}", tab.target_port.trim())
    }
}

/// The identifier a person sees on a row of the HTTP history: the `#` column is
/// the capture sequence, followed by the method and where it went.
fn transaction_label(summary: &TransactionSummary) -> String {
    format!(
        "#{} {} {}{}",
        summary.sequence, summary.method, summary.host, summary.path
    )
}

/// Attach `label` to each element of a serialized list, leaving every field that
/// was already there untouched.
fn with_labels<T: Serialize>(items: &[T], label_of: impl Fn(&T) -> String) -> Value {
    let mut values = serde_json::json!(items);
    if let Some(array) = values.as_array_mut() {
        for (value, item) in array.iter_mut().zip(items) {
            if let Some(object) = value.as_object_mut() {
                object.insert("label".to_string(), Value::String(label_of(item)));
            }
        }
    }
    values
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
        InterceptCommand::Get(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path = session_query_path(&format!("/api/intercepts/{}", args.id), session_id);
            let intercept: InterceptRecord = api.get_json(&path).await?;
            print_json(&intercept)
        }
        InterceptCommand::Wait(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let list_path = session_query_path("/api/intercepts", session_id);
            let Some(summary) = wait_for_first_intercept::<InterceptSummary>(
                &api,
                &list_path,
                args.timeout,
                args.poll_interval,
                |summary| summary.id,
            )
            .await?
            else {
                return Err(anyhow!(
                    "no request was intercepted within {}s",
                    args.timeout
                ));
            };
            let detail_path =
                session_query_path(&format!("/api/intercepts/{}", summary.id), session_id);
            let intercept: InterceptRecord = api.get_json(&detail_path).await?;
            print_json(&intercept)
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
        ResponseInterceptCommand::Wait(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let list_path = session_query_path("/api/response-intercepts", session_id);
            let Some(summary) = wait_for_first_intercept::<ResponseInterceptSummary>(
                &api,
                &list_path,
                args.timeout,
                args.poll_interval,
                |summary| summary.id,
            )
            .await?
            else {
                return Err(anyhow!(
                    "no response was intercepted within {}s",
                    args.timeout
                ));
            };
            let detail_path = session_query_path(
                &format!("/api/response-intercepts/{}", summary.id),
                session_id,
            );
            let item: ResponseInterceptRecord = api.get_json(&detail_path).await?;
            print_json(&item)
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

async fn pinned_read_session_id(api: &ApiClient, explicit: Option<Uuid>) -> Result<Uuid> {
    resolve_session_id_arg(api, explicit).await?.ok_or_else(|| {
        anyhow!("no active session; pass --session-id to choose a session explicitly")
    })
}

fn scanner_rule_schema(patch: bool) -> Value {
    let mut properties = json!({
        "id":{"type":"string","minLength":1,"pattern":"\\S","description":"Stable exact ID; at most 65536 UTF-8 bytes."},
        "name":{"type":"string","minLength":1,"pattern":"\\S"},
        "enabled":{"type":"boolean"},
        "target":{"type":"string","enum":["response_body","response_header","request_header"]},
        "header_name":{"type":"string","description":"Header name for header targets; an empty string keeps the existing all-headers behavior."},
        "pattern":{"type":"string","minLength":1,"pattern":"\\S","description":"Valid Rust regex, applied only to captured body previews or headers."},
        "severity":{"type":"string","enum":["info","low","medium","high","critical"]},
        "category":{"type":"string"},
        "description":{"type":"string"}
    });
    for property in properties.as_object_mut().unwrap().values_mut() {
        if property["type"] == "string" {
            property["maxLength"] = json!(MAX_SCANNER_FIELD_BYTES);
        }
    }
    let mut schema = json!({"type":"object","additionalProperties":false,"properties":properties});
    if patch {
        schema["properties"].as_object_mut().unwrap().remove("id");
        schema["minProperties"] = json!(1);
    } else {
        schema["required"] = json!([
            "id",
            "name",
            "enabled",
            "target",
            "pattern",
            "severity",
            "category",
            "description"
        ]);
    }
    schema
}

fn scanner_input_schema(operation: &str, required: &[&str]) -> Option<Value> {
    if !operation.starts_with("scanner.") {
        return None;
    }
    let mut properties = serde_json::Map::new();
    for field in call_allowed_fields(operation)? {
        let schema = match *field {
            "session_id" => {
                json!({"type":["string","null"],"format":"uuid","description":"Explicit session, including inactive sessions; omission pins the active session once."})
            }
            "id" if operation == "scanner.builtin.set_enabled" => {
                json!({"type":"string","enum":BUILTIN_RULES.iter().map(|(id, _)| *id).collect::<Vec<_>>()})
            }
            "id" => {
                json!({"type":"string","minLength":1,"pattern":"\\S","maxLength":MAX_SCANNER_FIELD_BYTES})
            }
            "enabled" => json!({"type":"boolean"}),
            "rule" => scanner_rule_schema(false),
            "patch" => scanner_rule_schema(true),
            "file" => {
                json!({"type":"string","minLength":1,"description":"Path to a UTF-8 JSON rule or patch file."})
            }
            "stdin" => {
                json!({"type":"boolean","description":"Read rule or patch JSON from stdin; cannot be combined with call --input -."})
            }
            _ => return None,
        };
        properties.insert((*field).into(), schema);
    }
    let mut schema = json!({"type":"object","additionalProperties":false,"required":required,"properties":properties});
    if matches!(operation, "scanner.custom.create" | "scanner.custom.update") {
        let source = if operation.ends_with(".create") {
            "rule"
        } else {
            "patch"
        };
        schema["oneOf"] = json!([
            {"required":[source],"not":{"anyOf":[{"required":["file"]},{"properties":{"stdin":{"const":true}},"required":["stdin"]}]}},
            {"required":["file"],"not":{"anyOf":[{"required":[source]},{"properties":{"stdin":{"const":true}},"required":["stdin"]}]}},
            {"required":["stdin"],"properties":{"stdin":{"const":true}},"not":{"anyOf":[{"required":[source]},{"required":["file"]}]}}
        ]);
    }
    Some(schema)
}

fn scanner_output_schema(operation: &str) -> Option<Value> {
    Some(match operation {
        "scanner.config.get" => json!({
            "type":"object","required":["session_id","config_token","enabled","rules","custom_rules","builtins"],
            "properties":{
                "session_id":{"type":"string","format":"uuid"},
                "config_token":{"type":"string","pattern":"^[0-9a-f]{64}$"},
                "enabled":{"type":"boolean"},
                "rules":{"type":"object","additionalProperties":{"type":"boolean"}},
                "custom_rules":{"type":"array","items":scanner_rule_schema(false)},
                "builtins":{"type":"array","items":{"type":"object","required":["id","name"],"properties":{"id":{"type":"string"},"name":{"type":"string"}}}}
            }
        }),
        "scanner.custom.list" => json!({"type":"array","items":scanner_rule_schema(false)}),
        "scanner.custom.get" => scanner_rule_schema(false),
        "scanner.config.set_enabled"
        | "scanner.builtin.set_enabled"
        | "scanner.custom.create"
        | "scanner.custom.update"
        | "scanner.custom.delete" => {
            let mut schema = json!({
                "type":"object","additionalProperties":false,"required":["session_id","config_token","changed"],
                "properties":{
                    "session_id":{"type":"string","format":"uuid"},
                    "config_token":{"type":"string","pattern":"^[0-9a-f]{64}$"},
                    "changed":{"type":"boolean"},"id":{"type":"string"}
                }
            });
            if operation != "scanner.config.set_enabled" {
                schema["required"].as_array_mut().unwrap().push(json!("id"));
            }
            schema
        }
        _ => return None,
    })
}

fn scanner_input_preview(command: &ScannerCommand) -> Value {
    let mut input = json!({"session_id":command.session_id()});
    match command {
        ScannerCommand::Config {
            command: ScannerConfigCommand::SetEnabled(args),
        } => {
            input["enabled"] = json!(args.enabled);
        }
        ScannerCommand::Builtin {
            command: ScannerBuiltinCommand::SetEnabled(args),
        } => {
            input["id"] = json!(args.id);
            input["enabled"] = json!(args.enabled);
        }
        ScannerCommand::Custom { command } => match command {
            ScannerCustomCommand::Get(args) | ScannerCustomCommand::Delete(args) => {
                input["id"] = json!(args.id)
            }
            ScannerCustomCommand::Create(args) => input["rule"] = json!(args.rule),
            ScannerCustomCommand::Update(args) => {
                input["id"] = json!(args.id);
                input["patch"] = json!(args.patch);
            }
            ScannerCustomCommand::List(_) => (),
        },
        _ => (),
    }
    input
}

fn scanner_api_preview(command: &ScannerCommand) -> Value {
    let read = api_preview(
        "GET",
        session_query_path("/api/scanner-config", command.session_id()),
        None,
    );
    if !command.is_write() {
        return read;
    }
    json!({
        "read":read,
        "write":{
            "method":"POST","path":session_query_path("/api/scanner-config", command.session_id()),
            "body_source":"Fetched enabled/rules/custom_rules with only the requested change; expected_config_token from the pinned GET.",
            "expected_active_session_id":if command.session_id().is_none() { json!("<resolved active session ID>") } else { Value::Null },
            "skip_if_unchanged":true,"automatic_retry":false
        }
    })
}

fn scanner_command_from_input(operation: &str, input: &Value) -> Result<ScannerCommand> {
    // Unlike omission, null is never an instruction to clear a field or source.
    for (field, value) in input.as_object().expect("call input was validated") {
        if field != "session_id" && value.is_null() {
            bail!("field `{field}` for `{operation}` cannot be null");
        }
    }
    let session_id = call_optional(operation, input, "session_id")?;
    Ok(match operation {
        "scanner.config.get" => ScannerCommand::Config {
            command: ScannerConfigCommand::Get(SessionReadArgs { session_id }),
        },
        "scanner.config.set_enabled" => ScannerCommand::Config {
            command: ScannerConfigCommand::SetEnabled(ScannerEnabledArgs {
                session_id,
                enabled: call_required(operation, input, "enabled")?,
            }),
        },
        "scanner.builtin.set_enabled" => ScannerCommand::Builtin {
            command: ScannerBuiltinCommand::SetEnabled(ScannerBuiltinEnabledArgs {
                session_id,
                id: call_required(operation, input, "id")?,
                enabled: call_required(operation, input, "enabled")?,
            }),
        },
        "scanner.custom.list" => ScannerCommand::Custom {
            command: ScannerCustomCommand::List(SessionReadArgs { session_id }),
        },
        "scanner.custom.get" | "scanner.custom.delete" => {
            let args = ScannerRuleIdArgs {
                session_id,
                id: call_required(operation, input, "id")?,
            };
            ScannerCommand::Custom {
                command: if operation.ends_with(".get") {
                    ScannerCustomCommand::Get(args)
                } else {
                    ScannerCustomCommand::Delete(args)
                },
            }
        }
        "scanner.custom.create" | "scanner.custom.update" => {
            let create = operation.ends_with(".create");
            let source = if create { "rule" } else { "patch" };
            let file: Option<PathBuf> = call_optional_path(operation, input, "file")?;
            if file
                .as_ref()
                .is_some_and(|path| path.as_os_str().is_empty())
            {
                bail!("field `file` for `{operation}` must be nonempty");
            }
            let stdin = call_bool(operation, input, "stdin")?;
            validate_call_exactly_one(
                operation,
                "rule_source",
                &[
                    (source, input.get(source).is_some()),
                    ("file", file.is_some()),
                    ("stdin", stdin),
                ],
            )?;
            ScannerCommand::Custom {
                command: if create {
                    ScannerCustomCommand::Create(ScannerCreateArgs {
                        session_id,
                        file,
                        stdin,
                        rule: input.get("rule").map(parse_scanner_rule).transpose()?,
                    })
                } else {
                    ScannerCustomCommand::Update(ScannerUpdateArgs {
                        session_id,
                        id: call_required(operation, input, "id")?,
                        file,
                        stdin,
                        patch: input.get("patch").map(parse_scanner_patch).transpose()?,
                    })
                },
            }
        }
        _ => bail!("unknown operation `{operation}`"),
    })
}

fn validate_scanner_rule_id(id: &str) -> Result<()> {
    if id.trim().is_empty() || id.len() > MAX_SCANNER_FIELD_BYTES {
        bail!("custom scanner rule id must be nonblank and at most {MAX_SCANNER_FIELD_BYTES} UTF-8 bytes");
    }
    Ok(())
}

fn parse_scanner_rule(input: &Value) -> Result<CustomRule> {
    let object = input
        .as_object()
        .ok_or_else(|| anyhow!("custom scanner rule must be a JSON object"))?;
    for (field, value) in object {
        if !matches!(
            field.as_str(),
            "id" | "name"
                | "enabled"
                | "target"
                | "header_name"
                | "pattern"
                | "severity"
                | "category"
                | "description"
        ) {
            bail!("invalid custom scanner rule field `{field}`");
        }
        if value.is_null() {
            bail!("custom scanner rule field `{field}` cannot be null");
        }
    }
    let rule: CustomRule = serde_json::from_value(input.clone())
        .context("failed to parse custom scanner rule JSON")?;
    validate_custom_rule(&rule).map_err(|message| anyhow!("invalid scanner rule: {message}"))?;
    Ok(rule)
}

fn parse_scanner_patch(input: &Value) -> Result<ScannerRulePatch> {
    let object = input
        .as_object()
        .ok_or_else(|| anyhow!("custom scanner rule patch must be a JSON object"))?;
    if object.is_empty() {
        bail!("provide at least one custom scanner rule patch field");
    }
    for (field, value) in object {
        if value.is_null() {
            bail!("custom scanner rule patch field `{field}` cannot be null");
        }
    }
    let patch: ScannerRulePatch = serde_json::from_value(input.clone())
        .context("failed to parse custom scanner rule patch JSON")?;
    // Validate the supplied fields offline without requiring unrelated fields
    // that are intentionally omitted. The merged saved rule is validated again.
    let mut example = CustomRule {
        id: "validation-only".into(),
        name: "Validation".into(),
        enabled: true,
        target: "response_body".into(),
        header_name: String::new(),
        pattern: "example".into(),
        severity: Severity::Info,
        category: String::new(),
        description: String::new(),
    };
    patch.apply(&mut example);
    validate_custom_rule(&example)
        .map_err(|message| anyhow!("invalid scanner rule patch: {message}"))?;
    Ok(patch)
}

fn prepare_scanner_command(command: &mut Command) -> Result<()> {
    let Command::Scanner { command } = command else {
        return Ok(());
    };
    match command {
        ScannerCommand::Builtin {
            command: ScannerBuiltinCommand::SetEnabled(args),
        } => {
            if !BUILTIN_RULES.iter().any(|(id, _)| *id == args.id) {
                bail!("invalid builtin scanner rule id; use scanner config get for known IDs");
            }
        }
        ScannerCommand::Custom { command } => match command {
            ScannerCustomCommand::Get(args) | ScannerCustomCommand::Delete(args) => {
                validate_scanner_rule_id(&args.id)?
            }
            ScannerCustomCommand::Create(args) => {
                if args.rule.is_none() {
                    let raw = read_text_input(args.file.clone(), args.stdin)?;
                    let input: Value = serde_json::from_str(&raw)
                        .context("failed to parse custom scanner rule JSON")?;
                    args.rule = Some(parse_scanner_rule(&input)?);
                }
            }
            ScannerCustomCommand::Update(args) => {
                validate_scanner_rule_id(&args.id)?;
                if args.patch.is_none() {
                    let raw = read_text_input(args.file.clone(), args.stdin)?;
                    let input: Value = serde_json::from_str(&raw)
                        .context("failed to parse custom scanner rule patch JSON")?;
                    args.patch = Some(parse_scanner_patch(&input)?);
                }
            }
            ScannerCustomCommand::List(_) => (),
        },
        _ => (),
    }
    Ok(())
}

fn parse_scanner_snapshot(value: Value, session_id: Uuid) -> Result<ScannerConfigSnapshot> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("scanner config response must be an object"))?;
    for field in [
        "session_id",
        "config_token",
        "enabled",
        "rules",
        "custom_rules",
    ] {
        if !object.contains_key(field) {
            bail!("scanner config response is missing required field `{field}`; refusing to use the snapshot");
        }
    }
    for field in object.keys() {
        if !matches!(
            field.as_str(),
            "session_id" | "config_token" | "enabled" | "rules" | "custom_rules"
        ) {
            bail!("scanner config response contains an unknown field; refusing to discard unsupported settings");
        }
    }
    if let Some(rules) = value["custom_rules"].as_array() {
        for rule in rules {
            parse_scanner_rule(rule)?;
        }
    }
    let snapshot: ScannerConfigSnapshot =
        serde_json::from_value(value).context("failed to parse scanner config snapshot")?;
    checked_scanner_snapshot(&snapshot, session_id)?;
    Ok(snapshot)
}

fn checked_scanner_snapshot(snapshot: &ScannerConfigSnapshot, session_id: Uuid) -> Result<()> {
    if snapshot.session_id != session_id {
        bail!("scanner config returned an unexpected session_id; refusing to use the snapshot");
    }
    if snapshot.config_token.len() != 64
        || !snapshot
            .config_token
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("scanner config must include a valid config_token; refusing to use the snapshot");
    }
    if snapshot.config_token != scanner_config_token(session_id, &snapshot.config) {
        bail!("scanner config returned an unexpected config_token; refusing to use the snapshot");
    }
    validate_scanner_config(&snapshot.config)
        .map_err(|message| anyhow!("invalid stored scanner config: {message}"))?;
    Ok(())
}

async fn handle_scanner(api: ApiClient, command: ScannerCommand) -> Result<()> {
    let explicit_session_id = command.session_id();
    let session_id = pinned_read_session_id(&api, explicit_session_id).await?;
    let read_path = session_query_path("/api/scanner-config", Some(session_id));
    let snapshot = parse_scanner_snapshot(api.get_json(&read_path).await?, session_id)?;
    match &command {
        ScannerCommand::Config {
            command: ScannerConfigCommand::Get(_),
        } => {
            let mut output = serde_json::to_value(&snapshot)?;
            output["builtins"] = json!(BUILTIN_RULES
                .iter()
                .map(|(id, name)| json!({"id":id,"name":name}))
                .collect::<Vec<_>>());
            return print_session_read_json(&output, session_id);
        }
        ScannerCommand::Custom {
            command: ScannerCustomCommand::List(_),
        } => {
            return print_session_read_json(&snapshot.config.custom_rules, session_id);
        }
        ScannerCommand::Custom {
            command: ScannerCustomCommand::Get(args),
        } => {
            let rule = snapshot
                .config
                .custom_rules
                .iter()
                .find(|rule| rule.id == args.id)
                .ok_or_else(|| anyhow!("custom scanner rule id not found in selected session"))?;
            return print_session_read_json(rule, session_id);
        }
        _ => (),
    }
    let mut config = snapshot.config.clone();
    let id = match &command {
        ScannerCommand::Config {
            command: ScannerConfigCommand::SetEnabled(args),
        } => {
            config.enabled = args.enabled;
            None
        }
        ScannerCommand::Builtin {
            command: ScannerBuiltinCommand::SetEnabled(args),
        } => {
            // A missing builtin toggle already means true; retain that omission
            // when this request would not change behavior.
            if config.rules.get(&args.id).copied().unwrap_or(true) != args.enabled {
                config.rules.insert(args.id.clone(), args.enabled);
            }
            Some(args.id.clone())
        }
        ScannerCommand::Custom {
            command: ScannerCustomCommand::Create(args),
        } => {
            let rule = args.rule.as_ref().expect("scanner input prepared");
            if config
                .custom_rules
                .iter()
                .any(|saved| saved.id.trim() == rule.id.trim())
            {
                bail!("invalid custom scanner rule: id already exists; use an exact-ID update");
            }
            config.custom_rules.push(rule.clone());
            Some(rule.id.clone())
        }
        ScannerCommand::Custom {
            command: ScannerCustomCommand::Update(args),
        } => {
            let rule = config
                .custom_rules
                .iter_mut()
                .find(|rule| rule.id == args.id)
                .ok_or_else(|| anyhow!("custom scanner rule id not found in selected session"))?;
            args.patch
                .as_ref()
                .expect("scanner input prepared")
                .apply(rule);
            Some(args.id.clone())
        }
        ScannerCommand::Custom {
            command: ScannerCustomCommand::Delete(args),
        } => {
            let position = config
                .custom_rules
                .iter()
                .position(|rule| rule.id == args.id)
                .ok_or_else(|| anyhow!("custom scanner rule id not found in selected session"))?;
            config.custom_rules.remove(position);
            Some(args.id.clone())
        }
        _ => unreachable!("read commands returned above"),
    };
    validate_scanner_config(&config)
        .map_err(|message| anyhow!("invalid scanner config: {message}"))?;
    let changed = serde_json::to_value(&config)? != serde_json::to_value(&snapshot.config)?;
    let config_token = if changed {
        let path = session_query_path_with_expected_active(
            "/api/scanner-config",
            Some(session_id),
            explicit_session_id.is_none().then_some(session_id),
        );
        let mut body = serde_json::to_value(&config)?;
        body["expected_config_token"] = json!(snapshot.config_token);
        let saved = parse_scanner_snapshot(api.post_json(&path, &body).await?, session_id)?;
        if serde_json::to_value(&saved.config)? != serde_json::to_value(&config)? {
            bail!("scanner config save returned unexpected settings; inspect current configuration before retrying");
        }
        saved.config_token
    } else {
        snapshot.config_token
    };
    let mut output = json!({"session_id":session_id,"config_token":config_token,"changed":changed});
    if let Some(id) = id {
        output["id"] = json!(id);
    }
    print_session_read_json(&output, session_id)
}

async fn handle_findings(api: ApiClient, command: FindingsCommand) -> Result<()> {
    match command {
        FindingsCommand::List(args) => {
            let session_id = pinned_read_session_id(&api, args.session_id).await?;
            let path = session_read_list_path("/api/findings", Some(session_id), args.limit);
            let findings: Vec<FindingSummary> = api.get_json(&path).await?;
            print_session_read_json(&findings, session_id)
        }
        FindingsCommand::Get(args) => {
            let session_id = pinned_read_session_id(&api, args.session_id).await?;
            let path = session_query_path(&format!("/api/findings/{}", args.id), Some(session_id));
            let finding: ScannerFinding = api.get_json(&path).await?;
            print_session_read_json(&finding, session_id)
        }
        FindingsCommand::Count(args) => {
            let session_id = pinned_read_session_id(&api, args.session_id).await?;
            let path = session_query_path("/api/findings/count", Some(session_id));
            let count: FindingsCount = api.get_json(&path).await?;
            print_session_read_json(&count, session_id)
        }
    }
}

async fn handle_event_log(api: ApiClient, command: EventLogCommand) -> Result<()> {
    let EventLogCommand::List(args) = command;
    let session_id = pinned_read_session_id(&api, args.session_id).await?;
    let path = session_read_list_path("/api/event-log", Some(session_id), args.limit);
    let entries: Vec<EventLogEntry> = api.get_json(&path).await?;
    print_session_read_json(&entries, session_id)
}

fn print_session_read_json<T: Serialize>(value: &T, session_id: Uuid) -> Result<()> {
    let context = output_context();
    if !context.success_envelope {
        return print_json(value);
    }
    // Keep API arrays intact while letting a caller reuse the same pinned session
    // for a later detail/count request, even if the active session changes.
    write_json_envelope(
        &json!({
            "ok":true, "operation":context.operation,
            "schema_version":output_schema_version(&context.operation),
            "data":value, "meta":{"session_id":session_id}, "warnings":[],
        }),
        context.format,
    )
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
    label: Option<String>,
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
        label,
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
        custom_label: label
            .as_deref()
            .map(normalize_replay_tab_label)
            .unwrap_or_default(),
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

// Same rule as the UI's tab rename (`normalizeReplayTabCustomLabel`), so a label
// set here looks exactly like one typed into the tab strip and stays within the
// server's 80-character limit instead of failing the whole workspace save.
fn normalize_replay_tab_label(label: &str) -> String {
    label
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(80)
        .collect()
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

fn history_search_path(session_id: Option<Uuid>, args: &HistorySearchArgs) -> String {
    let mut params = vec![("value".to_string(), args.value.clone())];
    let mut push = |key: &str, value: Option<String>| {
        if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
            params.push((key.to_string(), value));
        }
    };
    push("session_id", session_id.map(|id| id.to_string()));
    push("sides", Some(args.side.join(",")));
    push(
        "case_sensitive",
        args.case_sensitive.then(|| "true".to_string()),
    );
    push(
        "max_matches",
        args.max_matches.map(|value| value.to_string()),
    );
    push(
        "byte_budget",
        args.byte_budget.map(|value| value.to_string()),
    );
    push("context", args.context.map(|value| value.to_string()));
    push("q", args.query.clone());
    push("method", args.method.clone());
    push("host", args.host.clone());
    push("status", args.status.map(|value| value.to_string()));
    push("status_range", args.status_range.clone());
    push("since", args.since.clone());
    push("mime", args.mime.clone());
    format!("/api/transactions-search?{}", encode_query(params))
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
    // A new scheme drops the request's port only when that port was the old
    // scheme's default: example.com:443 over http means 80, but localhost:18891
    // means 18891 whatever the scheme. A raw request names no scheme at all, so
    // its guessed https made `--scheme http` throw an explicit Host port away.
    // `replay_update_should_preserve_current_port` applies the same rule.
    let inherited_port = fallback_explicit_port.filter(|port| {
        !scheme_changed_from_fallback
            || *port != default_port_for_scheme(&fallback_scheme).to_string()
    });
    let port = requested_port
        .or(parsed_host_port)
        .or_else(|| (!host_url_without_port).then_some(inherited_port).flatten())
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
    sniper::platform::default_data_dir()
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

#[cfg(windows)]
fn runtime_state_owner_process_is_running(pid: u32) -> bool {
    sniper::platform::running_process_path(pid).is_some()
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

#[cfg(windows)]
fn runtime_state_owner_process_path_matches(pid: u32, expected_process_path: &str) -> bool {
    sniper::platform::running_process_path(pid).is_some_and(|path| {
        process_path_strings_match(expected_process_path, &path.to_string_lossy())
    })
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

fn output_schema_version(operation: &str) -> &'static str {
    if operation.starts_with("saved.v1.") {
        sniper::saved_contract::CONTRACT_VERSION
    } else {
        CLI_SCHEMA_VERSION
    }
}

#[derive(Debug)]
struct SavedCliError {
    code: &'static str,
    message: String,
    outcome: String,
    operation_id: Option<Uuid>,
    session_id: Option<Uuid>,
}

impl fmt::Display for SavedCliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}
impl std::error::Error for SavedCliError {}

fn saved_cli_error(
    code: &'static str,
    message: &str,
    outcome: &str,
    input: &Value,
) -> anyhow::Error {
    anyhow!(SavedCliError {
        code,
        message: message.to_owned(),
        outcome: outcome.to_owned(),
        operation_id: input
            .get("operation_id")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok()),
        session_id: sniper::saved_contract::input_session_id(input),
    })
}

fn saved_uuid_field(value: &Value, field: &str) -> Option<Uuid> {
    value
        .get(field)
        .and_then(Value::as_str)
        .and_then(|text| Uuid::parse_str(text).ok())
}

fn validate_saved_response_binding(operation: &str, input: &Value, data: &Value) -> Result<()> {
    if sniper::saved_data::is_write(operation) {
        if saved_uuid_field(&data["receipt"], "operation_id")
            != saved_uuid_field(input, "operation_id")
            || saved_uuid_field(&data["receipt"], "session_id")
                != saved_uuid_field(input, "session_id")
        {
            bail!("saved mutation response is not bound to the request");
        }
    } else if operation == "saved.v1.operation.get" {
        if saved_uuid_field(data, "operation_id") != saved_uuid_field(input, "operation_id") {
            bail!("saved receipt lookup is not bound to the request");
        }
    } else if matches!(operation, "saved.v1.http.list" | "saved.v1.http.select") {
        let requested = saved_uuid_field(input.get("continuation").unwrap_or(input), "session_id");
        if requested.is_some() && requested != saved_uuid_field(data, "session_id") {
            bail!("saved HTTP response is not bound to the requested session");
        }
    }
    Ok(())
}

async fn run_saved_call(
    api_override: Option<String>,
    args: CallArgs,
    dry_run: bool,
    yes: bool,
) -> Result<()> {
    let input = parse_call_input(args.input).map_err(|_| {
        saved_cli_error(
            "INVALID_INPUT",
            "Could not parse saved-data input JSON",
            "not_applied",
            &Value::Null,
        )
    })?;
    let operation = args.operation;
    if saved_operation_name(&operation).is_none() {
        return Err(saved_cli_error(
            "UNKNOWN_OPERATION",
            "Unknown saved-data operation",
            "not_applied",
            &input,
        ));
    }
    sniper::saved_contract::validate_input(&operation, &input).map_err(|_| {
        saved_cli_error(
            "INVALID_INPUT",
            "Input does not satisfy the saved-data schema",
            "not_applied",
            &input,
        )
    })?;
    let write = sniper::saved_data::is_write(&operation);
    if dry_run {
        return print_json(
            &json!({"contract_version":sniper::saved_contract::CONTRACT_VERSION,
            "dry_run":true,"operation":operation,"input":input,"requires_confirmation":write,
            "outcome":"not_applied","method":"POST","path":"/api/saved/v1/call",
            "notes":["Validates input only. Does not reserve an operation ID or resolve a selection."]}),
        );
    }
    if write && !yes {
        return Err(saved_cli_error(
            "CONFIRMATION_REQUIRED",
            "This saved-data mutation requires --dry-run or --yes",
            "not_applied",
            &input,
        ));
    }
    let api = ApiClient::discover(api_override).await.map_err(|_| {
        saved_cli_error(
            "API_UNAVAILABLE",
            "Could not reach a Sniper API; no saved-data call was sent",
            "not_applied",
            &input,
        )
    })?;
    let uncertain_outcome = if write { "unknown" } else { "not_applied" };
    // A redirect can transparently resend a destructive POST to another runtime.
    // Keep this policy local to the opt-in contract; legacy clients are unchanged.
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(CLI_API_TIMEOUT)
        .build()
        .map_err(|_| {
            saved_cli_error(
                "TRANSPORT_ERROR",
                "Could not prepare the saved-data client; no call was sent",
                "not_applied",
                &input,
            )
        })?;
    // One request only. A timeout can mean that a mutation committed; the caller
    // keeps the supplied operation UUID for a subsequent read-only receipt lookup.
    let response = client
        .post(api.url("/api/saved/v1/call"))
        .json(&json!({"operation":operation,"input":input}))
        .send()
        .await
        .map_err(|_| {
            saved_cli_error(
                "TRANSPORT_ERROR",
                "Saved-data response unavailable; inspect the operation receipt",
                uncertain_outcome,
                &input,
            )
        })?;
    let status = response.status();
    if status.is_redirection() {
        return Err(saved_cli_error(
            "REDIRECT_REFUSED",
            "Saved-data redirects are not followed; inspect the original operation receipt",
            uncertain_outcome,
            &input,
        ));
    }
    let wire: Value = response.json().await.map_err(|_| {
        saved_cli_error(
            "INVALID_RESPONSE",
            "Could not decode the saved-data response; inspect the operation receipt",
            uncertain_outcome,
            &input,
        )
    })?;
    if wire.get("contract_version").and_then(Value::as_str)
        != Some(sniper::saved_contract::CONTRACT_VERSION)
    {
        return Err(saved_cli_error(
            "INVALID_RESPONSE",
            "Server did not identify a saved.v1 response; inspect the operation receipt",
            uncertain_outcome,
            &input,
        ));
    }
    if status.is_success() && wire.get("ok") == Some(&Value::Bool(true)) {
        if let Some(data) = wire.get("data") {
            sniper::saved_contract::validate_output(&operation, data).map_err(|_| saved_cli_error(
                "INVALID_RESPONSE", "Server data does not satisfy the saved.v1 output schema; inspect the operation receipt", uncertain_outcome, &input))?;
            validate_saved_response_binding(&operation, &input, data).map_err(|_| saved_cli_error(
                "INVALID_RESPONSE", "Saved-data response identifies a different request; inspect the original operation receipt", uncertain_outcome, &input))?;
            return print_json(data);
        }
    }
    if let Some(error) = wire.get("error").and_then(|value| {
        serde_json::from_value::<sniper::saved_data::SavedApiError>(value.clone()).ok()
    }) {
        if wire.get("ok") != Some(&Value::Bool(false))
            || error.retryable
            || matches!(
                error.outcome,
                sniper::saved_operations::SavedOperationOutcome::Applied
            )
            || error.operation_id != saved_uuid_field(&input, "operation_id")
            || error.session_id != sniper::saved_contract::input_session_id(&input)
        {
            return Err(saved_cli_error("INVALID_RESPONSE", "Saved-data error does not match this request; inspect the original operation receipt", uncertain_outcome, &input));
        }
        let outcome = match error.outcome {
            sniper::saved_operations::SavedOperationOutcome::Applied => "applied",
            sniper::saved_operations::SavedOperationOutcome::NotApplied => "not_applied",
            sniper::saved_operations::SavedOperationOutcome::Unknown => "unknown",
        };
        return Err(saved_cli_error(
            error.code.as_str(),
            &error.message,
            outcome,
            &input,
        ));
    }
    Err(saved_cli_error("INVALID_RESPONSE", "Server did not return a saved.v1 response; inspect the operation receipt before any further action", uncertain_outcome, &input))
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
    let mut args = args.iter().peekable();
    let mut positional_only = false;
    while let Some(arg) = args.next() {
        if positional_only {
            tokens.push(arg.as_str());
            continue;
        }
        if arg == "--" {
            positional_only = true;
            continue;
        }
        // Call input can precede the operation. Never promote its JSON or file
        // path into error metadata, even when clap rejects a later argument.
        if matches!(arg.as_str(), "--output" | "--api" | "--input") {
            if args
                .peek()
                .is_some_and(|value| !value.starts_with('-') || value.as_str() == "-")
            {
                args.next();
            }
            continue;
        }
        if arg.starts_with('-') {
            continue;
        }
        tokens.push(arg.as_str());
    }

    match tokens.as_slice() {
        ["scanner", group, action, ..] => format!("scanner.{group}.{}", action.replace('-', "_")),
        ["findings", action, ..] => format!("findings.{action}"),
        ["event-log", action, ..] => format!("event_log.{action}"),
        ["session", action, ..] => format!("session.{action}"),
        ["scope" | "target", "get-scope", ..] => "scope.get".to_string(),
        ["scope" | "target", "set-scope", ..] => "scope.set".to_string(),
        ["replay" | "repeater", action, ..] => format!("replay.{action}"),
        ["fuzzer", action, ..] => format!("fuzzer.{}", action.replace('-', "_")),
        ["sequence", action, ..] => format!("sequence.{}", action.replace('-', "_")),
        ["skills", action, ..] => format!("skills.{}", action.replace('-', "_")),
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
        ["capture", "browser", action, ..] => {
            format!("capture.browser.{}", action.replace('-', "_"))
        }
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
        "schema_version": output_schema_version(&context.operation),
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
        "schema_version": output_schema_version(&context.operation),
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
    if let Some(managed) = error.downcast_ref::<sniper::skill_managed::ManagedSkillError>() {
        return CliErrorPayload {
            code: "MANAGED_SKILL_ERROR",
            message: "Local skill operation could not be completed safely.".to_owned(),
            hint: Some("Inspect skills update-preview and the local staging directory before deliberately trying again. No activation is performed."),
            retryable: false,
            details: json!({"reason":managed.code}),
            exit_code: 5,
        };
    }
    if let Some(tab) = error.downcast_ref::<ReplayTabCliError>() {
        return CliErrorPayload {
            code: tab.code,
            message: tab.message.to_owned(),
            hint: Some("Inspect the selected session's saved tabs before deliberately issuing another operation; never automatically retry."),
            retryable: false,
            details: json!({"session_id":tab.session_id,"outcome":tab.outcome}),
            exit_code: if tab.code == "INVALID_INPUT" { 2 } else { 5 },
        };
    }
    if let Some(saved) = error.downcast_ref::<SavedCliError>() {
        return CliErrorPayload {
            code: saved.code,
            message: saved.message.clone(),
            hint: Some("Use saved.v1.operation.get with the original operation_id to inspect a receipt; never automatically retry a mutation."),
            retryable: false,
            details: json!({"outcome":saved.outcome,"operation_id":saved.operation_id,"session_id":saved.session_id}),
            exit_code: if matches!(saved.code, "INVALID_INPUT" | "UNKNOWN_OPERATION" | "CONFIRMATION_REQUIRED") { 2 } else { 5 },
        };
    }
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

fn validate_skill_cli_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() || path.to_string_lossy().contains('\0') {
        bail!("skill directory must be nonempty and contain no NUL characters");
    }
    Ok(())
}

fn single_skill_target(args: SingleSkillArgs) -> Result<(&'static str, PathBuf, &'static str)> {
    let (agent, root, default_root, bundled) = if args.codex {
        (
            "codex",
            args.codex_dir,
            skills::default_codex_skills_dir as fn() -> Option<PathBuf>,
            skills::CODEX_SKILL_TEMPLATE,
        )
    } else {
        (
            "claude",
            args.claude_dir,
            skills::default_claude_skills_dir as fn() -> Option<PathBuf>,
            skills::CLAUDE_SKILL_TEMPLATE,
        )
    };
    let root = root.or_else(default_root).with_context(|| {
        format!("could not determine {agent} skills directory; set HOME or pass --{agent}-dir")
    })?;
    Ok((agent, root, bundled))
}

fn skills_update_preview(args: SkillsInstallArgs) -> Result<Value> {
    let mut entries = Vec::new();
    for (selected, agent, root, default_root, bundled) in [
        (
            args.all || args.codex,
            "codex",
            args.codex_dir,
            skills::default_codex_skills_dir as fn() -> Option<PathBuf>,
            skills::CODEX_SKILL_TEMPLATE,
        ),
        (
            args.all || args.claude,
            "claude",
            args.claude_dir,
            skills::default_claude_skills_dir as fn() -> Option<PathBuf>,
            skills::CLAUDE_SKILL_TEMPLATE,
        ),
    ] {
        if selected {
            let root = root.or_else(default_root).with_context(|| {
                format!(
                    "could not determine {agent} skills directory; set HOME or pass --{agent}-dir"
                )
            })?;
            entries.push(sniper::skill_managed::preview_skill_update(
                agent,
                &root,
                bundled,
                env!("CARGO_PKG_VERSION"),
            )?);
        }
    }
    Ok(json!({"scope":"cli_host","bundled_version":env!("CARGO_PKG_VERSION"),"entries":entries}))
}

fn skills_status(args: SkillsInstallArgs) -> Result<Value> {
    let mut entries = Vec::new();
    for (selected, agent, root, default_root, bundled) in [
        (
            args.all || args.codex,
            "codex",
            args.codex_dir,
            skills::default_codex_skills_dir as fn() -> Option<PathBuf>,
            skills::CODEX_SKILL_TEMPLATE,
        ),
        (
            args.all || args.claude,
            "claude",
            args.claude_dir,
            skills::default_claude_skills_dir as fn() -> Option<PathBuf>,
            skills::CLAUDE_SKILL_TEMPLATE,
        ),
    ] {
        if selected {
            let root = root.or_else(default_root).with_context(|| {
                format!(
                    "could not determine {agent} skills directory; set HOME or pass --{agent}-dir"
                )
            })?;
            entries.push(sniper::skill_status::read_skill_status(
                agent, &root, bundled,
            )?);
        }
    }
    Ok(json!({"scope":"cli_host","bundled_version":env!("CARGO_PKG_VERSION"),"entries":entries}))
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
    use super::validate_saved_response_binding;
    use super::{
        active_session_id_from_summaries, api_failure_detail, api_url, attach_session_id,
        attach_workspace_save_error, auto_replace_write_session_id, browser_choices,
        browser_open_body, build_annotations_payload, build_editable_raw_request,
        build_editable_raw_request_with_version, build_oast_configure_update, clap_error_payload,
        cli_data_dir, cli_error_payload, cli_output_format_from_raw_args,
        cli_parse_error_operation, cli_partial_apply_error, command_from_call_args,
        command_from_operation_input, command_input_preview, default_cli_data_dir,
        default_editable_request, discover_api_base_url, discover_api_base_url_from_data_dir,
        dry_run_command, ensure_http_replay_tab, explicit_or_active_session_id,
        failed_record_output, fuzzer_active_target_for_request,
        fuzzer_target_request_authority_for_request, history_list_path, history_search_path,
        install_skills, json_value_with_session_and_workspace_save_error, manifest_operations,
        next_replay_tab_sequence, normalize_api_base_url, normalize_replay_port,
        normalize_target_inputs, oast_fields_for_output, operation_spec,
        parse_editable_raw_request, parse_editable_raw_request_bytes_with_version,
        parse_editable_raw_request_with_version, parse_editable_raw_response,
        parse_editable_raw_response_bytes, parse_editable_raw_response_for_request_method,
        parse_proxy_chain_input, prepare_cli_workspace_save, proxy_chain_output,
        push_replay_history_entry, read_limited_to_end, read_payloads_input,
        read_raw_request_input, read_raw_response_input, read_text_input, replay_send_http_version,
        replay_send_target_for_tab, replay_tab_target_as_request,
        replay_update_should_preserve_current_port, sequence_write_session_id,
        session_id_for_write_payload, session_query_path, session_query_path_with_expected_active,
        sniper_settings_probe_matches, split_host_port, split_payload_lines, strip_host_port,
        transaction_detail_path, validate_command_preflight, websocket_detail_path,
        websocket_list_path, workspace_conflict_message, workspace_state_conflict_detail,
        BrowserCommand, CaptureCommand, Cli, CliSideEffect, Command, FuzzerCommand, HistoryCommand,
        HistoryListArgs, HistoryListResponse, HistorySearchArgs, InterceptRuleCommand, OastCommand,
        OastConfigureArgs, OutputFormat, ReplayCommand, RuntimeUpdatePayload, SequenceCommand,
        SequenceCreateInput, SessionCommand, SkillsInstallArgs, TargetCommand, WebSocketListArgs,
        WebSocketListResponse, CLI_REPEATER_HISTORY_LIMIT, CLI_WORKSPACE_CLIENT_ID,
        MAX_CLI_INPUT_BYTES, MAX_OAST_POLLING_INTERVAL_SECS, SNIPER_API_PROBE_RETRY_DELAYS,
        SNIPER_DATA_DIR_ENV,
    };
    #[cfg(unix)]
    use super::{
        data_dir_strings_match, process_path_strings_match, validate_sniper_settings_probe,
        SniperApiProbeExpectation,
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

        // A port that is not the old scheme's default is kept: it names the
        // service, not the protocol. This is a raw request's `Host:` line.
        let fallback_with_service_port = EditableRequest {
            host: "localhost:18891".to_string(),
            ..fallback.clone()
        };
        let target = normalize_target_inputs(
            Some("http".to_string()),
            None,
            None,
            Some(&fallback_with_service_port),
        )
        .unwrap();
        assert_eq!(target.scheme, "http");
        assert_eq!(target.host, "localhost");
        assert_eq!(target.port, "18891");

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
    fn findings_and_event_log_read_commands_match_the_manifest() {
        let session = "11111111-1111-1111-1111-111111111111";
        let id = "22222222-2222-2222-2222-222222222222";
        for (operation, args, input, endpoint) in [
            (
                "findings.list",
                vec!["findings", "list", "--session-id", session, "--limit", "3"],
                json!({"session_id":session,"limit":3}),
                format!("/api/findings?limit=3&session_id={session}"),
            ),
            (
                "findings.get",
                vec!["findings", "get", "--session-id", session, "--id", id],
                json!({"session_id":session,"id":id}),
                format!("/api/findings/{id}?session_id={session}"),
            ),
            (
                "findings.count",
                vec!["findings", "count", "--session-id", session],
                json!({"session_id":session}),
                format!("/api/findings/count?session_id={session}"),
            ),
            (
                "event_log.list",
                vec!["event-log", "list", "--session-id", session, "--limit", "3"],
                json!({"session_id":session,"limit":3}),
                format!("/api/event-log?limit=3&session_id={session}"),
            ),
        ] {
            let mut argv = vec!["sniper-cli"];
            argv.extend(args);
            let direct = Cli::try_parse_from(argv).unwrap().command;
            let call = command_from_operation_input(operation, &input).unwrap();
            assert_eq!(direct.operation_name(), operation);
            assert_eq!(call.operation_name(), operation);
            assert!(!direct.requires_confirmation());
            assert_eq!(command_input_preview(&direct), command_input_preview(&call));
            let plan = dry_run_command(&direct).unwrap();
            assert_eq!(plan["side_effect"], "read");
            assert_eq!(plan["api"]["method"], "GET");
            assert_eq!(plan["api"]["path"], endpoint);
            assert!(plan["api"]["body"].is_null());
            let spec = operation_spec(operation).unwrap();
            assert_eq!(spec.input_schema["additionalProperties"], false);
            assert_eq!(
                spec.input_schema["properties"]["session_id"]["format"],
                "uuid"
            );
        }
    }

    #[test]
    fn findings_and_event_log_reject_invalid_or_unsupported_input() {
        for operation in [
            "findings.list",
            "findings.get",
            "findings.count",
            "event_log.list",
        ] {
            for input in [
                json!({"session_id":"invalid"}),
                json!({"url":"http://example.com"}),
                Value::Null,
            ] {
                let error = command_from_operation_input(operation, &input).unwrap_err();
                assert_eq!(
                    cli_error_payload(operation, &error).code,
                    "INVALID_INPUT",
                    "{operation}: {error}"
                );
            }
        }
        for operation in ["findings.list", "event_log.list"] {
            for input in [
                json!({"limit":0}),
                json!({"limit":-1}),
                json!({"limit":1.5}),
                json!({"limit":"3"}),
                json!({"offset":1}),
                json!({"page":true}),
            ] {
                let error = command_from_operation_input(operation, &input).unwrap_err();
                assert_eq!(cli_error_payload(operation, &error).code, "INVALID_INPUT");
            }
        }
        for input in [json!({}), json!({"id":"invalid"}), json!({"id":1})] {
            assert!(command_from_operation_input("findings.get", &input).is_err());
        }
        for group in ["findings", "event-log"] {
            assert!(Cli::try_parse_from(["sniper-cli", group, "list", "--limit", "0"]).is_err());
            assert!(Cli::try_parse_from(["sniper-cli", group, "clear"]).is_err());
        }
        for operation in ["findings.clear", "event_log.clear"] {
            assert!(operation_spec(operation).is_none());
            assert!(command_from_operation_input(operation, &json!({})).is_err());
        }
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

        // The flag's value is dropped and the value itself stays, so without an arm
        // of its own the envelope named this "capture".
        let browser_args: Vec<String> = ["capture", "browser", "open", "--browser", "firefox"]
            .map(str::to_string)
            .to_vec();
        assert_eq!(
            cli_parse_error_operation(&browser_args),
            "capture.browser.open"
        );
    }

    #[test]
    fn parse_error_operation_does_not_confuse_call_input_with_operation() {
        for (args, expected) in [
            (
                vec![
                    "call",
                    "--input",
                    r#"{"private":"saved metadata"}"#,
                    "findings.list",
                    "--unknown",
                ],
                "findings.list",
            ),
            (
                vec![
                    "call",
                    "--input",
                    "@local.json",
                    "saved.v1.http.list",
                    "--unknown",
                ],
                "saved.v1.http.list",
            ),
            (
                vec!["call", "--input=-", "findings.list", "--unknown"],
                "findings.list",
            ),
            (vec!["call", "findings.list", "--input"], "findings.list"),
            (vec!["call", "--input"], "call"),
            (
                vec!["call", "--input", "-", "findings.list", "--unknown"],
                "findings.list",
            ),
            (
                vec!["call", "--input", "--output", "compact", "findings.list"],
                "findings.list",
            ),
            (
                vec!["--api", "--output", "compact", "call", "findings.list"],
                "findings.list",
            ),
            (vec!["call", "--", "--api", "--unknown"], "--api"),
        ] {
            let raw_args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
            assert_eq!(cli_parse_error_operation(&raw_args), expected);
        }
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
            ("capture.browser.open", json!({"browser": "firefox"})),
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

    // The search value goes to the server verbatim — untrimmed, since leading
    // whitespace can be part of what was sent — and --side accepts both repeats
    // and commas, the two ways an agent is likely to spell a list.
    #[test]
    fn history_search_builds_its_query_from_every_flag() {
        let parsed = Cli::try_parse_from([
            "sniper-cli",
            "capture",
            "http",
            "search",
            "--value",
            " order_id&x",
            "--side",
            "request-body,headers",
            "--side",
            "url",
            "--case-sensitive",
            "--host",
            "shop.example",
        ])
        .unwrap();
        let Command::Capture {
            command:
                CaptureCommand::Http {
                    command: HistoryCommand::Search(args),
                },
        } = parsed.command
        else {
            panic!("expected capture http search");
        };
        assert_eq!(args.side, vec!["request-body", "headers", "url"]);
        assert_eq!(
            history_search_path(None, &args),
            "/api/transactions-search?value=+order_id%26x&sides=request-body%2Cheaders%2Curl&case_sensitive=true&host=shop.example"
        );

        let minimal = HistorySearchArgs {
            value: "token".to_string(),
            ..HistorySearchArgs::default()
        };
        assert_eq!(
            history_search_path(None, &minimal),
            "/api/transactions-search?value=token",
            "no --side means the server default: search everything"
        );
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "capture",
            "http",
            "search",
            "--value",
            "x",
            "--side",
            "body",
        ])
        .is_err());
    }

    // Opening a browser starts a process, so the manifest must call it a write and
    // an agent must pass --yes. The same body is what --dry-run shows and what the
    // server receives.
    #[test]
    fn capture_browser_open_is_a_confirmed_write_with_one_request_body() {
        let parsed = Cli::try_parse_from([
            "sniper-cli",
            "capture",
            "browser",
            "open",
            "--browser",
            "ego",
            "--url",
            "https://example.com",
            "--fresh",
        ])
        .unwrap();
        let Command::Capture {
            command:
                CaptureCommand::Browser {
                    command: BrowserCommand::Open(args),
                },
        } = parsed.command
        else {
            panic!("expected capture browser open");
        };
        assert_eq!(
            browser_open_body(&args),
            json!({"browser":"ego","url":"https://example.com","fresh":true,"agent":false})
        );
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "capture",
            "browser",
            "open",
            "--browser",
            "firefox",
        ])
        .is_err());

        let open = operation_spec("capture.browser.open").unwrap();
        assert_eq!(open.side_effect, CliSideEffect::Write);
        assert!(open.requires_confirmation);
        let list = operation_spec("capture.browser.list").unwrap();
        assert_eq!(list.side_effect, CliSideEffect::Read);
        assert!(!list.requires_confirmation);

        let mapped = command_from_operation_input(
            "capture.browser.open",
            &json!({"browser":"chrome","agent":true}),
        )
        .unwrap();
        let Command::Capture {
            command:
                CaptureCommand::Browser {
                    command: BrowserCommand::Open(mapped),
                },
        } = mapped
        else {
            panic!("expected the call mapper to build capture browser open");
        };
        assert_eq!(mapped.browser.as_deref(), Some("chrome"));
        assert!(mapped.agent && !mapped.fresh);
        assert!(
            command_from_operation_input("capture.browser.open", &json!({"debug_port": true}),)
                .is_err()
        );
    }

    // Saving a default changes stored settings, so an agent has to confirm it, and the
    // call path must refuse a missing or unknown name rather than clear the default.
    #[test]
    fn capture_browser_prefer_is_a_confirmed_write_that_needs_a_valid_name() {
        let prefer = operation_spec("capture.browser.prefer").unwrap();
        assert_eq!(prefer.side_effect, CliSideEffect::Write);
        assert!(prefer.requires_confirmation);

        for bad in [
            json!({}),
            json!({"browser": "netscape"}),
            json!({"browser": 7}),
        ] {
            let error = command_from_operation_input("capture.browser.prefer", &bad)
                .expect_err("call must not accept this");
            let payload = cli_error_payload("capture.browser.prefer", &error);
            assert_eq!(payload.code, "INVALID_INPUT", "{bad}: {error}");
        }
        assert!(Cli::try_parse_from(["sniper-cli", "capture", "browser", "prefer"]).is_err());
    }

    // The accepted names come from BrowserKind, so a browser added there must be
    // accepted by the flag and by `call` without anyone editing a list here.
    #[test]
    fn every_known_browser_is_accepted_by_the_flag_and_by_call() {
        for name in browser_choices() {
            Cli::try_parse_from([
                "sniper-cli",
                "capture",
                "browser",
                "prefer",
                "--browser",
                name,
            ])
            .unwrap_or_else(|error| panic!("prefer --browser {name}: {error}"));
            command_from_operation_input("capture.browser.prefer", &json!({"browser": name}))
                .unwrap_or_else(|error| panic!("call prefer {name}: {error}"));
            Cli::try_parse_from([
                "sniper-cli",
                "capture",
                "browser",
                "open",
                "--browser",
                name,
            ])
            .unwrap_or_else(|error| panic!("--browser {name}: {error}"));
            command_from_operation_input("capture.browser.open", &json!({"browser": name}))
                .unwrap_or_else(|error| panic!("call browser {name}: {error}"));
        }
        assert!(browser_choices().contains(&"auto") && browser_choices().contains(&"ego"));
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

    #[test]
    fn cli_data_dir_uses_windows_profile_without_home() {
        let _guard = ENV_LOCK.lock().unwrap();
        let root = std::env::temp_dir().join(format!("sniper-profile-{}", Uuid::new_v4()));
        let _data_dir = EnvVarGuard::remove(SNIPER_DATA_DIR_ENV);
        let _home = EnvVarGuard::remove("HOME");
        let _profile = EnvVarGuard::set("USERPROFILE", root.clone().into_os_string());
        assert_eq!(cli_data_dir(), root.join(".sniper"));
        assert_eq!(cli_data_dir(), sniper::certificate::default_data_dir());
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
    #[test]
    fn data_management_manifest_call_schema_and_confirmation_match() {
        for (operation, input) in [
            (
                "session.rename",
                serde_json::json!({"id":Uuid::nil(),"name":"Archive"}),
            ),
            (
                "capture.http.clear",
                serde_json::json!({"session_id":Uuid::nil()}),
            ),
            (
                "capture.http.delete",
                serde_json::json!({"session_id":Uuid::nil(),"ids":[Uuid::new_v4()]}),
            ),
            (
                "capture.http.select",
                serde_json::json!({"session_id":Uuid::nil(),"host":"example.com"}),
            ),
        ] {
            let command = super::command_from_operation_input(operation, &input).unwrap();
            super::validate_command_preflight(&command).unwrap();
            assert_eq!(command.operation_name(), operation);
            assert_eq!(
                command.requires_confirmation(),
                operation != "capture.http.select"
            );
            let plan = super::dry_run_command(&command).unwrap();
            assert_eq!(plan["operation"], operation);
            let spec = super::operation_spec(operation).unwrap();
            assert_eq!(spec.input_schema["additionalProperties"], false);
            assert_eq!(
                spec.input_schema["properties"][if operation == "session.rename" {
                    "id"
                } else {
                    "session_id"
                }]["format"],
                "uuid"
            );
        }
    }

    #[test]
    fn data_management_rejects_ambiguous_or_malformed_call_inputs() {
        for (operation, input) in [
            (
                "capture.http.clear",
                serde_json::json!({"host":"example.com"}),
            ),
            (
                "capture.http.delete",
                serde_json::json!({"ids":[Uuid::nil()]}),
            ),
            (
                "capture.http.delete",
                serde_json::json!({"session_id":Uuid::nil()}),
            ),
            (
                "capture.http.delete",
                serde_json::json!({"session_id":Uuid::nil(),"ids":[]}),
            ),
            (
                "capture.http.delete",
                serde_json::json!({"session_id":Uuid::nil(),"ids":[Uuid::nil()],"host":"example.com"}),
            ),
            (
                "capture.http.delete",
                serde_json::json!({"session_id":Uuid::nil(),"host":"example.com"}),
            ),
            (
                "capture.http.select",
                serde_json::json!({"session_id":Uuid::nil(),"since":"bad"}),
            ),
            (
                "capture.http.select",
                serde_json::json!({"session_id":Uuid::nil(),"status_range":"oops"}),
            ),
            (
                "capture.http.select",
                serde_json::json!({"session_id":Uuid::nil(),"hots":"example.com"}),
            ),
        ] {
            assert!(
                super::command_from_operation_input(operation, &input).is_err(),
                "{operation} accepted {input}"
            );
        }
    }

    #[test]
    fn data_management_legacy_parsing_and_preflight_match_calls() {
        let sid = Uuid::nil().to_string();
        let id = Uuid::new_v4().to_string();
        for argv in [
            vec![
                "sniper-cli",
                "capture",
                "http",
                "clear",
                "--session-id",
                &sid,
                "--dry-run",
            ],
            vec![
                "sniper-cli",
                "capture",
                "http",
                "delete",
                "--session-id",
                &sid,
                "--id",
                &id,
                "--dry-run",
            ],
            vec![
                "sniper-cli",
                "capture",
                "http",
                "select",
                "--session-id",
                &sid,
                "--host",
                "example.com",
            ],
            vec![
                "sniper-cli",
                "session",
                "rename",
                "--id",
                &sid,
                "--name",
                "Archive",
                "--dry-run",
            ],
        ] {
            let parsed = Cli::try_parse_from(argv).unwrap();
            super::validate_command_preflight(&parsed.command).unwrap();
            super::dry_run_command(&parsed.command).unwrap();
        }
        let parsed = Cli::try_parse_from([
            "sniper-cli",
            "capture",
            "http",
            "delete",
            "--session-id",
            &sid,
            "--host",
            " ",
            "--dry-run",
        ])
        .unwrap();
        assert!(super::validate_command_preflight(&parsed.command).is_err());
        let parsed = Cli::try_parse_from([
            "sniper-cli",
            "session",
            "rename",
            "--id",
            &sid,
            "--name",
            " ",
            "--dry-run",
        ])
        .unwrap();
        assert!(super::validate_command_preflight(&parsed.command).is_err());
    }
    #[test]
    fn saved_response_binding_rejects_valid_shapes_for_other_requests() {
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let input = json!({"session_id":first,"operation_id":first});
        let matched = json!({"receipt":{"session_id":first,"operation_id":first}});
        let wrong = json!({"receipt":{"session_id":first,"operation_id":second}});
        assert!(validate_saved_response_binding("saved.v1.http.clear", &input, &matched).is_ok());
        assert!(validate_saved_response_binding("saved.v1.http.clear", &input, &wrong).is_err());
        assert!(validate_saved_response_binding(
            "saved.v1.operation.get",
            &input,
            &json!({"operation_id":second})
        )
        .is_err());
        assert!(validate_saved_response_binding(
            "saved.v1.http.list",
            &json!({"continuation":{"session_id":first}}),
            &json!({"session_id":second})
        )
        .is_err());
        assert!(validate_saved_response_binding(
            "saved.v1.http.select",
            &input,
            &json!({"session_id":second})
        )
        .is_err());
        assert!(validate_saved_response_binding(
            "saved.v1.http.list",
            &json!({}),
            &json!({"session_id":second})
        )
        .is_ok());
    }

    #[test]
    fn proxy_chain_json_carries_bypass_hosts_beside_the_proxy() {
        let (proxy, bypass_hosts) = parse_proxy_chain_input(
            r#"{"enabled":true,"url":"http://127.0.0.1:8081","username":"","password":"","bypass_hosts":["localhost"]}"#,
        )
        .unwrap();
        assert!(proxy.enabled);
        assert_eq!(bypass_hosts, Some(vec!["localhost".to_string()]));
        let (_, bypass_hosts) = parse_proxy_chain_input(r#"{"enabled":false}"#).unwrap();
        assert_eq!(
            bypass_hosts, None,
            "leaving the list out keeps the saved one"
        );
        assert!(parse_proxy_chain_input(r#"{"enabled":true,"bypass_hosts":"localhost"}"#).is_err());
        assert!(parse_proxy_chain_input(r#"{"enabled":true,"surprise":1}"#).is_err());

        let output = proxy_chain_output(&json!({
            "upstream_proxy": {"enabled": true, "url": "http://127.0.0.1:8081", "username": "", "password": ""},
            "upstream_bypass_hosts": ["localhost"],
        }));
        assert_eq!(output["url"], "http://127.0.0.1:8081");
        assert_eq!(output["bypass_hosts"], json!(["localhost"]));
        let older_server = proxy_chain_output(&json!({"upstream_proxy": {"enabled": false}}));
        assert_eq!(older_server["bypass_hosts"], json!([]));
    }
}
