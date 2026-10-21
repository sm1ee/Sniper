use std::{
    env,
    ffi::OsStr,
    fmt, fs,
    io::{self, Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{ArgAction, ArgGroup, Args, CommandFactory, Parser, Subcommand, ValueEnum};
use reqwest::{Method, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sniper::{
    event_log::EventLogEntry,
    fuzzer::FuzzerAttackRecord,
    history_retention::{history_retention_config_token, HistoryRetentionPolicy},
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
    recon::{ReconEndpoint, ReconJob, StartRecon},
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
    service_map::{ServiceMap, ServiceMapEvidence, ServiceMapSocketPeerStatus},
    service_map_body::ServiceMapBodyReferences,
    service_map_html::ServiceMapHtmlGenerators,
    service_map_links::ServiceMapLinkDeclarations,
    service_map_peer_matches::ServiceMapSocketPeerMatches,
    service_map_technology::CatalogVersion,
    session::{validate_session_creation_name, SessionSummary},
    skills,
    workspace::{
        FuzzerWorkspaceState, ReplayHistoryEntryState, ReplayTabState, ReplayWorkspaceState,
        WorkspaceStateSnapshot,
    },
};
use url::Url;
use uuid::Uuid;

const SERVICE_MAP_CATALOG_HEADER: &str = "X-Sniper-Technology-Catalog-Version";
const SERVICE_MAP_ERROR_HEADER: &str = "x-sniper-service-map-error";
const SERVICE_MAP_LEGACY_CATALOG_WARNING: &str = "Warning: Service Map API returned legacy technology catalog v1; technology coverage is limited to v1.";
const SERVICE_MAP_PEER_SCOPE_WORK_WARNING: &str = "Warning: Recorded socket peer scope matching exceeded the work limit; use a smaller --max-records window or deliberately simplify scope rules. No retries or settings changes were made.";

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

const SAVED_READ_QUICK_START: &str = r#"Saved-data quick start (read-only):
  sniper-cli schema input saved.v1.session.list
  sniper-cli examples saved.v1.session.list
  sniper-cli call saved.v1.session.list --input '{"limit":20}'

Schema and examples are offline. The call reads a bounded page from a running local API;
it does not switch the active session. Use --api to select another known instance.
Saved-data operations are available through call; use manifest to discover them."#;

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
#[command(name = "sniper-cli", version = env!("CARGO_PKG_VERSION"), about = "Operate a local Sniper proxy through its JSON API.", after_help = SAVED_READ_QUICK_START)]
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
    /// List operation names and their contracts without contacting an API.
    Manifest,
    /// Show one operation's input or output JSON Schema offline.
    Schema {
        #[arg(value_enum)]
        kind: SchemaKind,
        operation: String,
    },
    /// Example inputs for one operation, or for every operation when none is named.
    Examples { operation: Option<String> },
    /// Invoke an operation by canonical manifest name.
    #[command(after_help = SAVED_READ_QUICK_START)]
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
    /// Discover endpoints with explicit scope and provider consent; list retained evidence.
    Recon {
        #[command(subcommand)]
        command: ReconCommand,
    },
    /// Manage session-scoped passive regex rules for captured response previews and headers.
    Scanner {
        #[command(subcommand)]
        command: ScannerCommand,
    },
    /// Manage the Nuclei template library and the passive templates that judge
    /// in-scope captured traffic.
    Templates {
        #[command(subcommand)]
        command: TemplatesCommand,
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
enum ReconCommand {
    /// Read this session's complete retained Recon inventory and job statuses.
    List(ReconSessionArgs),
    /// Start asynchronous network discovery; requires --dry-run or --yes.
    Start(ReconStartArgs),
    /// Cancel local work for this exact job; an accepted urlscan scan cannot be recalled.
    Stop(ReconStopArgs),
}

#[derive(Args, Debug)]
struct ReconSessionArgs {
    #[arg(long)]
    session_id: Uuid,
}

#[derive(Args, Debug)]
struct ReconStopArgs {
    #[arg(long)]
    session_id: Uuid,
    #[arg(long)]
    id: Uuid,
}

#[derive(Args, Debug)]
struct ReconStartArgs {
    #[arg(long)]
    session_id: Uuid,
    #[arg(long)]
    target_url: String,
    #[arg(long)]
    include_subdomains: bool,
    /// Repeat to select sources. No provider is enabled implicitly.
    #[arg(long = "source", required = true, value_parser = ["crawler", "urlscan", "wayback", "urlscan_submit"])]
    sources: Vec<String>,
    /// Per-job collection budget; 0 means unbounded, not disabled.
    #[arg(long, default_value_t = 0)]
    max_requests: usize,
    /// Crawl depth budget; 0 means unbounded, not seed-only.
    #[arg(long, default_value_t = 0)]
    max_depth: usize,
    /// New endpoint budget; 0 means unbounded.
    #[arg(long, default_value_t = 0)]
    max_endpoints: usize,
    /// Page budget per history provider; 0 means unbounded.
    #[arg(long, default_value_t = 0)]
    max_pages: usize,
    /// Acknowledge sharing the target hostname with selected history providers.
    #[arg(long)]
    history_acknowledged: bool,
    /// Separately acknowledge submitting the full target URL for a new urlscan scan.
    #[arg(long)]
    scan_acknowledged: bool,
    /// Required for urlscan_submit; unlisted is not private.
    #[arg(long, value_parser = ["private", "unlisted", "public"])]
    scan_visibility: Option<String>,
}

impl ReconStartArgs {
    fn request(&self) -> StartRecon {
        StartRecon {
            session_id: self.session_id,
            target_url: self.target_url.clone(),
            include_subdomains: self.include_subdomains,
            sources: self.sources.clone(),
            max_requests: self.max_requests,
            max_depth: self.max_depth,
            max_endpoints: self.max_endpoints,
            max_pages: self.max_pages,
            history_acknowledged: self.history_acknowledged,
            scan_acknowledged: self.scan_acknowledged,
            scan_visibility: self.scan_visibility.clone(),
        }
    }
}

impl ReconCommand {
    fn operation_name(&self) -> &'static str {
        match self {
            Self::List(_) => "recon.list",
            Self::Start(_) => "recon.start",
            Self::Stop(_) => "recon.stop",
        }
    }

    fn session_id(&self) -> Uuid {
        match self {
            Self::List(args) => args.session_id,
            Self::Start(args) => args.session_id,
            Self::Stop(args) => args.session_id,
        }
    }
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
enum TemplatesCommand {
    /// The installed template release: check for, download or import one.
    Library {
        #[command(subcommand)]
        command: TemplatesLibraryCommand,
    },
    /// List templates in the installed release.
    List(TemplatesListArgs),
    /// One template's metadata, why Sniper can or cannot run it, and its YAML.
    Get(TemplatesGetArgs),
    /// Turn passive templates on or off.
    Passive {
        #[command(subcommand)]
        command: TemplatesPassiveCommand,
    },
    /// Send templates to targets you name, when you ask: Template Scan.
    Scan {
        #[command(subcommand)]
        command: TemplatesScanCommand,
    },
}

#[derive(Subcommand, Debug)]
enum TemplatesScanCommand {
    /// Count the templates and requests a scan would send; sends nothing.
    Preview(TemplatesScanArgs),
    /// Send each selected template's requests to each target.
    Start(TemplatesScanArgs),
    /// The session's scans, newest first, without their results.
    List(TemplatesScanSessionArgs),
    /// One scan with its results and its latest requests.
    Get(TemplatesScanIdArgs),
    /// Stop the running scan.
    Stop(TemplatesScanIdArgs),
}

#[derive(Args, Debug, Clone)]
struct TemplatesScanArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    /// An http(s) origin, optionally with a path; repeat for up to 20. Its
    /// host must be in Scope.
    #[arg(long = "target", required = true)]
    targets: Vec<String>,
    /// A template id; repeat for several. Not with a filter.
    #[arg(long = "id")]
    ids: Vec<String>,
    #[command(flatten)]
    filter: TemplatesFilterArgs,
    /// A risk to allow by name: intrusive, default-login, bruteforce,
    /// token-spray, credential-stuffing, fuzz, fuzzing, dast, osint,
    /// method:put, method:delete or method:patch. Repeat for several;
    /// templates with any other risk are left out, and dos never runs.
    #[arg(long = "allow-risk")]
    allow_risks: Vec<String>,
    /// Requests a second across the scan.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..=50))]
    rate: u64,
    /// Templates in flight at once.
    #[arg(long, default_value_t = 4, value_parser = clap::value_parser!(u64).range(1..=8))]
    concurrency: u64,
    /// The most requests the scan sends, redirects included.
    #[arg(long, default_value_t = 10_000, value_parser = clap::value_parser!(u64).range(1..=50_000))]
    max_requests: u64,
    /// Apply this session's Match & Replace rules to the requests; one a rule
    /// would send elsewhere is not sent.
    #[arg(long)]
    apply_match_replace: bool,
}

#[derive(Args, Debug)]
struct TemplatesScanSessionArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug)]
struct TemplatesScanIdArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    /// Scan id, as `templates scan list` shows it.
    #[arg(long)]
    id: Uuid,
}

#[derive(Subcommand, Debug)]
enum TemplatesLibraryCommand {
    /// The installed release, its counts, and any download or import in progress.
    Status,
    /// Ask GitHub for the newest release tag: one request to api.github.com.
    Check,
    /// Download the newest release from GitHub, verify it and install it.
    Download,
    /// Install a release archive (.tar.gz) from disk, for networks without GitHub.
    Import(TemplatesImportArgs),
}

#[derive(Args, Debug)]
struct TemplatesImportArgs {
    /// A nuclei-templates release .tar.gz, at most 64 MiB.
    #[arg(long)]
    file: PathBuf,
}

#[derive(Args, Debug, Default, Clone)]
struct TemplatesFilterArgs {
    /// Substring of an id, name, path, tag or CVE, case-insensitive.
    #[arg(long)]
    search: Option<String>,
    /// Comma-separated severities: info, low, medium, high, critical, unknown.
    #[arg(long)]
    severity: Option<String>,
    /// One exact tag.
    #[arg(long)]
    tag: Option<String>,
}

#[derive(Args, Debug, Clone)]
struct TemplatesListArgs {
    #[command(flatten)]
    filter: TemplatesFilterArgs,
    /// Comma-separated protocols: http, dns, network, code and the rest.
    #[arg(long)]
    protocol: Option<String>,
    /// Templates Sniper can run passively or actively, or neither.
    #[arg(long, value_parser = ["passive", "active", "unsupported"])]
    support: Option<String>,
    /// Only passive templates that are on (true) or off (false).
    #[arg(long)]
    enabled: Option<bool>,
    /// The column to sort by; without one, templates Sniper can run come first.
    #[arg(long, value_parser = ["on", "severity", "name", "mode", "tags"])]
    sort: Option<String>,
    /// asc (the default; the most severe first for severity) or desc.
    #[arg(long, value_parser = ["asc", "desc"], requires = "sort")]
    direction: Option<String>,
    #[arg(long, default_value_t = 200, value_parser = clap::value_parser!(u64).range(1..=30_000))]
    limit: u64,
    #[arg(long, default_value_t = 0)]
    offset: u64,
}

#[derive(Args, Debug)]
struct TemplatesGetArgs {
    /// Template id, as `templates list` shows it.
    #[arg(long)]
    id: String,
}

#[derive(Subcommand, Debug)]
enum TemplatesPassiveCommand {
    /// Turn passive templates on or off by id, by filter, or all at once.
    SetEnabled(TemplatesPassiveArgs),
}

#[derive(Args, Debug)]
struct TemplatesPassiveArgs {
    #[arg(long, action = ArgAction::Set, required = true)]
    enabled: bool,
    /// A template id; repeat for several. Not with a filter or --all.
    #[arg(long = "id")]
    ids: Vec<String>,
    #[command(flatten)]
    filter: TemplatesFilterArgs,
    /// Every passive-capable template.
    #[arg(long)]
    all: bool,
}

impl TemplatesCommand {
    fn operation_name(&self) -> &'static str {
        match self {
            Self::Library { command } => match command {
                TemplatesLibraryCommand::Status => "templates.library.status",
                TemplatesLibraryCommand::Check => "templates.library.check",
                TemplatesLibraryCommand::Download => "templates.library.download",
                TemplatesLibraryCommand::Import(_) => "templates.library.import",
            },
            Self::List(_) => "templates.list",
            Self::Get(_) => "templates.get",
            Self::Passive { .. } => "templates.passive.set_enabled",
            Self::Scan { command } => match command {
                TemplatesScanCommand::Preview(_) => "templates.scan.preview",
                TemplatesScanCommand::Start(_) => "templates.scan.start",
                TemplatesScanCommand::List(_) => "templates.scan.list",
                TemplatesScanCommand::Get(_) => "templates.scan.get",
                TemplatesScanCommand::Stop(_) => "templates.scan.stop",
            },
        }
    }
}

/// Nuclei's own rule for a template id, checked before it becomes a path.
fn valid_template_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 200
        && id
            .split(['-', '_'])
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric()))
}

fn templates_filter_json(filter: &TemplatesFilterArgs) -> serde_json::Map<String, Value> {
    let mut map = serde_json::Map::new();
    for (key, value) in [
        ("search", &filter.search),
        ("severity", &filter.severity),
        ("tag", &filter.tag),
    ] {
        if let Some(value) = value {
            map.insert(key.into(), json!(value));
        }
    }
    map
}

fn templates_list_path(args: &TemplatesListArgs) -> String {
    let mut params: Vec<(String, String)> = templates_filter_json(&args.filter)
        .into_iter()
        .map(|(key, value)| (key, value.as_str().unwrap_or_default().to_string()))
        .collect();
    if let Some(protocol) = &args.protocol {
        params.push(("protocol".into(), protocol.clone()));
    }
    if let Some(support) = &args.support {
        params.push(("support".into(), support.clone()));
    }
    if let Some(enabled) = args.enabled {
        params.push(("enabled".into(), enabled.to_string()));
    }
    if let Some(sort) = &args.sort {
        params.push(("sort".into(), sort.clone()));
    }
    if let Some(direction) = &args.direction {
        params.push(("direction".into(), direction.clone()));
    }
    params.push(("limit".into(), args.limit.to_string()));
    params.push(("offset".into(), args.offset.to_string()));
    format!("/api/templates?{}", encode_query(params))
}

/// The passive request body: ids, a filter, or every passive-capable template,
/// exactly one of them.
fn templates_passive_body(args: &TemplatesPassiveArgs) -> Result<Value> {
    let filter = templates_filter_json(&args.filter);
    let ways = [!args.ids.is_empty(), !filter.is_empty(), args.all];
    if ways.iter().filter(|way| **way).count() != 1 {
        bail!("give template ids, a filter (--search, --severity, --tag), or --all; exactly one");
    }
    if let Some(id) = args.ids.iter().find(|id| !valid_template_id(id)) {
        bail!("`{id}` is not a template id");
    }
    Ok(if args.ids.is_empty() {
        let mut filter = filter;
        filter.insert("support".into(), json!("passive"));
        json!({"filter": filter, "enabled": args.enabled})
    } else {
        json!({"ids": args.ids, "enabled": args.enabled})
    })
}

/// A scan request: exactly one of ids or a filter, as the server takes it.
/// A preview sends nothing; a start carries the operator's acknowledgment,
/// which `--yes` gave.
fn templates_scan_body(
    args: &TemplatesScanArgs,
    session_id: Option<Uuid>,
    preview: bool,
) -> Result<Value> {
    let filter = templates_filter_json(&args.filter);
    if args.ids.is_empty() == filter.is_empty() {
        bail!("give template ids or a filter (--search, --severity, --tag); exactly one");
    }
    if let Some(id) = args.ids.iter().find(|id| !valid_template_id(id)) {
        bail!("`{id}` is not a template id");
    }
    let mut body = json!({
        "session_id": session_id,
        "targets": args.targets,
        "allow_risks": args.allow_risks,
        "rate": args.rate,
        "concurrency": args.concurrency,
        "max_requests": args.max_requests,
        "apply_match_replace": args.apply_match_replace,
    });
    if args.ids.is_empty() {
        body["filter"] = Value::Object(filter);
    } else {
        body["ids"] = json!(args.ids);
    }
    body[if preview { "preview" } else { "acknowledged" }] = json!(true);
    Ok(body)
}

fn templates_scan_input(args: &TemplatesScanArgs) -> Value {
    let mut input = templates_filter_json(&args.filter);
    for (key, value) in [
        ("session_id", json!(args.session_id)),
        ("targets", json!(args.targets)),
        ("ids", json!(args.ids)),
        ("allow_risks", json!(args.allow_risks)),
        ("rate", json!(args.rate)),
        ("concurrency", json!(args.concurrency)),
        ("max_requests", json!(args.max_requests)),
        ("apply_match_replace", json!(args.apply_match_replace)),
    ] {
        input.insert(key.into(), value);
    }
    Value::Object(input)
}

fn templates_input_preview(command: &TemplatesCommand) -> Value {
    match command {
        TemplatesCommand::Library {
            command: TemplatesLibraryCommand::Import(args),
        } => json!({ "file": args.file }),
        TemplatesCommand::Library { .. } => json!({}),
        TemplatesCommand::List(args) => {
            let mut input = templates_filter_json(&args.filter);
            input.insert("protocol".into(), json!(args.protocol));
            input.insert("support".into(), json!(args.support));
            input.insert("enabled".into(), json!(args.enabled));
            input.insert("limit".into(), json!(args.limit));
            input.insert("offset".into(), json!(args.offset));
            Value::Object(input)
        }
        TemplatesCommand::Get(args) => json!({ "id": args.id }),
        TemplatesCommand::Passive {
            command: TemplatesPassiveCommand::SetEnabled(args),
        } => {
            let mut input = templates_filter_json(&args.filter);
            input.insert("enabled".into(), json!(args.enabled));
            input.insert("ids".into(), json!(args.ids));
            input.insert("all".into(), json!(args.all));
            Value::Object(input)
        }
        TemplatesCommand::Scan { command } => match command {
            TemplatesScanCommand::Preview(args) | TemplatesScanCommand::Start(args) => {
                templates_scan_input(args)
            }
            TemplatesScanCommand::List(args) => json!({ "session_id": args.session_id }),
            TemplatesScanCommand::Get(args) | TemplatesScanCommand::Stop(args) => {
                json!({ "session_id": args.session_id, "id": args.id })
            }
        },
    }
}

fn templates_api_preview(command: &TemplatesCommand) -> Value {
    match command {
        TemplatesCommand::Library { command } => match command {
            TemplatesLibraryCommand::Status => api_preview("GET", "/api/templates/library", None),
            TemplatesLibraryCommand::Check => {
                api_preview("POST", "/api/templates/library/check", Some(json!({})))
            }
            TemplatesLibraryCommand::Download => api_preview(
                "POST",
                "/api/templates/library/download",
                Some(json!({ "acknowledged": true })),
            ),
            TemplatesLibraryCommand::Import(args) => api_preview(
                "POST",
                "/api/templates/library/import",
                Some(json!({ "file": args.file, "content_type": "application/gzip" })),
            ),
        },
        TemplatesCommand::List(args) => api_preview("GET", templates_list_path(args), None),
        TemplatesCommand::Get(args) => {
            api_preview("GET", format!("/api/templates/{}", args.id), None)
        }
        TemplatesCommand::Passive {
            command: TemplatesPassiveCommand::SetEnabled(args),
        } => api_preview(
            "POST",
            "/api/templates/passive",
            templates_passive_body(args).ok(),
        ),
        TemplatesCommand::Scan { command } => match command {
            TemplatesScanCommand::Preview(args) => api_preview(
                "POST",
                "/api/templates/scans",
                templates_scan_body(args, args.session_id, true).ok(),
            ),
            TemplatesScanCommand::Start(args) => api_preview(
                "POST",
                "/api/templates/scans",
                templates_scan_body(args, args.session_id, false).ok(),
            ),
            TemplatesScanCommand::List(args) => api_preview(
                "GET",
                session_query_path("/api/templates/scans", args.session_id),
                None,
            ),
            TemplatesScanCommand::Get(args) => api_preview(
                "GET",
                session_query_path(
                    &format!("/api/templates/scans/{}", args.id),
                    args.session_id,
                ),
                None,
            ),
            TemplatesScanCommand::Stop(args) => api_preview(
                "POST",
                format!("/api/templates/scans/{}/stop", args.id),
                Some(json!({ "session_id": args.session_id })),
            ),
        },
    }
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
    /// Create and activate a new Sniper session.
    Create(CreateSessionArgs),
    Switch(SessionSwitchArgs),
    Delete(SessionDeleteArgs),
    Rename(SessionRenameArgs),
    Reveal(SessionRevealArgs),
}

#[derive(Args, Debug)]
struct CreateSessionArgs {
    /// Optional name for the new session.
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
    /// Inspect or explicitly enable future observed socket peer capture for the active session.
    UpstreamPeer {
        #[command(subcommand)]
        command: UpstreamPeerCommand,
    },
    /// Inspect or explicitly opt into automatic saved HTTP history cleanup.
    Retention {
        #[command(subcommand)]
        command: HistoryRetentionCommand,
    },
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

#[derive(Subcommand, Debug)]
enum UpstreamPeerCommand {
    /// Read saved configuration and effective status; requires the current active session.
    Get(UpstreamPeerGetArgs),
    /// Save the active session switch. Off is the default and does not erase observations.
    #[command(
        after_help = "Requires --yes. Applies only to eligible future ordinary captured HTTP(S) responses; eligible in-flight work may finish after Off. Socket peers may be proxies or shared endpoints, not origin ownership. Observations persist in session files, exports and full-record JSON. No probes, backfill, Replay, WebSocket, CONNECT, TLS details or rendered-resource capture."
    )]
    Set(UpstreamPeerSetArgs),
}

impl UpstreamPeerCommand {
    fn session_id(&self) -> Uuid {
        match self {
            Self::Get(args) => args.session_id,
            Self::Set(args) => args.session_id,
        }
    }
}

#[derive(Args, Debug)]
struct UpstreamPeerGetArgs {
    /// Explicit current active session UUID; this command never switches sessions.
    #[arg(long)]
    session_id: Uuid,
}

#[derive(Args, Debug)]
struct UpstreamPeerSetArgs {
    /// Explicit current active session UUID; this command never switches sessions.
    #[arg(long)]
    session_id: Uuid,
    /// Enable or disable future socket peer capture. Off does not erase retained observations.
    #[arg(long, action = ArgAction::Set, required = true)]
    enabled: bool,
}

#[derive(Subcommand, Debug)]
enum HistoryRetentionCommand {
    /// Read the saved policy and current cleanup status for one session.
    Get(SessionReadArgs),
    /// Save a retention policy. Keep-newest can permanently delete old unprotected history.
    Set(HistoryRetentionSetArgs),
}

impl HistoryRetentionCommand {
    fn session_id(&self) -> Option<Uuid> {
        match self {
            Self::Get(args) => args.session_id,
            Self::Set(args) => args.session_id,
        }
    }
}

#[derive(Args, Debug)]
#[command(group(ArgGroup::new("retention_policy").required(true).args(["off", "max_entries"])))]
struct HistoryRetentionSetArgs {
    /// Change this session without switching it; omission pins the active session once.
    #[arg(long)]
    session_id: Option<Uuid>,
    /// Disable automatic cleanup. Does not restore deleted history.
    #[arg(long)]
    off: bool,
    /// Soft total-history target, including protected rows; oldest unprotected rows are removed first.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    max_entries: Option<u32>,
}

impl HistoryRetentionSetArgs {
    fn policy(&self) -> Value {
        match self.max_entries {
            Some(max_entries) => json!({"mode":"keep_newest","max_entries":max_entries}),
            None => json!({"mode":"off"}),
        }
    }
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

const HISTORY_SORT_KEYS: [&str; 11] = [
    "index",
    "host",
    "method",
    "path",
    "status",
    "length",
    "mime",
    "notes",
    "tls",
    "edited",
    "started_at",
];

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
    /// Sort key for paged history output, e.g. index, host, method, path, status, length, mime, notes, tls, edited, started_at.
    #[arg(long, value_parser = HISTORY_SORT_KEYS)]
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
    /// Summarize retained captured metadata; never contacts an upstream service.
    ServiceMap(ServiceMapArgs),
    /// Read safe metadata for the exact retained row referenced by a service map.
    ServiceMapEvidence(ServiceMapEvidenceArgs),
}

#[derive(Args, Debug)]
#[command(args_conflicts_with_subcommands = true)]
struct ServiceMapArgs {
    #[command(subcommand)]
    command: Option<ServiceMapCommand>,
    #[arg(long)]
    session_id: Option<Uuid>,
    /// Exact canonical HTTP(S) origin, with no path, credentials, query or fragment.
    #[arg(long, value_parser = parse_service_map_origin)]
    origin: Option<String>,
    /// Include only rows matching the selected session's current scope.
    #[arg(long)]
    in_scope_only: bool,
    /// Bound the retained rows considered; incomplete results say why.
    #[arg(long, default_value_t = 10_000, value_parser = parse_service_map_max_records)]
    max_records: usize,
    /// Read every retained row, as the desktop map does, instead of the newest
    /// --max-records rows. The server may answer from its last map of an
    /// unchanged or recent history.
    #[arg(long, conflicts_with = "max_records")]
    all_rows: bool,
    /// Select the literal response-header technology catalog (default: 2).
    #[arg(long, default_value_t = 2, value_parser = parse_service_map_catalog_version)]
    technology_catalog_version: u32,
    #[command(flatten)]
    filter: ServiceMapFilterArgs,
}

const SERVICE_MAP_MIME_TYPES: [&str; 7] = [
    "html",
    "script",
    "json",
    "css",
    "image",
    "websocket",
    "other",
];
const SERVICE_MAP_STATUS_CLASSES: [&str; 5] = [
    "success",
    "redirect",
    "client_error",
    "server_error",
    "other",
];

/// The Service Map display filter. Each condition hides rows exactly as the
/// HTTP history filter does; omitted conditions hide nothing.
#[derive(Args, Debug, Default)]
struct ServiceMapFilterArgs {
    /// Keep only rows in these MIME groups. Repeat or comma-separate.
    #[arg(long, value_delimiter = ',', value_parser = SERVICE_MAP_MIME_TYPES)]
    mime_types: Vec<String>,
    /// Keep only rows in these status classes. Repeat or comma-separate.
    #[arg(long, value_delimiter = ',', value_parser = SERVICE_MAP_STATUS_CLASSES)]
    status_classes: Vec<String>,
    /// Hide rows whose path ends in these extensions, e.g. png,css,woff2.
    #[arg(long, value_delimiter = ',', value_parser = parse_service_map_extension)]
    hidden_extensions: Vec<String>,
    /// Hide rows that have no response.
    #[arg(long)]
    hide_without_responses: bool,
    /// Keep only rows whose URL has a query string; body fields do not match.
    #[arg(long)]
    only_parameterized: bool,
}

fn parse_service_map_extension(value: &str) -> Result<String, String> {
    let extension = value.trim().trim_start_matches('.').to_ascii_lowercase();
    if !extension.is_empty()
        && extension.len() <= 16
        && extension.chars().all(|c| c.is_ascii_alphanumeric())
    {
        Ok(extension)
    } else {
        Err(format!(
            "extension must be 1-16 letters or digits, such as png or woff2: {value}"
        ))
    }
}

#[derive(Subcommand, Debug)]
enum ServiceMapCommand {
    /// Explicitly inspect one retained response preview in the active session only.
    #[command(
        after_help = "Requires the current active session UUID and an exact-row evidence token. An inactive session returns unavailable; this command never loads or activates it. Reads one retained UTF-8 HTML/JavaScript preview only, with no target requests, automatic reads, or batch reads. Literal HTTP(S) references do not establish calls or ownership; offsets address the retained preview, not wire bytes or a full body."
    )]
    BodyReferences(ServiceMapBodyReferencesArgs),
    /// Explicitly inspect literal generator declarations in one retained HTML preview.
    #[command(
        after_help = "Requires the current active session UUID and exact-row evidence token. Reads one retained UTF-8 text/html preview only; no inactive-session loading, target requests, automatic reads, batch reads, retries, or fallback. Fixed generator catalog 1 recognizes WordPress and Drupal declarations in an explicit HTML head. Partial or unsupported inspection does not mean no generator was found. Reported products and numeric versions are literal declarations, not verified software installations. Spans address retained UTF-8 bytes; the parser stop is a raw byte cursor, not a slicing boundary."
    )]
    HtmlGenerators(ServiceMapHtmlGeneratorsArgs),
    /// Explicitly inspect literal declarations in one retained response's Link headers.
    #[command(
        after_help = "Requires the current active session UUID and exact-row evidence token. Reads bounded retained response headers for GET or HEAD status 200 only; no bodies, inactive-session loading, target requests, automatic/batch reads, retries, redirects, or fallback. Fixed relation catalog 1 recognizes service-doc, service-desc, describedby, and preconnect. Partial or unsupported inspection does not mean no declarations exist. Origins and retained-header UTF-8 spans describe literal declarations, not verified calls, ownership, or connections."
    )]
    LinkDeclarations(ServiceMapLinkDeclarationsArgs),
    /// Explicitly compare recorded direct socket peers for one exact retained source row.
    #[command(
        after_help = "Requires the current active session UUID and unchanged exact-row evidence token. Compares only retained direct-route source, address family, IP and port observations in a bounded latest-row window. No arbitrary IP/host/URL input, target requests, discovery, capture changes, inactive loading, body/header reads, retries, redirects, or fallback. Counts are retained rows, including duplicate transaction UUIDs, and exclude the source. Inspect source.in_window, timestamps, reasons and omissions. Equal recorded peer values do not prove a shared physical endpoint, deployment, ownership, or origin IP."
    )]
    SocketPeerMatches(ServiceMapSocketPeerMatchesArgs),
    /// List the parameters one endpoint was called with, read from its newest retained rows.
    #[command(
        after_help = "Requires the current active session UUID. Reads the endpoint's newest 200 retained rows: query string pairs, and form, top-level JSON or multipart body fields from each body's first 64 KiB, at most 32 MiB of retained rows per read. Lists each parameter's name, where it was sent, the rows that carried it and up to three values as captured, each cut to 80 characters. No target requests, inactive-session loading or automatic reads."
    )]
    Parameters(ServiceMapParametersArgs),
    /// Describe one origin's API as an OpenAPI 3.1 document, from its retained rows.
    #[command(
        after_help = "Requires the current active session UUID. Reads every retained row of the origin: each method and path template (ID segments as {number}, {uuid}, {hex} or mixed {id}), query and form, top-level JSON or multipart body field names from each observed method/path variant's newest 20 rows, with native JSON types preserved and text types guessed from their values, response statuses with media types, and the credentials the rows showed as security schemes. No captured value is included. Operations that only answered with pages or static files, OPTIONS requests and methods OpenAPI cannot hold are left out; at most 500 operations are listed. No target requests, inactive-session loading or automatic reads."
    )]
    Openapi(ServiceMapOpenApiArgs),
    /// Show one origin's requests and those of the origins it links to, in time order by page load.
    #[command(
        after_help = "Reads the map's newest --max-records rows (default 10000, at most 50000) without bodies. Lanes are the origin and up to five origins it links to directly by an Origin or Referer header or a redirect. Steps are their rows in order, one phase per page load (a navigation), with the same request in one page load folded into a count. Open a step's row with capture http get --id <record_id>."
    )]
    Flow(ServiceMapFlowArgs),
    /// List what no rule names across the whole map, most widespread first.
    #[command(
        after_help = "Reads the session's whole map (every retained row) and gathers each origin's unnamed signals: Server and X-Powered-By banners, header names and cookie names no rule names. Each signal comes with how many origins and rows carried it, up to five of those origins and three evidence tokens to open with `scope service-map-evidence`. Most widespread first; --kind keeps one kind and --limit bounds the list. snapshot preserves source-map coverage, including complete, stopped_by and omitted_rows; omitted_signals counts only signals hidden by --limit, after --kind. No target requests or body reads beyond the map's own."
    )]
    Unnamed(ServiceMapUnnamedArgs),
}

#[derive(Args, Debug)]
struct ServiceMapUnnamedArgs {
    /// Session UUID; the active session when omitted.
    #[arg(long)]
    session_id: Option<Uuid>,
    /// Keep only banners, headers or cookies.
    #[arg(long, value_parser = ["banners", "headers", "cookies"])]
    kind: Option<String>,
    /// Signals returned, most widespread first.
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=1000))]
    limit: u32,
}

impl ServiceMapUnnamedArgs {
    /// The whole-history map this summary reads.
    fn map_args(&self) -> ServiceMapArgs {
        ServiceMapArgs {
            command: None,
            session_id: self.session_id,
            origin: None,
            in_scope_only: false,
            max_records: 10_000,
            all_rows: true,
            technology_catalog_version: 2,
            filter: ServiceMapFilterArgs::default(),
        }
    }
}

const UNNAMED_SAMPLE_ORIGINS: usize = 5;
const UNNAMED_SAMPLE_EVIDENCE: usize = 3;

/// One signal no rule names, with where it was seen.
#[derive(Debug, Serialize)]
struct UnnamedSignalSummary {
    kind: &'static str,
    value: String,
    origins: usize,
    rows: usize,
    sample_origins: Vec<String>,
    evidence: Vec<String>,
    /// What the map named on the same origins, most often first: a signal
    /// that travels with one product is likely that product's own.
    named_alongside: Vec<NamedAlongside>,
    #[serde(skip)]
    alongside: std::collections::BTreeMap<String, usize>,
}

/// A product the map named on the origins that carried a signal.
#[derive(Debug, Serialize)]
struct NamedAlongside {
    name: String,
    origins: usize,
}

/// What no rule names across one map: the queue an agent or a reader judges.
#[derive(Debug, Serialize)]
struct UnnamedSummary {
    schema_version: u32,
    session_id: Uuid,
    /// Source-map coverage is independent of the summary's kind and limit.
    snapshot: sniper::service_map::ServiceMapSnapshot,
    origins_read: usize,
    origins_with_unnamed: usize,
    distinct_signals: usize,
    omitted_signals: usize,
    signals: Vec<UnnamedSignalSummary>,
}

fn summarize_unnamed(map: &ServiceMap, kind: Option<&str>, limit: usize) -> UnnamedSummary {
    let origins = &map.origins;
    let mut by_value: std::collections::BTreeMap<(&'static str, String), UnnamedSignalSummary> =
        Default::default();
    let mut carrying = 0;
    for origin in origins {
        // The origin's own products: its servers, and what it served or set.
        let named: std::collections::BTreeSet<&str> = origin
            .server_technologies
            .iter()
            .map(|product| product.name.as_str())
            .chain(
                origin
                    .front_technologies
                    .iter()
                    .filter(|product| product.source_origin == origin.origin)
                    .map(|product| product.name.as_str()),
            )
            .collect();
        let groups = [
            ("banners", &origin.unnamed.banners),
            ("headers", &origin.unnamed.headers),
            ("cookies", &origin.unnamed.cookies),
        ];
        let mut any = false;
        for (name, signals) in groups {
            if kind.is_some_and(|wanted| wanted != name) {
                continue;
            }
            for signal in signals {
                any = true;
                let entry = by_value
                    .entry((name, signal.value.clone()))
                    .or_insert_with(|| UnnamedSignalSummary {
                        kind: name,
                        value: signal.value.clone(),
                        origins: 0,
                        rows: 0,
                        sample_origins: Vec::new(),
                        evidence: Vec::new(),
                        named_alongside: Vec::new(),
                        alongside: Default::default(),
                    });
                entry.origins += 1;
                entry.rows += signal.row_count;
                for name in &named {
                    *entry.alongside.entry((*name).to_string()).or_default() += 1;
                }
                if entry.sample_origins.len() < UNNAMED_SAMPLE_ORIGINS {
                    entry.sample_origins.push(origin.origin.clone());
                }
                for token in &signal.evidence {
                    if entry.evidence.len() < UNNAMED_SAMPLE_EVIDENCE {
                        entry.evidence.push(token.clone());
                    }
                }
            }
        }
        carrying += usize::from(any);
    }
    let mut signals: Vec<_> = by_value.into_values().collect();
    signals.sort_by(|a, b| {
        (b.origins, b.rows)
            .cmp(&(a.origins, a.rows))
            .then_with(|| a.kind.cmp(b.kind))
            .then_with(|| a.value.cmp(&b.value))
    });
    let distinct = signals.len();
    signals.truncate(limit);
    for signal in &mut signals {
        let mut named: Vec<_> = std::mem::take(&mut signal.alongside).into_iter().collect();
        named.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        signal.named_alongside = named
            .into_iter()
            .take(UNNAMED_SAMPLE_ORIGINS)
            .map(|(name, origins)| NamedAlongside { name, origins })
            .collect();
    }
    UnnamedSummary {
        schema_version: 1,
        session_id: map.session_id,
        snapshot: map.snapshot.clone(),
        origins_read: origins.len(),
        origins_with_unnamed: carrying,
        distinct_signals: distinct,
        omitted_signals: distinct - signals.len(),
        signals,
    }
}

#[derive(Args, Debug)]
struct ServiceMapOpenApiArgs {
    /// Explicit current active session UUID; an inactive session is refused.
    #[arg(long)]
    session_id: Uuid,
    /// Exact canonical HTTP(S) origin to describe.
    #[arg(long, value_parser = parse_service_map_origin)]
    origin: String,
}

#[derive(Args, Debug)]
struct ServiceMapFlowArgs {
    /// Read this session without switching to it; omitted means the active session.
    #[arg(long)]
    session_id: Option<Uuid>,
    /// Exact canonical HTTP(S) origin to follow.
    #[arg(long, value_parser = parse_service_map_origin)]
    origin: String,
    /// Keep only rows of in-scope hosts.
    #[arg(long)]
    in_scope_only: bool,
    /// Newest retained rows to read, 1 to 50000.
    #[arg(long, default_value_t = 10_000, value_parser = parse_service_map_max_records)]
    max_records: usize,
}

#[derive(Args, Debug)]
struct ServiceMapParametersArgs {
    /// Explicit current active session UUID; inactive sessions remain unavailable.
    #[arg(long)]
    session_id: Uuid,
    /// Exact canonical HTTP(S) origin of the endpoint.
    #[arg(long, value_parser = parse_service_map_origin)]
    origin: String,
    /// The endpoint's exact method, such as GET or POST.
    #[arg(long, value_parser = parse_service_map_parameters_method)]
    method: String,
    /// The endpoint's exact path, without query or fragment.
    #[arg(long, value_parser = parse_service_map_parameters_path)]
    path: String,
}

fn parse_service_map_parameters_method(value: &str) -> Result<String, String> {
    (value.len() <= 64 && is_http_method_token(value))
        .then(|| value.to_string())
        .ok_or_else(|| "method must be an HTTP method token of at most 64 characters".to_string())
}

fn parse_service_map_parameters_path(value: &str) -> Result<String, String> {
    (value.starts_with('/') && value.len() <= 4096 && !value.contains(['?', '#']))
        .then(|| value.to_string())
        .ok_or_else(|| {
            "path must start with / and carry no query or fragment, at most 4096 bytes".to_string()
        })
}

#[derive(Args, Debug)]
struct ServiceMapSocketPeerMatchesArgs {
    /// Explicit current active session UUID; inactive sessions remain unavailable.
    #[arg(long)]
    session_id: Uuid,
    /// Complete unchanged token from Service Map for exactly one retained source row.
    #[arg(long, value_parser = parse_service_map_peer_evidence_id)]
    evidence_id: String,
    /// Include only rows matching the active session's current shared scope matcher.
    #[arg(long)]
    in_scope_only: bool,
    /// Bound the latest retained rows considered, excluding the source from match counts.
    #[arg(long, default_value_t = 10_000, value_parser = parse_service_map_max_records)]
    max_records: usize,
}

#[derive(Args, Debug)]
struct ServiceMapLinkDeclarationsArgs {
    /// Explicit current active session UUID; inactive sessions remain unavailable.
    #[arg(long)]
    session_id: Uuid,
    /// Complete unchanged token from Service Map for exactly one retained row.
    #[arg(long, value_parser = parse_service_map_evidence_id)]
    evidence_id: String,
}

#[derive(Args, Debug)]
struct ServiceMapHtmlGeneratorsArgs {
    /// Explicit current active session UUID; inactive sessions remain unavailable.
    #[arg(long)]
    session_id: Uuid,
    /// Complete unchanged token from Service Map for exactly one retained row.
    #[arg(long, value_parser = parse_service_map_evidence_id)]
    evidence_id: String,
}

#[derive(Args, Debug)]
struct ServiceMapBodyReferencesArgs {
    /// Explicit current active session UUID; inactive sessions remain unavailable.
    #[arg(long)]
    session_id: Uuid,
    /// Complete unchanged token from Service Map for exactly one retained row.
    #[arg(long, value_parser = parse_service_map_evidence_id)]
    evidence_id: String,
}

#[derive(Args, Debug)]
struct ServiceMapEvidenceArgs {
    /// Select the literal response-header technology catalog (default: 2).
    #[arg(long, default_value_t = 2, value_parser = parse_service_map_catalog_version)]
    technology_catalog_version: u32,
    /// Use the exact session returned by the map; never resolve evidence across sessions.
    #[arg(long)]
    session_id: Uuid,
    /// Explicitly include one retained socket peer observation; never probes or enables capture.
    #[arg(long)]
    include_socket_peer: bool,
    /// Opaque evidence token returned by the map, not a transaction UUID.
    #[arg(long, value_parser = parse_service_map_evidence_id)]
    evidence_id: String,
}

fn parse_service_map_catalog_version(value: &str) -> std::result::Result<u32, String> {
    match value {
        "1" => Ok(1),
        "2" => Ok(2),
        _ => Err("technology-catalog-version must be 1 or 2".into()),
    }
}

fn call_service_map_catalog_version(input: &Value) -> Result<u32> {
    match input.get("technology_catalog_version") {
        None => Ok(2),
        Some(value) => value
            .as_u64()
            .filter(|version| matches!(*version, 1 | 2))
            .map(|version| version as u32)
            .ok_or_else(|| anyhow!("field `technology_catalog_version` must be integer 1 or 2")),
    }
}

fn parse_service_map_origin(value: &str) -> std::result::Result<String, String> {
    if sniper::service_map::canonical_origin(value).as_deref() != Some(value) {
        return Err("origin must be an exact canonical HTTP(S) origin without a path, credentials, query or fragment".into());
    }
    Ok(value.to_owned())
}

fn parse_service_map_max_records(value: &str) -> std::result::Result<usize, String> {
    let value = parse_nonzero_usize(value)?;
    if value > 50_000 {
        return Err("max-records must be between 1 and 50000".into());
    }
    Ok(value)
}

fn parse_service_map_peer_evidence_id(value: &str) -> std::result::Result<String, String> {
    if !sniper::service_map_peer_matches::is_canonical_evidence_id(value) {
        return Err(
            "evidence-id must be a complete unchanged canonical v1 token returned by Service Map"
                .into(),
        );
    }
    Ok(value.to_owned())
}

fn parse_service_map_evidence_id(value: &str) -> std::result::Result<String, String> {
    let fields: Vec<_> = value.split('.').collect();
    let valid = value.len() <= 200
        && fields.len() == 6
        && fields[0] == "v1"
        && [1, 2, 4, 5].into_iter().all(|index| {
            Uuid::parse_str(fields[index]).is_ok_and(|id| id.to_string() == fields[index])
        })
        && fields[3]
            .parse::<u64>()
            .is_ok_and(|sequence| sequence.to_string() == fields[3]);
    if !valid {
        return Err(
            "evidence-id must be a complete unchanged v1 token returned by Service Map".into(),
        );
    }
    Ok(value.to_owned())
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
    /// Stop the session's running fuzzer attack by ID
    Stop(FuzzerStatusArgs),
    /// Show fuzzer attack results by ID
    Results(FuzzerResultsArgs),
    /// List past fuzzer attacks
    List(FuzzerListArgs),
}

#[derive(Args, Debug, Default)]
struct FuzzerRunArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    /// Return once the attack starts instead of when it ends
    #[arg(long, alias = "async")]
    r#async: bool,
    /// How payloads fill the marked positions
    #[arg(long, value_enum, default_value_t)]
    attack_type: FuzzerAttackTypeArg,
    /// Put payloads into the URL as they are instead of percent-encoding them
    #[arg(long)]
    raw_payloads: bool,
    /// Requests sent at once, 1-16
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(1..=16))]
    concurrency: u8,
}

/// How payloads fill the marked positions, as Burp Intruder names it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
enum FuzzerAttackTypeArg {
    /// Each position in turn takes every payload; the others keep their value
    Sniper,
    /// Every position takes the same payload at once
    #[default]
    BatteringRam,
}

impl FuzzerAttackTypeArg {
    fn api_name(self) -> &'static str {
        match self {
            Self::Sniper => "sniper",
            Self::BatteringRam => "battering_ram",
        }
    }
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
    #[command(
        after_help = "Reads skill files on this CLI host, even when --api points elsewhere.\ncurrent means the installed file matches this build; modified_or_outdated means it differs.\nExit status 0 means the inspection finished; check each entries[].status."
    )]
    Status(SkillsInstallArgs),
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
    /// Change explicitly supplied fields on an existing saved rule.
    Update(InterceptRuleUpdateArgs),
    /// Assign an existing rule's enabled state; never toggles or creates it.
    SetEnabled(InterceptRuleSetEnabledArgs),
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
#[command(group(
    ArgGroup::new("rule_update")
        .args(["scope", "host_pattern", "path_pattern", "method_filter", "clear_methods", "enabled"])
        .multiple(true)
        .required(true)
))]
struct InterceptRuleUpdateArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long)]
    id: Uuid,
    #[arg(long, value_parser = ["request", "response", "both"])]
    scope: Option<String>,
    /// Replace the host pattern; an empty string clears it.
    #[arg(long)]
    host_pattern: Option<String>,
    /// Replace the path pattern; an empty string clears it.
    #[arg(long)]
    path_pattern: Option<String>,
    /// Replace the method list; repeat for multiple methods.
    #[arg(long = "method", action = ArgAction::Append, conflicts_with = "clear_methods")]
    method_filter: Option<Vec<String>>,
    /// Clear the method list, preserving host and path patterns.
    #[arg(long)]
    clear_methods: bool,
    #[arg(long)]
    enabled: Option<bool>,
}

impl InterceptRuleUpdateArgs {
    fn patch(&self) -> Value {
        let mut patch = serde_json::Map::new();
        for (key, value) in [
            ("scope", self.scope.as_ref()),
            ("host_pattern", self.host_pattern.as_ref()),
            ("path_pattern", self.path_pattern.as_ref()),
        ] {
            if let Some(value) = value {
                patch.insert(key.into(), json!(value));
            }
        }
        if let Some(methods) = &self.method_filter {
            patch.insert("method_filter".into(), json!(methods));
        } else if self.clear_methods {
            patch.insert("method_filter".into(), json!([]));
        }
        if let Some(enabled) = self.enabled {
            patch.insert("enabled".into(), json!(enabled));
        }
        Value::Object(patch)
    }
}

#[derive(Args, Debug)]
struct InterceptRuleSetEnabledArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long)]
    id: Uuid,
    /// Desired state; the explicit true or false value is required.
    #[arg(long, required = true, action = ArgAction::Set)]
    enabled: bool,
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
    edited: bool,
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
    session_metadata_write_errors: bool,
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
            session_metadata_write_errors: false,
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
            if self.session_metadata_write_errors {
                return Err(SessionMetadataHttpStatusError { status }.into());
            }
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
        .map_err(|error| {
            api_request_error(error, &method, format!("failed to {} {}", method, path))
        })?;

        let status = response.status();
        if !status.is_success() {
            if method == Method::GET {
                // Classify by headers alone: diagnostics can contain arbitrary
                // prose or sensitive data, and an error body can be incomplete.
                return Err(ReadHttpStatusError { status }.into());
            }
            if self.session_metadata_write_errors {
                // A sent mutation's status cannot be reclassified by untrusted
                // diagnostics, nor depend on a complete or timely error body.
                return Err(SessionMetadataHttpStatusError { status }.into());
            }
            let message = response.text().await.unwrap_or_else(|_| String::new());
            let detail = api_failure_detail(status, message);
            bail!("request to {} failed ({}): {}", path, status, detail);
        }

        response.json::<T>().await.map_err(|error| {
            api_request_error(
                error,
                &method,
                format!("failed to decode JSON response from {}", path),
            )
        })
    }

    fn url(&self, path: &str) -> Url {
        api_url(&self.base_url, path).expect("API base URL should be normalized")
    }
}

fn api_request_error(error: reqwest::Error, method: &Method, message: String) -> anyhow::Error {
    let error = anyhow::Error::new(error);
    if method == Method::GET {
        // Valid query text must not turn a transport or decode failure into an
        // input error merely by containing words like "invalid".
        error.context(ReadRequestError { message })
    } else {
        error.context(message)
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
    attack_type: &'static str,
    url_encode: bool,
    concurrency: u8,
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
    /// Whether the forwarded request differs from the held one. The server keeps
    /// the original and marks the row modified only when told: without this an
    /// edit from a file replaced the captured request with no trace.
    edited: bool,
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
            Command::Recon { command } => command.operation_name(),
            Command::Scanner { command } => command.operation_name(),
            Command::Templates { command } => command.operation_name(),
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
            HistoryCommand::UpstreamPeer { command } => match command {
                UpstreamPeerCommand::Get(_) => "capture.http.upstream_peer.get",
                UpstreamPeerCommand::Set(_) => "capture.http.upstream_peer.set",
            },
            HistoryCommand::Retention { command } => match command {
                HistoryRetentionCommand::Get(_) => "capture.http.retention.get",
                HistoryRetentionCommand::Set(_) => "capture.http.retention.set",
            },
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
            TargetCommand::ServiceMap(args) => match &args.command {
                Some(ServiceMapCommand::BodyReferences(_)) => {
                    "target.service_map.body_references.get"
                }
                Some(ServiceMapCommand::HtmlGenerators(_)) => {
                    "target.service_map.html_generators.get"
                }
                Some(ServiceMapCommand::LinkDeclarations(_)) => {
                    "target.service_map.link_declarations.get"
                }
                Some(ServiceMapCommand::SocketPeerMatches(_)) => {
                    "target.service_map.socket_peer_matches.get"
                }
                Some(ServiceMapCommand::Parameters(_)) => "target.service_map.parameters.get",
                Some(ServiceMapCommand::Openapi(_)) => "target.service_map.openapi.get",
                Some(ServiceMapCommand::Flow(_)) => "target.service_map.flow.get",
                Some(ServiceMapCommand::Unnamed(_)) => "target.service_map.unnamed.get",
                None => "target.service_map.get",
            },
            TargetCommand::ServiceMapEvidence(_) => "target.service_map.evidence.get",
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
            FuzzerCommand::Stop(_) => "fuzzer.stop",
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
            InterceptRuleCommand::Update(_) => "capture.intercept_rule.update",
            InterceptRuleCommand::SetEnabled(_) => "capture.intercept_rule.set_enabled",
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
            "Create and activate a new Sniper session.",
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
            "List newest stored finding summaries without detail, evidence or captured bodies. Each issue is stored once: a missing header, CORS policy or cookie flag per host, an exposed endpoint or open redirect per endpoint, a leaked value per value, linked to the first request that showed it. Defaults to 100; limit-only, not cursor pagination. Omitted session_id pins the active session.",
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
            "templates.library.status",
            "templates library status",
            "Read the installed Nuclei template release (tag, SHA-256, whether the release's checksum verified it), template counts by what Sniper can run, the passive templates turned on, and any download or import in progress. Local; contacts nothing.",
            Read,
            false,
            &[],
            vec![json!({})],
        ),
        op(
            "templates.library.check",
            "templates library check",
            "Ask GitHub for the newest nuclei-templates release tag: one request to api.github.com through the environment's proxy. Reports whether it differs from the installed one; installs nothing.",
            Read,
            false,
            &[],
            vec![json!({})],
        ),
        op(
            "templates.library.download",
            "templates library download",
            "Download the newest nuclei-templates release (MIT) from GitHub, verify it against the SHA-256 the release publishes, and install it for every session. Waits until installed. Templates are data: code, javascript and headless templates are listed but never run.",
            Write,
            true,
            &[],
            vec![json!({})],
        ),
        op(
            "templates.library.import",
            "templates library import --file <path>",
            "Install a nuclei-templates release .tar.gz from this machine, at most 64 MiB, for networks that cannot reach GitHub. Waits until installed. An imported archive is not checksum-verified.",
            Write,
            true,
            &["file"],
            vec![json!({"file":"nuclei-templates.tar.gz"})],
        ),
        op(
            "templates.list",
            "templates list",
            "List templates in the installed release with severity, tags, protocol, whether Sniper can run each passively or actively and why not, risk tags, and whether a passive one is on. Filters narrow it; limit and offset page it.",
            Read,
            false,
            &[],
            vec![json!({"support":"passive","limit":50}), json!({"search":"wordpress","severity":"high,critical"})],
        ),
        op(
            "templates.get",
            "templates get --id <id>",
            "Read one template: metadata, description, references, why Sniper can or cannot run it, and its YAML text.",
            Read,
            false,
            &["id"],
            vec![json!({"id":"tech-detect"})],
        ),
        op(
            "templates.passive.set_enabled",
            "templates passive set-enabled --enabled <true|false>",
            "Turn passive templates on or off, by ids, by a filter, or all passive-capable ones. Enabled passive templates judge captured responses whose host is in a non-empty Scope include list while Passive Scan is on; they never send requests. Findings appear under category nuclei; Rescan applies a change to stored history.",
            Write,
            true,
            &["enabled"],
            vec![json!({"ids":["tech-detect"],"enabled":true}), json!({"tag":"waf","enabled":false})],
        ),
        op(
            "templates.scan.preview",
            "templates scan preview --target <url>",
            "Count what a Template Scan would send: the templates selected by ids or a filter that can run actively, the requests they make before any redirect, the templates left out by risk, and the out-of-band templates left out because the session has no Interactsh server (oast_unavailable). Checks every target is an http(s) origin in a non-empty Scope include list and not Sniper itself. Sends nothing.",
            Read,
            false,
            &["targets"],
            vec![json!({"targets":["https://app.example.com"],"severity":"high,critical"}), json!({"targets":["https://app.example.com"],"ids":["git-config"]})],
        ),
        op(
            "templates.scan.start",
            "templates scan start --target <url>",
            "Send each selected template's requests to each target, paced and bounded, and keep in HTTP history only the exchanges a template matched; their findings appear under category nuclei as nuclei:<template-id>. Redirects are followed only while they stay in Scope. Templates with risk tags or PUT, DELETE or PATCH are left out unless allowed; dos never runs. Out-of-band templates ({{interactsh-url}}) are sent only where the session has an Interactsh server (capture oast) and match when the target calls back. Returns once the scan starts; read it with templates scan get.",
            Write,
            true,
            &["targets"],
            vec![json!({"targets":["https://app.example.com"],"severity":"high,critical","rate":5})],
        ),
        op(
            "templates.scan.list",
            "templates scan list",
            "List the session's Template Scan jobs, newest first: status, targets, counts of planned, sent, failed, blocked and matched requests, warnings. Results and the request log are left out; templates scan get has them.",
            Read,
            false,
            &[],
            vec![json!({})],
        ),
        op(
            "templates.scan.get",
            "templates scan get --id <uuid>",
            "Read one Template Scan job with its results (each naming the matched history record) and its latest 200 requests with status, time and errors.",
            Read,
            false,
            &["id"],
            vec![json!({"id":"22222222-2222-2222-2222-222222222222"})],
        ),
        op(
            "templates.scan.stop",
            "templates scan stop --id <uuid>",
            "Stop the session's running Template Scan. Requests in flight are dropped; matches already stored stay.",
            Write,
            true,
            &["id"],
            vec![json!({"id":"22222222-2222-2222-2222-222222222222"})],
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
            "capture.http.upstream_peer.get", "capture http upstream-peer get --session-id <uuid>",
            "Read default-Off observed socket peer configuration and effective status for the current active session only; no activation, upstream requests or traffic reads.",
            Read, false, &["session_id"], vec![json!({"session_id":"00000000-0000-0000-0000-000000000000"})],
        ),
        op(
            "capture.http.upstream_peer.set", "capture http upstream-peer set --session-id <uuid> --enabled <true|false>",
            "Explicitly save the active session's future observed socket peer switch. Requires --yes. One pinned configuration GET then one compare-and-swap POST; no retry or backfill. Retained observations remain in session files, exports and full-record JSON after Off. A socket peer may be a proxy or shared endpoint, not origin ownership.",
            Write, true, &["session_id", "enabled"], vec![json!({"session_id":"00000000-0000-0000-0000-000000000000","enabled":true}), json!({"session_id":"00000000-0000-0000-0000-000000000000","enabled":false})],
        ),
        op(
            "capture.http.retention.get", "capture http retention get [--session-id <uuid>]",
            "Read one session's saved HTTP retention policy and cleanup status without changing it. Off is the default.",
            Read, false, &[], vec![json!({}), json!({"session_id":"00000000-0000-0000-0000-000000000000"})],
        ),
        op(
            "capture.http.retention.set", "capture http retention set [--session-id <uuid>] (--off|--max-entries <integer>)",
            "Explicitly save Off or a keep-newest total-history target. Cleanup permanently deletes oldest unprotected rows; durable saved HTTP tab source originals and in-progress rows are protected, so totals may exceed the target. Requires --yes.",
            Write, true, &[], vec![json!({"off":true}), json!({"max_entries":10000})],
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
            "Update an HTTP Replay request or target, or change only the saved label of an HTTP or WebSocket tab. Label-only updates preserve all other saved tab fields and use workspace revision checks.",
            Write,
            false,
            &["tab_id"],
            vec![json!({"tab_id":"tab-1","host":"example.com"}), json!({"tab_id":"11111111-1111-4111-8111-111111111111","label":"Saved conversation"})],
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
            "Run the Fuzzer, sending the HTTP requests its positions and payloads make, and wait for the attack to end unless `async` is set.",
            Write,
            true,
            &[],
            vec![json!({}), json!({"attack_type":"sniper","concurrency":4})],
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
            "fuzzer.stop",
            "fuzzer stop --id <uuid>",
            "Stop the session's running Fuzzer attack. Requests in flight are dropped; results already received stay.",
            Write,
            true,
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
            "capture.intercept.get", "capture intercept get --id <uuid>",
            "Get one held request, including its potentially sensitive headers and body.",
            Read, false, &["id"],
            vec![json!({"id":"00000000-0000-0000-0000-000000000000"})],
        ),
        op(
            "capture.intercept.wait", "capture intercept wait",
            "Poll for a held request, then return its full detail without forwarding it. Timeout zero performs one queue check; the polling budget excludes API discovery and detail retrieval.",
            Read, false, &[], vec![json!({"timeout":30,"poll_interval":200})],
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
            "capture.response_intercept.wait", "capture response-intercept wait",
            "Poll for a held response, then return its full detail without forwarding it. Timeout zero performs one queue check; the polling budget excludes API discovery and detail retrieval.",
            Read, false, &[], vec![json!({"timeout":30,"poll_interval":200})],
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
            "capture.intercept_rule.update",
            "capture intercept-rule update --id <uuid>",
            "Patch explicit fields of an existing saved intercept rule. Omitted fields are preserved; empty patterns or method lists clear them. Missing IDs never create rules.",
            Write,
            true,
            &["id"],
            vec![json!({"id":"00000000-0000-0000-0000-000000000000","path_pattern":"/saved","method_filter":[]})],
        ),
        op(
            "capture.intercept_rule.set_enabled",
            "capture intercept-rule set-enabled --id <uuid> --enabled <true|false>",
            "Assign an existing saved rule's enabled boolean, preserving its matchers and scope. Repeated values never toggle or create it.",
            Write,
            true,
            &["id", "enabled"],
            vec![json!({"id":"00000000-0000-0000-0000-000000000000","enabled":false})],
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
    operations.extend(service_map_manifest_operations());
    operations.extend(recon_manifest_operations());
    operations.extend(scanner_manifest_operations());
    operations.extend(saved_manifest_operations());
    operations
}

fn service_map_object(properties: Value) -> Value {
    let required: Vec<_> = properties.as_object().unwrap().keys().cloned().collect();
    json!({"type":"object","additionalProperties":false,"required":required,"properties":properties})
}

// Keep product identities tied to the parser's fixed catalog. Header values and
// arbitrary server declarations must never become output-schema alternatives.
fn service_map_technology_schema(exact_row: bool, catalog_version: CatalogVersion) -> Value {
    use sniper::service_map_technology::{
        catalog_entries, MAX_OBSERVATIONS_PER_ROW, MAX_VERSION_BYTES,
    };
    let span = service_map_object(json!({
        "start":{"type":"integer","minimum":0,"maximum":4095},
        "end":{"type":"integer","minimum":1,"maximum":4096}
    }));
    let numeric_version = json!({
        "type":"string",
        "allOf":[
            {"pattern":"^[0-9]+(?:\\.[0-9]+)*$"},
            {"pattern":format!("^[0-9.]{{1,{MAX_VERSION_BYTES}}}$")}
        ]
    });
    let mut schema = service_map_object(json!({
        "product_id":{"type":"string"},"name":{"type":"string"},
        "catalog_category":{"type":"string","enum":["web_server","application_server","application_framework","language_runtime","cms","edge_service","connector","unknown"]},
        "reported_version":{"anyOf":[{"type":"null"},numeric_version]},
        "version_status":{"type":"string","enum":["reported","not_reported","unsupported_format","non_product_version"]},
        "source":{"type":"string","enum":["response_header"]},
        "strength":{"type":"string","enum":["literal_declaration"]},
        "header_name":{"type":"string"}
    }));
    let properties = schema["properties"].as_object_mut().unwrap();
    if exact_row {
        properties.extend([
            (
                "header_index".into(),
                json!({"type":"integer","minimum":0,"maximum":127}),
            ),
            ("product_span".into(), span.clone()),
            (
                "version_span".into(),
                json!({"anyOf":[{"type":"null"},span]}),
            ),
            (
                "offset_basis".into(),
                json!({"type":"string","enum":["retained_header_value_utf8"]}),
            ),
            ("rule_id".into(), json!({"type":"string"})),
        ]);
    } else {
        properties.extend([
            ("row_count".into(), json!({"type":"integer","minimum":1,"maximum":50000})),
            ("first_seen".into(), json!({"type":"string","format":"date-time"})),
            ("last_seen".into(), json!({"type":"string","format":"date-time"})),
            ("evidence".into(), json!({"type":"array","minItems":1,"maxItems":3,"items":{
                "type":"string","pattern":"^v1\\.[0-9a-f-]{36}\\.[0-9a-f-]{36}\\.(0|[1-9][0-9]{0,19})\\.[0-9a-f-]{36}\\.[0-9a-f-]{36}$"
            }})),
        ]);
    }
    let required: Vec<_> = properties.keys().cloned().collect();
    schema["required"] = json!(required);
    let catalog: Vec<_> = catalog_entries(catalog_version).map(|entry| {
        let mut fields = json!({
            "product_id":{"enum":[entry.product_id]},"name":{"enum":[entry.name]},
            "catalog_category":{"enum":[entry.catalog_category]},
            "header_name":{"enum":[entry.header_name]},
            "version_status":{"enum":if serde_json::to_value(entry.catalog_category).unwrap() == "connector" {
                json!(["not_reported","unsupported_format","non_product_version"])
            } else if exact_row && entry.rule_id == "server.jetty_parenthesized.v1" {
                json!(["reported","unsupported_format"])
            } else {
                json!(["reported","not_reported","unsupported_format"])
            }}
        });
        if exact_row {
            fields["rule_id"] = json!({"enum":[entry.rule_id]});
        }
        json!({"properties":fields})
    }).collect();
    schema["allOf"] = json!([
        {"anyOf":catalog},
        {"oneOf":[
            {"properties":{"version_status":{"enum":["reported"]},"reported_version":{"type":"string"}}},
            {"properties":{"version_status":{"enum":["not_reported","unsupported_format","non_product_version"]},"reported_version":{"type":"null"}}}
        ]}
    ]);
    if exact_row {
        schema["allOf"][1]["oneOf"][0]["properties"]["version_span"] = json!({"type":"object"});
        schema["allOf"][1]["oneOf"][1]["properties"]["version_span"] = json!({"type":"null"});
        schema["description"] = json!(format!("Literal allowlisted response-header declaration with UTF-8 byte spans. At most {MAX_OBSERVATIONS_PER_ROW} per exact retained row; no inferred software identity."));
    }
    schema
}

// The union supports negotiated v2 without allowing an unmarked legacy response
// to claim products that its effective v1 catalog cannot recognize.
fn service_map_catalog_output_schema(mut schema: Value, exact_row: bool) -> Value {
    schema["properties"]["technology_catalog_version"] = json!({"type":"integer","enum":[1,2],"description":"Present only when the API recognizes catalog negotiation. Absence means legacy v1 coverage; rule IDs retain their own version."});
    let observations =
        json!({"items":service_map_technology_schema(exact_row, CatalogVersion::V1)});
    let legacy_properties = if exact_row {
        json!({"technology_catalog_version":{"enum":[1]},"row":{"properties":{"technology_observations":observations}}})
    } else {
        json!({"technology_catalog_version":{"enum":[1]},"origins":{"items":{"properties":{"technology_observations":observations}}}})
    };
    schema["allOf"] = json!([{"anyOf":[
        {"required":["technology_catalog_version"],"properties":{"technology_catalog_version":{"enum":[2]}}},
        {"properties":legacy_properties}
    ]}]);
    schema
}

fn service_map_parameters_output_schema() -> Value {
    use sniper::service_map_parameters::{MAX_EXAMPLES, MAX_PARAMETERS, MAX_ROWS};
    let count = json!({"type":"integer","minimum":0});
    let parameter = service_map_object(json!({
        "name":{"type":"string"},
        "location":{"type":"string","enum":["query","form","json","multipart"]},
        "rows":{"type":"integer","minimum":1,"maximum":MAX_ROWS},
        "examples":{"type":"array","maxItems":MAX_EXAMPLES,"items":{"type":"string"},"description":"Distinct values as captured, each cut to 80 characters."}
    }));
    let mut result = service_map_object(json!({
        "schema_version":{"type":"integer","enum":[1]},
        "session_id":{"type":"string"},
        "available":{"type":"boolean"},
        "reasons":{"type":"array","items":{"type":"string"},"description":"Why the read was unavailable, such as inactive_session."},
        "origin":{"type":"string"},"method":{"type":"string"},"path":{"type":"string"},
        "rows":{"type":"integer","minimum":0,"maximum":MAX_ROWS,"description":"Matching rows read, newest first."},
        "more_rows":{"type":"boolean","description":"More rows matched than were read."},
        "parameters":{"type":"array","maxItems":MAX_PARAMETERS,"items":parameter},
        "omitted_parameters":count,
        "unread_bodies":{"type":"integer","minimum":1,"description":"Retained rows whose body was not read once the per-read byte budget was spent; their query strings still count."}
    }));
    result["required"] = json!([
        "schema_version",
        "session_id",
        "available",
        "origin",
        "method",
        "path",
        "rows",
        "more_rows",
        "parameters",
        "omitted_parameters"
    ]);
    result
}

fn service_map_flow_output_schema() -> Value {
    use sniper::service_map_flow::MAX_LANES;
    let string = json!({"type":"string"});
    let timestamp = json!({"type":"string","format":"date-time"});
    let target = service_map_object(json!({"origin":string,"path":string}));
    let mut step = service_map_object(json!({
        "origin":string,"method":string,"path":string,
        "request_kind":{"type":"string","enum":sniper::service_map::REQUEST_KINDS},
        "count":{"type":"integer","minimum":1},
        "first_seen":timestamp,"last_seen":timestamp,
        "evidence":{"type":"array","minItems":1,"maxItems":2,"items":string},
        "record_id":{"type":"string","format":"uuid"}
    }));
    step["properties"]["status"] = json!({"type":"integer","minimum":0,"maximum":65535});
    step["properties"]["redirect"] = target.clone();
    let mut phase = service_map_object(json!({"steps":{"type":"array","items":step}}));
    phase["properties"]["page"] = target;
    let mut flow = service_map_object(json!({
        "schema_version":{"type":"integer","enum":[1]},
        "session_id":{"type":"string","format":"uuid"},
        "origin":string,
        "lanes":{"type":"array","minItems":1,"maxItems":MAX_LANES,"items":string},
        "phases":{"type":"array","items":phase},
        "considered_rows":{"type":"integer","minimum":0},
        "flow_rows":{"type":"integer","minimum":0},
        "complete":{"type":"boolean"}
    }));
    flow["properties"]["stopped_by"] = json!({
        "type":"array","items":string,
        "description":"Why the flow is incomplete: the row window, lanes_limit (more than five linked origins) or steps_limit (the oldest steps were dropped)."
    });
    flow["description"] = json!("One origin's retained requests and those of the origins it links to directly, in time order, one phase per page load. A step's count folds the same request in one page load; evidence holds its first and newest rows, and record_id the newest.");
    flow
}

fn service_map_openapi_output_schema() -> Value {
    use sniper::service_map_openapi::MAX_OPERATIONS;
    json!({
        "type":"object",
        "description":"An OpenAPI 3.1 document of what one origin's retained rows showed (https://spec.openapis.org/oas/v3.1.0). Path templates mark ID segments as {number}, {uuid}, {hex} or mixed {id}; equivalent hierarchies combine their observations. JSON fields retain native types including null and mixed types; text field types are guessed from captured values, which are not included. Each operation's x-sniper-requests counts the rows it stands for and x-sniper-newest-transaction names the newest of them (open it with capture http get); security lists each credential the rows showed as an alternative, not what the server requires.",
        "required":["openapi","info","servers","paths"],
        "properties":{
            "openapi":{"type":"string","enum":["3.1.0"]},
            "info":{"type":"object","required":["title","version","description"],"properties":{
                "title":{"type":"string","description":"The origin."},
                "version":{"type":"string","enum":["observed"]},
                "description":{"type":"string","description":"How many rows it was built from, and what was left out."}
            }},
            "servers":{"type":"array","minItems":1,"maxItems":1,"items":{"type":"object","required":["url"],"properties":{"url":{"type":"string"}}}},
            "paths":{"type":"object","maxProperties":MAX_OPERATIONS,"propertyNames":{"pattern":"^/"}},
            "components":{"type":"object","properties":{"securitySchemes":{"type":"object"}}}
        }
    })
}

fn service_map_snapshot_schema() -> Value {
    let strings = json!({"type":"array","items":{"type":"string"}});
    let count = json!({"type":"integer","minimum":0});
    let timestamp = json!({"type":"string","format":"date-time"});
    let nullable_timestamp = json!({"type":["string","null"],"format":"date-time"});
    let uuid = json!({"type":"string","format":"uuid"});
    let boolean = json!({"type":"boolean"});
    let mut limits = serde_json::Map::new();
    for field in [
        "max_records",
        "metadata_bytes",
        "origins",
        "endpoints",
        "endpoints_per_origin",
        "evidence_per_item",
        "redirects_per_origin",
        "header_links_per_origin",
        "technology_clues_per_row",
        "statuses_per_endpoint",
        "content_types_per_endpoint",
        "path_bytes",
        "host_bytes",
        "method_bytes",
        "headers_per_row",
        "header_bytes_per_row",
        "header_value_bytes",
    ] {
        limits.insert(field.into(), json!({"type":"integer","minimum":1}));
    }
    let mut limits = service_map_object(Value::Object(limits));
    for (name, cap) in [
        ("technology_observations_per_row", 8),
        ("technology_observations_per_origin", 32),
        ("technology_observations", 2000),
        ("technology_version_bytes", 32),
        ("technology_token_candidates_per_row", 128),
    ] {
        limits["properties"][name] = json!({"type":"integer","enum":[cap]});
    }
    let mut snapshot = service_map_object(json!({
        "id":uuid,"generation":uuid,"captured_at":timestamp,
        "first_retained_started_at":nullable_timestamp,"last_retained_started_at":nullable_timestamp,
        "window_order":{"type":"string","enum":["newest_capture_sequence"]},
        "oldest_considered_at":nullable_timestamp,"latest_considered_at":nullable_timestamp,
        "retained_rows":count,"considered_rows":count,"non_http_rows":count,"filtered_rows":count,"projected_rows":count,"included_rows":count,
        "excluded_rows":count,"omitted_rows":count,"origin_count":count,"endpoint_count":count,
        "complete":boolean,"stopped_by":strings,"limits":limits
    }));
    // Present only when a display filter hid rows; older servers never send it.
    snapshot["required"]
        .as_array_mut()
        .unwrap()
        .retain(|name| name != "filtered_rows");
    snapshot["description"] = json!("Coverage of the source map before summary kind/limit filtering. complete is false when stopped_by reports a source limit or omission; omitted_rows counts omitted rows, not omitted signals. No completeness claim about removed or uncaptured traffic.");
    snapshot
}

fn service_map_unnamed_output_schema() -> Value {
    let count = json!({"type":"integer","minimum":0});
    json!({
        "type":"object", "additionalProperties":false,
        "description":"What no rule names across the session's whole map, most widespread first. A signal is a Server or X-Powered-By banner (`server: <value>`), a response header name, or a Set-Cookie name; never a header or cookie value. Open a signal's evidence tokens with `scope service-map-evidence` to judge it.",
        "required":["schema_version","session_id","snapshot","origins_read","origins_with_unnamed","distinct_signals","omitted_signals","signals"],
        "properties":{
            "schema_version":{"type":"integer","enum":[1]},
            "session_id":{"type":"string"},
            "snapshot":service_map_snapshot_schema(),
            "origins_read":count, "origins_with_unnamed":count,
            "distinct_signals":{"type":"integer","minimum":0,"description":"Distinct available source-map signals after --kind, before --limit; not a count of all captured or uncaptured signals."},
            "omitted_signals":{"type":"integer","minimum":0,"description":"Signals hidden only by --limit, after --kind. Zero does not imply complete source coverage; inspect snapshot.complete and snapshot.stopped_by."},
            "signals":{"type":"array","maxItems":1000,"items":{
                "type":"object", "additionalProperties":false,
                "required":["kind","value","origins","rows","sample_origins","evidence","named_alongside"],
                "properties":{
                    "kind":{"type":"string","enum":["banners","headers","cookies"]},
                    "value":{"type":"string"},
                    "origins":{"type":"integer","minimum":1,"description":"Origins whose responses carried it."},
                    "rows":count,
                    "sample_origins":{"type":"array","maxItems":UNNAMED_SAMPLE_ORIGINS,"items":{"type":"string"}},
                    "evidence":{"type":"array","maxItems":UNNAMED_SAMPLE_EVIDENCE,"items":{"type":"string"},"description":"Evidence tokens for `scope service-map-evidence`."},
                    "named_alongside":{"type":"array","maxItems":UNNAMED_SAMPLE_ORIGINS,"description":"Products the map named on the same origins, most often first. A signal whose origins all carry one product is likely that product's own.","items":{
                        "type":"object", "additionalProperties":false, "required":["name","origins"],
                        "properties":{"name":{"type":"string"},"origins":{"type":"integer","minimum":1}}
                    }}
                }
            }}
        }
    })
}

fn service_map_html_generators_output_schema() -> Value {
    use sniper::service_map_html::{ACQUISITION_REASONS, PARSER_STOP_REASONS, TRUNCATION_REASONS};
    let span = service_map_object(json!({
        "start":{"type":"integer","minimum":0,"maximum":262143},
        "end":{"type":"integer","minimum":1,"maximum":262144}
    }));
    let mut observation = service_map_object(json!({
        "product_id":{"type":"string","enum":["wordpress","drupal"]},
        "name":{"type":"string","enum":["WordPress","Drupal"]},
        "catalog_category":{"type":"string","enum":["cms"]},
        "reported_version":{"anyOf":[{"type":"null"},{"type":"string","allOf":[
            {"pattern":"^[0-9]+(?:\\.[0-9]+)*$"},{"pattern":"^[0-9.]{1,32}$"}
        ]}]},
        "version_status":{"type":"string","enum":["reported","not_reported","unsupported_format"]},
        "source":{"type":"string","enum":["response_html_meta_generator"]},
        "strength":{"type":"string","enum":["literal_declaration"]},
        "rule_id":{"type":"string","enum":["html_meta_generator.wordpress.v1","html_meta_generator.drupal.v1"]},
        "tag_span":span,"content_span":span,"product_span":span,
        "version_span":{"anyOf":[{"type":"null"},span]},
        "offset_basis":{"type":"string","enum":["retained_utf8_preview"]}
    }));
    observation["allOf"] = json!([
        {"oneOf":[
            {"properties":{"product_id":{"enum":["wordpress"]},"name":{"enum":["WordPress"]},"rule_id":{"enum":["html_meta_generator.wordpress.v1"]}}},
            {"properties":{"product_id":{"enum":["drupal"]},"name":{"enum":["Drupal"]},"rule_id":{"enum":["html_meta_generator.drupal.v1"]}}}
        ]},
        {"oneOf":[
            {"properties":{"version_status":{"enum":["reported"]},"reported_version":{"type":"string"},"version_span":{"type":"object"}}},
            {"properties":{"version_status":{"enum":["not_reported","unsupported_format"]},"reported_version":{"type":"null"},"version_span":{"type":"null"}}}
        ]}
    ]);
    observation["description"] = json!("Literal declaration only. Half-open retained UTF-8 byte spans must be ordered and contained: product starts at content.start, content is inside tag, numeric version ends at content.end after 1–32 ASCII whitespace bytes. Tags are disjoint and ordered. No raw HTML, unknown product or rejected version text.");
    let scan_reasons: Vec<_> = TRUNCATION_REASONS
        .iter()
        .chain(PARSER_STOP_REASONS)
        .copied()
        .collect();
    let reasons: Vec<_> = ACQUISITION_REASONS
        .iter()
        .copied()
        .chain(scan_reasons.iter().copied())
        .collect();
    let mut schema = service_map_object(json!({
        "schema_version":{"type":"integer","enum":[1]},
        "generator_catalog_version":{"type":"integer","enum":[1]},
        "session_id":{"type":"string","format":"uuid"},
        "evidence_id":{"type":"string","pattern":"^v1\\.[0-9a-f-]{36}\\.[0-9a-f-]{36}\\.(0|[1-9][0-9]{0,19})\\.[0-9a-f-]{36}\\.[0-9a-f-]{36}$"},
        "available":{"type":"boolean"},
        "status":{"type":"string","enum":["scanned","unsupported","unavailable"]},
        "complete":{"type":"boolean"},
        "reasons":{"type":"array","maxItems":3,"items":{"type":"string","enum":reasons}},
        "source_origin":{"type":["string","null"]},
        "source_sequence":{"type":["string","null"],"pattern":"^(0|[1-9][0-9]{0,19})$"},
        "source_started_at":{"type":["string","null"],"format":"date-time"},
        "retained_preview_bytes":{"type":["integer","null"],"minimum":0},
        "scan_prefix_bytes":{"type":"integer","minimum":0,"maximum":262144,"description":"Bounded UTF-8 prefix offered to the parser, not bytes fully parsed."},
        "capture_preview_truncated":{"type":"boolean"},"scan_prefix_truncated":{"type":"boolean"},
        "coverage":{"type":"string","enum":["literal_html_generator_explicit_head"]},
        "head_closed":{"type":"boolean"},
        "parser_stop":{"anyOf":[{"type":"null"},service_map_object(json!({
            "reason":{"type":"string","enum":PARSER_STOP_REASONS},
            "byte_cursor":{"type":"integer","minimum":0,"maximum":262144,"description":"Raw byte cursor; may split UTF-8. Never use to slice text."}
        }))]},
        "tag_candidates_inspected":{"type":"integer","minimum":0,"maximum":4096},
        "additional_tag_candidate_encountered":{"type":"boolean"},
        "additional_observation_encountered":{"type":"boolean"},
        "unknown_product_declarations":{"type":"integer","minimum":0,"maximum":4096},
        "observations":{"type":"array","maxItems":8,"items":observation},
        "limits":service_map_object(json!({
            "scan_bytes":{"type":"integer","enum":[262144]},
            "serialized_row_bytes":{"type":"integer","enum":[2097152]},
            "tag_candidates":{"type":"integer","enum":[4096]},
            "tag_bytes":{"type":"integer","enum":[4096]},
            "attributes":{"type":"integer","enum":[32]},
            "observations":{"type":"integer","enum":[8]},
            "version_bytes":{"type":"integer","enum":[32]},
            "version_separator_bytes":{"type":"integer","enum":[32]}
        })),
        "offset_basis":{"type":"string","enum":["retained_utf8_preview"]}
    }));
    schema["oneOf"] = json!([
        {"properties":{
            "available":{"enum":[true]},"status":{"enum":["scanned"]},
            "source_origin":{"type":"string"},"source_sequence":{"type":"string"},
            "source_started_at":{"type":"string"},"retained_preview_bytes":{"type":"integer"},
            "reasons":{"items":{"enum":scan_reasons}}
        },"allOf":[
            {"oneOf":[
                {"properties":{"head_closed":{"enum":[true]},"parser_stop":{"type":"null"},"tag_candidates_inspected":{"minimum":3}}},
                {"properties":{"head_closed":{"enum":[false]},"parser_stop":{"type":"object"}}}
            ]},
            {"oneOf":[
                {"properties":{"complete":{"enum":[true]},"reasons":{"enum":[[]]},"head_closed":{"enum":[true]},"capture_preview_truncated":{"enum":[false]},"scan_prefix_truncated":{"enum":[false]},"additional_tag_candidate_encountered":{"enum":[false]},"additional_observation_encountered":{"enum":[false]}}},
                {"properties":{"complete":{"enum":[false]},"reasons":{"minItems":1}}}
            ]}
        ]},
        {"properties":{
            "available":{"enum":[false]},"status":{"enum":["unsupported","unavailable"]},
            "complete":{"enum":[false]},"reasons":{"minItems":1,"maxItems":1,"items":{"enum":ACQUISITION_REASONS}},
            "source_origin":{"type":"null"},"source_sequence":{"type":"null"},
            "source_started_at":{"type":"null"},"retained_preview_bytes":{"type":"null"},
            "scan_prefix_bytes":{"enum":[0]},"capture_preview_truncated":{"enum":[false]},"scan_prefix_truncated":{"enum":[false]},
            "head_closed":{"enum":[false]},"parser_stop":{"type":"null"},
            "tag_candidates_inspected":{"enum":[0]},"additional_tag_candidate_encountered":{"enum":[false]},
            "additional_observation_encountered":{"enum":[false]},"unknown_product_declarations":{"enum":[0]},"observations":{"enum":[[]]}
        }}
    ]);
    schema["description"] = json!("Fixed generator catalog 1. Exact requested session/token binding is required. Partial accepted scans stay available=true/status=scanned; partial or unsupported never means no generator found. Source metadata and scan counters are cleared for unavailable/unsupported results. All nullable fields must be explicit null. Reasons are unique fixed codes and match truncation flags and parser stop. Bounds, span containment/order and exact source sequence are additionally checked at runtime. Declaration counters require two opening-tag candidates and, for a closed head, one closing-tag candidate in addition to each declaration.");
    schema
}

const LINK_ACQUISITION_REASONS: &[&str] = sniper::service_map_links::ACQUISITION_REASONS;
const LINK_SCAN_REASONS: &[&str] = sniper::service_map_links::PARSER_REASONS;

fn service_map_link_declarations_output_schema() -> Value {
    let span = service_map_object(json!({
        "start":{"type":"integer","minimum":0,"maximum":4095},
        "end":{"type":"integer","minimum":1,"maximum":4096}
    }));
    let mut observation = service_map_object(json!({
        "relation":{"type":"string","enum":["service-doc","service-desc","describedby","preconnect"]},
        "target_origin":{"type":"string"},
        "source":{"type":"string","enum":["response_link_header"]},
        "strength":{"type":"string","enum":["literal_declaration"]},
        "header_name":{"type":"string","enum":["link"]},
        "header_index":{"type":"integer","minimum":0,"maximum":127},
        "header_value_bytes":{"type":"integer","minimum":1,"maximum":4096},
        "link_value_span":span,"target_span":span,"relation_span":span,
        "rule_id":{"type":"string","enum":["response_link.service_doc.v1","response_link.service_desc.v1","response_link.describedby.v1","response_link.preconnect.v1"]},
        "offset_basis":{"type":"string","enum":["retained_header_value_utf8"]}
    }));
    observation["oneOf"] = json!([
        {"properties":{"relation":{"enum":["service-doc"]},"rule_id":{"enum":["response_link.service_doc.v1"]}}},
        {"properties":{"relation":{"enum":["service-desc"]},"rule_id":{"enum":["response_link.service_desc.v1"]}}},
        {"properties":{"relation":{"enum":["describedby"]},"rule_id":{"enum":["response_link.describedby.v1"]}}},
        {"properties":{"relation":{"enum":["preconnect"]},"rule_id":{"enum":["response_link.preconnect.v1"]}}}
    ]);
    observation["description"] = json!("Canonical origin only, at most 268 ASCII bytes. Half-open original retained-header UTF-8 spans: member starts at '<', target excludes brackets, relation follows target and has its literal relation-name length. Relations may share identical member/target spans with ordered distinct relation spans; separate members and headers remain ordered and disjoint. Same-header value lengths must agree. No raw header, rejected/unknown value, URL suffix, or parser diagnostic.");
    let count = |max| json!({"type":"integer","minimum":0,"maximum":max});
    let counts = service_map_object(json!({
        "headers_inspected":count(128),"header_bytes_admitted":count(32768),
        "link_fields_inspected":count(128),"candidates_inspected":count(128),
        "members_framed":count(128),"parameters_inspected":count(4096),
        "relation_tokens_inspected":count(4096),"unknown_relation_tokens_inspected":count(4096)
    }));
    let zero_counts = service_map_object(json!({
        "headers_inspected":{"enum":[0]},"header_bytes_admitted":{"enum":[0]},
        "link_fields_inspected":{"enum":[0]},"candidates_inspected":{"enum":[0]},
        "members_framed":{"enum":[0]},"parameters_inspected":{"enum":[0]},
        "relation_tokens_inspected":{"enum":[0]},"unknown_relation_tokens_inspected":{"enum":[0]}
    }));
    let reasons: Vec<_> = LINK_ACQUISITION_REASONS
        .iter()
        .chain(LINK_SCAN_REASONS)
        .copied()
        .collect();
    let mut schema = service_map_object(json!({
        "schema_version":{"type":"integer","enum":[1]},
        "relation_catalog_version":{"type":"integer","enum":[1]},
        "session_id":{"type":"string","format":"uuid"},
        "evidence_id":{"type":"string","pattern":"^v1\\.[0-9a-f-]{36}\\.[0-9a-f-]{36}\\.(0|[1-9][0-9]{0,19})\\.[0-9a-f-]{36}\\.[0-9a-f-]{36}$"},
        "available":{"type":"boolean"},"status":{"type":"string","enum":["scanned","unsupported","unavailable"]},
        "complete":{"type":"boolean"},"reasons":{"type":"array","maxItems":12,"items":{"type":"string","enum":reasons}},
        "source_origin":{"type":["string","null"]},
        "source_sequence":{"type":["string","null"],"pattern":"^(0|[1-9][0-9]{0,19})$"},
        "source_started_at":{"type":["string","null"],"format":"date-time"},
        "source_method":{"type":["string","null"],"enum":["GET","HEAD",null]},
        "source_status":{"type":["integer","null"],"enum":[200,null]},
        "retained_header_count":{"type":["integer","null"],"minimum":0,"maximum":9007199254740991u64},
        "coverage":{"type":"string","enum":["absolute_http_link_declarations"]},
        "offset_basis":{"type":"string","enum":["retained_header_value_utf8"]},
        "counts":counts,"observations":{"type":"array","maxItems":32,"items":observation},
        "limits":service_map_object(json!({
            "headers":{"type":"integer","enum":[128]},"header_bytes":{"type":"integer","enum":[32768]},
            "link_field_bytes":{"type":"integer","enum":[4096]},"target_bytes":{"type":"integer","enum":[4096]},
            "candidates":{"type":"integer","enum":[128]},"parameters_per_member":{"type":"integer","enum":[32]},
            "relation_tokens_per_member":{"type":"integer","enum":[32]},"observations":{"type":"integer","enum":[32]},
            "target_origin_bytes":{"type":"integer","enum":[268]}
        }))
    }));
    schema["oneOf"] = json!([
        {"properties":{
            "available":{"enum":[true]},"status":{"enum":["scanned"]},
            "source_origin":{"type":"string"},"source_sequence":{"type":"string"},
            "source_started_at":{"type":"string"},"source_method":{"type":"string"},
            "source_status":{"type":"integer"},"retained_header_count":{"type":"integer"},
            "reasons":{"items":{"enum":LINK_SCAN_REASONS}}
        },"oneOf":[
            {"properties":{"complete":{"enum":[true]},"reasons":{"enum":[[]]}}},
            {"properties":{"complete":{"enum":[false]},"reasons":{"minItems":1}}}
        ]},
        {"properties":{
            "available":{"enum":[false]},"status":{"enum":["unsupported","unavailable"]},
            "complete":{"enum":[false]},"reasons":{"minItems":1,"maxItems":1,"items":{"enum":LINK_ACQUISITION_REASONS}},
            "source_origin":{"type":"null"},"source_sequence":{"type":"null"},"source_started_at":{"type":"null"},
            "source_method":{"type":"null"},"source_status":{"type":"null"},"retained_header_count":{"type":"null"},
            "counts":zero_counts,"observations":{"enum":[[]]}
        }}
    ]);
    schema["description"] = json!("Fixed relation catalog 1, exact requested session/token and canonical decimal uint64 source sequence binding. Required nullable fields are explicit null. Reasons are sorted unique fixed codes; complete means no reasons within this bounded fixed grammar, never all relationships. Partial scans remain available. Runtime additionally validates canonical origins, ordered/contained spans, inspected counters and actual-cap consistency. Unknown-only complete coverage is valid. Unavailable/unsupported results contain exactly one acquisition reason and no source metadata or observations.");
    schema
}

fn service_map_socket_peer_matches_output_schema() -> Value {
    use sniper::service_map_peer_matches::{
        ACQUISITION_REASONS, MAX_HOST_BYTES, MAX_ORIGIN_GROUPS, MAX_PROJECTION_BYTES,
        MAX_SAMPLES_PER_ORIGIN, MAX_SCHEME_BYTES, MAX_SCOPE_PATTERN_BYTES,
        MAX_SCOPE_PATTERN_ENTRIES, MAX_SCOPE_WORK_UNITS, PARTIAL_REASONS,
    };
    let uuid_pattern = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
    let uuid = json!({"type":"string","format":"uuid","pattern":format!("^{uuid_pattern}$")});
    let token = json!({"type":"string","pattern":format!("^v1\\.{uuid_pattern}\\.{uuid_pattern}\\.(0|[1-9][0-9]{{0,19}})\\.{uuid_pattern}\\.{uuid_pattern}$")});
    let sequence = json!({"type":"string","pattern":"^(0|[1-9][0-9]{0,19})$","description":"Canonical decimal uint64, checked without floating-point conversion and bound to the exact evidence token."});
    let timestamp = json!({"type":"string","format":"date-time"});
    let origin = json!({"type":"string","description":"Bounded canonical HTTP(S) origin only; no credentials, path, query, fragment or raw rejected values."});
    let boolean = json!({"type":"boolean"});
    let count = json!({"type":"integer","minimum":0,"maximum":50000});
    let count_names = [
        "non_http_rows",
        "not_recorded_rows",
        "unavailable_observation_rows",
        "non_direct_rows",
        "invalid_observation_rows",
        "different_peer_rows",
        "invalid_metadata_rows",
        "scope_excluded_rows",
        "matching_rows",
        "returned_matching_rows",
        "omitted_matching_rows",
        "sample_rows",
        "omitted_sample_rows",
    ];
    let counts = service_map_object(Value::Object(
        count_names
            .iter()
            .map(|name| ((*name).into(), count.clone()))
            .collect(),
    ));
    let zero_counts = service_map_object(Value::Object(
        count_names
            .iter()
            .map(|name| ((*name).into(), json!({"type":"integer","enum":[0]})))
            .collect(),
    ));
    let mut peer = service_map_object(json!({
        "source":{"type":"string","enum":["http_response_remote_addr"]},
        "route":{"type":"string","enum":["direct"]},
        "address_family":{"type":"string","enum":["ipv4","ipv6"]},
        "address":service_map_object(json!({
            "ip":{"type":"string"},"port":{"type":"integer","minimum":1,"maximum":65535}
        }))
    }));
    peer["oneOf"] = json!([
        {"properties":{"address_family":{"enum":["ipv4"]},"address":{"properties":{"ip":{"format":"ipv4"}}}}},
        {"properties":{"address_family":{"enum":["ipv6"]},"address":{"properties":{"ip":{"format":"ipv6"}}}}}
    ]);
    peer["description"] = json!("Canonical IP serialization and permitted unicast address classes are additionally validated at runtime. IPv4 and mapped IPv6 remain distinct. This is a recorded observation key, never a physical endpoint, ownership, deployment or origin-IP finding.");
    let source = service_map_object(json!({
        "evidence_id":token,"sequence":sequence,"origin":origin,
        "started_at":timestamp,"observed_at":timestamp,"in_scope":boolean,"in_window":boolean
    }));
    let snapshot = service_map_object(json!({
        "id":uuid,"generation":uuid,"captured_at":timestamp,
        "window_order":{"type":"string","enum":["latest_retained_sequence"]},
        "retained_rows":{"type":"integer","minimum":1,"maximum":9007199254740991u64},
        "considered_rows":{"type":"integer","minimum":1,"maximum":50000},
        "oldest_considered_sequence":{"anyOf":[{"type":"null"},sequence]},
        "latest_considered_sequence":{"anyOf":[{"type":"null"},sequence]}
    }));
    let sample = service_map_object(json!({
        "evidence_id":token,"sequence":sequence,"started_at":timestamp,"observed_at":timestamp
    }));
    let group = service_map_object(json!({
        "origin":origin,"in_scope":boolean,"matching_rows":{"type":"integer","minimum":1,"maximum":50000},
        "first_observed_at":timestamp,"last_observed_at":timestamp,
        "samples":{"type":"array","maxItems":MAX_SAMPLES_PER_ORIGIN,"items":sample},
        "omitted_samples":count
    }));
    let reasons: Vec<_> = ACQUISITION_REASONS
        .iter()
        .chain(PARTIAL_REASONS)
        .copied()
        .collect();
    let mut schema = service_map_object(json!({
        "schema_version":{"type":"integer","enum":[1]},"session_id":uuid,"evidence_id":token,
        "available":boolean,"status":{"type":"string","enum":["matched","no_matches","unavailable"]},
        "complete":boolean,"reasons":{"type":"array","maxItems":PARTIAL_REASONS.len(),"items":{"type":"string","enum":reasons}},
        "in_scope_only":boolean,"coverage":{"type":"string","enum":["retained_direct_socket_peer_equality"]},
        "peer":{"anyOf":[{"type":"null"},peer]},
        "source":{"anyOf":[{"type":"null"},source]},
        "snapshot":{"anyOf":[{"type":"null"},snapshot]},
        "counts":counts,"origins":{"type":"array","maxItems":MAX_ORIGIN_GROUPS,"items":group},
        "limits":service_map_object(json!({
            "max_records":{"type":"integer","minimum":1,"maximum":50000},
            "origin_groups":{"type":"integer","enum":[MAX_ORIGIN_GROUPS]},
            "samples_per_origin":{"type":"integer","enum":[MAX_SAMPLES_PER_ORIGIN]},
            "projection_bytes":{"type":"integer","enum":[MAX_PROJECTION_BYTES]},
            "host_bytes":{"type":"integer","enum":[MAX_HOST_BYTES]},
            "scheme_bytes":{"type":"integer","enum":[MAX_SCHEME_BYTES]},
            "scope_pattern_entries":{"type":"integer","enum":[MAX_SCOPE_PATTERN_ENTRIES]},
            "scope_pattern_bytes":{"type":"integer","enum":[MAX_SCOPE_PATTERN_BYTES]},
            "scope_work_units":{"type":"integer","enum":[MAX_SCOPE_WORK_UNITS]}
        }))
    }));
    schema["oneOf"] = json!([
        {"properties":{
            "available":{"enum":[true]},"status":{"enum":["matched","no_matches"]},
            "peer":{"type":"object"},"source":{"type":"object"},"snapshot":{"type":"object","properties":{
                "oldest_considered_sequence":{"type":"string"},"latest_considered_sequence":{"type":"string"}
            }},"reasons":{"items":{"enum":PARTIAL_REASONS}}
        },"allOf":[
            {"oneOf":[
                {"properties":{"complete":{"enum":[true]},"reasons":{"enum":[[]]}}},
                {"properties":{"complete":{"enum":[false]},"reasons":{"minItems":1}}}
            ]},
            {"oneOf":[
                {"properties":{"status":{"enum":["matched"]},"counts":{"properties":{"matching_rows":{"minimum":1}}}}},
                {"properties":{"status":{"enum":["no_matches"]},"origins":{"enum":[[]]},"counts":{"properties":{
                    "matching_rows":{"enum":[0]},"returned_matching_rows":{"enum":[0]},"omitted_matching_rows":{"enum":[0]},
                    "sample_rows":{"enum":[0]},"omitted_sample_rows":{"enum":[0]}
                }}}}
            ]}
        ]},
        {"properties":{
            "available":{"enum":[false]},"status":{"enum":["unavailable"]},"complete":{"enum":[false]},
            "reasons":{"minItems":1,"maxItems":1,"items":{"enum":ACQUISITION_REASONS}},
            "peer":{"type":"null"},"source":{"type":"null"},"snapshot":{"type":"null"},
            "counts":zero_counts,"origins":{"enum":[[]]}
        }}
    ]);
    schema["description"] = json!("Explicit exact-source passive comparison. All nullable fields must be present. Runtime additionally validates session/token/generation/uint64 bindings, canonical IP/UUID/origin strings, sorted unique reasons/origins, descending unique sample sequences, window/counter partition, and honest cap/omission relationships. Counts classify considered rows excluding the source; duplicate transaction UUIDs are distinct rows. Samples bind to a containing group's time range; actual captured-origin membership is verified only by a later explicit exact-evidence read. Unavailable responses expose no peer/source/snapshot/groups. Partial coverage never means there are no other matches. Recorded observation times do not describe occupancy or connection duration. Scope preparation and matching are bounded by the fixed scope limits; scope_work_limit discards the whole inspection with no partial counts or source data. The encoded response is at most 262144 bytes.");
    schema
}

fn service_map_output_schema(operation: &str) -> Option<Value> {
    if !matches!(
        operation,
        "target.service_map.get"
            | "target.service_map.evidence.get"
            | "target.service_map.body_references.get"
            | "target.service_map.html_generators.get"
            | "target.service_map.link_declarations.get"
            | "target.service_map.socket_peer_matches.get"
            | "target.service_map.parameters.get"
            | "target.service_map.openapi.get"
            | "target.service_map.flow.get"
            | "target.service_map.unnamed.get"
    ) {
        return None;
    }
    if operation == "target.service_map.unnamed.get" {
        return Some(service_map_unnamed_output_schema());
    }
    if operation == "target.service_map.flow.get" {
        return Some(service_map_flow_output_schema());
    }
    if operation == "target.service_map.parameters.get" {
        return Some(service_map_parameters_output_schema());
    }
    if operation == "target.service_map.openapi.get" {
        return Some(service_map_openapi_output_schema());
    }
    if operation == "target.service_map.socket_peer_matches.get" {
        return Some(service_map_socket_peer_matches_output_schema());
    }
    if operation == "target.service_map.link_declarations.get" {
        return Some(service_map_link_declarations_output_schema());
    }
    if operation == "target.service_map.html_generators.get" {
        return Some(service_map_html_generators_output_schema());
    }
    let string = json!({"type":"string"});
    let strings = json!({"type":"array","items":string});
    let count = json!({"type":"integer","minimum":0});
    let timestamp = json!({"type":"string","format":"date-time"});
    let uuid = json!({"type":"string","format":"uuid"});
    let boolean = json!({"type":"boolean"});
    let port = json!({"type":"integer","minimum":0,"maximum":65535});
    let header_link = service_map_object(json!({
        "source_origin":string,
        "relationship":{"type":"string","enum":["origin_header","referer_header"]}
    }));
    if operation == "target.service_map.body_references.get" {
        let reference = service_map_object(json!({
            "target_origin":string,"occurrences":{"type":"integer","minimum":1,"maximum":4096},
            "preview_byte_offsets":{"type":"array","minItems":1,"maxItems":5,"items":{"type":"integer","minimum":0,"maximum":262143}},
            "omitted_offsets":{"type":"integer","minimum":0,"maximum":4091}
        }));
        let mut schema = service_map_object(json!({
            "schema_version":{"type":"integer","enum":[1]},"session_id":uuid,"evidence_id":string,
            "available":boolean,"status":{"type":"string","enum":["scanned","partial","unsupported","unavailable"]},
            "complete":boolean,"reasons":strings,
            "source_origin":string,"source_sequence":{"type":"string","pattern":"^(0|[1-9][0-9]*)$"},
            "source_started_at":timestamp,"retained_preview_bytes":count,
            "scanned_bytes":{"type":"integer","minimum":0,"maximum":262144},
            "capture_preview_truncated":boolean,"scan_prefix_truncated":boolean,
            "candidates_scanned":{"type":"integer","minimum":0,"maximum":4096},
            "omitted_reference_occurrences":{"type":"integer","minimum":0,"maximum":4096},"references":{"type":"array","maxItems":100,"items":reference},
            "limits":service_map_object(json!({
                "scan_bytes":{"type":"integer","enum":[262144]},
                "serialized_row_bytes":{"type":"integer","enum":[2097152]},
                "origins":{"type":"integer","enum":[100]},
                "candidates":{"type":"integer","enum":[4096]},
                "candidate_bytes":{"type":"integer","enum":[4096]},
                "offsets_per_origin":{"type":"integer","enum":[5]}
            })),
            "coverage":{"type":"string","enum":["literal_absolute_http_urls"]},
            "offset_basis":{"type":"string","enum":["retained_utf8_preview"]}
        }));
        schema["required"].as_array_mut().unwrap().retain(|name| {
            ![
                "source_origin",
                "source_sequence",
                "source_started_at",
                "retained_preview_bytes",
            ]
            .contains(&name.as_str().unwrap())
        });
        schema["oneOf"] = json!([
            {"required":["source_origin","source_sequence","source_started_at","retained_preview_bytes"],"properties":{"available":{"enum":[true]},"status":{"enum":["scanned"]},"complete":{"enum":[true]},"reasons":{"enum":[[]]},"capture_preview_truncated":{"enum":[false]},"scan_prefix_truncated":{"enum":[false]}}},
            {"required":["source_origin","source_sequence","source_started_at","retained_preview_bytes"],"properties":{"available":{"enum":[true]},"status":{"enum":["partial"]},"complete":{"enum":[false]},"reasons":{"minItems":1}}},
            {"properties":{"available":{"enum":[false]},"status":{"enum":["unsupported","unavailable"]},"complete":{"enum":[false]},"reasons":{"minItems":1},"references":{"enum":[[]]},"scanned_bytes":{"enum":[0]},"candidates_scanned":{"enum":[0]},"omitted_reference_occurrences":{"enum":[0]}}}
        ]);
        return Some(schema);
    }
    if operation == "target.service_map.evidence.get" {
        let mut row = service_map_object(json!({
            "evidence_id":string,"record_id":uuid,
            "sequence":{"type":"string","pattern":"^(0|[1-9][0-9]*)$"},
            "started_at":timestamp,"method":string,"origin":string,"host":string,
            "scheme":{"type":"string","enum":["http","https"]},"port":port,"path":string,
            "status":{"type":["integer","null"],"minimum":0,"maximum":65535},
            "content_type":{"type":["string","null"]},"is_websocket":boolean,
            "technology_clues":{"type":"array","items":service_map_object(json!({"name":string,"header_name":string}))},
            "redirect":{"anyOf":[{"type":"null"},service_map_object(json!({"target_origin":string,"target_path":string}))]},
            "header_links":{"type":"array","items":header_link},
            "metadata_complete":boolean,"omitted":strings
        }));
        row["properties"]["technology_observations"] = json!({
            "type":"array","maxItems":8,"items":service_map_technology_schema(true, CatalogVersion::V2)
        });
        let mut schema = service_map_object(json!({
            "schema_version":{"type":"integer","enum":[1]},"session_id":uuid,"evidence_id":string,
            "available":boolean,"reason":{"type":["string","null"]},
            "source":{"type":"string","enum":["captured_http_metadata"]},
            "row":{"anyOf":[{"type":"null"},row]}
        }));
        let observation = service_map_object(json!({
            "source":{"type":"string","enum":["http_response_remote_addr"]},
            "observed_at":timestamp,
            "route":{"type":"string","enum":["direct","http_proxy","socks_proxy","unknown"]},
            "address":{"anyOf":[{"type":"null"},service_map_object(json!({
                "ip":{"anyOf":[{"type":"string","format":"ipv4"},{"type":"string","format":"ipv6"}]},"port":port
            }))]},
            "reason":{"type":["string","null"],"enum":[null,"remote_addr_unavailable"]}
        }));
        let mut peer = service_map_object(json!({
            "status":{"type":"string","enum":["observed","not_recorded","unavailable"]},
            "observation":{"anyOf":[{"type":"null"},observation]}
        }));
        peer["oneOf"] = json!([
            {"properties":{"status":{"enum":["observed"]},"observation":{"type":"object","properties":{"address":{"type":"object"},"reason":{"type":"null"}}}}},
            {"properties":{"status":{"enum":["not_recorded"]},"observation":{"type":"null"}}},
            {"properties":{"status":{"enum":["unavailable"]},"observation":{"type":"object","properties":{"address":{"type":"null"},"reason":{"enum":["remote_addr_unavailable"]}}}}}
        ]);
        peer["description"] = json!("Present only after explicit include_socket_peer and successful exact-row validation. One bounded retained observation, never origin ownership or an aggregate peer map.");
        schema["properties"]["socket_peer"] = peer;
        schema["oneOf"] = json!([
            {"properties":{"available":{"enum":[true]},"reason":{"type":"null"},"row":{"type":"object"}}},
            {"properties":{"available":{"enum":[false]},"reason":{"type":"string"},"row":{"type":"null"},"socket_peer":{"enum":[]}}}
        ]);
        return Some(service_map_catalog_output_schema(schema, true));
    }
    let mut endpoint = service_map_object(json!({
        "method":string,"path":string,"path_group":{"type":["string","null"]},
        "request_count":count,"statuses":{"type":"array","items":port},
        "content_types":strings,"evidence":strings
    }));
    // Optional: older servers, and endpoints whose rows named no method, omit it.
    endpoint["properties"]["auth"] = json!({
        "type":"array","maxItems":15,"items":{"type":"string","enum":sniper::service_map_auth::KINDS},
        "description":"How this endpoint's rows authenticated, in the order of the kinds list."
    });
    let mut links = header_link;
    links["properties"]["source"] = json!({"type":"string","enum":["request_header_declaration"]});
    links["properties"]["evidence"] = strings.clone();
    links["required"]
        .as_array_mut()
        .unwrap()
        .extend([json!("source"), json!("evidence")]);
    // Optional: older servers send neither count.
    let request_count = json!({"type":"integer","minimum":1,"maximum":50000});
    links["properties"]["request_count"] = request_count.clone();
    links["properties"]["request_kinds"] = json!({
        "type":"object","additionalProperties":false,
        "properties":sniper::service_map::REQUEST_KINDS
            .iter()
            .map(|kind| (kind.to_string(), request_count.clone()))
            .collect::<serde_json::Map<_, _>>(),
        "description":"Rows carrying this declaration by request kind: Sec-Fetch-Dest when the client sent it, else the response type, then an Origin header or a non-GET method."
    });
    let mut cors = request_count.clone();
    cors["description"] = json!("Rows whose response let the source origin read it: a single Access-Control-Allow-Origin naming it or *. Absent when none.");
    links["properties"]["cors_allowed_count"] = cors;
    let mut credentials = request_count.clone();
    credentials["description"] = json!("Of those rows, how many named the source origin and sent Access-Control-Allow-Credentials: true. Absent when none.");
    links["properties"]["cors_credentials_count"] = credentials;
    // Optional: older servers, and origins no header names, omit it.
    let mut sources = service_map_object(json!({
        "source_origin":string,"request_count":request_count.clone()
    }));
    for field in [
        "request_kinds",
        "cors_allowed_count",
        "cors_credentials_count",
    ] {
        sources["properties"][field] = links["properties"][field].clone();
    }
    let header_sources = json!({
        "type":"array","items":sources,
        "description":"The header_links rows per source origin, a row naming it in both Origin and Referer counted once."
    });
    let mut redirect = service_map_object(json!({
        "target_origin":string,"target_path":string,
        "relationship":{"type":"string","enum":["redirect_instruction"]},
        "source":{"type":"string","enum":["response_location_header"]},"evidence":strings
    }));
    redirect["properties"]["request_count"] = request_count;
    let mut origin = service_map_object(json!({
        "origin":string,"host":string,"scheme":{"type":"string","enum":["http","https"]},
        "port":port,"in_scope":boolean,"request_count":count,"first_seen":timestamp,"last_seen":timestamp,
        "endpoints":{"type":"array","items":endpoint},
        "technology_clues":{"type":"array","items":service_map_object(json!({
            "name":string,"source":{"type":"string","enum":["response_header"]},"header_name":string,
            "confidence":{"type":"string","enum":["observed_header"]},"evidence":strings
        }))},
        "redirects":{"type":"array","items":redirect},
        "header_links":{"type":"array","items":links}
    }));
    origin["properties"]["header_sources"] = header_sources;
    origin["properties"]["technology_observations"] = json!({
        "type":"array","maxItems":32,"items":service_map_technology_schema(false, CatalogVersion::V2)
    });
    // Optional: older servers, and origins nothing names, omit it.
    let mut front = service_map_object(json!({
        "product_id":{"type":"string","pattern":"^[a-z0-9_]{1,40}$"},
        "name":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9 .!+_-]{0,39}$"},
        "category":{"type":"string","enum":sniper::service_map_libraries::CATEGORIES},
        "version":{"type":"string","pattern":"^[0-9][0-9A-Za-z.+-]{0,39}$"},
        "source_origin":string,"row_count":count,"evidence":strings
    }));
    // A product named without a version omits it.
    front["required"] = json!([
        "product_id",
        "name",
        "category",
        "source_origin",
        "row_count",
        "evidence"
    ]);
    let mut server = service_map_object(json!({
        "product_id":{"type":"string","pattern":"^[a-z0-9_]{1,40}$"},
        "name":{"type":"string","pattern":"^[A-Za-z.][A-Za-z0-9 .()!+_-]{0,39}$"},
        "category":{"type":"string","enum":sniper::service_map_servers::CATEGORIES},
        "version":{"type":"string","pattern":"^[0-9][0-9A-Za-z.+-]{0,39}$"},
        "signals":{"type":"array","minItems":1,"maxItems":3,"items":{"type":"string","enum":sniper::service_map_servers::SIGNALS}},
        "row_count":count,"evidence":strings
    }));
    server["required"] = json!([
        "product_id",
        "name",
        "category",
        "signals",
        "row_count",
        "evidence"
    ]);
    origin["properties"]["server_technologies"] = json!({
        "type":"array","maxItems":32,
        "description":"What the origin's own responses say about the servers behind it, outermost layer first (edge, gateway, platform, web_server, app_server, backend, language, database, os), and what they expose (category exposure: debug pages, stack traces, SQL errors, directory listings, API documents, a backend address in a BIG-IP cookie). Read from vendor header names, header values the technology catalog does not name, the names of cookies it sets, and error, default and debug page bodies. Never from another origin's rows.",
        "items":server
    });
    let mut auth = service_map_object(json!({
        "kind":{"type":"string","enum":sniper::service_map_auth::KINDS},
        "name":{"type":"string","pattern":"^[A-Za-z0-9._-]{1,64}$"},
        "row_count":count,"evidence":strings
    }));
    // A kind with no header, cookie, parameter or scheme name omits it.
    auth["required"] = json!(["kind", "row_count", "evidence"]);
    origin["properties"]["auth"] = json!({
        "type":"array","maxItems":16,
        "description":"How the origin's requests authenticate, busiest first: the Authorization scheme (bearer_jwt, bearer, basic, digest, negotiate, ntlm, aws_sigv4, or another scheme), an API key header, session or JWT cookies by name, a credential in the query string, and OAuth 2.0, OpenID Connect and SAML parameters. Read from names and shapes only; no credential value is kept or reported.",
        "items":auth
    });
    let unnamed_signal = service_map_object(json!({
        "value":{"type":"string","pattern":"^[\\x20-\\x7e]{1,80}$"},
        "row_count":count,"evidence":strings
    }));
    let unnamed_list = |what: &str| json!({"type":"array","maxItems":16,"items":unnamed_signal.clone(),"description":what});
    origin["properties"]["unnamed"] = json!({
        "type":"object","additionalProperties":false,
        "properties":{
            "banners":unnamed_list("Server and X-Powered-By values no rule names, as `server: HeRay`."),
            "headers":unnamed_list("Response header names no rule names and no server sends by default."),
            "cookies":unnamed_list("Names of cookies the origin set that no rule names.")
        },
        "description":"What the origin's responses carried that no rule names, busiest first and at most 16 of each, for the reader to judge: a banner, a header name, a cookie name. Only the Server and X-Powered-By values are kept, never another header's value; each entry's evidence opens a row that carried it. Absent when everything was named, and on older servers."
    });
    origin["properties"]["favicon"] = json!({
        "type":"string","pattern":"^v1\\.",
        "description":"Evidence of the origin's newest retained icon: a GET answered 200 with a raster image at a favicon or apple-touch-icon path, kept whole. The GUI's card shows it. Found before the display filter; never fetched from the target. Absent when none was captured."
    });
    origin["properties"]["front_technologies"] = json!({
        "type":"array","maxItems":32,
        "description":"Front-end frameworks, CMSs, UI kits, libraries and analytics retained scripts, pages and asset URLs name: license banners, runtime values such as Next.js's window.next, page markup such as ng-version or data-v- attributes, <meta name=generator>, CDN package@version paths, versioned file names and build directories such as /_next/static/. An asset's goes to the page that loaded it when that page is in the map.",
        "items":front
    });
    let entry_kinds = sniper::service_map::REQUEST_KINDS
        .iter()
        .map(|kind| (kind.to_string(), json!({"type":"integer","minimum":1})))
        .collect::<serde_json::Map<_, _>>();
    let mut client_origin = service_map_object(json!({
        "origin":string,"request_count":count,
        "entry_kinds":{"type":"object","additionalProperties":false,"properties":entry_kinds,
            "description":"Rows the client sent to this origin itself, with no Origin or Referer (a typed address, a bookmark, an app's call), by request kind. Absent when a page started every row."}
    }));
    client_origin["required"] = json!(["origin", "request_count"]);
    let mut client = service_map_object(json!({
        "kind":{"type":"string","enum":sniper::service_map_clients::KINDS},
        "name":{"type":"string","enum":sniper::service_map_clients::names()},
        "versions":{"type":"array","maxItems":8,"items":{"type":"integer","minimum":0},"description":"Major versions its rows named, newest first; one client however many versions it updated through."},
        "os":{"type":"string","enum":sniper::service_map_clients::SYSTEMS},
        "request_count":count,
        "addresses":{"type":"array","maxItems":8,"items":{"type":"string","pattern":"^[0-9A-Fa-f:.]{2,45}$"},"description":"IP addresses the client connected to the proxy from (this machine, a phone on the network). Absent when none was kept, and on older servers."},
        "origins":{"type":"array","maxItems":64,"items":client_origin},
        "evidence":strings
    }));
    client["required"] = json!(["kind", "name", "request_count", "origins", "evidence"]);
    let mut map = service_map_object(json!({
        "schema_version":{"type":"integer","enum":[1]},"session_id":uuid,"snapshot":service_map_snapshot_schema(),
        "in_scope_only":boolean,"origin_filter":{"type":["string","null"]},
        "origins":{"type":"array","items":origin},
        "clients":{"type":"array","maxItems":16,"items":client,
            "description":"Clients named by each row's User-Agent and, for Chromium browsers, Client Hints: browsers, app WebViews, app HTTP stacks, tools, libraries and crawlers, busiest first. Only these fixed names are reported, never the header. Absent when there are none, and on older servers."},
        "unavailable":strings,"deferred":strings,"warnings":strings
    }));
    map["required"]
        .as_array_mut()
        .unwrap()
        .retain(|name| name != "clients");
    Some(service_map_catalog_output_schema(map, false))
}

fn service_map_input_schema(operation: &str) -> Option<Value> {
    let uuid = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
    let evidence_pattern =
        format!("^v1\\.{uuid}\\.{uuid}\\.(0|[1-9][0-9]{{0,19}})\\.{uuid}\\.{uuid}$");
    let catalog = json!({"type":"integer","enum":[1,2],"default":2,"description":"Request this technology catalog using an API-only header. One target GET, without retries or fallback requests. An unmarked legacy response is strictly v1 and reports reduced coverage on stderr."});
    match operation {
        "target.service_map.get" => Some(json!({
            "type":"object", "additionalProperties":false, "required":[],
            "properties":{
                "technology_catalog_version":catalog,
                "session_id":legacy_uuid_input_schema(true, "Read this retained session without switching it. Omitted or null pins the active session once."),
                "origin":{"type":["string","null"],"description":"Exact canonical HTTP(S) origin (for example https://example.com), without path, credentials, query, fragment, or explicit default port. Omitted or null selects all observed origins."},
                "in_scope_only":{"type":["boolean","null"],"default":false,"description":"Filter retained rows using the session's current shared scope matcher. Null uses false."},
                "max_records":{"type":["integer","null"],"minimum":1,"maximum":50000,"default":10000,"description":"Bound the retained metadata rows considered. Null uses the default; inspect snapshot.complete and stopped_by."},
                "all_rows":{"type":["boolean","null"],"default":false,"description":"Read every retained row, as the desktop map does, instead of the newest max_records rows; omit max_records with it. The server may answer from its last map of an unchanged or recent history. Null uses false."},
                "mime_types":{"type":["array","null"],"items":{"type":"string","enum":SERVICE_MAP_MIME_TYPES},"description":"Display filter: keep only rows in these MIME groups, as HTTP history does. Omitted, null or empty keeps every group; snapshot.filtered_rows counts hidden rows."},
                "status_classes":{"type":["array","null"],"items":{"type":"string","enum":SERVICE_MAP_STATUS_CLASSES},"description":"Display filter: keep only rows in these status classes. Omitted, null or empty keeps every class."},
                "hidden_extensions":{"type":["array","null"],"items":{"type":"string","pattern":"^\\.?[A-Za-z0-9]{1,16}$"},"description":"Display filter: hide rows whose path ends in these extensions, such as png or woff2. Omitted, null or empty hides none."},
                "hide_without_responses":{"type":["boolean","null"],"default":false,"description":"Display filter: hide rows that have no response. Null uses false."},
                "only_parameterized":{"type":["boolean","null"],"default":false,"description":"Display filter: keep only rows whose URL has a query string; body fields do not match. Null uses false."}
            },
            "not":{"required":["all_rows","max_records"],"properties":{"all_rows":{"const":true},"max_records":{"type":"integer"}}}
        })),
        "target.service_map.socket_peer_matches.get" => Some(json!({
            "type":"object", "additionalProperties":false, "required":["session_id","evidence_id"],
            "properties":{
                "session_id":legacy_uuid_input_schema(false, "Explicit current active session UUID. This read never loads or activates an inactive session."),
                "evidence_id":{"type":"string","minLength":1,"maxLength":200,"pattern":evidence_pattern,"description":"Complete unchanged exact source-row token from Service Map. Never an IP, hostname, URL or transaction UUID."},
                "in_scope_only":{"type":"boolean","default":false,"description":"Filter with the existing shared scope matcher on captured host spelling. Omission selects false; null is invalid."},
                "max_records":{"type":"integer","minimum":1,"maximum":50000,"default":10000,"description":"Latest retained rows considered, including the source when in-window. Counts of matches exclude the source. Omission selects 10000; null is invalid."}
            }
        })),
        "target.service_map.body_references.get"
        | "target.service_map.html_generators.get"
        | "target.service_map.link_declarations.get" => Some(json!({
            "type":"object", "additionalProperties":false, "required":["session_id","evidence_id"],
            "properties":{
                "session_id":legacy_uuid_input_schema(false, "Explicit current active session UUID. Inactive sessions return unavailable; this read never loads or activates a session."),
                "evidence_id":{"type":"string","minLength":1,"maxLength":200,"pattern":evidence_pattern,"description":"Complete unchanged v1 evidence token for one retained row. Explicit one-row retained inspection only; no batch reads or target requests."}
            }
        })),
        "target.service_map.parameters.get" => Some(json!({
            "type":"object", "additionalProperties":false, "required":["session_id","origin","method","path"],
            "properties":{
                "session_id":legacy_uuid_input_schema(false, "Explicit current active session UUID. Inactive sessions return unavailable; this read never loads or activates a session."),
                "origin":{"type":"string","description":"Exact canonical HTTP(S) origin of the endpoint, as a map card names it."},
                "method":{"type":"string","minLength":1,"maxLength":64,"not":{"pattern":"[^A-Za-z0-9!#$%&'*+.^_`|~-]"},"description":"The endpoint's exact HTTP method token, preserving case and punctuation."},
                "path":{"type":"string","pattern":"^/[^?#]{0,4095}$","description":"The endpoint's exact path, without query or fragment."}
            }
        })),
        "target.service_map.unnamed.get" => Some(json!({
            "type":"object", "additionalProperties":false,
            "properties":{
                "session_id":legacy_uuid_input_schema(false, "Session UUID; the active session when omitted."),
                "kind":{"type":"string","enum":["banners","headers","cookies"],"description":"Keep only one kind of signal."},
                "limit":{"type":"integer","minimum":1,"maximum":1000,"default":100,"description":"Signals returned, most widespread first."}
            }
        })),
        "target.service_map.flow.get" => Some(json!({
            "type":"object", "additionalProperties":false, "required":["origin"],
            "properties":{
                "session_id":legacy_uuid_input_schema(true, "Read this session without switching it; omitted or null selects the active session."),
                "origin":{"type":"string","description":"Exact canonical HTTP(S) origin to follow, as a map card names it."},
                "in_scope_only":{"type":["boolean","null"],"default":false,"description":"Keep only rows of in-scope hosts."},
                "max_records":{"type":["integer","null"],"minimum":1,"maximum":50000,"default":10000,"description":"Newest retained rows to read."}
            }
        })),
        "target.service_map.openapi.get" => Some(json!({
            "type":"object", "additionalProperties":false, "required":["session_id","origin"],
            "properties":{
                "session_id":legacy_uuid_input_schema(false, "Explicit current active session UUID. An inactive session is refused; this read never loads or activates a session."),
                "origin":{"type":"string","description":"Exact canonical HTTP(S) origin to describe, as a map card names it."}
            }
        })),
        "target.service_map.evidence.get" => Some(json!({
            "type":"object", "additionalProperties":false, "required":["session_id","evidence_id"],
            "properties":{
                "technology_catalog_version":catalog,
                "include_socket_peer":{"type":"boolean","default":false,"description":"Explicitly read one retained observed socket peer after exact-token validation. Does not enable capture, probe, aggregate peers or infer origin ownership. Omission preserves the default evidence shape."},
                "session_id":legacy_uuid_input_schema(false, "Exact session UUID returned by the service map. Always explicit, including for inactive sessions."),
                "evidence_id":{"type":"string","minLength":1,"maxLength":200,"pattern":evidence_pattern,"description":"Complete v1 evidence token returned by the map, with canonical UUID components and an unsigned 64-bit sequence. At most 200 UTF-8 bytes; pass unchanged, not a transaction UUID."}
            }
        })),
        _ => None,
    }
}

fn service_map_path(args: &ServiceMapArgs, session_id: Option<Uuid>) -> String {
    let mut params = vec![
        ("in_scope_only".into(), args.in_scope_only.to_string()),
        if args.all_rows {
            ("all_rows".into(), "true".into())
        } else {
            ("max_records".into(), args.max_records.to_string())
        },
    ];
    if let Some(origin) = &args.origin {
        params.push(("origin".into(), origin.clone()));
    }
    let filter = &args.filter;
    for (name, values) in [
        ("mime_types", &filter.mime_types),
        ("status_classes", &filter.status_classes),
        ("hidden_extensions", &filter.hidden_extensions),
    ] {
        if !values.is_empty() {
            params.push((name.into(), values.join(",")));
        }
    }
    for (name, enabled) in [
        ("hide_without_responses", filter.hide_without_responses),
        ("only_parameterized", filter.only_parameterized),
    ] {
        if enabled {
            params.push((name.into(), "true".into()));
        }
    }
    let query = encode_query(params);
    session_query_path(&format!("/api/target/service-map?{query}"), session_id)
}

fn service_map_evidence_path(args: &ServiceMapEvidenceArgs) -> String {
    let mut params = vec![("evidence_id".into(), args.evidence_id.clone())];
    if args.include_socket_peer {
        params.push(("include_socket_peer".into(), "true".into()));
    }
    let query = encode_query(params);
    session_query_path(
        &format!("/api/target/service-map/evidence?{query}"),
        Some(args.session_id),
    )
}

fn service_map_body_references_path(args: &ServiceMapBodyReferencesArgs) -> String {
    let query = encode_query(vec![("evidence_id".into(), args.evidence_id.clone())]);
    session_query_path(
        &format!("/api/target/service-map/body-references?{query}"),
        Some(args.session_id),
    )
}

fn service_map_parameters_path(args: &ServiceMapParametersArgs) -> String {
    let query = encode_query(vec![
        ("origin".into(), args.origin.clone()),
        ("method".into(), args.method.clone()),
        ("path".into(), args.path.clone()),
    ]);
    session_query_path(
        &format!("/api/target/service-map/parameters?{query}"),
        Some(args.session_id),
    )
}

fn service_map_flow_path(args: &ServiceMapFlowArgs) -> String {
    let mut query = vec![
        ("origin".into(), args.origin.clone()),
        ("max_records".into(), args.max_records.to_string()),
    ];
    if args.in_scope_only {
        query.push(("in_scope_only".into(), "true".into()));
    }
    session_query_path(
        &format!("/api/target/service-map/flow?{}", encode_query(query)),
        args.session_id,
    )
}

fn service_map_openapi_path(args: &ServiceMapOpenApiArgs) -> String {
    let query = encode_query(vec![("origin".into(), args.origin.clone())]);
    session_query_path(
        &format!("/api/target/service-map/openapi?{query}"),
        Some(args.session_id),
    )
}

fn service_map_html_generators_path(args: &ServiceMapHtmlGeneratorsArgs) -> String {
    let query = encode_query(vec![("evidence_id".into(), args.evidence_id.clone())]);
    session_query_path(
        &format!("/api/target/service-map/html-generators?{query}"),
        Some(args.session_id),
    )
}

fn service_map_link_declarations_path(args: &ServiceMapLinkDeclarationsArgs) -> String {
    let query = encode_query(vec![("evidence_id".into(), args.evidence_id.clone())]);
    session_query_path(
        &format!("/api/target/service-map/link-declarations?{query}"),
        Some(args.session_id),
    )
}

fn service_map_socket_peer_matches_path(args: &ServiceMapSocketPeerMatchesArgs) -> String {
    let query = encode_query(vec![
        ("evidence_id".into(), args.evidence_id.clone()),
        ("in_scope_only".into(), args.in_scope_only.to_string()),
        ("max_records".into(), args.max_records.to_string()),
    ]);
    session_query_path(
        &format!("/api/target/service-map/socket-peer-matches?{query}"),
        Some(args.session_id),
    )
}

fn service_map_manifest_operations() -> Vec<CliOperationSpec> {
    vec![
        op(
            "target.service_map.get",
            "scope service-map [--technology-catalog-version <1|2>]",
            "Read a bounded passive inventory from retained captured metadata. No requests to mapped services, scans, replay, or crawling. Counts include duplicate-ID rows; inspect completeness and unavailable fields. Catalog 2 is requested by default; explicit 1 limits coverage. Legacy servers return strict v1 with a stderr warning; negotiation never adds requests or retries.",
            CliSideEffect::Read,
            false,
            &[],
            vec![json!({}), json!({"session_id":"00000000-0000-0000-0000-000000000000","in_scope_only":true,"max_records":10000,"technology_catalog_version":2}), json!({"all_rows":true}), json!({"technology_catalog_version":1})],
        ),
        op(
            "target.service_map.body_references.get",
            "scope service-map body-references --session-id <uuid> --evidence-id <token>",
            "Explicitly read literal absolute HTTP(S) URL references from one retained UTF-8 HTML/JavaScript response preview. Active session only; inactive sessions return unavailable without loading or activation. Returns origins and preview-byte offsets, never body text or URL paths, queries, or credentials. No target requests or automatic/batch reads; references do not prove calls or ownership. Inspect status, completeness, truncation, reasons, and limits.",
            CliSideEffect::Read,
            false,
            &["session_id", "evidence_id"],
            vec![json!({"session_id":"00000000-0000-0000-0000-000000000000","evidence_id":"v1.00000000-0000-0000-0000-000000000000.00000000-0000-0000-0000-000000000000.1.00000000-0000-0000-0000-000000000000.00000000-0000-0000-0000-000000000000"})],
        ),
        op(
            "target.service_map.parameters.get",
            "scope service-map parameters --session-id <uuid> --origin <origin> --method <method> --path <path>",
            "List the parameters one endpoint was called with, from its newest 200 retained rows: query string pairs and form, top-level JSON or multipart body fields, each with where it was sent, the rows that carried it and up to three values as captured, cut to 80 characters. Active session only; inactive sessions return unavailable without loading or activation. Reads retained request bodies from their first 64 KiB, at most 32 MiB per read; no target requests or automatic reads.",
            CliSideEffect::Read,
            false,
            &["session_id", "origin", "method", "path"],
            vec![json!({"session_id":"00000000-0000-0000-0000-000000000000","origin":"https://example.com","method":"GET","path":"/search"})],
        ),
        op(
            "target.service_map.unnamed.get",
            "scope service-map unnamed [--session-id <uuid>] [--kind banners|headers|cookies] [--limit <n>]",
            "List what no rule names across the session's whole map: Server and X-Powered-By banners, response header names and Set-Cookie names, each with how many origins and rows carried it, up to five of those origins and three evidence tokens. Most widespread first. Reads the same whole-history map as `scope service-map --all-rows`; no target requests. Judge a signal by opening its evidence, then record a conclusion with `capture http annotate`.",
            CliSideEffect::Read,
            false,
            &["session_id", "kind", "limit"],
            vec![json!({}), json!({"kind":"headers","limit":50})],
        ),
        op(
            "target.service_map.openapi.get",
            "scope service-map openapi --session-id <uuid> --origin <origin>",
            "Describe one origin's API as an OpenAPI 3.1 document built from all its retained rows: each method and path template with ID segments as {number}, {uuid}, {hex} or mixed {id}, query and body field names with native JSON types preserved and text types guessed from their values, response statuses and media types, and the credentials the rows showed as security schemes. No captured value is included; operations that only served pages or static files are left out, and at most 500 are listed. Active session only; an inactive session is refused without loading or activation. No target requests or automatic reads.",
            CliSideEffect::Read,
            false,
            &["session_id", "origin"],
            vec![json!({"session_id":"00000000-0000-0000-0000-000000000000","origin":"https://example.com"})],
        ),
        op(
            "target.service_map.flow.get",
            "scope service-map flow --origin <origin> [--session-id <uuid>] [--in-scope-only] [--max-records N]",
            "Show one origin's retained requests and those of the origins it links to directly by Origin, Referer or a redirect, in time order with one phase per page load. The same request in one page load folds into a count; each step names its newest row's record_id. Reads the newest max_records rows (default 10000) without bodies and sends nothing to targets.",
            CliSideEffect::Read,
            false,
            &["origin"],
            vec![json!({"origin":"https://example.com"}), json!({"session_id":"00000000-0000-0000-0000-000000000000","origin":"https://example.com","max_records":50000})],
        ),
        op(
            "target.service_map.html_generators.get",
            "scope service-map html-generators --session-id <uuid> --evidence-id <token>",
            "Explicitly inspect one retained UTF-8 text/html response preview for literal WordPress or Drupal meta generator declarations. Active session only; no loading or activation. Fixed generator catalog 1, independent of response-header catalogs and URL references. One inspection GET after existing identity checks, with no target requests, automatic/batch reads, retries, or fallback. Returns safe products, numeric versions, bounded counters and original preview byte spans, never raw content. Inspect completeness, head closure, truncation and parser stop; partial/unsupported never means no generator found. Declarations do not prove installed software or ownership.",
            CliSideEffect::Read,
            false,
            &["session_id", "evidence_id"],
            vec![json!({"session_id":"00000000-0000-0000-0000-000000000000","evidence_id":"v1.00000000-0000-0000-0000-000000000000.00000000-0000-0000-0000-000000000000.1.00000000-0000-0000-0000-000000000000.00000000-0000-0000-0000-000000000000"})],
        ),
        op(
            "target.service_map.link_declarations.get",
            "scope service-map link-declarations --session-id <uuid> --evidence-id <token>",
            "Explicitly inspect bounded retained response Link headers for one exact active-session GET or HEAD status 200 row. Fixed relation catalog 1 recognizes service-doc, service-desc, describedby, and preconnect, independently of technology catalogs and body inspectors. One inspection GET after identity checks; no bodies, inactive loading, target requests, automatic/batch reads, retries, redirects, or fallback. Returns origin-only literal declarations and original retained-header UTF-8 spans. Partial/unsupported never means no declarations exist; completeness is within the fixed grammar only. Declarations do not prove calls, ownership, or connections.",
            CliSideEffect::Read,
            false,
            &["session_id", "evidence_id"],
            vec![json!({"session_id":"00000000-0000-0000-0000-000000000000","evidence_id":"v1.00000000-0000-0000-0000-000000000000.00000000-0000-0000-0000-000000000000.1.00000000-0000-0000-0000-000000000000.00000000-0000-0000-0000-000000000000"})],
        ),
        op(
            "target.service_map.socket_peer_matches.get",
            "scope service-map socket-peer-matches --session-id <uuid> --evidence-id <token> [--in-scope-only] [--max-records <1..50000>]",
            "Explicitly compare equal recorded direct-route socket source/address-family/IP/port observations for one exact active-session source row. Bounded latest retained window; row counts include duplicate transaction UUIDs and exclude the source. One feature GET after existing identity checks; no target traffic, capture changes, discovery, body/header reads, inactive loading, retries, redirects, or fallback. Inspect source.in_window, recorded times, limits, partial reasons, origin-group and sample omissions. Equal recorded values do not establish physical endpoint identity, deployment, ownership, or origin IP. Default map/evidence output is unchanged.",
            CliSideEffect::Read,
            false,
            &["session_id", "evidence_id"],
            vec![json!({"session_id":"00000000-0000-0000-0000-000000000000","evidence_id":"v1.00000000-0000-0000-0000-000000000000.00000000-0000-0000-0000-000000000000.1.00000000-0000-0000-0000-000000000000.00000000-0000-0000-0000-000000000000","in_scope_only":false,"max_records":10000})],
        ),
        op(
            "target.service_map.evidence.get",
            "scope service-map-evidence --session-id <uuid> --evidence-id <token> [--include-socket-peer] [--technology-catalog-version <1|2>]",
            "Read safe metadata for an exact retained row using its session-bound opaque evidence token. Stale, edited, deleted, or ambiguous evidence is explicitly unavailable; never falls back to UUID-only history lookup. Explicit include_socket_peer adds one retained observation without enabling capture or probing; socket peers do not prove origin ownership. Catalog 2 is requested by default; explicit 1 limits coverage. An unmarked legacy response is strictly v1 with a stderr warning; no negotiation retries or fallback requests.",
            CliSideEffect::Read,
            false,
            &["session_id", "evidence_id"],
            vec![json!({"session_id":"00000000-0000-0000-0000-000000000000","evidence_id":"v1.00000000-0000-0000-0000-000000000000.00000000-0000-0000-0000-000000000000.1.00000000-0000-0000-0000-000000000000.00000000-0000-0000-0000-000000000000","technology_catalog_version":2}), json!({"session_id":"00000000-0000-0000-0000-000000000000","evidence_id":"v1.00000000-0000-0000-0000-000000000000.00000000-0000-0000-0000-000000000000.1.00000000-0000-0000-0000-000000000000.00000000-0000-0000-0000-000000000000","include_socket_peer":true,"technology_catalog_version":1})],
        ),
    ]
}

fn recon_manifest_operations() -> Vec<CliOperationSpec> {
    use CliSideEffect::{Read, Write};
    let session = "00000000-0000-0000-0000-000000000000";
    vec![
        op("recon.list", "recon list --session-id <uuid>", "Read all retained Recon jobs and endpoint evidence from one explicit session without target or provider requests. URLs can contain sensitive data.", Read, false, &["session_id"], vec![json!({"session_id":session})]),
        op("recon.start", "recon start --session-id <uuid> --target-url <url> --source <source>", "Start asynchronous, explicitly scoped endpoint discovery. Requires target authorization, write confirmation and separate provider-sharing acknowledgments. Zero budgets are unbounded; API timeout does not stop the job.", Write, true, &["session_id","target_url","sources"], vec![
            json!({"session_id":session,"target_url":"https://example.com/","sources":["crawler"],"max_requests":50,"max_depth":2,"max_endpoints":500}),
            json!({"session_id":session,"target_url":"https://example.com/","sources":["urlscan","wayback"],"history_acknowledged":true,"max_pages":2,"max_endpoints":500}),
            json!({"session_id":session,"target_url":"https://example.com/","sources":["urlscan_submit"],"scan_acknowledged":true,"scan_visibility":"private","max_endpoints":500}),
        ]),
        op("recon.stop", "recon stop --session-id <uuid> --id <uuid>", "Cancel this exact session-owned job's local work. Cannot cancel a scan already accepted by urlscan; never retry a start automatically.", Write, true, &["session_id","id"], vec![json!({"session_id":session,"id":"22222222-2222-2222-2222-222222222222"})]),
    ]
}

fn recon_input_schema(operation: &str) -> Option<Value> {
    if !matches!(operation, "recon.list" | "recon.start" | "recon.stop") {
        return None;
    }
    let mut schema = json!({"type":"object","additionalProperties":false,"required":["session_id"],"properties":{
        "session_id":{"type":"string","format":"uuid","description":"Explicit session UUID. Never switches the active session."}
    }});
    if operation == "recon.stop" {
        schema["required"] = json!(["session_id", "id"]);
        schema["properties"]["id"] = json!({"type":"string","format":"uuid"});
    } else if operation == "recon.start" {
        schema["required"] = json!(["session_id", "target_url", "sources"]);
        let fields = json!({
            "target_url":{"type":"string","format":"uri","description":"Absolute HTTP(S) URL without credentials, control characters, wildcard hostname or port zero. Scope is hostname, scheme and port, not path. urlscan_submit also rejects any query or fragment; do not submit a confidential path."},
            "include_subdomains":{"type":"boolean","default":false,"description":"Explicitly expand scope to DNS subdomains; not valid for IP literals."},
            "sources":{"type":"array","minItems":1,"maxItems":4,"uniqueItems":true,"items":{"type":"string","enum":["crawler","urlscan","wayback","urlscan_submit"]}},
            "history_acknowledged":{"type":"boolean","default":false,"description":"Explicit consent to disclose the target hostname to selected history providers, separate from --yes."},
            "scan_acknowledged":{"type":"boolean","default":false,"description":"Explicit consent to submit the full target URL to urlscan and run its remote browser, separate from --yes."},
            "scan_visibility":{"type":["string","null"],"enum":["private","unlisted","public",null],"description":"Required non-null for urlscan_submit; no fallback. Unlisted is not private."}
        });
        for (key, value) in fields.as_object().unwrap() {
            schema["properties"][key] = value.clone();
        }
        for field in ["max_requests", "max_depth", "max_endpoints", "max_pages"] {
            schema["properties"][field] = json!({"type":"integer","minimum":0,"maximum":usize::MAX,"default":0,"description":"Optional collection budget; zero means unbounded. max_pages applies per history provider; max_endpoints counts new entries."});
        }
        schema["allOf"] = json!([
            {"if":{"properties":{"sources":{"contains":{"enum":["urlscan","wayback"]}}}},"then":{"required":["history_acknowledged"],"properties":{"history_acknowledged":{"const":true}}}},
            {"if":{"properties":{"sources":{"contains":{"const":"urlscan_submit"}}}},"then":{"required":["scan_acknowledged","scan_visibility"],"properties":{"scan_acknowledged":{"const":true},"scan_visibility":{"type":"string","enum":["private","unlisted","public"]}}}}
        ]);
    }
    Some(schema)
}

fn recon_output_schema(operation: &str) -> Option<Value> {
    if !matches!(operation, "recon.list" | "recon.start" | "recon.stop") {
        return None;
    }
    let uuid = json!({"type":"string","format":"uuid"});
    if operation == "recon.stop" {
        return Some(service_map_object(
            json!({"session_id":uuid,"stopped":{"type":"boolean","enum":[true]}}),
        ));
    }
    let timestamp = json!({"type":"string","format":"date-time"});
    let string = json!({"type":"string"});
    let strings = json!({"type":"array","items":string});
    let count = json!({"type":"integer","minimum":0});
    let source = service_map_object(json!({
        "source":string,"status":string,"requests":count,"discovered":count,
        "truncated":{"type":"boolean"},"warnings":strings
    }));
    let job = service_map_object(json!({
        "id":uuid,"target_url":string,"status":string,"started_at":timestamp,
        "finished_at":{"type":["string","null"],"format":"date-time"},
        "sources":{"type":"array","items":source},"error":{"type":["string","null"]}
    }));
    if operation == "recon.start" {
        return Some(job);
    }
    let evidence = service_map_object(json!({
        "source":string,"kind":string,"location":string,"timestamp":{"type":["string","null"]},
        "status":{"type":["integer","null"],"minimum":0,"maximum":65535}
    }));
    let endpoint = service_map_object(json!({
        "url":string,"method":string,"raw_urls":strings,"evidence":{"type":"array","items":evidence},
        "first_seen":timestamp,"last_seen":timestamp
    }));
    let mut schema = service_map_object(json!({
        "session_id":uuid,"jobs":{"type":"array","items":job},"endpoints":{"type":"array","items":endpoint}
    }));
    schema["description"] = json!("Full retained session inventory, not paginated. Check each source status, truncated and warnings. Completed can still be partial; history/candidate/observed evidence never proves current liveness. URLs and evidence can be sensitive.");
    Some(schema)
}

fn recon_command_from_input(operation: &str, input: &Value) -> Result<ReconCommand> {
    let session_id = call_required(operation, input, "session_id")?;
    Ok(match operation {
        "recon.list" => ReconCommand::List(ReconSessionArgs { session_id }),
        "recon.stop" => ReconCommand::Stop(ReconStopArgs {
            session_id,
            id: call_required(operation, input, "id")?,
        }),
        "recon.start" => ReconCommand::Start(ReconStartArgs {
            session_id,
            target_url: call_required(operation, input, "target_url")?,
            sources: call_required(operation, input, "sources")?,
            include_subdomains: call_present(operation, input, "include_subdomains")?
                .unwrap_or(false),
            max_requests: call_present(operation, input, "max_requests")?.unwrap_or(0),
            max_depth: call_present(operation, input, "max_depth")?.unwrap_or(0),
            max_endpoints: call_present(operation, input, "max_endpoints")?.unwrap_or(0),
            max_pages: call_present(operation, input, "max_pages")?.unwrap_or(0),
            history_acknowledged: call_present(operation, input, "history_acknowledged")?
                .unwrap_or(false),
            scan_acknowledged: call_present(operation, input, "scan_acknowledged")?
                .unwrap_or(false),
            scan_visibility: call_optional(operation, input, "scan_visibility")?,
        }),
        _ => bail!("unknown operation `{operation}`"),
    })
}

fn recon_input_preview(command: &ReconCommand) -> Value {
    match command {
        ReconCommand::List(args) => json!({"session_id":args.session_id}),
        ReconCommand::Start(args) => json!(args.request()),
        ReconCommand::Stop(args) => json!({"session_id":args.session_id,"id":args.id}),
    }
}

fn recon_api_preview(command: &ReconCommand) -> Value {
    match command {
        ReconCommand::List(args) => api_preview(
            "GET",
            session_query_path("/api/recon", Some(args.session_id)),
            None,
        ),
        ReconCommand::Start(args) => {
            api_preview("POST", "/api/recon/jobs", Some(json!(args.request())))
        }
        ReconCommand::Stop(args) => api_preview(
            "POST",
            format!("/api/recon/jobs/{}/stop", args.id),
            Some(json!({"session_id":args.session_id})),
        ),
    }
}

async fn discover_recon_api(cli_api: Option<String>) -> Result<ApiClient> {
    // A redirect or transport retry must never repeat a submission elsewhere.
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(CLI_API_TIMEOUT)
        .build()
        .context("failed to build Recon API client")?;
    let base_url = discover_api_base_url(cli_api, &client).await?;
    Ok(ApiClient {
        base_url,
        client: client.clone(),
        long_client: client,
        session_metadata_write_errors: false,
    })
}

#[derive(Debug)]
struct ReconCliError {
    code: &'static str,
    status: Option<u16>,
    write: bool,
}

impl fmt::Display for ReconCliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.code {
            "HTTP_STATUS_ERROR" => "Recon API returned a non-success status",
            "INVALID_RESPONSE" => "Recon API returned an invalid or mismatched response",
            _ => "Recon API request failed or timed out",
        })
    }
}
impl std::error::Error for ReconCliError {}

async fn recon_request<T: DeserializeOwned>(
    api: &ApiClient,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<T> {
    let write = method == Method::POST;
    let error = |code, status| ReconCliError {
        code,
        status,
        write,
    };
    let mut request = api.client.request(method, api.url(path));
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request
        .send()
        .await
        .map_err(|_| error("API_REQUEST_FAILED", None))?;
    if !response.status().is_success() {
        // Do not echo provider diagnostics or raw URLs in failure envelopes.
        return Err(error("HTTP_STATUS_ERROR", Some(response.status().as_u16())).into());
    }
    response
        .json()
        .await
        .map_err(|_| error("INVALID_RESPONSE", None).into())
}

#[derive(Deserialize, Serialize)]
struct ReconInventory {
    session_id: Uuid,
    jobs: Vec<ReconJob>,
    endpoints: Vec<ReconEndpoint>,
}

#[derive(Deserialize, Serialize)]
struct ReconStopped {
    session_id: Uuid,
    stopped: bool,
}

async fn handle_recon(api: ApiClient, command: ReconCommand) -> Result<()> {
    let session_id = command.session_id();
    let invalid = |write| ReconCliError {
        code: "INVALID_RESPONSE",
        status: None,
        write,
    };
    match command {
        ReconCommand::List(_) => {
            let inventory: ReconInventory = recon_request(
                &api,
                Method::GET,
                &session_query_path("/api/recon", Some(session_id)),
                None,
            )
            .await?;
            if inventory.session_id != session_id {
                return Err(invalid(false).into());
            }
            print_session_read_json(&inventory, session_id)
        }
        ReconCommand::Start(args) => {
            let job: ReconJob = recon_request(
                &api,
                Method::POST,
                "/api/recon/jobs",
                Some(json!(args.request())),
            )
            .await?;
            if job.target_url != args.target_url
                || job
                    .sources
                    .iter()
                    .map(|source| &source.source)
                    .ne(args.sources.iter())
            {
                return Err(invalid(true).into());
            }
            print_session_read_json(&job, session_id)
        }
        ReconCommand::Stop(args) => {
            let stopped: ReconStopped = recon_request(
                &api,
                Method::POST,
                &format!("/api/recon/jobs/{}/stop", args.id),
                Some(json!({"session_id":session_id})),
            )
            .await?;
            if stopped.session_id != session_id || !stopped.stopped {
                return Err(invalid(true).into());
            }
            print_session_read_json(&stopped, session_id)
        }
    }
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

fn intercept_rule_update_output_schema(operation: &str) -> Option<Value> {
    matches!(operation, "capture.intercept_rule.update" | "capture.intercept_rule.set_enabled").then(|| json!({
        "type":"object", "additionalProperties":false,
        "required":["id","session_id","enabled","scope","host_pattern","path_pattern","method_filter"],
        "properties":{
            "id":{"type":"string","format":"uuid"},
            "session_id":{"type":"string","format":"uuid"},
            "enabled":{"type":"boolean"},
            "scope":{"type":"string","enum":["request","response","both"]},
            "host_pattern":{"type":"string"}, "path_pattern":{"type":"string"},
            "method_filter":{"type":"array","items":{"type":"string"}}
        }
    }))
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
        output_schema: intercept_rule_update_output_schema(operation)
            .or_else(|| replay_saved_tab_output_schema(operation))
            .or_else(|| service_map_output_schema(operation))
            .or_else(|| recon_output_schema(operation))
            .or_else(|| scanner_output_schema(operation))
            .or_else(|| upstream_peer_output_schema(operation))
            .or_else(|| history_retention_output_schema(operation))
            .or_else(|| session_list_output_schema(operation))
            .or_else(|| session_read_output_schema(operation))
            .or_else(|| skills_status_output_schema(operation))
            .or_else(|| examples_output_schema(operation))
            .or_else(|| history_list_output_schema(operation))
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

fn templates_input_schema(operation: &str) -> Option<Value> {
    let filter = json!({
        "search":{"type":["string","null"],"maxLength":200,"description":"Substring of an id, name, path, tag or CVE, case-insensitive."},
        "severity":{"type":["string","null"],"maxLength":200,"description":"Comma-separated severities: info, low, medium, high, critical, unknown."},
        "tag":{"type":["string","null"],"maxLength":200,"description":"One exact tag, case-insensitive."}
    });
    let empty = json!({"type":"object","additionalProperties":false,"required":[],"properties":{}});
    Some(match operation {
        "templates.library.status" | "templates.library.check" | "templates.library.download" => {
            empty
        }
        "templates.library.import" => json!({
            "type":"object","additionalProperties":false,"required":["file"],
            "properties":{"file":{"type":"string","minLength":1,"description":"Path to a nuclei-templates release .tar.gz on this machine, at most 64 MiB."}}
        }),
        "templates.list" => {
            let mut properties = filter;
            properties["protocol"] = json!({"type":["string","null"],"maxLength":200,"description":"Comma-separated protocols: http, dns, network, code and the rest."});
            properties["support"] = json!({"type":["string","null"],"enum":["passive","active","unsupported",null],"description":"Templates Sniper can run passively or actively, or neither. Omitted or null lists all."});
            properties["enabled"] = json!({"type":["boolean","null"],"description":"Only passive templates that are on (true) or off (false)."});
            properties["sort"] = json!({"type":["string","null"],"enum":["on","severity","name","mode","tags",null],"description":"The column to sort by. Omitted or null lists templates Sniper can run first."});
            properties["direction"] = json!({"type":["string","null"],"enum":["asc","desc",null],"description":"asc (the default; the most severe first for severity) or desc."});
            properties["limit"] = json!({"type":["integer","null"],"minimum":1,"maximum":30000,"default":200,"description":"Page size. Null uses 200."});
            properties["offset"] = json!({"type":["integer","null"],"minimum":0,"default":0,"description":"Templates to skip. Null uses 0."});
            json!({"type":"object","additionalProperties":false,"required":[],"properties":properties})
        }
        "templates.get" => json!({
            "type":"object","additionalProperties":false,"required":["id"],
            "properties":{"id":{"type":"string","minLength":1,"maxLength":200,"pattern":"^([a-zA-Z0-9]+[-_])*[a-zA-Z0-9]+$","description":"Template id."}}
        }),
        "templates.scan.preview" | "templates.scan.start" => {
            let mut properties = filter;
            properties["session_id"] = legacy_uuid_input_schema(
                true,
                "The session to scan in; omitted or null selects the active session.",
            );
            properties["targets"] = json!({"type":"array","minItems":1,"maxItems":20,"items":{"type":"string","minLength":1,"maxLength":2048},"description":"http(s) origins, optionally with a path, without credentials, query or fragment; each host must be in a non-empty Scope include list."});
            properties["ids"] = json!({"type":["array","null"],"items":{"type":"string","pattern":"^([a-zA-Z0-9]+[-_])*[a-zA-Z0-9]+$"},"maxItems":30000,"description":"Template ids. Exactly one of ids or a filter (search, severity, tag)."});
            properties["allow_risks"] = json!({"type":["array","null"],"items":{"type":"string","enum":["intrusive","default-login","bruteforce","token-spray","credential-stuffing","fuzz","fuzzing","dast","osint","method:put","method:delete","method:patch"]},"description":"Risks to allow by name; templates with any other risk are left out. dos never runs."});
            properties["rate"] = json!({"type":["integer","null"],"minimum":1,"maximum":50,"default":10,"description":"Requests a second across the scan. Null uses 10."});
            properties["concurrency"] = json!({"type":["integer","null"],"minimum":1,"maximum":8,"default":4,"description":"Templates in flight at once. Null uses 4."});
            properties["max_requests"] = json!({"type":["integer","null"],"minimum":1,"maximum":50000,"default":10000,"description":"The most requests the scan sends, redirects included. Null uses 10000."});
            properties["apply_match_replace"] = json!({"type":["boolean","null"],"default":false,"description":"Apply the session's Match & Replace rules; a request a rule would send elsewhere is not sent."});
            json!({"type":"object","additionalProperties":false,"required":["targets"],"properties":properties})
        }
        "templates.scan.list" => json!({
            "type":"object","additionalProperties":false,"required":[],
            "properties":{"session_id":legacy_uuid_input_schema(true, "Omitted or null selects the active session.")}
        }),
        "templates.scan.get" | "templates.scan.stop" => json!({
            "type":"object","additionalProperties":false,"required":["id"],
            "properties":{
                "session_id":legacy_uuid_input_schema(true, "Omitted or null selects the active session."),
                "id":legacy_uuid_input_schema(false, "Scan id.")
            }
        }),
        "templates.passive.set_enabled" => {
            let mut properties = filter;
            properties["enabled"] = json!({"type":"boolean","description":"Turn the selected templates on (true) or off (false)."});
            properties["ids"] = json!({"type":["array","null"],"items":{"type":"string","pattern":"^([a-zA-Z0-9]+[-_])*[a-zA-Z0-9]+$"},"maxItems":30000,"description":"Template ids. Exactly one of ids, a filter (search, severity, tag) or all."});
            properties["all"] = json!({"type":["boolean","null"],"default":false,"description":"Every passive-capable template."});
            json!({"type":"object","additionalProperties":false,"required":["enabled"],"properties":properties})
        }
        _ => return None,
    })
}

fn examples_output_schema(operation: &str) -> Option<Value> {
    if operation != "examples" {
        return None;
    }
    let specific = json!({
        "type":"object", "additionalProperties":false,
        "required":["operation","examples"],
        "properties":{
            "operation":{"type":"string"},
            "examples":{"type":"array","items":{}}
        }
    });
    let mut catalog_item = specific.clone();
    catalog_item["properties"]["command"] = json!({"type":"string"});
    catalog_item["required"]
        .as_array_mut()?
        .push(json!("command"));
    Some(json!({
        "description":"Example inputs returned in the envelope data field: a catalog array when operation is omitted or null, or an object for one operation.",
        "oneOf":[
            {"type":"array","items":catalog_item},
            specific
        ]
    }))
}

fn history_list_output_schema(operation: &str) -> Option<Value> {
    if operation != "capture.http.list" {
        return None;
    }
    let mut item = sniper::saved_contract::transaction_summary_schema();
    item["properties"]["label"] = json!({"type":"string"});
    item["required"].as_array_mut()?.push(json!("label"));
    let items = json!({"type":"array","items":item});
    let count = json!({"type":["integer","null"],"minimum":0});
    Some(json!({
        "description":"Labeled transaction summaries returned in the envelope data field. Only page=true includes pagination metadata; sorting, offset and cursor options alone still return an array. Unavailable page metadata is null.",
        "oneOf":[
            items,
            {
                "type":"object", "additionalProperties":false,
                "required":["items","total","filtered_total","hidden_connect_total","offset","limit","has_more"],
                "properties":{
                    "items":items,
                    "total":count,"filtered_total":count,"hidden_connect_total":count,
                    "offset":count,"limit":count,"has_more":{"type":["boolean","null"]}
                }
            }
        ]
    }))
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

// A root override must never silently fall back to another agent's default root.
fn skill_root_selection_schema() -> Value {
    let constraints: Vec<Value> = [("codex", "codex_dir"), ("claude", "claude_dir")]
        .into_iter()
        .map(|(agent, root)| {
            json!({"anyOf":[
                {"properties":{root:{"type":"null"}}},
                {"required":[agent],"properties":{agent:{"const":true}}},
                {"required":["all"],"properties":{"all":{"const":true}}},
            ]})
        })
        .collect();
    json!(constraints)
}

// Legacy Uuid arguments accept spellings that strict JSON Schema uuid formats reject.
fn legacy_uuid_input_schema(nullable: bool, context: &str) -> Value {
    json!({
        "type": if nullable { json!(["string", "null"]) } else { json!("string") },
        "description": format!("UUID: hyphenated, 32 hexadecimal digits, braced hyphenated, or lowercase urn:uuid: prefix followed by a hyphenated UUID. Hexadecimal digits may use either case. {context}")
    })
}

fn input_schema(operation: &str, required_fields: &[&'static str]) -> Value {
    if matches!(
        operation,
        "capture.intercept.get" | "capture.intercept.wait" | "capture.response_intercept.wait"
    ) {
        let mut schema = json!({"type":"object","additionalProperties":false,"required":required_fields,
            "properties":{"session_id":legacy_uuid_input_schema(true, "Read this session without switching it; omitted or null selects the active session.")}});
        if operation.ends_with(".get") {
            schema["properties"]["id"] = legacy_uuid_input_schema(false, "Held request UUID.");
        } else {
            schema["properties"]["timeout"] = json!({"type":["integer","null"],"minimum":0,"maximum":u64::MAX,"default":30,"description":"Polling timeout in seconds; must fit the host's monotonic clock. Zero checks once. Omission or null uses 30."});
            schema["properties"]["poll_interval"] = json!({"type":["integer","null"],"minimum":0,"maximum":u64::MAX,"default":200,"description":"Polling interval in milliseconds, clamped to at least 25 and the remaining polling budget. Omission or null uses 200."});
        }
        return schema;
    }
    if let Some(schema) = service_map_input_schema(operation) {
        return schema;
    }
    if let Some(schema) = upstream_peer_input_schema(operation) {
        return schema;
    }
    if let Some(schema) = history_retention_input_schema(operation) {
        return schema;
    }
    if matches!(operation, "skills.install" | "skills.status") {
        return json!({
            "type":"object", "additionalProperties":false, "required":[],
            "properties":{
                "codex":{"type":["boolean","null"],"default":false},
                "claude":{"type":["boolean","null"],"default":false},
                "all":{"type":["boolean","null"],"default":false},
                "codex_dir":{"type":["string","null"],"minLength":1,"pattern":"^[^\\u0000]*$","description":"Codex skills root on the CLI host; requires the matching agent selector (or all where supported); omission or null uses the selected agent’s install default."},
                "claude_dir":{"type":["string","null"],"minLength":1,"pattern":"^[^\\u0000]*$","description":"Claude skills root on the CLI host; requires the matching agent selector (or all where supported); omission or null uses the selected agent’s install default."}
            },
            "allOf":skill_root_selection_schema(),
            "anyOf":[
                {"required":["codex"],"properties":{"codex":{"const":true}}},
                {"required":["claude"],"properties":{"claude":{"const":true}}},
                {"required":["all"],"properties":{"all":{"const":true}}}
            ]
        });
    }
    if matches!(
        operation,
        "replay.close" | "replay.duplicate" | "replay.set_pinned"
    ) {
        let mut schema = json!({
            "type":"object", "additionalProperties":false, "required":["tab_id"],
            "properties":{
                "tab_id":{"type":"string","minLength":1,"maxLength":128,"pattern":"\\S","description":"Exact saved HTTP tab ID; nonblank, at most 128 UTF-8 bytes, never trimmed or treated as a label."},
                "session_id":legacy_uuid_input_schema(false, "Selected saved session, including inactive sessions. Omission pins the active session once.")
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
    if matches!(
        operation,
        "capture.intercept_rule.update" | "capture.intercept_rule.set_enabled"
    ) {
        let mut schema = json!({
            "type":"object", "additionalProperties":false, "required":required_fields,
            "properties":{
                "id":legacy_uuid_input_schema(false, "Existing rule UUID; missing IDs never create a rule."),
                "session_id":legacy_uuid_input_schema(false, "Select a saved session without switching it; omission pins the active session."),
                "enabled":{"type":"boolean","description":"Desired enabled state, never a toggle."}
            }
        });
        if operation == "capture.intercept_rule.update" {
            for (key, value) in [
                (
                    "scope",
                    json!({"type":"string","enum":["request","response","both"]}),
                ),
                (
                    "host_pattern",
                    json!({"type":"string","description":"Replacement host pattern. Empty string clears; omission preserves."}),
                ),
                (
                    "path_pattern",
                    json!({"type":"string","description":"Replacement path pattern. Empty string clears; omission preserves."}),
                ),
                (
                    "method_filter",
                    json!({"type":"array","items":{"type":"string"},"description":"Replacement method list. Empty array clears; omission preserves."}),
                ),
                (
                    "clear_methods",
                    json!({"type":"boolean","default":false,"description":"Clear the method list; conflicts with method_filter even when empty."}),
                ),
            ] {
                schema["properties"][key] = value;
            }
            schema["anyOf"] = json!([
                {"required":["scope"]}, {"required":["host_pattern"]}, {"required":["path_pattern"]},
                {"required":["method_filter"]}, {"required":["enabled"]},
                {"required":["clear_methods"],"properties":{"clear_methods":{"const":true}}}
            ]);
            schema["not"] = json!({"required":["method_filter","clear_methods"],"properties":{"clear_methods":{"const":true}}});
        }
        return schema;
    }
    if let Some(schema) = recon_input_schema(operation) {
        return schema;
    }
    if let Some(schema) = scanner_input_schema(operation, required_fields) {
        return schema;
    }
    if let Some(schema) = templates_input_schema(operation) {
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
    if operation == "capture.http.list" {
        let mut sort_keys: Vec<Value> = HISTORY_SORT_KEYS.into_iter().map(Value::from).collect();
        sort_keys.push(Value::Null);
        properties.insert("sort_key".into(), json!({
            "type":["string","null"],"enum":sort_keys,
            "description":"Sort key for paged history output. Omission or null uses the server's default order."
        }));
    }
    if operation == "examples" {
        properties.insert("operation".into(), json!({
            "type":["string","null"],
            "description":"Operation to show examples for; omitted or null lists all operations."
        }));
    }
    if operation == "schema" {
        properties.insert(
            "kind".into(),
            json!({"type":"string","enum":["input","output"]}),
        );
        properties.insert(
            "operation".into(),
            json!({
                "type":"string","description":"Operation name from the CLI manifest."
            }),
        );
    }
    if operation == "session.create" {
        properties.insert("name".into(), json!({
            "type":["string","null"],
            "description":"The server trims the name and limits it to 256 UTF-8 bytes after trimming. Omitted, null, empty or whitespace-only names use the server's timestamp-based default."
        }));
    }
    if matches!(
        operation,
        "session.switch" | "session.delete" | "session.reveal"
    ) {
        properties.insert(
            "id".into(),
            legacy_uuid_input_schema(false, "Session UUID."),
        );
    }
    if operation == "replay.list" {
        properties.insert(
            "session_id".into(),
            legacy_uuid_input_schema(
                true,
                "Session UUID. Omitted or null selects the active session.",
            ),
        );
    }
    if session_read_output_schema(operation).is_some() {
        properties.insert(
            "session_id".into(),
            legacy_uuid_input_schema(
                true,
                "Read this session without switching it; omitted or null pins the active session.",
            ),
        );
        if properties.contains_key("id") {
            properties.insert(
                "id".into(),
                legacy_uuid_input_schema(false, "Finding UUID."),
            );
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
    if operation == "session.rename" {
        properties.insert(
            "id".into(),
            legacy_uuid_input_schema(false, "Session UUID."),
        );
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
        "skills.install" | "skills.status" => {
            &["codex", "claude", "all", "codex_dir", "claude_dir"]
        }
        "session.create" => &["name"],
        "session.rename" => &["id", "name"],
        "findings.list" | "event_log.list" => &["session_id", "limit"],
        "findings.get" => &["id", "session_id"],
        "findings.count" => &["session_id"],
        "recon.list" => &["session_id"],
        "recon.stop" => &["session_id", "id"],
        "recon.start" => &[
            "session_id",
            "target_url",
            "include_subdomains",
            "sources",
            "max_requests",
            "max_depth",
            "max_endpoints",
            "max_pages",
            "history_acknowledged",
            "scan_acknowledged",
            "scan_visibility",
        ],
        "scanner.config.get" | "scanner.custom.list" => &["session_id"],
        "scanner.config.set_enabled" => &["session_id", "enabled"],
        "scanner.builtin.set_enabled" => &["session_id", "id", "enabled"],
        "scanner.custom.get" | "scanner.custom.delete" => &["session_id", "id"],
        "scanner.custom.create" => &["session_id", "rule", "file", "stdin"],
        "scanner.custom.update" => &["session_id", "id", "patch", "file", "stdin"],
        "capture.http.upstream_peer.get" => &["session_id"],
        "capture.http.upstream_peer.set" => &["session_id", "enabled"],
        "capture.http.retention.get" => &["session_id"],
        "capture.http.retention.set" => &["session_id", "off", "max_entries"],
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
        "templates.library.status" | "templates.library.check" | "templates.library.download" => {
            &[]
        }
        "templates.library.import" => &["file"],
        "templates.list" => &[
            "search",
            "severity",
            "tag",
            "protocol",
            "support",
            "enabled",
            "sort",
            "direction",
            "limit",
            "offset",
        ],
        "templates.get" => &["id"],
        "templates.passive.set_enabled" => &["enabled", "ids", "search", "severity", "tag", "all"],
        "templates.scan.preview" | "templates.scan.start" => &[
            "session_id",
            "targets",
            "ids",
            "search",
            "severity",
            "tag",
            "allow_risks",
            "rate",
            "concurrency",
            "max_requests",
            "apply_match_replace",
        ],
        "templates.scan.list" => &["session_id"],
        "templates.scan.get" | "templates.scan.stop" => &["session_id", "id"],
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
        "target.service_map.get" => &[
            "session_id",
            "origin",
            "in_scope_only",
            "max_records",
            "all_rows",
            "technology_catalog_version",
            "mime_types",
            "status_classes",
            "hidden_extensions",
            "hide_without_responses",
            "only_parameterized",
        ],
        "target.service_map.evidence.get" => &[
            "session_id",
            "evidence_id",
            "include_socket_peer",
            "technology_catalog_version",
        ],
        "target.service_map.body_references.get"
        | "target.service_map.html_generators.get"
        | "target.service_map.link_declarations.get" => &["session_id", "evidence_id"],
        "target.service_map.parameters.get" => &["session_id", "origin", "method", "path"],
        "target.service_map.openapi.get" => &["session_id", "origin"],
        "target.service_map.flow.get" => &["session_id", "origin", "in_scope_only", "max_records"],
        "target.service_map.unnamed.get" => &["session_id", "kind", "limit"],
        "target.service_map.socket_peer_matches.get" => {
            &["session_id", "evidence_id", "in_scope_only", "max_records"]
        }
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
        "fuzzer.run" => &[
            "session_id",
            "async",
            "r#async",
            "attack_type",
            "raw_payloads",
            "concurrency",
        ],
        "fuzzer.status" | "fuzzer.results" | "fuzzer.stop" => &["id", "session_id"],
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
        "capture.intercept.get" => &["id", "session_id"],
        "capture.intercept.wait" | "capture.response_intercept.wait" => {
            &["session_id", "timeout", "poll_interval"]
        }
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
        "capture.intercept_rule.set_enabled" => &["id", "session_id", "enabled"],
        "capture.intercept_rule.update" => &[
            "id",
            "session_id",
            "scope",
            "host_pattern",
            "path_pattern",
            "method_filter",
            "clear_methods",
            "enabled",
        ],
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
        Command::Recon { command } => recon_input_preview(command),
        Command::Scanner { command } => scanner_input_preview(command),
        Command::Templates { command } => templates_input_preview(command),
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
            TargetCommand::ServiceMap(args) => match &args.command {
                Some(ServiceMapCommand::BodyReferences(args)) => json!({
                    "session_id": args.session_id,"evidence_id":args.evidence_id,
                }),
                Some(ServiceMapCommand::HtmlGenerators(args)) => json!({
                    "session_id": args.session_id,"evidence_id":args.evidence_id,
                }),
                Some(ServiceMapCommand::LinkDeclarations(args)) => json!({
                    "session_id": args.session_id,"evidence_id":args.evidence_id,
                }),
                Some(ServiceMapCommand::SocketPeerMatches(args)) => json!({
                    "session_id":args.session_id,"evidence_id":args.evidence_id,
                    "in_scope_only":args.in_scope_only,"max_records":args.max_records,
                }),
                Some(ServiceMapCommand::Parameters(args)) => json!({
                    "session_id":args.session_id,"origin":args.origin,
                    "method":args.method,"path":args.path,
                }),
                Some(ServiceMapCommand::Openapi(args)) => json!({
                    "session_id":args.session_id,"origin":args.origin,
                }),
                Some(ServiceMapCommand::Flow(args)) => json!({
                    "session_id":args.session_id,"origin":args.origin,
                    "in_scope_only":args.in_scope_only,"max_records":args.max_records,
                }),
                Some(ServiceMapCommand::Unnamed(args)) => json!({
                    "session_id":args.session_id,"kind":args.kind,"limit":args.limit,
                }),
                None => {
                    let mut preview = json!({
                        "session_id": args.session_id,
                        "in_scope_only": args.in_scope_only,
                        "origin": args.origin,
                        "max_records": args.max_records,
                        "technology_catalog_version": args.technology_catalog_version,
                    });
                    // A whole-history read has no row window to show.
                    if args.all_rows {
                        preview["all_rows"] = json!(true);
                        preview
                            .as_object_mut()
                            .map(|fields| fields.remove("max_records"));
                    }
                    preview
                }
            },
            TargetCommand::ServiceMapEvidence(args) => json!({
                "session_id": args.session_id,
                "evidence_id": args.evidence_id,
                "include_socket_peer": args.include_socket_peer,
                "technology_catalog_version": args.technology_catalog_version,
            }),
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
        Command::Skills {
            command: SkillsCommand::Install(args) | SkillsCommand::Status(args),
        } => json!({
            "codex": args.codex,
            "claude": args.claude,
            "all": args.all,
            "codex_dir": args.codex_dir,
            "claude_dir": args.claude_dir,
        }),
        Command::History { command } => history_input_preview(command),
        Command::Intercept { command } => intercept_input_preview(command),
        Command::Websocket { command } => websocket_input_preview(command),
        Command::AutoReplace { command } => auto_replace_input_preview(command),
    }
}

fn history_input_preview(command: &HistoryCommand) -> Value {
    match command {
        HistoryCommand::UpstreamPeer { command } => match command {
            UpstreamPeerCommand::Get(args) => json!({"session_id":args.session_id}),
            UpstreamPeerCommand::Set(args) => {
                json!({"session_id":args.session_id,"enabled":args.enabled})
            }
        },
        HistoryCommand::Retention { command } => match command {
            HistoryRetentionCommand::Get(args) => json!({"session_id":args.session_id}),
            HistoryRetentionCommand::Set(args) => {
                let mut input = json!({"session_id":args.session_id});
                if args.off {
                    input["off"] = json!(true);
                } else {
                    input["max_entries"] = json!(args.max_entries);
                }
                input
            }
        },
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
        FuzzerCommand::Run(args) => json!({
            "session_id": args.session_id,
            "async": args.r#async,
            "attack_type": args.attack_type.api_name(),
            "raw_payloads": args.raw_payloads,
            "concurrency": args.concurrency,
        }),
        FuzzerCommand::Status(args) | FuzzerCommand::Stop(args) => {
            json!({ "id": args.id, "session_id": args.session_id })
        }
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
            json!({ "session_id": args.session_id, "timeout": args.timeout, "poll_interval": args.poll_interval })
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
            json!({ "session_id": args.session_id, "timeout": args.timeout, "poll_interval": args.poll_interval })
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
        InterceptRuleCommand::Update(args) => {
            let mut input = args.patch();
            input["id"] = json!(args.id);
            if let Some(session_id) = args.session_id {
                input["session_id"] = json!(session_id);
            }
            input
        }
        InterceptRuleCommand::SetEnabled(args) => {
            let mut input = json!({"id":args.id,"enabled":args.enabled});
            if let Some(session_id) = args.session_id {
                input["session_id"] = json!(session_id);
            }
            input
        }
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
        Command::Recon { command } => recon_api_preview(command),
        Command::Scanner { command } => scanner_api_preview(command),
        Command::Templates { command } => templates_api_preview(command),
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
            TargetCommand::ServiceMap(args) => match &args.command {
                Some(ServiceMapCommand::BodyReferences(args)) => {
                    api_preview("GET", service_map_body_references_path(args), None)
                }
                Some(ServiceMapCommand::HtmlGenerators(args)) => {
                    api_preview("GET", service_map_html_generators_path(args), None)
                }
                Some(ServiceMapCommand::Parameters(args)) => {
                    api_preview("GET", service_map_parameters_path(args), None)
                }
                Some(ServiceMapCommand::Openapi(args)) => {
                    api_preview("GET", service_map_openapi_path(args), None)
                }
                Some(ServiceMapCommand::Flow(args)) => {
                    api_preview("GET", service_map_flow_path(args), None)
                }
                Some(ServiceMapCommand::Unnamed(args)) => service_map_catalog_api_preview(
                    service_map_path(&args.map_args(), args.session_id),
                    2,
                ),
                Some(ServiceMapCommand::LinkDeclarations(args)) => {
                    api_preview("GET", service_map_link_declarations_path(args), None)
                }
                Some(ServiceMapCommand::SocketPeerMatches(args)) => {
                    api_preview("GET", service_map_socket_peer_matches_path(args), None)
                }
                None => service_map_catalog_api_preview(
                    service_map_path(args, args.session_id),
                    args.technology_catalog_version,
                ),
            },
            TargetCommand::ServiceMapEvidence(args) => service_map_catalog_api_preview(
                service_map_evidence_path(args),
                args.technology_catalog_version,
            ),
            TargetCommand::GetScope(args) => api_preview(
                "GET",
                session_query_path("/api/runtime", args.session_id),
                None,
            ),
            // The run replaces the whole list; null here read as "keep the
            // current scope". A file or stdin is named, not read: a dry run
            // stays offline and must not consume stdin.
            TargetCommand::SetScope(args) => api_preview(
                "POST",
                "/api/runtime",
                Some(json!({
                    "session_id": args.session_id,
                    "scope_patterns": if args.clear {
                        json!([])
                    } else if let Some(file) = &args.file {
                        json!({ "replaced_by_lines_of": file })
                    } else if args.stdin {
                        json!({ "replaced_by_lines_of": "stdin" })
                    } else {
                        json!(args.patterns)
                    },
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
        HistoryCommand::UpstreamPeer { command } => upstream_peer_api_preview(command),
        HistoryCommand::Retention { command } => history_retention_api_preview(command),
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
        ReplayCommand::Update(args) if replay_update_is_label_only(args) => api_preview(
            "POST",
            "/api/replay/tabs/set-label",
            Some(json!({
                "tab_id":args.tab_id,
                "label":normalize_replay_tab_label(args.label.as_deref().unwrap()),
                "session_id":args.session_id.map(|id| json!(id)).unwrap_or_else(|| json!("<resolved active session ID>")),
                "expected_workspace_revision":"<loaded workspace revision>",
                "note":"changes only the saved label on an existing HTTP or WebSocket tab; no traffic is sent"
            })),
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
            Some(json!({ "note": "starts payload-generated HTTP requests in the background" })),
        ),
        FuzzerCommand::Stop(args) => api_preview(
            "POST",
            format!("/api/fuzzer/attacks/{}/stop", args.id),
            Some(json!({ "session_id": args.session_id })),
        ),
        FuzzerCommand::Status(args) => api_preview(
            "GET",
            session_query_path(&format!("/api/fuzzer/attacks/{}", args.id), args.session_id),
            None,
        ),
        // The attack record carries its results; there is no `/results` route.
        FuzzerCommand::Results(args) => api_preview(
            "GET",
            session_query_path(&format!("/api/fuzzer/attacks/{}", args.id), args.session_id),
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
        // The rule as it is sent; its id is minted when the command runs.
        InterceptRuleCommand::Create(args) => api_preview(
            "POST",
            session_query_path("/api/intercept-rules", args.session_id),
            Some(json!({
                "id": "<new uuid>",
                "enabled": args.enabled.unwrap_or(true),
                "scope": args.scope,
                "host_pattern": args.host_pattern.clone().unwrap_or_default(),
                "path_pattern": args.path_pattern.clone().unwrap_or_default(),
                "method_filter": args.method_filter,
            })),
        ),
        InterceptRuleCommand::Update(args) => api_preview(
            "PATCH",
            session_query_path(
                &format!("/api/intercept-rules/{}", args.id),
                args.session_id,
            ),
            Some(args.patch()),
        ),
        InterceptRuleCommand::SetEnabled(args) => api_preview(
            "PATCH",
            session_query_path(
                &format!("/api/intercept-rules/{}", args.id),
                args.session_id,
            ),
            Some(json!({"enabled": args.enabled})),
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
        // Both send the session in the body, which is where the server reads it.
        SequenceCommand::Create(args) => api_preview(
            "POST",
            "/api/sequences",
            Some(json!({
                "session_id": args.session_id,
                "definition": "<sequence definition from file/stdin>",
            })),
        ),
        SequenceCommand::Run(args) => api_preview(
            "POST",
            &format!("/api/sequences/{}/run", args.id),
            Some(json!({ "session_id": args.session_id })),
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

fn service_map_catalog_api_preview(path: String, version: u32) -> Value {
    let mut preview = api_preview("GET", path, None);
    preview["headers"] = json!({(SERVICE_MAP_CATALOG_HEADER):version.to_string()});
    preview
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
    if matches!(
        command.operation_name(),
        "target.service_map.get"
            | "target.service_map.evidence.get"
            | "target.service_map.body_references.get"
            | "target.service_map.html_generators.get"
            | "target.service_map.link_declarations.get"
            | "target.service_map.socket_peer_matches.get"
            | "target.service_map.parameters.get"
            | "target.service_map.openapi.get"
            | "target.service_map.flow.get"
            | "target.service_map.unnamed.get"
    ) {
        if command.operation_name() == "target.service_map.flow.get" {
            notes.push("Reads the map's newest max_records rows without bodies in one GET; no target requests, automatic reads, retries or fallback.");
        } else if command.operation_name() == "target.service_map.unnamed.get" {
            notes.push("Reads the session's whole map, as `scope service-map --all-rows` does, and gathers its unnamed signals locally. snapshot preserves source-map coverage; omitted_signals counts only --limit truncation after --kind. One GET; no target requests, retries or fallback.");
            notes.push("Signals are banner values, header names and cookie names, never header or cookie values. Counts are origins and rows in this map; open the evidence tokens before naming anything.");
        } else if command.operation_name() == "target.service_map.openapi.get" {
            notes.push("Explicit read of every retained row of one origin in an already active session. One GET after identity checks; no target requests, inactive-session loading, automatic reads, retries or fallback.");
            notes.push("The document holds names, guessed types, statuses, media types and security schemes, never captured values. Parameters come from each operation's newest 20 rows, at most 32 MiB of retained rows per read; at most 500 operations are listed.");
        } else if command.operation_name() == "target.service_map.parameters.get" {
            notes.push("Explicit read of one endpoint's newest 200 retained rows in an already active session. One GET after identity checks; no target requests, inactive-session loading, automatic reads, retries or fallback.");
            notes.push("Values are shown as captured, each cut to 80 characters, and may hold credentials or personal data. Request bodies are parsed from their first 64 KiB, at most 32 MiB of retained rows per read; unread_bodies counts the rest, whose query strings still count.");
        } else if command.operation_name() == "target.service_map.socket_peer_matches.get" {
            notes.push("Explicit recorded direct socket peer equality inspection only. Requires an already active session and an unchanged exact source-row token. One feature GET after identity checks; no arbitrary address input, target requests, capture/settings changes, discovery, body/header reads, inactive loading, retries, redirects, or fallback.");
            notes.push("Counts are rows, including duplicate transaction UUIDs, within a latest retained sequence window and exclude the source. Inspect source.in_window, recorded timestamps, diagnostics, origin-group and sample omissions. Equal source/address-family/IP/port values do not prove a shared physical endpoint, deployment, ownership, or origin IP. Samples may become stale; no UUID-only fallback is permitted.");
        } else if command.operation_name() == "target.service_map.link_declarations.get" {
            notes.push("Explicit one-row retained response-header inspection only, with fixed relation catalog 1. Requires an already active session and retained GET/HEAD status 200 metadata. One inspection GET after identity checks, with no body reads, inactive loading, target requests, automatic/batch reads, retries, redirects, fallback, or technology-catalog selector.");
            notes.push("Only canonical origins, fixed relation names, bounded counters and original retained-header UTF-8 spans are returned. Multiple relations may share a member. Partial/unsupported does not mean no declarations exist; completeness applies only to the fixed literal grammar. Declarations do not establish calls, ownership, availability, or connections.");
        } else if command.operation_name() == "target.service_map.html_generators.get" {
            notes.push("Explicit one-row retained UTF-8 text/html preview read only, with fixed generator catalog 1. The session must already be active. One inspection GET after identity checks, with no target requests, inactive-session loading, automatic/batch reads, retries, fallback, or technology-catalog selector.");
            notes.push("Products and numeric versions are literal generator declarations, not proven software installations or ownership. Partial/unsupported never means no generator found. Inspect head_closed, complete, reasons, truncation and bounds. scan_prefix_bytes describes the offered prefix, not bytes fully parsed; parser_stop.byte_cursor may split UTF-8 and must not be used to slice text. No raw HTML or rejected declaration text is exposed.");
        } else if command.operation_name() == "target.service_map.body_references.get" {
            notes.push("Explicit one-row retained-preview read only. The session must already be active; an inactive session returns unavailable without being loaded or activated. No target requests, automatic reads, or batch reads.");
            notes.push("Literal absolute HTTP(S) references do not prove calls or ownership. Results expose canonical origins and retained UTF-8 preview byte offsets, never body text or full URLs. Completeness applies only to the supported bounded literal grammar.");
        } else {
            notes.push("Offline preview only. Execution reads retained metadata from one pinned session; it never probes, scans, replays, crawls, or follows service redirects.");
            notes.push("The API-only technology catalog header requests catalog 2 by default or explicit catalog 1. One target GET is made, with no negotiation retries or fallback requests. An unmarked legacy response is validated only as v1 and reports reduced coverage on stderr.");
            notes.push("Counts include retained rows with duplicate UUIDs. Inspect completeness and unavailable data; evidence tokens identify exact row states and never fall back to UUID-only lookup.");
        }
    }
    if command.requires_confirmation() {
        notes.push("Use --yes to apply this side-effecting operation after reviewing the dry-run.");
    }
    if matches!(
        command,
        Command::Session {
            command: SessionCommand::Create(_)
        }
    ) {
        notes.push("On success, the new session becomes the active session; this preview does not create or activate a session.");
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
        command.operation_name(),
        "capture.http.upstream_peer.get" | "capture.http.upstream_peer.set"
    ) {
        notes.push("Dry-run is fully offline. The explicit session must already be active; execution never switches or activates it. Discovery and settings reads do not inspect traffic or contact upstream services.");
        if command.operation_name().ends_with(".set") {
            notes.push("Execution performs one session-fenced configuration GET and one token-bound POST with expected_active_session_id. No redirects, automatic retry or uncertain-write readback. Inspect the same session's settings deliberately after an uncertain outcome.");
        }
        notes.push("Default Off. Eligibility is frozen before an ordinary captured HTTP(S) request's first send; eligible in-flight responses may finish after Off. No backfill, probes, Replay, WebSocket, CONNECT, rendered resources or TLS/DNS details. Observations persist in session files, exports and full-record JSON; Off does not erase them. A proxy, CDN or shared socket peer does not prove origin ownership or a backend chain.");
    }
    if matches!(
        command.operation_name(),
        "capture.http.retention.get" | "capture.http.retention.set"
    ) {
        notes.push("Dry-run is fully offline: no API discovery, session resolution, token read, history inspection or deletion count.");
        if command.operation_name() == "capture.http.retention.set" {
            notes.push("The exact requested policy is shown in api.write.body.policy. Write execution pins one session, fetches its policy-configuration config_token and sends one compare-and-swap write. An inferred session also carries expected_active_session_id. No redirect, automatic retry or uncertain-write readback is performed.");
        }
        notes.push("Off is the default. Keep-newest is a soft total-history target: oldest unprotected rows are removed first, while durable saved HTTP tab source originals and in-progress rows survive. Policy-save success does not mean pending logical or disk cleanup is finished.");
    }
    if let Command::Recon { command } = command {
        notes.push("Offline preview only; session existence and current job state are not checked. Explicit session_id never switches the active session.");
        notes.push("Recon URLs, raw spellings, evidence locations and warnings can contain sensitive paths or query values; summarize rather than paste them.");
        match command {
            ReconCommand::Start(_) => {
                notes.push("Only start against an authorized target. Crawler sends scoped unauthenticated GETs, which can still have side effects. Scope is host/scheme/port, not path; subdomains must be selected explicitly.");
                notes.push("History sends the target hostname to selected providers. urlscan_submit sends the full URL and triggers a remote browser that may load out-of-scope resources; unlisted is not private. Provider acknowledgments are separate from --yes.");
                notes.push("Zero budgets mean unbounded collection. Start returns a job immediately; the 60-second API timeout does not cancel it. Read recon list before any deliberate retry after an uncertain result; never resubmit automatically.");
            }
            ReconCommand::Stop(_) => notes.push("Stops local work only; an accepted urlscan submission cannot be cancelled. An already finished or unknown job may return not found; reread its state rather than assuming it is running."),
            ReconCommand::List(_) => notes.push("Reads all retained jobs and endpoints without target/provider requests. Check each source's status, truncated flag and warnings; history and candidate evidence do not prove current liveness."),
        }
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
    match command.operation_name() {
        "templates.library.check" | "templates.library.download" => notes.push("Contacts GitHub through the environment's proxy: the latest-release API, then for a download the release's checksums file and source .tar.gz. A download that does not match the published SHA-256 is not installed. Dry-run contacts nothing."),
        "templates.library.import" => notes.push("Reads the local .tar.gz and uploads it to the running Sniper, which installs it; nothing contacts GitHub. Dry-run reads nothing."),
        "templates.passive.set_enabled" => notes.push("Enabled passive templates judge captured responses whose host is in a non-empty Scope include list while Passive Scan is on, and never send requests. Run findings rescan to apply a change to stored history."),
        "templates.scan.start" => notes.push("Sends the templates' requests to the targets once it runs. Dry-run contacts nothing; templates scan preview asks Sniper what would be sent and still sends nothing to a target."),
        _ => {}
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
    // Local paths may contain words used by the legacy error classifier. Keep
    // input failures typed so those words cannot change the code or retry hint.
    load_call_input(source).map_err(Into::into)
}

fn load_call_input(source: Option<String>) -> std::result::Result<Value, CallInputError> {
    let Some(source) = source else {
        return Ok(json!({}));
    };
    let raw = if source == "-" {
        read_text_input(None, true).map_err(|error| CallInputError::Source(error.to_string()))?
    } else if let Some(path) = source.strip_prefix('@') {
        if path.is_empty() {
            return Err(CallInputError::Source(
                "call --input @ requires a file path".into(),
            ));
        }
        read_text_input(Some(PathBuf::from(path)), false)
            .map_err(|error| CallInputError::Source(error.to_string()))?
    } else {
        source
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_str(trimmed).map_err(|_| CallInputError::JsonSyntax)
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
        "skills.status" => Command::Skills {
            command: SkillsCommand::Status(SkillsInstallArgs {
                codex: call_bool(operation, input, "codex")?,
                claude: call_bool(operation, input, "claude")?,
                all: call_bool(operation, input, "all")?,
                codex_dir: call_optional_path(operation, input, "codex_dir")?,
                claude_dir: call_optional_path(operation, input, "claude_dir")?,
            }),
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
        "session.rename" => Command::Session {
            command: SessionCommand::Rename(SessionRenameArgs {
                id: call_required(operation, input, "id")?,
                name: call_required(operation, input, "name")?,
            }),
        },
        "capture.http.upstream_peer.get" | "capture.http.upstream_peer.set" => Command::Capture {
            command: CaptureCommand::Http {
                command: HistoryCommand::UpstreamPeer {
                    command: upstream_peer_from_input(operation, input)?,
                },
            },
        },
        "capture.http.retention.get" | "capture.http.retention.set" => Command::Capture {
            command: CaptureCommand::Http {
                command: HistoryCommand::Retention {
                    command: history_retention_from_input(operation, input)?,
                },
            },
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
                            &HISTORY_SORT_KEYS,
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
                    side: call_history_search_sides(operation, input)?,
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
        operation if operation.starts_with("recon.") => Command::Recon {
            command: recon_command_from_input(operation, input)?,
        },
        operation if operation.starts_with("scanner.") => Command::Scanner {
            command: scanner_command_from_input(operation, input)?,
        },
        "templates.library.status" => Command::Templates {
            command: TemplatesCommand::Library {
                command: TemplatesLibraryCommand::Status,
            },
        },
        "templates.library.check" => Command::Templates {
            command: TemplatesCommand::Library {
                command: TemplatesLibraryCommand::Check,
            },
        },
        "templates.library.download" => Command::Templates {
            command: TemplatesCommand::Library {
                command: TemplatesLibraryCommand::Download,
            },
        },
        "templates.library.import" => Command::Templates {
            command: TemplatesCommand::Library {
                command: TemplatesLibraryCommand::Import(TemplatesImportArgs {
                    file: call_required::<String>(operation, input, "file")?.into(),
                }),
            },
        },
        "templates.list" => {
            let limit = call_optional::<u64>(operation, input, "limit")?.unwrap_or(200);
            if !(1..=30_000).contains(&limit) {
                bail!("invalid field `limit` for `{operation}`; expected 1 to 30000");
            }
            Command::Templates {
                command: TemplatesCommand::List(TemplatesListArgs {
                    filter: call_templates_filter(operation, input)?,
                    protocol: call_optional(operation, input, "protocol")?,
                    support: call_optional_enum_string(
                        operation,
                        input,
                        "support",
                        &["passive", "active", "unsupported"],
                    )?,
                    enabled: call_optional(operation, input, "enabled")?,
                    sort: call_optional_enum_string(
                        operation,
                        input,
                        "sort",
                        &["on", "severity", "name", "mode", "tags"],
                    )?,
                    direction: call_optional_enum_string(
                        operation,
                        input,
                        "direction",
                        &["asc", "desc"],
                    )?,
                    limit,
                    offset: call_optional(operation, input, "offset")?.unwrap_or(0),
                }),
            }
        }
        "templates.get" => {
            let id: String = call_required(operation, input, "id")?;
            if !valid_template_id(&id) {
                bail!("invalid field `id` for `{operation}`");
            }
            Command::Templates {
                command: TemplatesCommand::Get(TemplatesGetArgs { id }),
            }
        }
        "templates.passive.set_enabled" => {
            let args = TemplatesPassiveArgs {
                enabled: call_required(operation, input, "enabled")?,
                ids: call_optional(operation, input, "ids")?.unwrap_or_default(),
                filter: call_templates_filter(operation, input)?,
                all: call_bool(operation, input, "all")?,
            };
            templates_passive_body(&args)?;
            Command::Templates {
                command: TemplatesCommand::Passive {
                    command: TemplatesPassiveCommand::SetEnabled(args),
                },
            }
        }
        "templates.scan.preview" | "templates.scan.start" => {
            let bounded = |field: &str, default: u64, max: u64| -> Result<u64> {
                let value = call_optional::<u64>(operation, input, field)?.unwrap_or(default);
                if !(1..=max).contains(&value) {
                    bail!("invalid field `{field}` for `{operation}`; expected 1 to {max}");
                }
                Ok(value)
            };
            let args = TemplatesScanArgs {
                session_id: call_optional(operation, input, "session_id")?,
                targets: call_required(operation, input, "targets")?,
                ids: call_optional(operation, input, "ids")?.unwrap_or_default(),
                filter: call_templates_filter(operation, input)?,
                allow_risks: call_optional(operation, input, "allow_risks")?.unwrap_or_default(),
                rate: bounded("rate", 10, 50)?,
                concurrency: bounded("concurrency", 4, 8)?,
                max_requests: bounded("max_requests", 10_000, 50_000)?,
                apply_match_replace: call_bool(operation, input, "apply_match_replace")?,
            };
            templates_scan_body(&args, None, true)?;
            let command = if operation == "templates.scan.preview" {
                TemplatesScanCommand::Preview(args)
            } else {
                TemplatesScanCommand::Start(args)
            };
            Command::Templates {
                command: TemplatesCommand::Scan { command },
            }
        }
        "templates.scan.list" => Command::Templates {
            command: TemplatesCommand::Scan {
                command: TemplatesScanCommand::List(TemplatesScanSessionArgs {
                    session_id: call_optional(operation, input, "session_id")?,
                }),
            },
        },
        "templates.scan.get" | "templates.scan.stop" => {
            let args = TemplatesScanIdArgs {
                session_id: call_optional(operation, input, "session_id")?,
                id: call_required(operation, input, "id")?,
            };
            let command = if operation == "templates.scan.get" {
                TemplatesScanCommand::Get(args)
            } else {
                TemplatesScanCommand::Stop(args)
            };
            Command::Templates {
                command: TemplatesCommand::Scan { command },
            }
        }
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
        "target.service_map.get" => {
            let all_rows = call_bool(operation, input, "all_rows")?;
            let explicit_max_records =
                call_optional_nonzero_usize(operation, input, "max_records")?;
            if all_rows && explicit_max_records.is_some() {
                bail!("field `all_rows` cannot be combined with `max_records`: it reads every retained row");
            }
            let max_records = explicit_max_records.unwrap_or(10_000);
            parse_service_map_max_records(&max_records.to_string())
                .map_err(|message| anyhow!(message))?;
            Command::Scope {
                command: TargetCommand::ServiceMap(ServiceMapArgs {
                    command: None,
                    session_id: call_optional(operation, input, "session_id")?,
                    in_scope_only: call_bool(operation, input, "in_scope_only")?,
                    origin: call_optional::<String>(operation, input, "origin")?
                        .map(|value| {
                            parse_service_map_origin(&value).map_err(|message| anyhow!(message))
                        })
                        .transpose()?,
                    max_records,
                    all_rows,
                    technology_catalog_version: call_service_map_catalog_version(input)?,
                    filter: ServiceMapFilterArgs {
                        mime_types: call_service_map_tokens(
                            operation,
                            input,
                            "mime_types",
                            &SERVICE_MAP_MIME_TYPES,
                        )?,
                        status_classes: call_service_map_tokens(
                            operation,
                            input,
                            "status_classes",
                            &SERVICE_MAP_STATUS_CLASSES,
                        )?,
                        hidden_extensions: call_optional::<Vec<String>>(
                            operation,
                            input,
                            "hidden_extensions",
                        )?
                        .unwrap_or_default()
                        .iter()
                        .map(|value| {
                            parse_service_map_extension(value).map_err(|message| anyhow!(message))
                        })
                        .collect::<Result<_>>()?,
                        hide_without_responses: call_bool(
                            operation,
                            input,
                            "hide_without_responses",
                        )?,
                        only_parameterized: call_bool(operation, input, "only_parameterized")?,
                    },
                }),
            }
        }
        "target.service_map.body_references.get" => {
            let evidence_id: String = call_required(operation, input, "evidence_id")?;
            let evidence_id =
                parse_service_map_evidence_id(&evidence_id).map_err(|message| anyhow!(message))?;
            Command::Scope {
                command: TargetCommand::ServiceMap(ServiceMapArgs {
                    command: Some(ServiceMapCommand::BodyReferences(
                        ServiceMapBodyReferencesArgs {
                            session_id: call_required(operation, input, "session_id")?,
                            evidence_id,
                        },
                    )),
                    session_id: None,
                    origin: None,
                    in_scope_only: false,
                    max_records: 10_000,
                    all_rows: false,
                    technology_catalog_version: 2,
                    filter: ServiceMapFilterArgs::default(),
                }),
            }
        }
        "target.service_map.unnamed.get" => {
            let kind: Option<String> = call_present(operation, input, "kind")?;
            if kind
                .as_deref()
                .is_some_and(|kind| !["banners", "headers", "cookies"].contains(&kind))
            {
                return Err(anyhow!("kind must be banners, headers or cookies"));
            }
            let limit: u32 = call_present(operation, input, "limit")?.unwrap_or(100);
            if !(1..=1000).contains(&limit) {
                return Err(anyhow!("limit must be between 1 and 1000"));
            }
            let args = ServiceMapUnnamedArgs {
                session_id: call_present(operation, input, "session_id")?,
                kind,
                limit,
            };
            Command::Scope {
                command: TargetCommand::ServiceMap(ServiceMapArgs {
                    command: Some(ServiceMapCommand::Unnamed(args)),
                    session_id: None,
                    origin: None,
                    in_scope_only: false,
                    max_records: 10_000,
                    all_rows: false,
                    technology_catalog_version: 2,
                    filter: ServiceMapFilterArgs::default(),
                }),
            }
        }
        "target.service_map.flow.get" => {
            let origin: String = call_required(operation, input, "origin")?;
            let max_records =
                call_optional::<usize>(operation, input, "max_records")?.unwrap_or(10_000);
            if !(1..=50_000).contains(&max_records) {
                bail!("max_records must be between 1 and 50000");
            }
            let args = ServiceMapFlowArgs {
                session_id: call_optional(operation, input, "session_id")?,
                origin: parse_service_map_origin(&origin).map_err(|message| anyhow!(message))?,
                in_scope_only: call_bool(operation, input, "in_scope_only")?,
                max_records,
            };
            Command::Scope {
                command: TargetCommand::ServiceMap(ServiceMapArgs {
                    command: Some(ServiceMapCommand::Flow(args)),
                    session_id: None,
                    origin: None,
                    in_scope_only: false,
                    max_records: 10_000,
                    all_rows: false,
                    technology_catalog_version: 2,
                    filter: ServiceMapFilterArgs::default(),
                }),
            }
        }
        "target.service_map.openapi.get" => {
            let origin: String = call_required(operation, input, "origin")?;
            let args = ServiceMapOpenApiArgs {
                session_id: call_required(operation, input, "session_id")?,
                origin: parse_service_map_origin(&origin).map_err(|message| anyhow!(message))?,
            };
            Command::Scope {
                command: TargetCommand::ServiceMap(ServiceMapArgs {
                    command: Some(ServiceMapCommand::Openapi(args)),
                    session_id: None,
                    origin: None,
                    in_scope_only: false,
                    max_records: 10_000,
                    all_rows: false,
                    technology_catalog_version: 2,
                    filter: ServiceMapFilterArgs::default(),
                }),
            }
        }
        "target.service_map.parameters.get" => {
            let text = |field: &str| -> Result<String> { call_required(operation, input, field) };
            let args = ServiceMapParametersArgs {
                session_id: call_required(operation, input, "session_id")?,
                origin: parse_service_map_origin(&text("origin")?)
                    .map_err(|message| anyhow!(message))?,
                method: parse_service_map_parameters_method(&text("method")?)
                    .map_err(|message| anyhow!(message))?,
                path: parse_service_map_parameters_path(&text("path")?)
                    .map_err(|message| anyhow!(message))?,
            };
            Command::Scope {
                command: TargetCommand::ServiceMap(ServiceMapArgs {
                    command: Some(ServiceMapCommand::Parameters(args)),
                    session_id: None,
                    origin: None,
                    in_scope_only: false,
                    max_records: 10_000,
                    all_rows: false,
                    technology_catalog_version: 2,
                    filter: ServiceMapFilterArgs::default(),
                }),
            }
        }
        "target.service_map.html_generators.get" => {
            let evidence_id: String = call_required(operation, input, "evidence_id")?;
            let evidence_id =
                parse_service_map_evidence_id(&evidence_id).map_err(|message| anyhow!(message))?;
            Command::Scope {
                command: TargetCommand::ServiceMap(ServiceMapArgs {
                    command: Some(ServiceMapCommand::HtmlGenerators(
                        ServiceMapHtmlGeneratorsArgs {
                            session_id: call_required(operation, input, "session_id")?,
                            evidence_id,
                        },
                    )),
                    session_id: None,
                    origin: None,
                    in_scope_only: false,
                    max_records: 10_000,
                    all_rows: false,
                    technology_catalog_version: 2,
                    filter: ServiceMapFilterArgs::default(),
                }),
            }
        }
        "target.service_map.socket_peer_matches.get" => {
            let evidence_id: String = call_required(operation, input, "evidence_id")?;
            let evidence_id = parse_service_map_peer_evidence_id(&evidence_id)
                .map_err(|message| anyhow!(message))?;
            let in_scope_only = match input.get("in_scope_only") {
                None => false,
                Some(value) => value
                    .as_bool()
                    .ok_or_else(|| anyhow!("field `in_scope_only` must be a boolean"))?,
            };
            let max_records = match input.get("max_records") {
                None => 10_000,
                Some(value) => value
                    .as_u64()
                    .filter(|value| (1..=50_000).contains(value))
                    .ok_or_else(|| {
                        anyhow!("field `max_records` must be an integer between 1 and 50000")
                    })? as usize,
            };
            Command::Scope {
                command: TargetCommand::ServiceMap(ServiceMapArgs {
                    command: Some(ServiceMapCommand::SocketPeerMatches(
                        ServiceMapSocketPeerMatchesArgs {
                            session_id: call_required(operation, input, "session_id")?,
                            evidence_id,
                            in_scope_only,
                            max_records,
                        },
                    )),
                    session_id: None,
                    origin: None,
                    in_scope_only: false,
                    max_records: 10_000,
                    all_rows: false,
                    technology_catalog_version: 2,
                    filter: ServiceMapFilterArgs::default(),
                }),
            }
        }
        "target.service_map.link_declarations.get" => {
            let evidence_id: String = call_required(operation, input, "evidence_id")?;
            let evidence_id =
                parse_service_map_evidence_id(&evidence_id).map_err(|message| anyhow!(message))?;
            Command::Scope {
                command: TargetCommand::ServiceMap(ServiceMapArgs {
                    command: Some(ServiceMapCommand::LinkDeclarations(
                        ServiceMapLinkDeclarationsArgs {
                            session_id: call_required(operation, input, "session_id")?,
                            evidence_id,
                        },
                    )),
                    session_id: None,
                    origin: None,
                    in_scope_only: false,
                    max_records: 10_000,
                    all_rows: false,
                    technology_catalog_version: 2,
                    filter: ServiceMapFilterArgs::default(),
                }),
            }
        }
        "target.service_map.evidence.get" => {
            let evidence_id: String = call_required(operation, input, "evidence_id")?;
            let evidence_id =
                parse_service_map_evidence_id(&evidence_id).map_err(|message| anyhow!(message))?;
            Command::Scope {
                command: TargetCommand::ServiceMapEvidence(ServiceMapEvidenceArgs {
                    technology_catalog_version: call_service_map_catalog_version(input)?,
                    session_id: call_required(operation, input, "session_id")?,
                    evidence_id,
                    include_socket_peer: match input.get("include_socket_peer") {
                        None => false,
                        Some(value) => value.as_bool().ok_or_else(|| {
                            anyhow!("field `include_socket_peer` must be a boolean")
                        })?,
                    },
                }),
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
        "fuzzer.run" => {
            let attack_type = call_optional_enum_string(
                operation,
                input,
                "attack_type",
                &["sniper", "battering-ram", "battering_ram"],
            )?;
            let concurrency = call_optional::<u8>(operation, input, "concurrency")?.unwrap_or(1);
            if !(1..=16).contains(&concurrency) {
                bail!("invalid field `concurrency` for `{operation}`; expected 1-16");
            }
            Command::Fuzzer {
                command: FuzzerCommand::Run(FuzzerRunArgs {
                    session_id: call_optional(operation, input, "session_id")?,
                    r#async: call_bool_any(operation, input, &["async", "r#async"])?,
                    attack_type: if attack_type.as_deref() == Some("sniper") {
                        FuzzerAttackTypeArg::Sniper
                    } else {
                        FuzzerAttackTypeArg::BatteringRam
                    },
                    raw_payloads: call_bool_any(operation, input, &["raw_payloads"])?,
                    concurrency,
                }),
            }
        }
        "fuzzer.stop" => Command::Fuzzer {
            command: FuzzerCommand::Stop(FuzzerStatusArgs {
                id: call_required(operation, input, "id")?,
                session_id: call_optional(operation, input, "session_id")?,
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
        "capture.intercept.get" => Command::Capture {
            command: CaptureCommand::Intercept {
                command: InterceptCommand::Get(InterceptGetArgs {
                    id: call_required(operation, input, "id")?,
                    session_id: call_optional(operation, input, "session_id")?,
                }),
            },
        },
        "capture.intercept.wait" | "capture.response_intercept.wait" => {
            let args = InterceptWaitArgs {
                session_id: call_optional(operation, input, "session_id")?,
                timeout: call_optional(operation, input, "timeout")?.unwrap_or(30),
                poll_interval: call_optional(operation, input, "poll_interval")?.unwrap_or(200),
            };
            Command::Capture {
                command: if operation == "capture.intercept.wait" {
                    CaptureCommand::Intercept {
                        command: InterceptCommand::Wait(args),
                    }
                } else {
                    CaptureCommand::ResponseIntercept {
                        command: ResponseInterceptCommand::Wait(args),
                    }
                },
            }
        }
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
        "capture.intercept_rule.update" => {
            let args = InterceptRuleUpdateArgs {
                id: call_required(operation, input, "id")?,
                session_id: call_present(operation, input, "session_id")?,
                scope: call_present(operation, input, "scope")?,
                host_pattern: call_present(operation, input, "host_pattern")?,
                path_pattern: call_present(operation, input, "path_pattern")?,
                method_filter: call_present(operation, input, "method_filter")?,
                clear_methods: call_present(operation, input, "clear_methods")?.unwrap_or(false),
                enabled: call_present(operation, input, "enabled")?,
            };
            validate_intercept_rule_update(&args)?;
            Command::Capture {
                command: CaptureCommand::InterceptRule {
                    command: InterceptRuleCommand::Update(args),
                },
            }
        }
        "capture.intercept_rule.set_enabled" => Command::Capture {
            command: CaptureCommand::InterceptRule {
                command: InterceptRuleCommand::SetEnabled(InterceptRuleSetEnabledArgs {
                    id: call_required(operation, input, "id")?,
                    session_id: call_present(operation, input, "session_id")?,
                    enabled: call_required(operation, input, "enabled")?,
                }),
            },
        },
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

fn call_present<T: DeserializeOwned>(
    operation: &str,
    input: &Value,
    field: &str,
) -> Result<Option<T>> {
    if input.get(field).is_some() {
        call_required(operation, input, field).map(Some)
    } else {
        Ok(None)
    }
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

fn call_templates_filter(operation: &str, input: &Value) -> Result<TemplatesFilterArgs> {
    Ok(TemplatesFilterArgs {
        search: call_optional(operation, input, "search")?,
        severity: call_optional(operation, input, "severity")?,
        tag: call_optional(operation, input, "tag")?,
    })
}

fn call_bool(operation: &str, input: &Value, field: &str) -> Result<bool> {
    Ok(call_optional::<bool>(operation, input, field)?.unwrap_or(false))
}

fn call_service_map_tokens(
    operation: &str,
    input: &Value,
    field: &str,
    allowed: &[&str],
) -> Result<Vec<String>> {
    let values = call_optional::<Vec<String>>(operation, input, field)?.unwrap_or_default();
    if let Some(value) = values
        .iter()
        .find(|value| !allowed.contains(&value.as_str()))
    {
        bail!("{field} accepts {}; got {value}", allowed.join(", "));
    }
    Ok(values)
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

/// The `--side` values the command line accepts. Unchecked here, `"body"`
/// passed a dry run and then failed with 400.
fn call_history_search_sides(operation: &str, input: &Value) -> Result<Vec<String>> {
    const SIDES: [&str; 4] = ["url", "request-body", "response-body", "headers"];
    let sides: Vec<String> = call_optional(operation, input, "side")?.unwrap_or_default();
    if let Some(side) = sides.iter().find(|side| !SIDES.contains(&side.as_str())) {
        bail!(
            "field `side` for `{operation}` must contain only {}; got `{side}`",
            SIDES.join(", ")
        );
    }
    Ok(sides)
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
            let raw_args: Vec<_> = env::args_os().skip(1).collect();
            let operation = cli_parse_error_operation(&raw_args);
            let _ = CLI_OUTPUT_CONTEXT.set(CliOutputContext {
                format: cli_output_format_from_raw_args(&raw_args),
                operation: operation.clone(),
                success_envelope: true,
            });
            // Some clap diagnostics render rejected OS strings lossily. Keep
            // those argument bytes out of JSON and the stderr fallback alike.
            let error = if operation.starts_with("target.service_map.")
                || matches!(
                    operation.as_str(),
                    "capture.http.upstream_peer.get" | "capture.http.upstream_peer.set"
                ) {
                clap::Error::raw(error.kind(), "Invalid command arguments; inspect the command's --help or input schema. Argument values are omitted.")
            } else if raw_args.iter().any(|arg| arg.to_str().is_none()) {
                clap::Error::raw(
                    clap::error::ErrorKind::InvalidUtf8,
                    "Command-line arguments must contain valid Unicode.",
                )
            } else {
                error
            };
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
        command => {
            let api = if matches!(command, Command::Recon { .. }) {
                discover_recon_api(api_override).await?
            } else if matches!(
                command.operation_name(),
                "target.service_map.get"
                    | "target.service_map.evidence.get"
                    | "target.service_map.body_references.get"
                    | "target.service_map.html_generators.get"
                    | "target.service_map.link_declarations.get"
                    | "target.service_map.socket_peer_matches.get"
                    | "target.service_map.parameters.get"
                    | "target.service_map.openapi.get"
                    | "target.service_map.flow.get"
                    | "target.service_map.unnamed.get"
                    | "capture.http.upstream_peer.get"
                    | "capture.http.upstream_peer.set"
            ) {
                discover_service_map_api(api_override).await?
            } else {
                ApiClient::discover(api_override).await?
            };
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
                Command::Recon { command } => handle_recon(api, command).await,
                Command::Scanner { command } => handle_scanner(api, command).await,
                Command::Templates { command } => handle_templates(api, command).await,
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

fn validate_skill_root_selection(
    codex_selected: bool,
    claude_selected: bool,
    codex_dir: &Option<PathBuf>,
    claude_dir: &Option<PathBuf>,
) -> Result<()> {
    for (agent, selected, root) in [
        ("codex", codex_selected, codex_dir),
        ("claude", claude_selected, claude_dir),
    ] {
        if root.is_some() && !selected {
            bail!("invalid directory override: --{agent}-dir ({agent}_dir) requires --{agent} ({agent}=true) or --all (all=true); select that agent or omit its directory override");
        }
    }
    Ok(())
}

fn validate_command_preflight(command: &Command) -> Result<()> {
    if let Command::Recon {
        command: ReconCommand::Start(args),
    } = command
    {
        args.request()
            .validate()
            .map_err(|message| anyhow!("invalid Recon input: {message}"))?;
        if args
            .scan_visibility
            .as_deref()
            .is_some_and(|visibility| !["private", "unlisted", "public"].contains(&visibility))
        {
            bail!("invalid Recon scan_visibility");
        }
    }
    match command {
        Command::Capture {
            command:
                CaptureCommand::Intercept {
                    command: InterceptCommand::Wait(args),
                },
        }
        | Command::Intercept {
            command: InterceptCommand::Wait(args),
        }
        | Command::Capture {
            command:
                CaptureCommand::ResponseIntercept {
                    command: ResponseInterceptCommand::Wait(args),
                },
        } => {
            intercept_wait_deadline(args.timeout)?;
        }
        _ => {}
    }
    if let Command::Capture {
        command:
            CaptureCommand::InterceptRule {
                command: InterceptRuleCommand::Update(args),
            },
    } = command
    {
        validate_intercept_rule_update(args)?;
    }
    if let Command::Schema { operation, .. }
    | Command::Examples {
        operation: Some(operation),
    } = command
    {
        operation_spec(operation).ok_or_else(|| anyhow!("unknown operation `{operation}`"))?;
    }

    if let Command::Session {
        command: SessionCommand::Create(args),
    } = command
    {
        validate_session_creation_name(args.name.as_deref())?;
    }

    if let Command::Skills {
        command: SkillsCommand::Install(args) | SkillsCommand::Status(args),
    } = command
    {
        if !(args.codex || args.claude || args.all) {
            bail!("must select at least one destination with --codex, --claude, or --all");
        }
        validate_skill_root_selection(
            args.codex || args.all,
            args.claude || args.all,
            &args.codex_dir,
            &args.claude_dir,
        )?;
        for path in [&args.codex_dir, &args.claude_dir].into_iter().flatten() {
            validate_skill_cli_path(path)?;
        }
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

/// How long a download or import may take before the CLI stops waiting; the
/// server keeps going and `templates library status` reports the outcome.
const TEMPLATE_LIBRARY_WAIT: std::time::Duration = std::time::Duration::from_secs(600);
const MAX_TEMPLATE_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;

async fn wait_for_template_library(api: &ApiClient) -> Result<Value> {
    let deadline = std::time::Instant::now() + TEMPLATE_LIBRARY_WAIT;
    loop {
        let status: Value = api.get_json("/api/templates/library").await?;
        match status["state"].as_str() {
            Some("idle") => return Ok(status),
            Some("failed") => bail!(
                "the template library failed: {}",
                status["error"].as_str().unwrap_or("unknown error")
            ),
            _ if std::time::Instant::now() >= deadline => bail!(
                "still busy after {} seconds; `templates library status` reports the outcome",
                TEMPLATE_LIBRARY_WAIT.as_secs()
            ),
            _ => tokio::time::sleep(std::time::Duration::from_secs(1)).await,
        }
    }
}

async fn handle_templates(api: ApiClient, command: TemplatesCommand) -> Result<()> {
    match command {
        TemplatesCommand::Library { command } => match command {
            TemplatesLibraryCommand::Status => {
                let status: Value = api.get_json("/api/templates/library").await?;
                print_json(&status)
            }
            TemplatesLibraryCommand::Check => {
                let checked: Value = api
                    .post_json("/api/templates/library/check", &json!({}))
                    .await?;
                print_json(&checked)
            }
            TemplatesLibraryCommand::Download => {
                let _: Value = api
                    .post_json(
                        "/api/templates/library/download",
                        &json!({ "acknowledged": true }),
                    )
                    .await?;
                print_json(&wait_for_template_library(&api).await?)
            }
            TemplatesLibraryCommand::Import(args) => {
                let size = std::fs::metadata(&args.file)
                    .with_context(|| format!("cannot read {}", args.file.display()))?
                    .len();
                if size > MAX_TEMPLATE_ARCHIVE_BYTES {
                    bail!("{} is larger than 64 MiB", args.file.display());
                }
                let bytes = std::fs::read(&args.file)
                    .with_context(|| format!("cannot read {}", args.file.display()))?;
                const PATH: &str = "/api/templates/library/import";
                let response = api
                    .long_client
                    .post(api.url(PATH))
                    .header(reqwest::header::CONTENT_TYPE, "application/gzip")
                    .body(bytes)
                    .send()
                    .await
                    .with_context(|| format!("failed to POST {PATH}"))?;
                let status = response.status();
                if !status.is_success() {
                    let message = response.text().await.unwrap_or_default();
                    bail!(
                        "request to {PATH} failed ({status}): {}",
                        api_failure_detail(status, message)
                    );
                }
                print_json(&wait_for_template_library(&api).await?)
            }
        },
        TemplatesCommand::List(args) => {
            let page: Value = api.get_json(&templates_list_path(&args)).await?;
            print_json(&page)
        }
        TemplatesCommand::Get(args) => {
            if !valid_template_id(&args.id) {
                bail!("`{}` is not a template id", args.id);
            }
            let detail: Value = api.get_json(&format!("/api/templates/{}", args.id)).await?;
            print_json(&detail)
        }
        TemplatesCommand::Passive {
            command: TemplatesPassiveCommand::SetEnabled(args),
        } => {
            let body = templates_passive_body(&args)?;
            let saved: Value = api.post_json("/api/templates/passive", &body).await?;
            print_json(&saved)
        }
        TemplatesCommand::Scan { command } => {
            let explicit = match &command {
                TemplatesScanCommand::Preview(args) | TemplatesScanCommand::Start(args) => {
                    args.session_id
                }
                TemplatesScanCommand::List(args) => args.session_id,
                TemplatesScanCommand::Get(args) | TemplatesScanCommand::Stop(args) => {
                    args.session_id
                }
            };
            let session_id = resolve_session_id_arg(&api, explicit)
                .await?
                .ok_or_else(|| anyhow!("no session; pass --session-id"))?;
            let result: Value = match command {
                TemplatesScanCommand::Preview(args) => {
                    let body = templates_scan_body(&args, Some(session_id), true)?;
                    api.post_json("/api/templates/scans", &body).await?
                }
                TemplatesScanCommand::Start(args) => {
                    let body = templates_scan_body(&args, Some(session_id), false)?;
                    api.post_json("/api/templates/scans", &body).await?
                }
                TemplatesScanCommand::List(_) => {
                    api.get_json(&session_query_path(
                        "/api/templates/scans",
                        Some(session_id),
                    ))
                    .await?
                }
                TemplatesScanCommand::Get(args) => {
                    api.get_json(&session_query_path(
                        &format!("/api/templates/scans/{}", args.id),
                        Some(session_id),
                    ))
                    .await?
                }
                TemplatesScanCommand::Stop(args) => {
                    api.post_json(
                        &format!("/api/templates/scans/{}/stop", args.id),
                        &json!({ "session_id": session_id }),
                    )
                    .await?
                }
            };
            print_json(&result)
        }
    }
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

async fn handle_session(mut api: ApiClient, command: SessionCommand) -> Result<()> {
    if matches!(
        &command,
        SessionCommand::Create(_)
            | SessionCommand::Switch(_)
            | SessionCommand::Delete(_)
            | SessionCommand::Rename(_)
    ) {
        api.client = saved_configuration_write_client()?;
        api.session_metadata_write_errors = true;
    }
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
            validate_session_metadata_response_id(&session, args.id)?;
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
            validate_session_metadata_response_id(&session, args.id)?;
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

fn validate_session_metadata_response_id(
    session: &SessionSummary,
    requested_id: Uuid,
) -> Result<()> {
    if session.id != requested_id {
        bail!("session metadata response did not match the requested session; mutation outcome is unknown; inspect current state before retrying");
    }
    Ok(())
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
        HistoryCommand::UpstreamPeer { command } => handle_upstream_peer(api, command).await,
        HistoryCommand::Retention { command } => handle_history_retention(api, command).await,
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

#[derive(Debug)]
struct ServiceMapCliError {
    code: &'static str,
    message: &'static str,
    status: Option<u16>,
}

impl fmt::Display for ServiceMapCliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}
impl std::error::Error for ServiceMapCliError {}

fn service_map_error(code: &'static str, message: &'static str) -> anyhow::Error {
    ServiceMapCliError {
        code,
        message,
        status: None,
    }
    .into()
}

fn service_map_runtime_state(data_dir: &Path) -> Result<Option<RuntimeStateSnapshot>> {
    let invalid = || {
        service_map_error("API_UNAVAILABLE", "Could not read valid local runtime identity for Service Map; existing state was preserved")
    };
    let path = sniper::runtime_state::runtime_state_path(data_dir);
    let metadata = match fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(invalid()),
    };
    if !metadata.is_file() || metadata.len() > 64 * 1024 {
        return Err(invalid());
    }
    // Runtime-state replacements are atomic. Unlike the general loader, this
    // passive path creates no lock file and never repairs or moves invalid state.
    let mut file = fs::File::open(&path).map_err(|_| invalid())?;
    let bytes =
        read_limited_to_end(&mut file, "runtime identity", 64 * 1024).map_err(|_| invalid())?;
    let mut snapshot: RuntimeStateSnapshot =
        serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let proxy_addr: std::net::SocketAddr = snapshot.proxy_addr.parse().map_err(|_| invalid())?;
    let ui_addr: std::net::SocketAddr = snapshot.ui_addr.parse().map_err(|_| invalid())?;
    snapshot.proxy_addr = proxy_addr.to_string();
    snapshot.ui_addr = sniper::runtime_state::advertise_local_api_addr(ui_addr).to_string();
    Ok(Some(snapshot))
}

async fn discover_service_map_api(cli_api: Option<String>) -> Result<ApiClient> {
    let explicit = cli_api.or_else(|| {
        env::var("SNIPER_API_ADDR")
            .ok()
            .filter(|api| !api.trim().is_empty())
    });
    let data_dir = cli_data_dir();
    let runtime_state = if explicit.is_none() {
        service_map_runtime_state(&data_dir)?
    } else {
        None
    };
    let raw = explicit
        .or_else(|| {
            runtime_state
                .as_ref()
                .map(RuntimeStateSnapshot::api_base_url)
        })
        .ok_or_else(|| {
            service_map_error(
                "API_UNAVAILABLE",
                "Could not discover the Service Map API; pass --api or start Sniper Desktop",
            )
        })?;
    let base_url = normalize_api_base_url(&raw).map_err(|_| service_map_error(
        "INVALID_INPUT", "Invalid Service Map API address; supply an HTTP(S) origin without credentials, path, query, or fragment",
    ))?;
    let client = service_map_read_client()?;
    let api = ApiClient {
        base_url,
        client: client.clone(),
        long_client: client,
        session_metadata_write_errors: false,
    };
    let probe_client = service_map_client(SNIPER_API_PROBE_TIMEOUT)?;
    let payload: Value = service_map_get(&api, &probe_client, "/api/settings").await?;
    let expected = runtime_state
        .as_ref()
        .map(|runtime_state| SniperApiProbeExpectation {
            runtime_state,
            data_dir: &data_dir,
        });
    validate_sniper_settings_probe(&payload, expected).map_err(|_| service_map_error(
        "INVALID_RESPONSE", "The selected Service Map API did not match the expected Sniper identity; existing runtime state was preserved",
    ))?;
    Ok(api)
}

fn service_map_read_client() -> Result<reqwest::Client> {
    service_map_client(CLI_API_TIMEOUT)
}

fn service_map_client(timeout: std::time::Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(timeout)
        .build()
        .map_err(|_| {
            service_map_error(
                "API_UNAVAILABLE",
                "Could not prepare the Service Map read client",
            )
        })
}

async fn service_map_get<T: DeserializeOwned>(
    api: &ApiClient,
    client: &reqwest::Client,
    path: &str,
) -> Result<T> {
    service_map_get_with_catalog(api, client, path, None).await
}

fn service_map_refresh_error(
    path: &str,
    status: StatusCode,
    headers: &reqwest::header::HeaderMap,
) -> Option<ServiceMapCliError> {
    if !path.starts_with("/api/target/service-map?") {
        return None;
    }
    let mut values = headers.get_all(SERVICE_MAP_ERROR_HEADER).iter();
    let token = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    // Only this endpoint's fixed header contract may select a diagnostic.
    // Never classify server prose, combined headers, or response bodies.
    let (code, message) = match (status.as_u16(), token) {
        (429, "busy") => (
            "SERVICE_MAP_BUSY",
            "A Service Map refresh is already running; wait for it to finish before deliberately refreshing again",
        ),
        (422, "scope_work_limit") => (
            "SERVICE_MAP_SCOPE_WORK_LIMIT",
            "Service Map scope matching exceeded the work limit; use a smaller --max-records window or deliberately simplify scope rules",
        ),
        (409, "session_changed") => (
            "SERVICE_MAP_SESSION_CHANGED",
            "The selected session changed while building the Service Map; deliberately refresh the same session",
        ),
        (409, "scope_changed") => (
            "SERVICE_MAP_SCOPE_CHANGED",
            "Scope changed while building the Service Map; deliberately refresh to use the current scope",
        ),
        (409, "history_changed") => (
            "SERVICE_MAP_HISTORY_CHANGED",
            "Retained history changed while building the Service Map; deliberately refresh to use the current history",
        ),
        (500, "build_failed") => (
            "SERVICE_MAP_BUILD_FAILED",
            "The selected API could not build the Service Map",
        ),
        _ => return None,
    };
    Some(ServiceMapCliError {
        code,
        message,
        status: Some(status.as_u16()),
    })
}

async fn service_map_get_with_catalog<T: DeserializeOwned>(
    api: &ApiClient,
    client: &reqwest::Client,
    path: &str,
    catalog_version: Option<u32>,
) -> Result<T> {
    let mut request = client.get(api.url(path));
    if let Some(version) = catalog_version {
        request = request.header(SERVICE_MAP_CATALOG_HEADER, version.to_string());
    }
    let response = request.send().await.map_err(|_| {
        service_map_error(
            "API_UNAVAILABLE",
            "Could not read Service Map metadata from the selected API",
        )
    })?;
    let status = response.status();
    if !status.is_success() {
        if let Some(error) = service_map_refresh_error(path, status, response.headers()) {
            return Err(error.into());
        }
        if status == StatusCode::NOT_FOUND
            && path.starts_with("/api/target/service-map/html-generators?")
        {
            return Err(ServiceMapCliError {
                code: "UNSUPPORTED_FEATURE",
                message: "The selected API does not support retained HTML generator inspection; update the app to use this feature",
                status: Some(404),
            }.into());
        }
        if status == StatusCode::NOT_FOUND
            && path.starts_with("/api/target/service-map/socket-peer-matches?")
        {
            return Err(ServiceMapCliError {
                code: "UNSUPPORTED_FEATURE",
                message: "The selected API does not support recorded socket peer matches; update the app to use this feature",
                status: Some(404),
            }.into());
        }
        if path.starts_with("/api/target/service-map/flow?") && status == StatusCode::NOT_FOUND {
            return Err(ServiceMapCliError {
                code: "UNSUPPORTED_FEATURE",
                message: "The selected API does not draw flows; update the app to use this feature",
                status: Some(404),
            }
            .into());
        }
        if path.starts_with("/api/target/service-map/openapi?") {
            if status == StatusCode::NOT_FOUND {
                return Err(ServiceMapCliError {
                    code: "UNSUPPORTED_FEATURE",
                    message: "The selected API does not describe origins in OpenAPI; update the app to use this feature",
                    status: Some(404),
                }
                .into());
            }
            if status == StatusCode::CONFLICT {
                return Err(ServiceMapCliError {
                    code: "SESSION_INACTIVE",
                    message: "OpenAPI reads the active session only; activate that session first",
                    status: Some(409),
                }
                .into());
            }
        }
        if status == StatusCode::NOT_FOUND
            && path.starts_with("/api/target/service-map/link-declarations?")
        {
            return Err(ServiceMapCliError {
                code: "UNSUPPORTED_FEATURE",
                message: "The selected API does not support retained Link declaration inspection; update the app to use this feature",
                status: Some(404),
            }.into());
        }
        return Err(ServiceMapCliError {
            code: if status.is_redirection() {
                "REDIRECT_REFUSED"
            } else {
                "HTTP_STATUS_ERROR"
            },
            message: if status.is_redirection() {
                "Service Map API redirects are not followed"
            } else {
                "The selected API could not return Service Map metadata"
            },
            status: Some(status.as_u16()),
        }
        .into());
    }
    if path.starts_with("/api/target/service-map/socket-peer-matches?") {
        use sniper::service_map_peer_matches::MAX_PROJECTION_BYTES;
        let invalid = || {
            service_map_error(
                "INVALID_RESPONSE",
                "The selected API returned invalid or oversized recorded socket peer matches",
            )
        };
        if response
            .content_length()
            .is_some_and(|length| length > MAX_PROJECTION_BYTES as u64)
        {
            return Err(invalid());
        }
        // Bound the encoded response before JSON allocation, including chunked
        // responses which cannot be checked from Content-Length alone.
        let mut response = response;
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| invalid())? {
            if chunk.len() > MAX_PROJECTION_BYTES.saturating_sub(bytes.len()) {
                return Err(invalid());
            }
            bytes.extend_from_slice(&chunk);
        }
        return serde_json::from_slice(&bytes).map_err(|_| invalid());
    }
    response.json().await.map_err(|_| {
        service_map_error(
            "INVALID_RESPONSE",
            "The selected API returned invalid Service Map metadata",
        )
    })
}

fn service_map_safe_path(path: &str) -> bool {
    path.starts_with('/') && !path.contains(['?', '#']) && !path.chars().any(char::is_control)
}

fn service_map_safe_origin(origin: &str) -> bool {
    sniper::service_map::canonical_origin(origin).as_deref() == Some(origin)
}

fn service_map_technology_response_valid(
    result: &ServiceMap,
    catalog_version: CatalogVersion,
) -> bool {
    use sniper::service_map_technology::{
        MAX_OBSERVATIONS, MAX_OBSERVATIONS_PER_ORIGIN, MAX_OBSERVATIONS_PER_ROW,
        MAX_TOKEN_CANDIDATES_PER_ROW, MAX_VERSION_BYTES,
    };
    let limits = &result.snapshot.limits;
    if ![
        (
            limits.technology_observations_per_row,
            MAX_OBSERVATIONS_PER_ROW,
        ),
        (
            limits.technology_observations_per_origin,
            MAX_OBSERVATIONS_PER_ORIGIN,
        ),
        (limits.technology_observations, MAX_OBSERVATIONS),
        (limits.technology_version_bytes, MAX_VERSION_BYTES),
        (
            limits.technology_token_candidates_per_row,
            MAX_TOKEN_CANDIDATES_PER_ROW,
        ),
    ]
    .into_iter()
    .all(|(actual, expected)| actual.is_none_or(|value| value == expected))
    {
        return false;
    }
    let mut total = 0usize;
    let mut row_sources = std::collections::HashMap::new();
    let session = result.session_id.to_string();
    let generation = result.snapshot.generation.to_string();
    for origin in &result.origins {
        let Some(observations) = &origin.technology_observations else {
            continue;
        };
        total = total.saturating_add(observations.len());
        if total > MAX_OBSERVATIONS || observations.len() > MAX_OBSERVATIONS_PER_ORIGIN {
            return false;
        }
        let mut keys = std::collections::BTreeSet::new();
        for observation in observations {
            let mut rows = std::collections::HashSet::new();
            if !observation.is_valid_for_catalog(catalog_version)
                || observation.row_count > origin.request_count
                || observation.first_seen < origin.first_seen
                || observation.last_seen > origin.last_seen
                || !keys.insert((
                    observation.product_id.as_str(),
                    observation.header_name.as_str(),
                    observation.reported_version.as_deref(),
                    observation.version_status,
                ))
                || !observation.evidence.iter().all(|token| {
                    if parse_service_map_evidence_id(token).is_err() {
                        return false;
                    }
                    let fields: Vec<_> = token.split('.').collect();
                    fields[1] == session
                        && fields[2] == generation
                        && rows.insert(fields[3])
                        && row_sources
                            .insert(fields[3], (token.as_str(), origin.origin.as_str()))
                            .is_none_or(|previous| {
                                previous == (token.as_str(), origin.origin.as_str())
                            })
                })
            {
                return false;
            }
        }
    }
    // Existing evidence may sample a different subset of rows. When a sequence
    // is shared, it must identify the same retained row revision everywhere.
    for origin in &result.origins {
        let evidence = origin
            .endpoints
            .iter()
            .flat_map(|item| &item.evidence)
            .chain(
                origin
                    .technology_clues
                    .iter()
                    .flat_map(|item| &item.evidence),
            )
            .chain(origin.redirects.iter().flat_map(|item| &item.evidence))
            .chain(origin.header_links.iter().flat_map(|item| &item.evidence));
        for token in evidence {
            let fields: Vec<_> = token.split('.').collect();
            if fields.len() == 6
                && row_sources
                    .get(fields[3])
                    .is_some_and(|expected| *expected != (token.as_str(), origin.origin.as_str()))
            {
                return false;
            }
        }
    }
    (!result
        .snapshot
        .stopped_by
        .iter()
        .any(|reason| reason == "technology_observations_map_limit")
        || total == MAX_OBSERVATIONS)
        && (!result
            .snapshot
            .stopped_by
            .iter()
            .any(|reason| reason == "technology_observations_per_origin_limit")
            || result.origins.iter().any(|origin| {
                origin
                    .technology_observations
                    .as_ref()
                    .is_some_and(|items| items.len() == MAX_OBSERVATIONS_PER_ORIGIN)
            }))
}

fn service_map_row_technology_valid(
    row: &sniper::service_map::ServiceMapRow,
    catalog_version: CatalogVersion,
) -> bool {
    use sniper::service_map_technology::MAX_OBSERVATIONS_PER_ROW;
    if row.metadata_complete
        && row
            .omitted
            .iter()
            .any(|reason| reason == "technology_token_scan_limit")
    {
        return false;
    }
    let Some(observations) = &row.technology_observations else {
        return true;
    };
    let mut ranges = std::collections::HashMap::<usize, Vec<(usize, usize)>>::new();
    let mut headers = std::collections::HashMap::new();
    observations.len() <= MAX_OBSERVATIONS_PER_ROW
        && row.metadata_complete == row.omitted.is_empty()
        && (!row
            .omitted
            .iter()
            .any(|reason| reason == "technology_observations_limit")
            || observations.len() == MAX_OBSERVATIONS_PER_ROW)
        && observations.iter().all(|observation| {
            observation.is_valid_for_catalog(catalog_version)
                && std::iter::once(observation.product_span)
                    .chain(observation.version_span)
                    .all(|span| {
                        let retained = ranges.entry(observation.header_index).or_default();
                        if retained
                            .iter()
                            .any(|(start, end)| span.start < *end && *start < span.end)
                        {
                            return false;
                        }
                        retained.push((span.start, span.end));
                        true
                    })
                && headers
                    .insert(observation.header_index, observation.header_name.as_str())
                    .is_none_or(|name| name == observation.header_name)
        })
}

fn service_map_response_catalog(marker: Option<u32>, requested: u32) -> Result<CatalogVersion> {
    match marker {
        None => Ok(CatalogVersion::V1),
        Some(version) if version == requested => {
            CatalogVersion::from_number(version).ok_or_else(|| {
                service_map_error(
                    "INVALID_RESPONSE",
                    "Service Map returned an unsupported technology catalog",
                )
            })
        }
        Some(_) => Err(service_map_error(
            "INVALID_RESPONSE",
            "Service Map technology catalog does not match the requested catalog",
        )),
    }
}

fn warn_legacy_service_map_catalog(marker: Option<u32>) {
    if marker.is_none() {
        eprintln!("{SERVICE_MAP_LEGACY_CATALOG_WARNING}");
    }
}

fn validate_service_map_response(
    result: &ServiceMap,
    args: &ServiceMapArgs,
    session_id: Uuid,
) -> Result<()> {
    let catalog_version = service_map_response_catalog(
        result.technology_catalog_version,
        args.technology_catalog_version,
    )?;
    let snapshot = &result.snapshot;
    let valid = result.schema_version == 1
        && service_map_technology_response_valid(result, catalog_version)
        && result.session_id == session_id
        && result.in_scope_only == args.in_scope_only
        && result.origin_filter == args.origin
        && snapshot.window_order == "newest_capture_sequence"
        // A whole-history read has no window: it considers every retained row.
        && (args.all_rows || snapshot.limits.max_records == args.max_records)
        && (args.all_rows || snapshot.considered_rows <= args.max_records)
        && snapshot.considered_rows <= snapshot.retained_rows
        && snapshot.projected_rows <= snapshot.considered_rows
        && snapshot.complete == snapshot.stopped_by.is_empty()
        && snapshot.origin_count == result.origins.len()
        && result.clients.len() <= 16
        && result.clients.iter().all(|client| {
            let names = sniper::service_map_clients::names();
            sniper::service_map_clients::KINDS.contains(&client.kind.as_str())
                && names.contains(&client.name.as_str())
                && client.os.as_deref().is_none_or(|os| {
                    sniper::service_map_clients::SYSTEMS.contains(&os)
                })
                && client.request_count > 0
                && client.origins.len() <= 64
                // Each origin's rows are some of the client's, and its own
                // visits some of those.
                && client.origins.iter().map(|origin| origin.request_count).sum::<usize>()
                    <= client.request_count
                && client.origins.iter().all(|origin| {
                    service_map_safe_origin(&origin.origin)
                        && origin.request_count > 0
                        && origin
                            .entry_kinds
                            .keys()
                            .all(|kind| sniper::service_map::REQUEST_KINDS.contains(&kind.as_str()))
                        && origin.entry_kinds.values().sum::<usize>() <= origin.request_count
                })
        })
        && snapshot.endpoint_count
            == result
                .origins
                .iter()
                .map(|origin| origin.endpoints.len())
                .sum::<usize>()
        && result.origins.iter().all(|origin| {
            service_map_safe_origin(&origin.origin)
                && matches!(origin.scheme.as_str(), "http" | "https")
                && (!args.in_scope_only || origin.in_scope)
                && args
                    .origin
                    .as_ref()
                    .is_none_or(|filter| *filter == origin.origin)
                && origin.endpoints.iter().all(|endpoint| {
                    service_map_safe_path(&endpoint.path)
                        && endpoint
                            .path_group
                            .as_deref()
                            .is_none_or(service_map_safe_path)
                })
                && origin.technology_clues.iter().all(|clue| {
                    clue.source == "response_header" && clue.confidence == "observed_header"
                })
                && origin.redirects.iter().all(|redirect| {
                    redirect.relationship == "redirect_instruction"
                        && redirect.source == "response_location_header"
                        && service_map_safe_origin(&redirect.target_origin)
                        && service_map_safe_path(&redirect.target_path)
                })
                && origin.header_links.iter().all(|link| {
                    link.source == "request_header_declaration"
                        && matches!(
                            link.relationship.as_str(),
                            "origin_header" | "referer_header"
                        )
                        && service_map_safe_origin(&link.source_origin)
                        && link
                            .request_kinds
                            .keys()
                            .all(|kind| sniper::service_map::REQUEST_KINDS.contains(&kind.as_str()))
                        // Every count is a share of the same rows.
                        && link.request_kinds.values().sum::<usize>() == link.request_count
                        && link.cors_credentials_count <= link.cors_allowed_count
                        && link.cors_allowed_count <= link.request_count
                })
                && origin.header_sources.iter().all(|source| {
                    service_map_safe_origin(&source.source_origin)
                        && source
                            .request_kinds
                            .keys()
                            .all(|kind| sniper::service_map::REQUEST_KINDS.contains(&kind.as_str()))
                        && source.request_kinds.values().sum::<usize>() == source.request_count
                        && source.cors_credentials_count <= source.cors_allowed_count
                        && source.cors_allowed_count <= source.request_count
                })
                && origin
                    .favicon
                    .as_deref()
                    .is_none_or(|token| token.len() <= 200 && token.starts_with("v1."))
                && [
                    &origin.unnamed.banners,
                    &origin.unnamed.headers,
                    &origin.unnamed.cookies,
                ]
                .iter()
                .all(|signals| {
                    signals.len() <= 16
                        && signals.iter().all(|signal| {
                            signal.row_count > 0
                                && (1..=80).contains(&signal.value.len())
                                && signal.value.bytes().all(|b| (0x20..0x7f).contains(&b))
                        })
                })
                && origin.auth.iter().all(|method| {
                    sniper::service_map_auth::KINDS.contains(&method.kind.as_str())
                        && method.row_count > 0
                        && method.name.as_deref().is_none_or(|name| {
                            !name.is_empty()
                                && name.len() <= 64
                                && name
                                    .bytes()
                                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
                        })
                })
                && origin.endpoints.iter().all(|endpoint| {
                    endpoint
                        .auth
                        .iter()
                        .all(|kind| sniper::service_map_auth::KINDS.contains(&kind.as_str()))
                })
                && origin.server_technologies.iter().all(|item| {
                    !item.product_id.is_empty()
                        && item.product_id.len() <= 40
                        && item
                            .product_id
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                        && !item.name.is_empty()
                        && item.name.len() <= 40
                        && sniper::service_map_servers::CATEGORIES.contains(&item.category.as_str())
                        && !item.signals.is_empty()
                        && item.signals.iter().all(|signal| {
                            sniper::service_map_servers::SIGNALS.contains(&signal.as_str())
                        })
                        && item.version.as_deref().is_none_or(|version| {
                            version.len() <= 40 && version.starts_with(|c: char| c.is_ascii_digit())
                        })
                        && item.row_count > 0
                })
                && origin.front_technologies.iter().all(|item| {
                    !item.product_id.is_empty()
                        && item.product_id.len() <= 40
                        && item
                            .product_id
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                        && item.name.len() <= 40
                        // A brand may open with a digit: 6sense, 33Across.
                        && item.name.starts_with(|c: char| c.is_ascii_alphanumeric())
                        && item.name.bytes().all(|b| {
                            b.is_ascii_alphanumeric()
                                || matches!(b, b' ' | b'.' | b'!' | b'+' | b'_' | b'-')
                        })
                        && sniper::service_map_libraries::CATEGORIES
                            .contains(&item.category.as_str())
                        && item.version.as_deref().is_none_or(|version| {
                            version.len() <= 40
                                && version.starts_with(|c: char| c.is_ascii_digit())
                                && version.bytes().all(|b| {
                                    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+')
                                })
                        })
                        && service_map_safe_origin(&item.source_origin)
                        && item.row_count > 0
                })
        });
    if !valid {
        return Err(service_map_error("INVALID_RESPONSE", "Service Map metadata does not match the requested session, filters, limits, or safe response contract"));
    }
    Ok(())
}

fn validate_service_map_evidence_response(
    result: &ServiceMapEvidence,
    args: &ServiceMapEvidenceArgs,
) -> Result<()> {
    let catalog_version = service_map_response_catalog(
        result.technology_catalog_version,
        args.technology_catalog_version,
    )?;
    let token_fields: Vec<_> = args.evidence_id.split('.').collect();
    let token_valid = parse_service_map_evidence_id(&args.evidence_id).is_ok();
    let row_valid = match (
        result.available,
        result.row.as_ref(),
        result.reason.as_deref(),
    ) {
        (true, Some(row), None) => {
            token_valid
                && row.evidence_id == args.evidence_id
                && token_fields[1] == args.session_id.to_string()
                && token_fields[3] == row.sequence
                && token_fields[5] == row.record_id.to_string()
                && row
                    .sequence
                    .parse::<u64>()
                    .is_ok_and(|sequence| sequence.to_string() == row.sequence)
                && service_map_safe_origin(&row.origin)
                && matches!(row.scheme.as_str(), "http" | "https")
                && service_map_safe_path(&row.path)
                && service_map_row_technology_valid(row, catalog_version)
                && row.redirect.as_ref().is_none_or(|redirect| {
                    service_map_safe_origin(&redirect.target_origin)
                        && service_map_safe_path(&redirect.target_path)
                })
                && row.header_links.iter().all(|link| {
                    service_map_safe_origin(&link.source_origin)
                        && matches!(
                            link.relationship.as_str(),
                            "origin_header" | "referer_header"
                        )
                })
        }
        // Backend absence reasons are fixed protocol codes, never diagnostic
        // text. Reject unknown values rather than echoing captured data here.
        (false, None, Some(reason)) => matches!(
            reason,
            "invalid_evidence_id"
                | "session_mismatch"
                | "stale_generation"
                | "record_missing"
                | "record_changed"
                | "metadata_unavailable"
                | "session_source_changed"
        ),
        _ => false,
    };
    let peer_valid = match result.socket_peer.as_ref() {
        None => !args.include_socket_peer || !result.available,
        Some(peer) if args.include_socket_peer && result.available => {
            match (&peer.status, peer.observation.as_ref()) {
                (ServiceMapSocketPeerStatus::NotRecorded, None) => true,
                (ServiceMapSocketPeerStatus::Observed, Some(observation)) => {
                    observation.is_valid() && observation.address.is_some()
                }
                (ServiceMapSocketPeerStatus::Unavailable, Some(observation)) => {
                    observation.is_valid() && observation.address.is_none()
                }
                _ => false,
            }
        }
        Some(_) => false,
    };
    if result.schema_version != 1
        || result.session_id != args.session_id
        || result.evidence_id != args.evidence_id
        || result.source != "captured_http_metadata"
        || !peer_valid
        || !row_valid
    {
        return Err(service_map_error("INVALID_RESPONSE", "Service Map evidence does not match the requested session, token, availability, or safe row contract"));
    }
    Ok(())
}

fn service_map_body_safe_origin(origin: &str) -> bool {
    origin.len() <= sniper::service_map_body::MAX_CANDIDATE_BYTES
        && Url::parse(origin).is_ok_and(|url| {
            matches!(url.scheme(), "http" | "https")
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && url.origin().ascii_serialization() == origin
        })
}

fn validate_service_map_body_references_response(
    result: &ServiceMapBodyReferences,
    args: &ServiceMapBodyReferencesArgs,
) -> Result<()> {
    use sniper::service_map_body::{
        MAX_CANDIDATES, MAX_CANDIDATE_BYTES, MAX_OFFSETS_PER_ORIGIN, MAX_ORIGINS, MAX_SCAN_BYTES,
        MAX_SERIALIZED_ROW_BYTES,
    };
    let token_fields: Vec<_> = args.evidence_id.split('.').collect();
    let token_valid = parse_service_map_evidence_id(&args.evidence_id).is_ok();
    let partial_reasons = [
        "capture_preview_truncated",
        "scan_prefix_truncated",
        "candidate_limit",
        "candidate_bytes",
        "origin_limit",
        "offset_limit",
    ];
    let unsupported_reasons = [
        "unsupported_metadata",
        "metadata_limit",
        "unsupported_content_type",
        "unsupported_body_encoding",
        "unsupported_content_encoding",
    ];
    let unavailable_reasons = [
        "invalid_evidence_id",
        "session_mismatch",
        "stale_generation",
        "record_missing",
        "record_changed",
        "body_identity_unverifiable",
        "body_storage_unavailable",
        "body_read_failed",
        "serialized_row_limit",
        "malformed_retained_row",
        "response_unavailable",
        "retained_preview_unavailable",
        "body_scan_failed",
        "inactive_session",
        "session_source_changed",
        "metadata_unavailable",
    ];
    let has_reason = |reason: &str| result.reasons.iter().any(|value| value == reason);
    // An acquisition failure cannot authenticate references from a partial scan.
    // Both failure constructors clear their source metadata and scan counters.
    let status_valid = match result.status.as_str() {
        "scanned" | "partial" => {
            result.available
                && result.complete == (result.status == "scanned")
                && result.complete == result.reasons.is_empty()
                && result.reasons.len() <= partial_reasons.len()
                && result
                    .reasons
                    .iter()
                    .all(|reason| partial_reasons.contains(&reason.as_str()))
                && result.reasons.windows(2).all(|pair| pair[0] < pair[1])
        }
        "unsupported" | "unavailable" => {
            !result.available
                && !result.complete
                && result.reasons.len() == 1
                && if result.status == "unsupported" {
                    unsupported_reasons.contains(&result.reasons[0].as_str())
                } else {
                    unavailable_reasons.contains(&result.reasons[0].as_str())
                }
                && result.source_origin.is_none()
                && result.source_sequence.is_none()
                && result.source_started_at.is_none()
                && result.retained_preview_bytes.is_none()
                && !result.capture_preview_truncated
                && !result.scan_prefix_truncated
                && result.references.is_empty()
                && result.scanned_bytes == 0
                && result.candidates_scanned == 0
                && result.omitted_reference_occurrences == 0
        }
        _ => false,
    };
    let mut origins = std::collections::HashSet::new();
    let references_valid = result.references.iter().all(|reference| {
        service_map_body_safe_origin(&reference.target_origin)
            && origins.insert(&reference.target_origin)
            && reference.occurrences > 0
            && reference.occurrences <= MAX_CANDIDATES
            && reference.preview_byte_offsets.len()
                == reference.occurrences.min(MAX_OFFSETS_PER_ORIGIN)
            && reference.omitted_offsets
                == reference.occurrences - reference.preview_byte_offsets.len()
            && (reference.omitted_offsets == 0
                || result.reasons.iter().any(|reason| reason == "offset_limit"))
            && reference
                .preview_byte_offsets
                .iter()
                .all(|offset| *offset < result.scanned_bytes)
            && reference
                .preview_byte_offsets
                .windows(2)
                .all(|pair| pair[0] < pair[1])
    });
    let valid = result.schema_version == 1
        && result.session_id == args.session_id
        && result.evidence_id == args.evidence_id
        && result.coverage == "literal_absolute_http_urls"
        && result.offset_basis == "retained_utf8_preview"
        && status_valid
        && token_valid
        && result
            .source_origin
            .as_deref()
            .is_none_or(service_map_safe_origin)
        && result.source_sequence.as_ref().is_none_or(|sequence| {
            token_fields[1] == args.session_id.to_string()
                && token_fields[3] == sequence
                && sequence
                    .parse::<u64>()
                    .is_ok_and(|value| value.to_string() == *sequence)
        })
        && (!result.available
            || (result.source_origin.is_some()
                && result.source_sequence.is_some()
                && result.source_started_at.is_some()
                && result.retained_preview_bytes.is_some()))
        && result.scanned_bytes <= MAX_SCAN_BYTES
        && result
            .retained_preview_bytes
            .is_none_or(|bytes| result.scanned_bytes <= bytes)
        && result.candidates_scanned <= MAX_CANDIDATES
        && result.references.len() <= MAX_ORIGINS
        && result.omitted_reference_occurrences <= result.candidates_scanned
        && result.references.iter().fold(0usize, |total, reference| {
            total.saturating_add(reference.occurrences)
        }) <= result
            .candidates_scanned
            .saturating_sub(result.omitted_reference_occurrences)
        && (!result.available
            || (has_reason("capture_preview_truncated") == result.capture_preview_truncated
                && has_reason("scan_prefix_truncated") == result.scan_prefix_truncated
                && result.scan_prefix_truncated
                    == result
                        .retained_preview_bytes
                        .is_some_and(|bytes| result.scanned_bytes < bytes)
                && result.retained_preview_bytes.is_some_and(|bytes| {
                    if bytes <= MAX_SCAN_BYTES {
                        result.scanned_bytes == bytes
                    } else {
                        (MAX_SCAN_BYTES - 3..=MAX_SCAN_BYTES).contains(&result.scanned_bytes)
                    }
                })
                && (!has_reason("candidate_limit")
                    || result.candidates_scanned == MAX_CANDIDATES)
                && (!has_reason("candidate_bytes") || result.candidates_scanned > 0)
                && has_reason("origin_limit") == (result.omitted_reference_occurrences > 0)
                && (!has_reason("origin_limit") || result.references.len() == MAX_ORIGINS)
                && has_reason("offset_limit")
                    == result
                        .references
                        .iter()
                        .any(|reference| reference.omitted_offsets > 0)))
        && result.limits.scan_bytes == MAX_SCAN_BYTES
        && result.limits.serialized_row_bytes == MAX_SERIALIZED_ROW_BYTES
        && result.limits.origins == MAX_ORIGINS
        && result.limits.candidates == MAX_CANDIDATES
        && result.limits.candidate_bytes == MAX_CANDIDATE_BYTES
        && result.limits.offsets_per_origin == MAX_OFFSETS_PER_ORIGIN
        && references_valid;
    if !valid {
        return Err(service_map_error("INVALID_RESPONSE", "Service Map body references do not match the requested session, exact-row token, bounds, or origin-only response contract"));
    }
    Ok(())
}

// Version 1 deliberately has no additive free-text fields. Compare the complete
// shape before printing typed output, including every explicit nullable field.
fn service_map_html_response_shape(raw: &Value, typed: &Value) -> bool {
    match (raw, typed) {
        (Value::Object(raw), Value::Object(typed)) => {
            raw.len() == typed.len()
                && typed.iter().all(|(key, value)| {
                    raw.get(key)
                        .is_some_and(|raw| service_map_html_response_shape(raw, value))
                })
        }
        (Value::Array(raw), Value::Array(typed)) => {
            raw.len() == typed.len()
                && raw
                    .iter()
                    .zip(typed)
                    .all(|(raw, typed)| service_map_html_response_shape(raw, typed))
        }
        _ => true,
    }
}

fn validate_service_map_html_generators_response(
    result: &ServiceMapHtmlGenerators,
    args: &ServiceMapHtmlGeneratorsArgs,
) -> Result<()> {
    use sniper::service_map_html::{
        ByteSpan, ServiceMapHtmlLimits, ACQUISITION_REASONS, MAX_OBSERVATIONS, MAX_SCAN_BYTES,
        MAX_TAG_BYTES, MAX_TAG_CANDIDATES, MAX_VERSION_BYTES, MAX_VERSION_SEPARATOR_BYTES,
        PARSER_STOP_REASONS, TRUNCATION_REASONS,
    };
    let invalid = || {
        service_map_error("INVALID_RESPONSE", "HTML generator inspection does not match the requested session, exact-row token, fixed catalog, bounds, or safe declaration contract")
    };
    let token_fields: Vec<_> = args.evidence_id.split('.').collect();
    if parse_service_map_evidence_id(&args.evidence_id).is_err()
        || result.schema_version != 1
        || result.generator_catalog_version != 1
        || result.session_id != args.session_id
        || result.evidence_id != args.evidence_id
        || result.coverage != "literal_html_generator_explicit_head"
        || result.offset_basis != "retained_utf8_preview"
        || serde_json::to_value(&result.limits).ok()
            != serde_json::to_value(ServiceMapHtmlLimits::default()).ok()
    {
        return Err(invalid());
    }
    if !result.available {
        let valid = matches!(result.status.as_str(), "unsupported" | "unavailable")
            && !result.complete
            && result.reasons.len() == 1
            && ACQUISITION_REASONS.contains(&result.reasons[0].as_str())
            // Missing constructors also accept eligibility reasons; only unsupported is narrower.
            && (result.status != "unsupported"
                || matches!(
                    result.reasons[0].as_str(),
                    "metadata_limit"
                        | "unsupported_content_type"
                        | "unsupported_body_encoding"
                        | "unsupported_content_encoding"
                        | "unsupported_metadata"
                ))
            && result.source_origin.is_none()
            && result.source_sequence.is_none()
            && result.source_started_at.is_none()
            && result.retained_preview_bytes.is_none()
            && result.scan_prefix_bytes == 0
            && !result.capture_preview_truncated
            && !result.scan_prefix_truncated
            && !result.head_closed
            && result.parser_stop.is_none()
            && result.tag_candidates_inspected == 0
            && !result.additional_tag_candidate_encountered
            && !result.additional_observation_encountered
            && result.unknown_product_declarations == 0
            && result.observations.is_empty();
        return if valid { Ok(()) } else { Err(invalid()) };
    }
    let Some(retained_bytes) = result.retained_preview_bytes else {
        return Err(invalid());
    };
    let prefix_bytes = result.scan_prefix_bytes;
    let mut expected_reasons = std::collections::BTreeSet::new();
    if result.capture_preview_truncated {
        expected_reasons.insert(TRUNCATION_REASONS[0]);
    }
    if result.scan_prefix_truncated {
        expected_reasons.insert(TRUNCATION_REASONS[1]);
    }
    if let Some(stop) = &result.parser_stop {
        // The parser's stop cursor is a raw byte position. Unlike an accepted
        // span it need not be a character boundary, and never slices text here.
        if !PARSER_STOP_REASONS.contains(&stop.reason.as_str())
            || stop.byte_cursor > prefix_bytes
            || (stop.reason == "end_of_preview"
                && (stop.byte_cursor != prefix_bytes || result.scan_prefix_truncated))
            || (stop.reason == "input_limit"
                && (stop.byte_cursor != prefix_bytes || !result.scan_prefix_truncated))
        {
            return Err(invalid());
        }
        expected_reasons.insert(stop.reason.as_str());
    }
    let reasons: std::collections::BTreeSet<_> =
        result.reasons.iter().map(String::as_str).collect();
    let stop_reason = result.parser_stop.as_ref().map(|stop| stop.reason.as_str());
    let capped_prefix_valid = if retained_bytes <= MAX_SCAN_BYTES {
        prefix_bytes == retained_bytes
    } else {
        (MAX_SCAN_BYTES - 3..=MAX_SCAN_BYTES).contains(&prefix_bytes)
    };
    // Every declaration is inside the two explicit opening tags. A closed
    // head adds its own candidate, including when it contains no declarations.
    let declaration_count = result
        .unknown_product_declarations
        .saturating_add(result.observations.len())
        .saturating_add(usize::from(result.additional_observation_encountered));
    let minimum_candidates = if declaration_count > 0 {
        declaration_count
            .saturating_add(2)
            .saturating_add(usize::from(result.head_closed))
    } else if result.head_closed {
        3
    } else {
        0
    };
    if result.status != "scanned"
        || token_fields[1] != args.session_id.to_string()
        || result.source_sequence.as_deref() != Some(token_fields[3])
        || !result
            .source_origin
            .as_deref()
            .is_some_and(service_map_safe_origin)
        || result.source_started_at.is_none()
        || !capped_prefix_valid
        || result.scan_prefix_truncated != (prefix_bytes < retained_bytes)
        || result.complete != expected_reasons.is_empty()
        || result.head_closed != result.parser_stop.is_none()
        || reasons != expected_reasons
        || reasons.len() != result.reasons.len()
        || result.tag_candidates_inspected > MAX_TAG_CANDIDATES
        || result.tag_candidates_inspected > prefix_bytes
        || result.tag_candidates_inspected < minimum_candidates
        || result.parser_stop.as_ref().is_some_and(|stop| {
            result.tag_candidates_inspected > stop.byte_cursor.saturating_add(1)
        })
        || result.observations.len() > MAX_OBSERVATIONS
        || result.unknown_product_declarations > MAX_TAG_CANDIDATES
        || result.additional_tag_candidate_encountered
            != (stop_reason == Some("tag_candidate_limit"))
        || (result.additional_tag_candidate_encountered
            && result.tag_candidates_inspected != MAX_TAG_CANDIDATES)
        || result.additional_observation_encountered != (stop_reason == Some("observation_limit"))
        || (result.additional_observation_encountered
            && result.observations.len() != MAX_OBSERVATIONS)
    {
        return Err(invalid());
    }
    let valid_span = |span: ByteSpan| span.start < span.end && span.end <= prefix_bytes;
    let mut last_tag_end = 0;
    for observation in &result.observations {
        let (name, rule) = match observation.product_id.as_str() {
            "wordpress" => ("WordPress", "html_meta_generator.wordpress.v1"),
            "drupal" => ("Drupal", "html_meta_generator.drupal.v1"),
            _ => return Err(invalid()),
        };
        let tag = observation.tag_span;
        let content = observation.content_span;
        let product = observation.product_span;
        if observation.name != name
            || observation.rule_id != rule
            || observation.catalog_category != "cms"
            || observation.source != "response_html_meta_generator"
            || observation.strength != "literal_declaration"
            || observation.offset_basis != "retained_utf8_preview"
            || ![tag, content, product].into_iter().all(valid_span)
            || tag.end - tag.start > MAX_TAG_BYTES
            || tag.start < last_tag_end
            || tag.start >= content.start
            || content.end >= tag.end
            || product.start != content.start
            || product.end > content.end
            || product.end - product.start != name.len()
            || result
                .parser_stop
                .as_ref()
                .is_some_and(|stop| tag.end > stop.byte_cursor)
        {
            return Err(invalid());
        }
        last_tag_end = tag.end;
        let version_valid = match (
            observation.version_status.as_str(),
            observation.reported_version.as_deref(),
            observation.version_span,
        ) {
            ("reported", Some(version), Some(span)) => {
                !version.is_empty()
                    && version.len() <= MAX_VERSION_BYTES
                    && version.split('.').all(|part| {
                        !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())
                    })
                    && valid_span(span)
                    && span.start > product.end
                    && span.start - product.end <= MAX_VERSION_SEPARATOR_BYTES
                    && span.end == content.end
                    && span.end - span.start == version.len()
            }
            ("not_reported", None, None) => product.end == content.end,
            ("unsupported_format", None, None) => product.end < content.end,
            _ => false,
        };
        if !version_valid {
            return Err(invalid());
        }
    }
    Ok(())
}

fn validate_service_map_link_declarations_response(
    result: &ServiceMapLinkDeclarations,
    args: &ServiceMapLinkDeclarationsArgs,
) -> Result<()> {
    let invalid = || {
        service_map_error("INVALID_RESPONSE", "Link declaration inspection does not match the requested session, exact-row token, fixed catalog, bounds, or safe declaration contract")
    };
    let fields: Vec<_> = args.evidence_id.split('.').collect();
    let c = &result.counts;
    if parse_service_map_evidence_id(&args.evidence_id).is_err()
        || result.schema_version != 1
        || result.relation_catalog_version != 1
        || result.session_id != args.session_id
        || result.evidence_id != args.evidence_id
        || result.coverage != "absolute_http_link_declarations"
        || result.offset_basis != "retained_header_value_utf8"
        || serde_json::to_value(&result.limits).ok()
            != Some(json!({
                "headers":128,"header_bytes":32768,"link_field_bytes":4096,"target_bytes":4096,
                "candidates":128,"parameters_per_member":32,"relation_tokens_per_member":32,
                "observations":32,"target_origin_bytes":268
            }))
    {
        return Err(invalid());
    }
    if !result.available {
        let valid = matches!(result.status.as_str(), "unsupported" | "unavailable")
            && !result.complete
            && result.reasons.len() == 1
            && LINK_ACQUISITION_REASONS.contains(&result.reasons[0].as_str())
            && (result.status != "unsupported"
                || result.reasons[0] == "unsupported_source_context")
            && result.source_origin.is_none()
            && result.source_sequence.is_none()
            && result.source_started_at.is_none()
            && result.source_method.is_none()
            && result.source_status.is_none()
            && result.retained_header_count.is_none()
            && c.headers_inspected == 0
            && c.header_bytes_admitted == 0
            && c.link_fields_inspected == 0
            && c.candidates_inspected == 0
            && c.members_framed == 0
            && c.parameters_inspected == 0
            && c.relation_tokens_inspected == 0
            && c.unknown_relation_tokens_inspected == 0
            && result.observations.is_empty();
        return if valid { Ok(()) } else { Err(invalid()) };
    }
    let Some(retained) = result.retained_header_count else {
        return Err(invalid());
    };
    let has = |reason: &str| result.reasons.iter().any(|value| value == reason);
    if result.status != "scanned"
        || fields[1] != args.session_id.to_string()
        || result.source_sequence.as_deref() != Some(fields[3])
        || !result
            .source_origin
            .as_deref()
            .is_some_and(service_map_safe_origin)
        || result.source_started_at.is_none()
        || !matches!(result.source_method.as_deref(), Some("GET" | "HEAD"))
        || result.source_status != Some(200)
        || retained as u128 > 9_007_199_254_740_991
        || result.complete != result.reasons.is_empty()
        || !result
            .reasons
            .iter()
            .all(|reason| LINK_SCAN_REASONS.contains(&reason.as_str()))
        || !result.reasons.windows(2).all(|pair| pair[0] < pair[1])
        || c.headers_inspected > 128
        || c.headers_inspected > retained
        || c.header_bytes_admitted > 32768
        || (c.headers_inspected == 0 && c.header_bytes_admitted != 0)
        || c.link_fields_inspected > c.headers_inspected
        || c.header_bytes_admitted < c.link_fields_inspected * 4
        || c.candidates_inspected > 128
        || (c.link_fields_inspected == 0 && c.candidates_inspected != 0)
        || c.members_framed > c.candidates_inspected
        || c.parameters_inspected > c.candidates_inspected * 32
        || c.relation_tokens_inspected > c.members_framed * 32
        || c.unknown_relation_tokens_inspected > c.relation_tokens_inspected
        || result.observations.len() > 32
        || result.observations.len()
            > c.relation_tokens_inspected
                .saturating_sub(c.unknown_relation_tokens_inspected)
        || (c.headers_inspected < retained
            && !has("header_count_limit")
            && !has("header_byte_limit")
            && !has("candidate_limit"))
        || (has("header_count_limit") && (c.headers_inspected != 128 || retained <= 128))
        || (has("header_byte_limit") && c.headers_inspected >= retained)
        || (has("candidate_limit") && c.candidates_inspected != 128)
        || (has("parameter_limit") && c.parameters_inspected < 32)
        || (has("relation_token_limit") && c.relation_tokens_inspected < 32)
        || (has("link_field_byte_limit")
            && (c.link_fields_inspected == 0 || c.header_bytes_admitted < 4101))
        || (has("observation_limit")
            && (result.observations.len() != 32
                || c.relation_tokens_inspected
                    .saturating_sub(c.unknown_relation_tokens_inspected)
                    <= 32))
        || (result.complete
            && (c.headers_inspected != retained
                || c.candidates_inspected != c.members_framed
                || result.observations.len()
                    != c.relation_tokens_inspected
                        .saturating_sub(c.unknown_relation_tokens_inspected)))
    {
        return Err(invalid());
    }
    let mut previous: Option<&sniper::service_map_links::LinkDeclarationObservation> = None;
    let mut emitted_headers = 0;
    let mut emitted_members = 0;
    let mut observed_header_bytes = 0;
    for observation in &result.observations {
        let rule = match observation.relation.as_str() {
            "service-doc" => "response_link.service_doc.v1",
            "service-desc" => "response_link.service_desc.v1",
            "describedby" => "response_link.describedby.v1",
            "preconnect" => "response_link.preconnect.v1",
            _ => return Err(invalid()),
        };
        let member = (
            observation.link_value_span.start,
            observation.link_value_span.end,
        );
        let target = (observation.target_span.start, observation.target_span.end);
        let relation = (
            observation.relation_span.start,
            observation.relation_span.end,
        );
        let bytes = observation.header_value_bytes;
        if observation.rule_id != rule
            || observation.source != "response_link_header"
            || observation.strength != "literal_declaration"
            || observation.header_name != "link"
            || observation.offset_basis != "retained_header_value_utf8"
            || !sniper::service_map_links::is_canonical_target_origin(&observation.target_origin)
            || observation.header_index >= c.headers_inspected
            || bytes > 4096
            || ![member, target, relation]
                .iter()
                .all(|&(start, end)| start < end && end <= bytes)
            || target.0 != member.0 + 1
            || target.1 >= relation.0
            || relation.1 > member.1
            || relation.1 - relation.0 != observation.relation.len()
        {
            return Err(invalid());
        }
        // A rel list emits several ordered tokens from one fully framed member.
        // It must not be mistaken for overlapping distinct members or deduplicated.
        let mut new_header = true;
        let mut new_member = true;
        if let Some(last) = previous {
            if observation.header_index < last.header_index {
                return Err(invalid());
            }
            if observation.header_index == last.header_index {
                new_header = false;
                if bytes != last.header_value_bytes {
                    return Err(invalid());
                }
                if observation.link_value_span == last.link_value_span {
                    new_member = false;
                    if observation.target_span != last.target_span
                        || observation.target_origin != last.target_origin
                        || relation.0 <= last.relation_span.end
                    {
                        return Err(invalid());
                    }
                } else if member.0 <= last.link_value_span.end {
                    return Err(invalid());
                }
            }
        }
        emitted_headers += usize::from(new_header);
        emitted_members += usize::from(new_member);
        if new_header {
            observed_header_bytes += bytes + 4;
        }
        previous = Some(observation);
    }
    if emitted_headers > c.link_fields_inspected
        || emitted_members > c.members_framed
        || emitted_members > c.parameters_inspected
        || observed_header_bytes > c.header_bytes_admitted
    {
        return Err(invalid());
    }
    Ok(())
}

async fn read_service_map_socket_peer_matches(
    api: &ApiClient,
    args: &ServiceMapSocketPeerMatchesArgs,
) -> Result<ServiceMapSocketPeerMatches> {
    let client = service_map_read_client()?;
    let raw: Value =
        service_map_get(api, &client, &service_map_socket_peer_matches_path(args)).await?;
    let invalid = || {
        service_map_error(
            "INVALID_RESPONSE",
            "The selected API returned an invalid recorded socket peer match envelope",
        )
    };
    let result: ServiceMapSocketPeerMatches =
        serde_json::from_value(raw.clone()).map_err(|_| invalid())?;
    let typed = serde_json::to_value(&result).map_err(|_| invalid())?;
    // Shape checks require explicit nullable keys. Compare only identities that
    // must be canonical; valid RFC3339 timestamp offsets may normalize in serde.
    if !service_map_html_response_shape(&raw, &typed)
        || raw["session_id"] != args.session_id.to_string()
        || raw["evidence_id"] != args.evidence_id
        || raw.pointer("/snapshot/id") != typed.pointer("/snapshot/id")
        || raw.pointer("/snapshot/generation") != typed.pointer("/snapshot/generation")
        || raw.pointer("/peer/address/ip") != typed.pointer("/peer/address/ip")
        || !result.validate_response(
            args.session_id,
            &args.evidence_id,
            args.in_scope_only,
            args.max_records,
        )
    {
        return Err(invalid());
    }
    if !result.available
        && result
            .reasons
            .iter()
            .any(|reason| reason == "scope_work_limit")
    {
        eprintln!("{SERVICE_MAP_PEER_SCOPE_WORK_WARNING}");
    }
    Ok(result)
}

async fn read_service_map_link_declarations(
    api: &ApiClient,
    args: &ServiceMapLinkDeclarationsArgs,
) -> Result<ServiceMapLinkDeclarations> {
    let client = service_map_read_client()?;
    let raw: Value =
        service_map_get(api, &client, &service_map_link_declarations_path(args)).await?;
    let invalid = || {
        service_map_error(
            "INVALID_RESPONSE",
            "The selected API returned an invalid Link declaration inspection envelope",
        )
    };
    let result: ServiceMapLinkDeclarations =
        serde_json::from_value(raw.clone()).map_err(|_| invalid())?;
    let typed = serde_json::to_value(&result).map_err(|_| invalid())?;
    if !service_map_html_response_shape(&raw, &typed)
        || raw["session_id"] != args.session_id.to_string()
        || raw["evidence_id"] != args.evidence_id
    {
        return Err(invalid());
    }
    validate_service_map_link_declarations_response(&result, args)?;
    Ok(result)
}

/// One endpoint's parameters, checked against what was asked and the
/// server's own bounds before any of it is printed.
fn validate_service_map_parameters_response(
    result: &sniper::service_map_parameters::EndpointParameters,
    args: &ServiceMapParametersArgs,
) -> Result<()> {
    use sniper::service_map_parameters::{
        MAX_EXAMPLES, MAX_EXAMPLE_CHARS, MAX_PARAMETERS, MAX_ROWS,
    };
    let valid = result.schema_version == 1
        && result.session_id == args.session_id
        && result.origin == args.origin
        && result.method == args.method
        && result.path == args.path
        && result.rows <= MAX_ROWS
        && result.parameters.len() <= MAX_PARAMETERS
        && (result.available || !result.reasons.is_empty() && result.parameters.is_empty())
        && result.parameters.iter().all(|parameter| {
            ["query", "form", "json", "multipart"].contains(&parameter.location.as_str())
                && (1..=result.rows).contains(&parameter.rows)
                && parameter.examples.len() <= MAX_EXAMPLES
                // A cut value ends with an ellipsis.
                && parameter
                    .examples
                    .iter()
                    .all(|example| example.chars().count() <= MAX_EXAMPLE_CHARS + 1)
        });
    if !valid {
        return Err(service_map_error(
            "INVALID_RESPONSE",
            "Endpoint parameters do not match the requested session, endpoint, or bounds",
        ));
    }
    Ok(())
}

async fn read_service_map_parameters(
    api: &ApiClient,
    args: &ServiceMapParametersArgs,
) -> Result<sniper::service_map_parameters::EndpointParameters> {
    let client = service_map_read_client()?;
    let raw: Value = service_map_get(api, &client, &service_map_parameters_path(args)).await?;
    let invalid = || {
        service_map_error(
            "INVALID_RESPONSE",
            "The selected API returned an invalid endpoint parameters envelope",
        )
    };
    let result: sniper::service_map_parameters::EndpointParameters =
        serde_json::from_value(raw.clone()).map_err(|_| invalid())?;
    // Unknown fields would be dropped above; refuse them instead.
    if serde_json::to_value(&result).map_err(|_| invalid())? != raw {
        return Err(invalid());
    }
    validate_service_map_parameters_response(&result, args)?;
    Ok(result)
}

/// One origin's OpenAPI document, checked against the origin asked for and
/// the server's own bounds before any of it is printed.
fn validate_service_map_openapi_response(
    document: &Value,
    args: &ServiceMapOpenApiArgs,
) -> Result<()> {
    use sniper::service_map_openapi::{MAX_OPERATIONS, METHODS};
    let paths = document["paths"].as_object();
    let operations: usize = paths.map_or(0, |paths| {
        paths
            .values()
            .map(|item| {
                METHODS
                    .iter()
                    .filter(|method| item.get(**method).is_some())
                    .count()
            })
            .sum()
    });
    let valid = document["openapi"] == "3.1.0"
        && document["info"]["title"] == args.origin
        && document["servers"] == json!([{ "url": args.origin }])
        && paths.is_some_and(|paths| {
            paths
                .iter()
                .all(|(path, item)| path.starts_with('/') && item.is_object())
        })
        && operations <= MAX_OPERATIONS;
    if !valid {
        return Err(service_map_error(
            "INVALID_RESPONSE",
            "The OpenAPI document does not match the requested origin or bounds",
        ));
    }
    Ok(())
}

/// One origin's flow, checked against the origin and session asked for and the
/// server's own bounds before any of it is printed. Returns its session.
fn validate_service_map_flow_response(flow: &Value, args: &ServiceMapFlowArgs) -> Result<Uuid> {
    use sniper::service_map_flow::{MAX_LANES, MAX_STEPS};
    let lanes: Vec<&str> = flow["lanes"]
        .as_array()
        .map(|lanes| lanes.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let steps: Vec<&Value> = flow["phases"]
        .as_array()
        .map(|phases| {
            phases
                .iter()
                .flat_map(|phase| phase["steps"].as_array().into_iter().flatten())
                .collect()
        })
        .unwrap_or_default();
    let session = flow["session_id"]
        .as_str()
        .and_then(|id| Uuid::parse_str(id).ok());
    let valid = flow["schema_version"] == 1
        && flow["origin"] == args.origin
        && session.is_some_and(|session| args.session_id.is_none_or(|asked| asked == session))
        && lanes.first() == Some(&args.origin.as_str())
        && lanes.len() <= MAX_LANES
        && flow["lanes"]
            .as_array()
            .is_some_and(|all| all.len() == lanes.len())
        && steps.len() <= MAX_STEPS
        && steps.iter().all(|step| {
            step["origin"]
                .as_str()
                .is_some_and(|origin| lanes.contains(&origin))
                && step["count"].as_u64().is_some_and(|count| count >= 1)
                && step["record_id"]
                    .as_str()
                    .is_some_and(|id| Uuid::parse_str(id).is_ok())
        });
    match session {
        Some(session) if valid => Ok(session),
        _ => Err(service_map_error(
            "INVALID_RESPONSE",
            "The flow does not match the requested origin, session or bounds",
        )),
    }
}

async fn read_service_map_flow(
    api: &ApiClient,
    args: &ServiceMapFlowArgs,
) -> Result<(Value, Uuid)> {
    let client = service_map_read_client()?;
    let flow: Value = service_map_get(api, &client, &service_map_flow_path(args)).await?;
    let session = validate_service_map_flow_response(&flow, args)?;
    Ok((flow, session))
}

async fn read_service_map_openapi(api: &ApiClient, args: &ServiceMapOpenApiArgs) -> Result<Value> {
    let client = service_map_read_client()?;
    let document: Value = service_map_get(api, &client, &service_map_openapi_path(args)).await?;
    validate_service_map_openapi_response(&document, args)?;
    Ok(document)
}

async fn read_service_map_html_generators(
    api: &ApiClient,
    args: &ServiceMapHtmlGeneratorsArgs,
) -> Result<ServiceMapHtmlGenerators> {
    let client = service_map_read_client()?;
    let raw: Value = service_map_get(api, &client, &service_map_html_generators_path(args)).await?;
    let invalid = || {
        service_map_error(
            "INVALID_RESPONSE",
            "The selected API returned an invalid HTML generator inspection envelope",
        )
    };
    let result: ServiceMapHtmlGenerators =
        serde_json::from_value(raw.clone()).map_err(|_| invalid())?;
    let typed = serde_json::to_value(&result).map_err(|_| invalid())?;
    if !service_map_html_response_shape(&raw, &typed) {
        return Err(invalid());
    }
    validate_service_map_html_generators_response(&result, args)?;
    Ok(result)
}

async fn read_service_map_body_references(
    api: &ApiClient,
    args: &ServiceMapBodyReferencesArgs,
) -> Result<ServiceMapBodyReferences> {
    let client = service_map_read_client()?;
    let result: ServiceMapBodyReferences =
        service_map_get(api, &client, &service_map_body_references_path(args)).await?;
    validate_service_map_body_references_response(&result, args)?;
    Ok(result)
}

async fn read_service_map(api: &ApiClient, args: &ServiceMapArgs) -> Result<ServiceMap> {
    let client = service_map_read_client()?;
    let session_id = if let Some(session_id) = args.session_id {
        session_id
    } else {
        let sessions: Vec<SessionSummary> = service_map_get(api, &client, "/api/sessions").await?;
        active_session_id_from_summaries(&sessions)?.ok_or_else(|| {
            anyhow!("no active session; pass --session-id to choose a session explicitly")
        })?
    };
    let result: ServiceMap = service_map_get_with_catalog(
        api,
        &client,
        &service_map_path(args, Some(session_id)),
        Some(args.technology_catalog_version),
    )
    .await?;
    validate_service_map_response(&result, args, session_id)?;
    warn_legacy_service_map_catalog(result.technology_catalog_version);
    Ok(result)
}

async fn read_service_map_evidence(
    api: &ApiClient,
    args: &ServiceMapEvidenceArgs,
) -> Result<ServiceMapEvidence> {
    let client = service_map_read_client()?;
    let result: ServiceMapEvidence = service_map_get_with_catalog(
        api,
        &client,
        &service_map_evidence_path(args),
        Some(args.technology_catalog_version),
    )
    .await?;
    validate_service_map_evidence_response(&result, args)?;
    warn_legacy_service_map_catalog(result.technology_catalog_version);
    Ok(result)
}

async fn handle_target(api: ApiClient, command: TargetCommand) -> Result<()> {
    match command {
        TargetCommand::ServiceMap(args) => match &args.command {
            Some(ServiceMapCommand::BodyReferences(args)) => {
                let result = read_service_map_body_references(&api, args).await?;
                print_session_read_json(&result, args.session_id)
            }
            Some(ServiceMapCommand::HtmlGenerators(args)) => {
                let result = read_service_map_html_generators(&api, args).await?;
                print_session_read_json(&result, args.session_id)
            }
            Some(ServiceMapCommand::Parameters(args)) => {
                let result = read_service_map_parameters(&api, args).await?;
                print_session_read_json(&result, args.session_id)
            }
            Some(ServiceMapCommand::Openapi(args)) => {
                let result = read_service_map_openapi(&api, args).await?;
                print_session_read_json(&result, args.session_id)
            }
            Some(ServiceMapCommand::Flow(args)) => {
                let (result, session) = read_service_map_flow(&api, args).await?;
                print_session_read_json(&result, session)
            }
            Some(ServiceMapCommand::Unnamed(args)) => {
                let map = read_service_map(&api, &args.map_args()).await?;
                let summary = summarize_unnamed(&map, args.kind.as_deref(), args.limit as usize);
                print_session_read_json(&summary, summary.session_id)
            }
            Some(ServiceMapCommand::LinkDeclarations(args)) => {
                let result = read_service_map_link_declarations(&api, args).await?;
                print_session_read_json(&result, args.session_id)
            }
            Some(ServiceMapCommand::SocketPeerMatches(args)) => {
                let result = read_service_map_socket_peer_matches(&api, args).await?;
                print_session_read_json(&result, args.session_id)
            }
            None => {
                let result = read_service_map(&api, &args).await?;
                print_session_read_json(&result, result.session_id)
            }
        },
        TargetCommand::ServiceMapEvidence(args) => {
            let result = read_service_map_evidence(&api, &args).await?;
            print_session_read_json(&result, args.session_id)
        }
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

#[derive(Serialize, Deserialize)]
struct ReplayLabelUpdateResult {
    session_id: Uuid,
    revision: u64,
    tab: ReplayTabState,
}

// Persistence defaults support old saved inputs, but cannot prove a complete
// acknowledgement. Check the fields the current serializer actually emits,
// allowing absent nullable fields and additive fields from newer servers.
fn metadata_acknowledgement_has_fields(raw: &Value, serialized: &Value) -> bool {
    match serialized {
        Value::Object(fields) => fields.iter().all(|(key, value)| match raw.get(key) {
            Some(actual) => metadata_acknowledgement_has_fields(actual, value),
            None => value.is_null(),
        }),
        Value::Array(values) => raw.as_array().is_some_and(|actual| {
            actual.len() == values.len()
                && actual
                    .iter()
                    .zip(values)
                    .all(|(raw, value)| metadata_acknowledgement_has_fields(raw, value))
        }),
        _ => true,
    }
}

fn decode_metadata_acknowledgement<T: DeserializeOwned + Serialize>(raw: Value) -> Result<T> {
    let result: T =
        serde_json::from_value(raw.clone()).map_err(|_| MetadataAcknowledgementError)?;
    let serialized = serde_json::to_value(&result).map_err(|_| MetadataAcknowledgementError)?;
    if !metadata_acknowledgement_has_fields(&raw, &serialized) {
        return Err(MetadataAcknowledgementError.into());
    }
    Ok(result)
}

fn metadata_acknowledgement_decode_error(error: anyhow::Error) -> anyhow::Error {
    if error
        .downcast_ref::<reqwest::Error>()
        .is_some_and(|error| error.is_decode() || error.is_body() || error.is_timeout())
    {
        MetadataAcknowledgementError.into()
    } else {
        error
    }
}

fn replay_update_is_label_only(args: &ReplayUpdateArgs) -> bool {
    args.label.is_some()
        && args.request_file.is_none()
        && !args.stdin
        && args.scheme.is_none()
        && args.host.is_none()
        && args.port.is_none()
}

fn saved_configuration_write_client() -> Result<reqwest::Client> {
    // A metadata write must not be replayed automatically or sent to a redirect target.
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(CLI_API_TIMEOUT)
        .build()
        .context("failed to prepare saved configuration client; no mutation was sent")
}

async fn update_saved_replay_label(api: &ApiClient, args: ReplayUpdateArgs) -> Result<()> {
    let (session_id, expected_active_session_id) =
        runtime_write_session_ids(api, args.session_id).await?;
    let session_id = session_id
        .ok_or_else(|| anyhow!("no active session was found; select an explicit --session-id"))?;
    let workspace: WorkspaceStateSnapshot = api
        .get_json(&session_query_path(
            "/api/workspace-state",
            Some(session_id),
        ))
        .await?;
    if workspace.session_id != Some(session_id) {
        bail!("workspace response did not match the selected session; no mutation was sent");
    }
    find_replay_tab(&workspace.replay, &args.tab_id)?;
    let mut payload = json!({
        "session_id":session_id,
        "tab_id":args.tab_id,
        "expected_workspace_revision":workspace.revision,
        "label":normalize_replay_tab_label(args.label.as_deref().unwrap()),
    });
    if let Some(expected_active_session_id) = expected_active_session_id {
        payload["expected_active_session_id"] = json!(expected_active_session_id);
    }
    let client = saved_configuration_write_client()?;
    let raw: Value = api
        .request_json_with_client(
            &client,
            Method::POST,
            "/api/replay/tabs/set-label",
            Some(&payload),
        )
        .await
        .map_err(metadata_acknowledgement_decode_error)?;
    let result: ReplayLabelUpdateResult = decode_metadata_acknowledgement(raw)?;
    if result.session_id != session_id
        || Some(result.revision) != workspace.revision.checked_add(1)
        || result.tab.id != args.tab_id
        || result.tab.custom_label != payload["label"].as_str().unwrap()
    {
        return Err(MetadataAcknowledgementError.into());
    }
    print_json_with_session(&result.tab, Some(result.session_id))
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
            if replay_update_is_label_only(&args) {
                return update_saved_replay_label(&api, args).await;
            }
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
            adopt_target_scheme_for_uncaptured_request(
                tab.base_request.as_mut(),
                tab.source_transaction_id,
                &tab.target_scheme,
            );
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

            let started: FuzzerAttackRecord = api
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
                        attack_type: args.attack_type.api_name(),
                        url_encode: !args.raw_payloads,
                        concurrency: args.concurrency.max(1),
                    },
                )
                .await?;
            workspace.fuzzer.attack_record_id = Some(started.id);
            workspace.fuzzer.attack_record = None;
            workspace.fuzzer.notice.clear();
            let workspace_save_error = post_workspace_state(&api, &mut workspace, args.session_id)
                .await
                .err();

            if args.r#async {
                let mut async_output = json!({
                    "async_requested": true,
                    "session_id": workspace.session_id,
                    "message": format!(
                        "The attack runs in the background. Read it with `fuzzer status --id {id}` or `fuzzer results --id {id}`, and stop it with `fuzzer stop --id {id}`.",
                        id = started.id
                    ),
                    "attack": started,
                });
                if let Some(save_error) = workspace_save_error.as_ref() {
                    attach_workspace_save_error(&mut async_output, save_error);
                }
                return print_json(&async_output);
            }
            let record = wait_for_fuzzer_attack(&api, started.id, workspace.session_id).await?;

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
            print_json(&record_output)
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
                "status": fuzzer_attack_state(&record),
                "running": record.running,
                "stopped": record.stopped,
                "started_at": record.started_at,
                "completed_at": record.completed_at,
                "payload_count": record.payload_count,
                "planned": record.planned,
                "result_count": record.results.len(),
                "marker_count": record.marker_count,
            }))
        }
        FuzzerCommand::Stop(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let record: FuzzerAttackRecord = api
                .post_json(
                    &format!("/api/fuzzer/attacks/{}/stop", args.id),
                    &json!({ "session_id": session_id }),
                )
                .await?;
            print_json(&json!({
                "id": record.id,
                "status": fuzzer_attack_state(&record),
                "running": record.running,
                "stopped": record.stopped,
                "planned": record.planned,
                "result_count": record.results.len(),
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

/// One word for where an attack is. The record keeps `status` to completed and
/// failed, which older builds read, and says running and stopped apart.
fn fuzzer_attack_state(record: &FuzzerAttackRecord) -> Value {
    if record.running {
        json!("running")
    } else if record.stopped {
        json!("stopped")
    } else {
        json!(record.status)
    }
}

/// Reads an attack until it ends; the attack itself caps how long that is.
async fn wait_for_fuzzer_attack(
    api: &ApiClient,
    id: Uuid,
    session_id: Option<Uuid>,
) -> Result<FuzzerAttackRecord> {
    let path = session_query_path(&format!("/api/fuzzer/attacks/{id}"), session_id);
    loop {
        let record: FuzzerAttackRecord = api.get_json(&path).await?;
        if !record.running {
            return Ok(record);
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

fn intercept_wait_deadline(timeout_secs: u64) -> Result<std::time::Instant> {
    std::time::Instant::now()
        .checked_add(std::time::Duration::from_secs(timeout_secs))
        .ok_or_else(|| anyhow!("invalid timeout: exceeds the host monotonic clock range"))
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
    let deadline = intercept_wait_deadline(timeout_secs)?;
    let interval = std::time::Duration::from_millis(poll_interval_ms.max(25));
    loop {
        // Zero retains the one-shot queue check. Positive timeouts also bound
        // an unresponsive queue read, not only the delay between polls.
        let mut queued: Vec<T> = if timeout_secs == 0 {
            api.get_json(list_path).await?
        } else {
            match tokio::time::timeout_at(deadline.into(), api.get_json(list_path)).await {
                Ok(result) => result?,
                Err(_) => return Ok(None),
            }
        };
        if !queued.is_empty() {
            return Ok(Some(queued.remove(0)));
        }
        if std::time::Instant::now() >= deadline {
            return Ok(None);
        }
        tokio::time::sleep(
            interval.min(deadline.saturating_duration_since(std::time::Instant::now())),
        )
        .await;
        if std::time::Instant::now() >= deadline {
            return Ok(None);
        }
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
            let (request, edited) = if args.request_file.is_some() || args.stdin {
                let parsed = read_raw_request_input(
                    args.request_file,
                    args.stdin,
                    Some(&intercept.request),
                )?
                .0
                .request;
                // The held request as its raw text parses back: parsing normalises
                // headers, so an unchanged file must not count as an edit.
                let held = parse_editable_raw_request_with_version(
                    &build_editable_raw_request(&intercept.request),
                    Some(&intercept.request),
                )
                .map(|held| held.request)
                .unwrap_or_else(|_| intercept.request.clone());
                let edited = parsed != held && parsed != intercept.request;
                (parsed, edited)
            } else {
                (intercept.request, false)
            };
            let session_id = read_session_id;
            let action_path = session_query_path_with_expected_active(
                &format!("/api/intercepts/{}/forward", args.id),
                read_session_id,
                expected_active_session_id,
            );
            api.post_status(&action_path, &InterceptForwardPayload { request, edited })
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
            let (response, edited) = if args.response_file.is_some() || args.stdin {
                let parsed = read_raw_response_input(
                    args.response_file,
                    args.stdin,
                    Some(&item.response),
                    &item.method,
                )?;
                // ponytail: compared as parsed, so a file that only re-spells the
                // held response may still read as an edit; that keeps the
                // original either way.
                let edited =
                    serde_json::to_value(&parsed).ok() != serde_json::to_value(&item.response).ok();
                (parsed, edited)
            } else {
                (item.response, false)
            };
            let session_id = read_session_id;
            let action_path = session_query_path_with_expected_active(
                &format!("/api/response-intercepts/{}/forward", args.id),
                read_session_id,
                expected_active_session_id,
            );
            api.post_status(
                &action_path,
                &ResponseInterceptForwardPayload { response, edited },
            )
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

fn validate_intercept_rule_update(args: &InterceptRuleUpdateArgs) -> Result<()> {
    if args
        .scope
        .as_deref()
        .is_some_and(|scope| !matches!(scope, "request" | "response" | "both"))
    {
        bail!("invalid field `scope`: expected request, response, or both");
    }
    if args.clear_methods && args.method_filter.is_some() {
        bail!("fields `clear_methods` and `method_filter` have conflicts");
    }
    if args.patch().as_object().unwrap().is_empty() {
        bail!("provide at least one rule update field");
    }
    Ok(())
}

async fn patch_intercept_rule(
    api: &ApiClient,
    id: Uuid,
    session_id: Option<Uuid>,
    patch: Value,
) -> Result<()> {
    let (session_id, expected_active_session_id) =
        runtime_write_session_ids(api, session_id).await?;
    let session_id = session_id
        .ok_or_else(|| anyhow!("no active session was found; select an explicit --session-id"))?;
    let path = session_query_path_with_expected_active(
        &format!("/api/intercept-rules/{id}"),
        Some(session_id),
        expected_active_session_id,
    );
    let client = saved_configuration_write_client()?;
    let raw: Value = api
        .request_json_with_client(&client, Method::PATCH, &path, Some(&patch))
        .await
        .map_err(metadata_acknowledgement_decode_error)?;
    let rule: InterceptRule = decode_metadata_acknowledgement(raw)?;
    let returned = serde_json::to_value(&rule)?;
    if rule.id != id
        || patch
            .as_object()
            .unwrap()
            .iter()
            .any(|(key, value)| returned.get(key) != Some(value))
    {
        return Err(MetadataAcknowledgementError.into());
    }
    print_json_with_session(&rule, Some(session_id))
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
        InterceptRuleCommand::Update(args) => {
            patch_intercept_rule(&api, args.id, args.session_id, args.patch()).await
        }
        InterceptRuleCommand::SetEnabled(args) => {
            patch_intercept_rule(
                &api,
                args.id,
                args.session_id,
                json!({"enabled":args.enabled}),
            )
            .await
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

fn upstream_peer_input_schema(operation: &str) -> Option<Value> {
    if !matches!(
        operation,
        "capture.http.upstream_peer.get" | "capture.http.upstream_peer.set"
    ) {
        return None;
    }
    let mut session_id = legacy_uuid_input_schema(
        false,
        "Explicit current active session UUID. Never loads or activates a session.",
    );
    let hyphenated = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}";
    session_id["pattern"] = json!(format!(
        r"^(?:[0-9a-fA-F]{{32}}|{hyphenated}|\{{{hyphenated}\}}|urn:uuid:{hyphenated})$"
    ));
    let mut schema = json!({
        "type":"object","additionalProperties":false,"required":["session_id"],
        "properties":{"session_id":session_id}
    });
    if operation.ends_with(".set") {
        schema["required"].as_array_mut()?.push(json!("enabled"));
        schema["properties"]["enabled"] = json!({"type":"boolean","description":"Save future observed socket peer capture On or Off; default Off. Does not erase retained observations or backfill old rows."});
    }
    Some(schema)
}

fn upstream_peer_output_schema(operation: &str) -> Option<Value> {
    if !matches!(
        operation,
        "capture.http.upstream_peer.get" | "capture.http.upstream_peer.set"
    ) {
        return None;
    }
    let mut schema = service_map_object(json!({
        "session_id":{"type":"string","format":"uuid"},
        "enabled":{"type":"boolean"},
        "config_revision":history_retention_revision_schema(),
        "config_token":{"type":"string","pattern":"^[0-9a-f]{64}$","description":"Opaque feature/session/configuration-bound compare-and-swap token. Pass unchanged only to this feature's pinned session POST."},
        "status":service_map_object(json!({
            "effective_enabled":{"type":"boolean"},
            "blocked_reason":{"type":["string","null"],"enum":[null,"persistence_uncertain","invalid_configuration","http_capture_paused"]}
        }))
    }));
    if operation.ends_with(".set") {
        schema["required"].as_array_mut()?.push(json!("changed"));
        schema["properties"]["changed"] = json!({"type":"boolean","description":"Whether the saved switch changed; not evidence that any response has been captured."});
    }
    Some(schema)
}

fn upstream_peer_from_input(operation: &str, input: &Value) -> Result<UpstreamPeerCommand> {
    let session_id = call_required(operation, input, "session_id")?;
    if operation.ends_with(".get") {
        Ok(UpstreamPeerCommand::Get(UpstreamPeerGetArgs { session_id }))
    } else {
        Ok(UpstreamPeerCommand::Set(UpstreamPeerSetArgs {
            session_id,
            enabled: call_required(operation, input, "enabled")?,
        }))
    }
}

fn upstream_peer_path(session_id: Uuid) -> String {
    session_query_path_with_expected_active(
        "/api/transactions/upstream-peer-settings",
        Some(session_id),
        Some(session_id),
    )
}

fn upstream_peer_api_preview(command: &UpstreamPeerCommand) -> Value {
    let path = upstream_peer_path(command.session_id());
    let read = api_preview("GET", path.clone(), None);
    let UpstreamPeerCommand::Set(args) = command else {
        return read;
    };
    json!({
        "read":read,
        "write":{
            "method":"POST","path":path,
            "body":{"enabled":args.enabled,"expected_config_token":"<from the pinned settings GET>"},
            "automatic_retry":false
        }
    })
}

#[derive(Debug)]
struct UpstreamPeerCliError {
    code: &'static str,
    message: &'static str,
    outcome: &'static str,
    session_id: Uuid,
    status: Option<u16>,
}

impl fmt::Display for UpstreamPeerCliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for UpstreamPeerCliError {}

fn upstream_peer_error(
    code: &'static str,
    message: &'static str,
    outcome: &'static str,
    session_id: Uuid,
    status: Option<StatusCode>,
) -> anyhow::Error {
    UpstreamPeerCliError {
        code,
        message,
        outcome,
        session_id,
        status: status.map(|value| value.as_u16()),
    }
    .into()
}

fn checked_upstream_peer_response(
    value: Value,
    session_id: Uuid,
    requested_enabled: Option<bool>,
    expected_changed: Option<bool>,
    expected_revision: Option<u64>,
) -> Result<Value> {
    let invalid = || {
        upstream_peer_error(
            "INVALID_RESPONSE",
            if requested_enabled.is_some() {
                "Socket peer settings acknowledgement did not match this operation; mutation outcome is unknown"
            } else {
                "Socket peer settings were invalid; no mutation was sent"
            },
            if requested_enabled.is_some() {
                "unknown"
            } else {
                "not_applied"
            },
            session_id,
            None,
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
    let enabled = value
        .get("enabled")
        .and_then(Value::as_bool)
        .ok_or_else(invalid)?;
    if requested_enabled.is_some_and(|requested| requested != enabled) {
        return Err(invalid());
    }
    let revision_text = value
        .get("config_revision")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let revision = revision_text
        .parse::<u64>()
        .ok()
        .filter(|revision| revision.to_string() == revision_text)
        .ok_or_else(invalid)?;
    if expected_revision.is_some_and(|expected| expected != revision) {
        return Err(invalid());
    }
    let token = value
        .get("config_token")
        .and_then(Value::as_str)
        .filter(|token| {
            token.len() == 64
                && token
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .ok_or_else(invalid)?;
    let status = value
        .get("status")
        .and_then(Value::as_object)
        .ok_or_else(invalid)?;
    let effective = status
        .get("effective_enabled")
        .and_then(Value::as_bool)
        .ok_or_else(invalid)?;
    let blocked = status.get("blocked_reason").ok_or_else(invalid)?;
    if (!blocked.is_null()
        && !matches!(
            blocked.as_str(),
            Some("persistence_uncertain" | "invalid_configuration" | "http_capture_paused")
        ))
        || effective != (enabled && blocked.is_null())
    {
        return Err(invalid());
    }
    // Project a narrow allowlist so unrelated response data cannot become CLI output.
    let mut result = json!({
        "session_id":session_id,"enabled":enabled,"config_revision":revision_text,"config_token":token,
        "status":{"effective_enabled":effective,"blocked_reason":blocked}
    });
    if let Some(expected) = expected_changed {
        if value.get("changed").and_then(Value::as_bool) != Some(expected) {
            return Err(invalid());
        }
        result["changed"] = json!(expected);
    }
    Ok(result)
}

async fn handle_upstream_peer(api: ApiClient, command: UpstreamPeerCommand) -> Result<()> {
    let session_id = command.session_id();
    let client = saved_configuration_write_client().map_err(|_| {
        upstream_peer_error(
            "TRANSPORT_ERROR",
            "Could not prepare socket peer settings client; no mutation was sent",
            "not_applied",
            session_id,
            None,
        )
    })?;
    let path = upstream_peer_path(session_id);
    let response = client.get(api.url(&path)).send().await.map_err(|_| {
        upstream_peer_error(
            "TRANSPORT_ERROR",
            "Socket peer settings read failed; no mutation was sent",
            "not_applied",
            session_id,
            None,
        )
    })?;
    let status = response.status();
    if !status.is_success() {
        return Err(upstream_peer_error(
            if status.is_redirection() {
                "REDIRECT_REFUSED"
            } else {
                "HTTP_STATUS_ERROR"
            },
            "Socket peer settings read failed; no mutation was sent",
            "not_applied",
            session_id,
            Some(status),
        ));
    }
    let raw = saved_replay_response_json(response, 16 * 1024).await.map_err(|_| upstream_peer_error(
        "INVALID_RESPONSE", "Socket peer settings read was missing, malformed or too large; no mutation was sent", "not_applied", session_id, None,
    ))?;
    let current = checked_upstream_peer_response(raw, session_id, None, None, None)?;
    let UpstreamPeerCommand::Set(args) = command else {
        return print_session_read_json(&current, session_id);
    };
    let changed = current["enabled"] != args.enabled;
    let revision = current["config_revision"]
        .as_str()
        .expect("validated revision")
        .parse::<u64>()
        .expect("validated revision");
    let expected_revision = revision.checked_add(u64::from(changed)).ok_or_else(|| {
        upstream_peer_error(
            "UPSTREAM_PEER_REVISION_EXHAUSTED",
            "Socket peer configuration revision cannot be advanced; no mutation was sent",
            "not_applied",
            session_id,
            None,
        )
    })?;
    let response = client
        .post(api.url(&path))
        .json(&json!({"enabled":args.enabled,"expected_config_token":current["config_token"]}))
        .send()
        .await
        .map_err(|_| {
            upstream_peer_error(
                "TRANSPORT_ERROR",
                "Socket peer settings acknowledgement was lost; mutation outcome is unknown",
                "unknown",
                session_id,
                None,
            )
        })?;
    let status = response.status();
    if !status.is_success() {
        // Never follow a redirect, read diagnostic bodies, retry, or silently reconcile a write.
        return Err(upstream_peer_error(
            if status.is_redirection() {
                "REDIRECT_REFUSED"
            } else {
                "HTTP_STATUS_ERROR"
            },
            "Socket peer settings write did not return success; mutation outcome is unknown",
            "unknown",
            session_id,
            Some(status),
        ));
    }
    let raw = saved_replay_response_json(response, 16 * 1024).await.map_err(|_| upstream_peer_error(
        "INVALID_RESPONSE", "Socket peer settings acknowledgement was missing, malformed or too large; mutation outcome is unknown", "unknown", session_id, None,
    ))?;
    let saved = checked_upstream_peer_response(
        raw,
        session_id,
        Some(args.enabled),
        Some(changed),
        Some(expected_revision),
    )?;
    if (changed && saved["config_token"] == current["config_token"])
        || (!changed && saved["config_token"] != current["config_token"])
        || saved["status"]["blocked_reason"] == "persistence_uncertain"
    {
        return Err(upstream_peer_error(
            "INVALID_RESPONSE",
            "Socket peer settings acknowledgement did not confirm the token transition and durable state; mutation outcome is unknown",
            "unknown",
            session_id,
            None,
        ));
    }
    print_session_read_json(&saved, session_id)
}

fn history_retention_limit_schema() -> Value {
    json!({
        "type":"integer","minimum":1,"maximum":u32::MAX,
        "x-sniper-json-number-representation":"unsigned-integer",
        "description":"An unsigned JSON integer token from 1 through 4294967295, without a decimal point or exponent. This is a soft total-history target including protected rows."
    })
}

fn history_retention_revision_schema() -> Value {
    let maximum = u64::MAX.to_string();
    let mut alternatives = vec![
        "0".to_owned(),
        "[1-9][0-9]{0,18}".to_owned(),
        maximum.clone(),
    ];
    for (index, digit) in maximum.bytes().enumerate().skip(1) {
        if digit > b'0' {
            alternatives.push(format!(
                "{}[0-{}][0-9]{{{}}}",
                &maximum[..index],
                char::from(digit - 1),
                maximum.len() - index - 1
            ));
        }
    }
    json!({"type":"string","pattern":format!("^(?:{})$", alternatives.join("|")),
        "description":"Canonical decimal u64 configuration revision (0 through 18446744073709551615), encoded as a string to preserve precision. Changes advance the revision; a no-op preserves it."})
}

fn history_retention_policy_schema() -> Value {
    json!({"oneOf":[
        {"type":"object","additionalProperties":false,"required":["mode"],"properties":{"mode":{"const":"off"}}},
        {"type":"object","additionalProperties":false,"required":["mode","max_entries"],"properties":{"mode":{"const":"keep_newest"},"max_entries":history_retention_limit_schema()}}
    ]})
}

fn history_retention_input_schema(operation: &str) -> Option<Value> {
    if !matches!(
        operation,
        "capture.http.retention.get" | "capture.http.retention.set"
    ) {
        return None;
    }
    let mut session_id = legacy_uuid_input_schema(true, "Explicit sessions, including inactive sessions, are isolated without switching. Omission or null pins the active session once.");
    let hyphenated = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}";
    session_id["pattern"] = json!(format!(
        r"^(?:[0-9a-fA-F]{{32}}|{hyphenated}|\{{{hyphenated}\}}|urn:uuid:{hyphenated})$"
    ));
    let mut schema = json!({
        "type":"object","additionalProperties":false,"required":[],
        "properties":{"session_id":session_id}
    });
    if operation.ends_with(".set") {
        schema["properties"]["off"] = json!({"type":"boolean","default":false,"description":"True disables future automatic cleanup; it does not restore deleted history."});
        schema["properties"]["max_entries"] = history_retention_limit_schema();
        schema["oneOf"] = json!([
            {"required":["off"],"properties":{"off":{"const":true}},"not":{"required":["max_entries"]}},
            {"required":["max_entries"],"properties":{"off":{"const":false}}}
        ]);
    }
    Some(schema)
}

fn history_retention_output_schema(operation: &str) -> Option<Value> {
    if !matches!(
        operation,
        "capture.http.retention.get" | "capture.http.retention.set"
    ) {
        return None;
    }
    let count = json!({"type":"integer","minimum":0});
    let mut schema = json!({
        "type":"object","additionalProperties":false,
        "description":"Validated retention metadata only. A saved policy acknowledgement does not mean cleanup or disk reclamation has finished.",
        "required":["session_id","config_token","config_revision","policy","status"],
        "properties":{
            "session_id":{"type":"string","format":"uuid"},
            "config_token":{"type":"string","pattern":"^[0-9a-f]{64}$","description":"Compare-and-swap token bound to this session, saved policy and configuration revision, never traffic counts."},
            "config_revision":history_retention_revision_schema(),
            "policy":history_retention_policy_schema(),
            "status":{
                "type":"object","additionalProperties":false,
                "required":["total_count","protected_count","pending","disk_cleanup_pending","blocked_reason"],
                "properties":{
                    "total_count":count,"protected_count":count,
                    "pending":{"type":"boolean","description":"Logical work remains or disk cleanup is queued; protected rows can keep the total above the target."},
                    "disk_cleanup_pending":{"type":"boolean","description":"Physical cleanup remains pending, independently of the saved policy acknowledgement."},
                    "blocked_reason":{"type":["string","null"],"enum":[null,"protected_records","workspace_durability_uncertain","persistence_error","record_identity_conflict"]}
                }
            }
        }
    });
    if operation.ends_with(".set") {
        schema["required"].as_array_mut()?.push(json!("changed"));
        schema["properties"]["changed"] = json!({"type":"boolean","description":"Whether the saved policy changed; this is not a deletion count or completion signal."});
    }
    Some(schema)
}

fn history_retention_from_input(operation: &str, input: &Value) -> Result<HistoryRetentionCommand> {
    let session_id = call_optional(operation, input, "session_id")?;
    if operation.ends_with(".get") {
        return Ok(HistoryRetentionCommand::Get(SessionReadArgs { session_id }));
    }
    for field in ["off", "max_entries"] {
        if input.get(field).is_some_and(Value::is_null) {
            bail!("field `{field}` for `{operation}` cannot be null");
        }
    }
    let off = call_bool(operation, input, "off")?;
    let max_entries: Option<u32> = call_optional(operation, input, "max_entries")?;
    validate_call_exactly_one(
        operation,
        "retention policy",
        &[("off", off), ("max_entries", max_entries.is_some())],
    )?;
    if max_entries == Some(0) {
        bail!("field `max_entries` for `{operation}` must be between 1 and 4294967295");
    }
    Ok(HistoryRetentionCommand::Set(HistoryRetentionSetArgs {
        session_id,
        off,
        max_entries,
    }))
}

fn history_retention_api_preview(command: &HistoryRetentionCommand) -> Value {
    let read = api_preview(
        "GET",
        session_query_path("/api/transactions/retention", command.session_id()),
        None,
    );
    let HistoryRetentionCommand::Set(args) = command else {
        return read;
    };
    json!({
        "read":read,
        "write":{
            "method":"POST","path":session_query_path("/api/transactions/retention", args.session_id),
            "body":{"policy":args.policy(),"expected_config_token":"<from the pinned policy GET>"},
            "expected_active_session_id":if args.session_id.is_none() { json!("<resolved active session ID; sent in query>") } else { Value::Null },
            "automatic_retry":false
        }
    })
}

#[derive(Debug)]
struct HistoryRetentionCliError {
    code: &'static str,
    message: &'static str,
    outcome: &'static str,
    session_id: Option<Uuid>,
    status: Option<u16>,
}

impl fmt::Display for HistoryRetentionCliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for HistoryRetentionCliError {}

fn history_retention_error(
    code: &'static str,
    message: &'static str,
    outcome: &'static str,
    session_id: Option<Uuid>,
    status: Option<StatusCode>,
) -> anyhow::Error {
    HistoryRetentionCliError {
        code,
        message,
        outcome,
        session_id,
        status: status.map(|status| status.as_u16()),
    }
    .into()
}

async fn history_retention_get(
    api: &ApiClient,
    client: &reqwest::Client,
    path: &str,
    session_id: Option<Uuid>,
    limit: usize,
) -> Result<Value> {
    let response = client.get(api.url(path)).send().await.map_err(|_| {
        history_retention_error(
            "TRANSPORT_ERROR",
            "Retention metadata read failed; no mutation was sent",
            "not_applied",
            session_id,
            None,
        )
    })?;
    let status = response.status();
    if !status.is_success() {
        return Err(history_retention_error(
            if status.is_redirection() {
                "REDIRECT_REFUSED"
            } else {
                "HTTP_STATUS_ERROR"
            },
            "Retention metadata read failed; no mutation was sent",
            "not_applied",
            session_id,
            Some(status),
        ));
    }
    saved_replay_response_json(response, limit)
        .await
        .map_err(|_| {
            history_retention_error(
                "INVALID_RESPONSE",
                "Retention metadata read was missing, malformed or too large; no mutation was sent",
                "not_applied",
                session_id,
                None,
            )
        })
}

fn checked_history_retention_response(
    value: Value,
    session_id: Uuid,
    requested_policy: Option<&Value>,
    expected_changed: Option<bool>,
    expected_revision: Option<u64>,
) -> Result<Value> {
    let invalid = || {
        history_retention_error(
            "INVALID_RESPONSE",
            if requested_policy.is_some() {
                "Retention acknowledgement did not match this operation; mutation outcome is unknown"
            } else {
                "Retention metadata was invalid; no mutation was sent"
            },
            if requested_policy.is_some() {
                "unknown"
            } else {
                "not_applied"
            },
            Some(session_id),
            None,
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
    let raw_policy = value
        .get("policy")
        .and_then(Value::as_object)
        .ok_or_else(invalid)?;
    // Accept additive response fields, but project only validated known metadata.
    // A known field in the wrong policy variant is still an invalid shape.
    let policy = match raw_policy.get("mode").and_then(Value::as_str) {
        Some("off") if !raw_policy.contains_key("max_entries") => json!({"mode":"off"}),
        Some("keep_newest") => {
            let limit = raw_policy
                .get("max_entries")
                .and_then(Value::as_u64)
                .filter(|limit| (1..=u32::MAX as u64).contains(limit))
                .ok_or_else(invalid)?;
            json!({"mode":"keep_newest","max_entries":limit})
        }
        _ => return Err(invalid()),
    };
    let typed_policy: HistoryRetentionPolicy =
        serde_json::from_value(policy.clone()).map_err(|_| invalid())?;
    let revision_text = value
        .get("config_revision")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let revision = revision_text
        .parse::<u64>()
        .ok()
        .filter(|revision| revision.to_string() == revision_text)
        .ok_or_else(invalid)?;
    if expected_revision.is_some_and(|expected| expected != revision) {
        return Err(invalid());
    }
    let config_token = value
        .get("config_token")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    if config_token != history_retention_config_token(session_id, &typed_policy, revision)
        || requested_policy.is_some_and(|requested| requested != &policy)
    {
        return Err(invalid());
    }
    let status = value
        .get("status")
        .and_then(Value::as_object)
        .ok_or_else(invalid)?;
    let total = status
        .get("total_count")
        .and_then(Value::as_u64)
        .ok_or_else(invalid)?;
    let protected = status
        .get("protected_count")
        .and_then(Value::as_u64)
        .filter(|protected| *protected <= total)
        .ok_or_else(invalid)?;
    let pending = status
        .get("pending")
        .and_then(Value::as_bool)
        .ok_or_else(invalid)?;
    let disk_pending = status
        .get("disk_cleanup_pending")
        .and_then(Value::as_bool)
        .ok_or_else(invalid)?;
    let blocked = status.get("blocked_reason").ok_or_else(invalid)?;
    if !blocked.is_null()
        && !matches!(
            blocked.as_str(),
            Some(
                "protected_records"
                    | "workspace_durability_uncertain"
                    | "persistence_error"
                    | "record_identity_conflict"
            )
        )
    {
        return Err(invalid());
    }
    let mut output = json!({
        "session_id":session_id,"config_token":config_token,"config_revision":revision_text,"policy":policy,
        "status":{"total_count":total,"protected_count":protected,"pending":pending,"disk_cleanup_pending":disk_pending,"blocked_reason":blocked}
    });
    if let Some(expected) = expected_changed {
        if value.get("changed").and_then(Value::as_bool) != Some(expected) {
            return Err(invalid());
        }
        output["changed"] = json!(expected);
    }
    Ok(output)
}

async fn handle_history_retention(api: ApiClient, command: HistoryRetentionCommand) -> Result<()> {
    let explicit = command.session_id();
    let client = saved_configuration_write_client().map_err(|_| {
        history_retention_error(
            "TRANSPORT_ERROR",
            "Could not prepare retention metadata client; no mutation was sent",
            "not_applied",
            explicit,
            None,
        )
    })?;
    let session_id = if let Some(id) = explicit {
        id
    } else {
        let value =
            history_retention_get(&api, &client, "/api/sessions", None, MAX_CLI_INPUT_BYTES)
                .await?;
        let sessions: Vec<SessionSummary> = serde_json::from_value(value).map_err(|_| {
            history_retention_error(
                "INVALID_RESPONSE",
                "Session metadata was invalid; no mutation was sent",
                "not_applied",
                None,
                None,
            )
        })?;
        active_session_id_from_summaries(&sessions)
            .ok()
            .flatten()
            .ok_or_else(|| {
                history_retention_error(
                    "INVALID_RESPONSE",
                    "Expected exactly one active session; pass --session-id explicitly",
                    "not_applied",
                    None,
                    None,
                )
            })?
    };
    let path = session_query_path("/api/transactions/retention", Some(session_id));
    let raw = history_retention_get(&api, &client, &path, Some(session_id), 64 * 1024).await?;
    let current = checked_history_retention_response(raw, session_id, None, None, None)?;
    let HistoryRetentionCommand::Set(args) = command else {
        return print_session_read_json(&current, session_id);
    };
    let policy = args.policy();
    let changed = policy != current["policy"];
    let revision = current["config_revision"]
        .as_str()
        .expect("validated revision")
        .parse::<u64>()
        .expect("validated revision");
    let expected_revision = revision.checked_add(u64::from(changed)).ok_or_else(|| {
        history_retention_error(
            "RETENTION_REVISION_EXHAUSTED",
            "Retention configuration revision cannot be advanced; no mutation was sent",
            "not_applied",
            Some(session_id),
            None,
        )
    })?;
    let path = session_query_path_with_expected_active(
        "/api/transactions/retention",
        Some(session_id),
        explicit.is_none().then_some(session_id),
    );
    let response = client
        .post(api.url(&path))
        .json(&json!({"expected_config_token":current["config_token"],"policy":policy}))
        .send()
        .await
        .map_err(|_| {
            history_retention_error(
                "TRANSPORT_ERROR",
                "Retention acknowledgement was lost; mutation outcome is unknown",
                "unknown",
                Some(session_id),
                None,
            )
        })?;
    let status = response.status();
    if !status.is_success() {
        // Status is authoritative; diagnostic bodies and redirect targets are never read.
        return Err(history_retention_error(
            if status.is_redirection() {
                "REDIRECT_REFUSED"
            } else {
                "HTTP_STATUS_ERROR"
            },
            "Retention policy write did not return success; mutation outcome is unknown",
            "unknown",
            Some(session_id),
            Some(status),
        ));
    }
    let raw = saved_replay_response_json(response, 64 * 1024).await.map_err(|_| history_retention_error(
        "INVALID_RESPONSE", "Retention acknowledgement was missing, malformed or too large; mutation outcome is unknown", "unknown", Some(session_id), None,
    ))?;
    let saved = checked_history_retention_response(
        raw,
        session_id,
        Some(&policy),
        Some(changed),
        Some(expected_revision),
    )?;
    print_session_read_json(&saved, session_id)
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

/// A request read from a file or stdin, or the placeholder `replay open` starts
/// from, names no scheme of its own, so the scheme it is sent with is its scheme.
/// Left at the parser's default, a different target scheme reads as an override,
/// which the server refuses when the request's host is an IP address: plain HTTP to
/// `127.0.0.1` could not be set up from the CLI at all. A captured request keeps the
/// scheme it was captured with, and a scheme change on it stays an override.
fn adopt_target_scheme_for_uncaptured_request(
    request: Option<&mut EditableRequest>,
    source_transaction_id: Option<Uuid>,
    target_scheme: &str,
) {
    if source_transaction_id.is_some() || target_scheme.is_empty() {
        return;
    }
    if let Some(request) = request {
        request.scheme = target_scheme.to_string();
    }
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
    let (mut base_request, source_transaction_id, request_text) = resolve_request_source(
        api,
        workspace.session_id,
        transaction_id,
        request_file,
        stdin,
    )
    .await?;
    let normalized = normalize_target_inputs(scheme, host, port, base_request.as_ref())?;
    adopt_target_scheme_for_uncaptured_request(
        base_request.as_mut(),
        source_transaction_id,
        &normalized.scheme,
    );
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
    // Trim the end after the cut: it can stop on the joining space, which the
    // server's own pass removes, and the saved label then never matched.
    label
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(80)
        .collect::<String>()
        .trim_end()
        .to_string()
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
    // Drop path-bearing causes as well as their display text: output failures
    // print the original error chain to stderr instead of the JSON envelope.
    let runtime_state = load_runtime_state(&data_dir).map_err(|_| LocalRuntimeStateReadError)?;
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
    // An incomplete body says nothing about server identity. Keep transport
    // failures separate from invalid, fully received JSON so a live owner's
    // runtime-state survives a timeout or a dropped connection after headers.
    let body = response.bytes().await.map_err(|error| {
        SniperApiProbeFailure::unreachable(anyhow!(
            "failed to probe Sniper API at {url}: failed to read response body: {error}"
        ))
    })?;
    let payload: serde_json::Value = serde_json::from_slice(&body).map_err(|error| {
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
        if target.bytes().any(|byte| byte.is_ascii_control()) {
            bail!("absolute request target must not include control characters");
        }
        let authority_and_path = target.split_once("://").unwrap().1;
        let authority_end = authority_and_path
            .find(['/', '?', '#'])
            .unwrap_or(authority_and_path.len());
        let raw_authority = &authority_and_path[..authority_end];
        if raw_authority.is_empty() || raw_authority.contains('\\') {
            bail!("absolute request target has an invalid authority");
        }
        if raw_authority.contains('@') {
            bail!("absolute request target must not include credentials");
        }
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
        // URL parsing validates the destination but normalizes dot segments.
        // Keep the original request-target bytes, including an empty query.
        let raw_path_and_query = &authority_and_path[authority_end..];
        path = if raw_path_and_query.starts_with('/') {
            raw_path_and_query.to_string()
        } else {
            format!("/{raw_path_and_query}")
        };
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

fn saved_response_diagnostic(
    operation: &str,
    read_message: &'static str,
    receipt_message: &'static str,
) -> &'static str {
    if sniper::saved_contract::OPERATIONS.contains(&operation)
        && !sniper::saved_data::is_write(operation)
        && operation != "saved.v1.operation.get"
    {
        read_message
    } else {
        receipt_message
    }
}

// Call only after output schema and request binding validation: ok:true means
// the receipt was read successfully, not that its mutation was applied.
fn saved_receipt_warnings(operation: &str, data: &Value) -> Vec<&'static str> {
    if operation == "saved.v1.operation.get" && data["found"] == false {
        return vec!["No receipt was found. This does not prove the mutation was not applied. Inspect current saved state; do not automatically retry or issue a new operation_id to repeat the mutation."];
    }
    if operation != "saved.v1.operation.get" && !sniper::saved_data::is_write(operation) {
        return Vec::new();
    }
    match data["receipt"]["outcome"].as_str() {
        Some("unknown") => vec!["The mutation outcome is unknown. Inspect saved.v1.operation.get with the original operation_id and current saved state; do not automatically retry or issue a new operation_id to repeat the mutation."],
        Some("not_applied") => vec!["This mutation attempt was not applied. Review the receipt's code and current saved state before deciding on a new attempt. Repeating the same request with the original operation_id returns its receipt, not a fresh attempt."],
        _ => Vec::new(),
    }
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
    match operation {
        "saved.v1.session.rename" if data["receipt"]["outcome"] == "applied" => {
            // Replayed receipts retain the original result and are bound to the
            // same input fingerprint; do not compare with newer session state.
            if data["receipt"]["result"]["session"]["name"] != input["name"] {
                bail!("saved rename result is not bound to the requested name");
            }
        }
        "saved.v1.http.select" => {
            if let Some(requested) = input.get("ids").and_then(Value::as_array) {
                // Selection resolves every requested ID, but sorts and deduplicates
                // parsed UUIDs rather than preserving input order or letter case.
                let uuid_set = |ids: &[Value]| -> Result<std::collections::HashSet<Uuid>> {
                    ids.iter()
                        .map(|id| {
                            Uuid::parse_str(id.as_str().context("missing selection UUID")?)
                                .context("invalid selection UUID")
                        })
                        .collect()
                };
                let returned = data["ids"].as_array().context("missing selection IDs")?;
                if uuid_set(requested)? != uuid_set(returned)? {
                    bail!("saved selection response is not bound to the requested IDs");
                }
            }
        }
        "saved.v1.http.list" | "saved.v1.session.list" => {
            let source = input.get("continuation").unwrap_or(input);
            let limit = source
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(sniper::saved_contract::DEFAULT_LIMIT as u64);
            if data["limit"].as_u64() != Some(limit) {
                bail!("saved page is not bound to the requested limit");
            }
            let items = data["items"]
                .as_array()
                .context("missing saved page items")?;
            if operation == "saved.v1.http.list" {
                if let Some(cursor) = input.get("continuation") {
                    let before = cursor["before_sequence"]
                        .as_u64()
                        .context("missing HTTP continuation boundary")?;
                    if items
                        .iter()
                        .any(|item| item["sequence"].as_u64().is_none_or(|seq| seq >= before))
                    {
                        bail!("saved HTTP page crosses the requested sequence boundary");
                    }
                    // Terminal pages do not return a generation. Only a next
                    // cursor can carry forward the pinned generation.
                    if !data["continuation"].is_null()
                        && saved_uuid_field(&data["continuation"], "store_generation")
                            != saved_uuid_field(cursor, "store_generation")
                    {
                        bail!("saved HTTP continuation changed the requested store generation");
                    }
                }
            } else if let Some(after) = saved_uuid_field(input, "after_id") {
                if items
                    .iter()
                    .any(|item| saved_uuid_field(item, "id").is_none_or(|id| id <= after))
                {
                    bail!("saved session page crosses the requested UUID boundary");
                }
            }
        }
        _ => {}
    }
    Ok(())
}

async fn run_saved_call(
    api_override: Option<String>,
    args: CallArgs,
    dry_run: bool,
    yes: bool,
) -> Result<()> {
    // Sanitize before propagation too: stdout failures can print the original
    // error chain rather than the JSON payload.
    let input = load_call_input(args.input).map_err(CallInputError::for_saved_input)?;
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
                saved_response_diagnostic(
                    &operation,
                    "Saved-data read response unavailable",
                    "Saved-data response unavailable; inspect the operation receipt",
                ),
                uncertain_outcome,
                &input,
            )
        })?;
    let status = response.status();
    if status.is_redirection() {
        return Err(saved_cli_error(
            "REDIRECT_REFUSED",
            saved_response_diagnostic(
                &operation,
                "Saved-data read redirects are not followed",
                "Saved-data redirects are not followed; inspect the original operation receipt",
            ),
            uncertain_outcome,
            &input,
        ));
    }
    let wire: Value = response.json().await.map_err(|_| {
        saved_cli_error(
            "INVALID_RESPONSE",
            saved_response_diagnostic(
                &operation,
                "Could not decode the saved-data read response",
                "Could not decode the saved-data response; inspect the operation receipt",
            ),
            uncertain_outcome,
            &input,
        )
    })?;
    if wire.get("contract_version").and_then(Value::as_str)
        != Some(sniper::saved_contract::CONTRACT_VERSION)
    {
        return Err(saved_cli_error(
            "INVALID_RESPONSE",
            saved_response_diagnostic(
                &operation,
                "Server did not identify a saved.v1 read response",
                "Server did not identify a saved.v1 response; inspect the operation receipt",
            ),
            uncertain_outcome,
            &input,
        ));
    }
    if status.is_success() && wire.get("ok") == Some(&Value::Bool(true)) {
        if let Some(data) = wire.get("data") {
            sniper::saved_contract::validate_output(&operation, data).map_err(|_| {
                saved_cli_error(
                    "INVALID_RESPONSE",
                    saved_response_diagnostic(
                        &operation,
                        "Server read data does not satisfy the saved.v1 output schema",
                        "Server data does not satisfy the saved.v1 output schema; inspect the operation receipt",
                    ),
                    uncertain_outcome,
                    &input,
                )
            })?;
            validate_saved_response_binding(&operation, &input, data).map_err(|_| {
                saved_cli_error(
                    "INVALID_RESPONSE",
                    saved_response_diagnostic(
                        &operation,
                        "Saved-data read response identifies a different request",
                        "Saved-data response identifies a different request; inspect the original operation receipt",
                    ),
                    uncertain_outcome,
                    &input,
                )
            })?;
            return print_json_with_warnings(data, &saved_receipt_warnings(&operation, data));
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
            return Err(saved_cli_error(
                "INVALID_RESPONSE",
                saved_response_diagnostic(
                    &operation,
                    "Saved-data read error does not match this request",
                    "Saved-data error does not match this request; inspect the original operation receipt",
                ),
                uncertain_outcome,
                &input,
            ));
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
    Err(saved_cli_error(
        "INVALID_RESPONSE",
        saved_response_diagnostic(
            &operation,
            "Server did not return a saved.v1 read response",
            "Server did not return a saved.v1 response; inspect the operation receipt before any further action",
        ),
        uncertain_outcome,
        &input,
    ))
}

#[derive(Debug)]
struct LocalRuntimeStateReadError;

impl fmt::Display for LocalRuntimeStateReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Could not read local Sniper runtime-state; no API call was sent")
    }
}

impl std::error::Error for LocalRuntimeStateReadError {}

#[derive(Debug)]
struct ReadHttpStatusError {
    status: StatusCode,
}

impl fmt::Display for ReadHttpStatusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "API read failed ({})", self.status)
    }
}

impl std::error::Error for ReadHttpStatusError {}

#[derive(Debug)]
struct ReadRequestError {
    message: String,
}

impl fmt::Display for ReadRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ReadRequestError {}

#[derive(Debug)]
struct SessionMetadataHttpStatusError {
    status: StatusCode,
}

impl fmt::Display for SessionMetadataHttpStatusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Session metadata write failed ({}); mutation outcome is unknown",
            self.status
        )
    }
}

impl std::error::Error for SessionMetadataHttpStatusError {}

#[derive(Debug)]
struct MetadataAcknowledgementError;

impl fmt::Display for MetadataAcknowledgementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Saved metadata acknowledgement was incomplete or did not match; mutation outcome is unknown")
    }
}

impl std::error::Error for MetadataAcknowledgementError {}

#[derive(Debug)]
enum CallInputError {
    Source(String),
    SavedSource,
    JsonSyntax,
}

impl CallInputError {
    fn for_saved_input(self) -> Self {
        match self {
            Self::Source(_) => Self::SavedSource,
            other => other,
        }
    }
}

impl fmt::Display for CallInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(message) => formatter.write_str(message),
            Self::SavedSource => formatter.write_str("Could not read saved-data input source"),
            Self::JsonSyntax => formatter.write_str("failed to parse call input JSON"),
        }
    }
}

impl std::error::Error for CallInputError {}

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

fn cli_output_format_from_raw_args(args: &[impl AsRef<OsStr>]) -> OutputFormat {
    for (index, arg) in args.iter().enumerate() {
        let arg = arg.as_ref();
        if let Some(value) = arg.as_encoded_bytes().strip_prefix(b"--output=") {
            return output_format_from_raw_value(value).unwrap_or(OutputFormat::Pretty);
        }
        if arg == "--output" {
            if let Some(value) = args.get(index + 1) {
                return output_format_from_raw_value(value.as_ref().as_encoded_bytes())
                    .unwrap_or(OutputFormat::Pretty);
            }
        }
    }
    OutputFormat::Pretty
}

fn output_format_from_raw_value(value: &[u8]) -> Option<OutputFormat> {
    match value {
        b"compact" => Some(OutputFormat::Compact),
        b"pretty" => Some(OutputFormat::Pretty),
        _ => None,
    }
}

fn cli_parse_error_option_takes_value(command: &clap::Command, name: &str) -> Option<bool> {
    // Recognize misplaced child options too, so their operands cannot become
    // command names merely because clap rejects the option at this position.
    command
        .get_arguments()
        .find(|arg| {
            arg.get_long() == Some(name)
                || arg
                    .get_all_aliases()
                    .is_some_and(|aliases| aliases.contains(&name))
        })
        .map(|arg| arg.get_action().takes_values())
        .or_else(|| {
            command
                .get_subcommands()
                .find_map(|child| cli_parse_error_option_takes_value(child, name))
        })
}

fn cli_parse_error_long_option(arg: &OsStr) -> Option<(&str, bool)> {
    let option = arg.as_encoded_bytes().strip_prefix(b"--")?;
    let (name, inline_value) = option
        .iter()
        .position(|&byte| byte == b'=')
        .map_or((option, false), |index| (&option[..index], true));
    // Only the name must be Unicode: an inline operand may contain arbitrary
    // OS bytes, and still must not change option arity or become an operation.
    Some((std::str::from_utf8(name).ok()?, inline_value))
}

fn cli_parse_error_operation(args: &[impl AsRef<OsStr>]) -> String {
    let cli = Cli::command();
    let mut command = &cli;
    let mut path = Vec::new();
    let mut args = args.iter().map(|arg| arg.as_ref()).peekable();
    let mut positional_only = false;
    while let Some(arg) = args.next() {
        let is_call = path.as_slice() == ["call"];
        if positional_only {
            if let Some(arg) = arg.to_str() {
                return arg.to_owned();
            }
            break;
        }
        if arg == "--" {
            if is_call {
                positional_only = true;
                continue;
            }
            break;
        }
        if arg.as_encoded_bytes().starts_with(b"-") {
            let takes_value = if is_call {
                // Call operations are free-form, including unknown names. Keep
                // their existing input skipping and delimiter semantics.
                if arg.to_str().is_none() && cli_parse_error_long_option(arg).is_none() {
                    break;
                }
                matches!(arg.as_encoded_bytes(), b"--output" | b"--api" | b"--input")
            } else if let Some((name, inline_value)) = cli_parse_error_long_option(arg) {
                let Some(takes_value) = cli_parse_error_option_takes_value(&cli, name) else {
                    // An unknown option may own the following token. Do not
                    // mistake that operand for a declared command or action.
                    break;
                };
                takes_value && !inline_value
            } else {
                break;
            };
            if takes_value
                && args.peek().is_some_and(|value| {
                    let bytes = value.as_encoded_bytes();
                    !bytes.starts_with(b"-") || bytes == b"-"
                })
            {
                args.next();
            }
            continue;
        }
        let Some(arg) = arg.to_str() else {
            break;
        };
        if is_call {
            return arg.to_owned();
        }
        let Some(child) = command.find_subcommand(arg) else {
            break;
        };
        path.push(child.get_name());
        command = child;
    }

    // Hidden top-level wrappers expose the same operations as capture. Only
    // canonical names from clap, never raw option operands, enter this path.
    if matches!(
        path.first(),
        Some(&("http" | "intercept" | "web-socket" | "auto-replace"))
    ) {
        path.insert(0, "capture");
    }
    let fallback = path.first().copied().unwrap_or("parse");
    let mut operations = manifest_operations().into_iter().filter(|spec| {
        spec.command
            .split_ascii_whitespace()
            .take_while(|token| !token.starts_with(['-', '<', '[']))
            .eq(path.iter().copied())
    });
    match (operations.next(), operations.next()) {
        // Flag-dependent commands such as capture proxy deliberately retain
        // the group fallback rather than guessing among multiple operations.
        (Some(spec), None) => spec.operation.to_string(),
        _ => fallback.to_string(),
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
    print_json_with_warnings(value, &[])
}

fn print_json_with_warnings<T: Serialize>(value: &T, warnings: &[&str]) -> Result<()> {
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
        "warnings": warnings,
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
    if let Some(recon) = error.downcast_ref::<ReconCliError>() {
        return CliErrorPayload {
            code: recon.code,
            message: recon.to_string(),
            hint: Some(if recon.write {
                "The operation may have applied. Inspect recon list --session-id <the same UUID> before a deliberate retry; never automatically resubmit. Stopping local work cannot recall an accepted urlscan scan."
            } else {
                "Inspect the selected API and session deliberately; a failed read is not an empty inventory."
            }),
            retryable: false,
            details: json!({"status":recon.status,"outcome":if recon.write {"unknown"} else {"not_applied"}}),
            exit_code: if recon.status.is_some_and(|status| status < 500) {
                5
            } else {
                6
            },
        };
    }

    if let Some(map) = error.downcast_ref::<ServiceMapCliError>() {
        return CliErrorPayload {
            code: map.code,
            message: map.message.into(),
            hint: Some("Check the selected API and CLI/app compatibility, then deliberately reread the same session. Never substitute a UUID-only detail lookup or generate traffic to fill missing map evidence."),
            retryable: false,
            details: json!({"status":map.status}),
            exit_code: if map.code == "INVALID_INPUT" { 2 } else if map.code == "API_UNAVAILABLE" || map.status.is_some_and(|status| status >= 500) { 6 } else { 5 },
        };
    }

    if let Some(discovery) = error.downcast_ref::<LocalRuntimeStateReadError>() {
        return CliErrorPayload {
            code: "API_UNAVAILABLE",
            message: discovery.to_string(),
            hint: Some("Check Sniper's local data directory (SNIPER_DATA_DIR if set) and its runtime-state files, or pass --api http://HOST:PORT for the intended running instance. Preserve existing runtime-state files."),
            retryable: false,
            details: json!({}),
            exit_code: 6,
        };
    }
    if let Some(input) = error.downcast_ref::<CallInputError>() {
        let saved = operation.starts_with("saved.v1.");
        // Preserve the failure phase without exposing saved input paths,
        // contents, or parser excerpts in diagnostics.
        let (message, hint) = if saved {
            match input {
                CallInputError::Source(_) | CallInputError::SavedSource => (
                    "Could not read saved-data input source".to_owned(),
                    "Check a readable regular UTF-8 @file or UTF-8 stdin within the input size limit; then inspect `sniper-cli schema input <operation>`.",
                ),
                CallInputError::JsonSyntax => (
                    "Could not parse saved-data input JSON".to_owned(),
                    "Correct the JSON syntax in --input, @file, or stdin; see `sniper-cli examples <operation>` and `sniper-cli schema input <operation>`.",
                ),
            }
        } else {
            (
                input.to_string(),
                "Check `sniper-cli schema input <operation>` or run the command with --help.",
            )
        };
        return CliErrorPayload {
            code: "INVALID_INPUT",
            message,
            hint: Some(hint),
            retryable: false,
            details: if saved {
                json!({"outcome":"not_applied","operation_id":null,"session_id":null})
            } else {
                json!({ "operation": operation })
            },
            exit_code: 2,
        };
    }
    if let Some(peer) = error.downcast_ref::<UpstreamPeerCliError>() {
        return CliErrorPayload {
            code: peer.code,
            message: peer.message.to_owned(),
            hint: Some("Deliberately inspect capture http upstream-peer get --session-id <the same active session UUID> before another write; never automatically retry or switch sessions."),
            retryable: false,
            details: json!({"session_id":peer.session_id,"outcome":peer.outcome,"status":peer.status}),
            exit_code: if peer.status.is_some_and(|status| status >= 500) { 6 } else { 5 },
        };
    }
    if let Some(retention) = error.downcast_ref::<HistoryRetentionCliError>() {
        return CliErrorPayload {
            code: retention.code,
            message: retention.message.to_owned(),
            hint: Some("Inspect capture http retention get --session-id <the same session UUID> before deliberately issuing another write; never automatically retry."),
            retryable: false,
            details: json!({"session_id":retention.session_id,"outcome":retention.outcome,"status":retention.status}),
            exit_code: if retention.status.is_some_and(|status| status >= 500) { 6 } else { 5 },
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
        let known_read = saved.outcome == "not_applied"
            && sniper::saved_contract::OPERATIONS.contains(&operation)
            && !sniper::saved_data::is_write(operation);
        let hint = if known_read && saved.code == "INVALID_INPUT" {
            "Inspect sniper-cli schema input <operation> for this operation's accepted input, then correct the input."
        } else if known_read && operation != "saved.v1.operation.get" {
            // Summary/selection reads have no operation ID or mutation receipt.
            match saved.code {
                "STALE_CONTINUATION" if operation == "saved.v1.session.list" => "Discard the stale continuation and deliberately start a fresh session listing on the same selected API with the same page limit. Treat it as a new traversal, not a continuation of earlier results.",
                "STALE_CONTINUATION" => "Discard the stale continuation and deliberately start a fresh listing with the same explicit session_id. Treat it as a new traversal, not a continuation of earlier results.",
                "SESSION_NOT_FOUND" => "Use saved.v1.session.list to inspect available sessions, then deliberately select an existing session UUID. Do not silently switch sessions.",
                "API_UNAVAILABLE" => "Check the selected API endpoint and that Sniper is running, then deliberately rerun this read.",
                "UNKNOWN_OPERATION" => "The selected API does not recognize this saved-data operation. Check the intended API and compatibility of the CLI and running Sniper app before deliberately rerunning this read; never automatically retry a mutation.",
                _ => "Inspect the error and selected API/session context before deliberately rerunning this read; never automatically retry a mutation.",
            }
        } else {
            "Use saved.v1.operation.get with the original operation_id to inspect a receipt; never automatically retry a mutation."
        };
        return CliErrorPayload {
            code: saved.code,
            message: saved.message.clone(),
            hint: Some(hint),
            retryable: false,
            details: json!({"outcome":saved.outcome,"operation_id":saved.operation_id,"session_id":saved.session_id}),
            exit_code: if matches!(
                saved.code,
                "INVALID_INPUT" | "UNKNOWN_OPERATION" | "CONFIRMATION_REQUIRED"
            ) {
                2
            } else {
                5
            },
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

    if error
        .downcast_ref::<MetadataAcknowledgementError>()
        .is_some()
    {
        return CliErrorPayload {
            code: "INVALID_RESPONSE",
            message: MetadataAcknowledgementError.to_string(),
            hint: Some("Inspect current state before deliberately issuing another write; never automatically retry."),
            retryable: false,
            details: json!({"idempotent":false,"outcome":"unknown"}),
            exit_code: 5,
        };
    }

    if let Some(write) = error.downcast_ref::<SessionMetadataHttpStatusError>() {
        let status = write.status.as_u16();
        return CliErrorPayload {
            code: "HTTP_STATUS_ERROR",
            message: write.to_string(),
            hint: Some("Inspect session list and current state before deliberately issuing another write; never automatically retry."),
            retryable: false,
            details: json!({"status":status,"idempotent":false,"outcome":"unknown"}),
            exit_code: if status < 500 { 5 } else { 6 },
        };
    }

    let message = error.to_string();
    // A read's server diagnostic must not turn its actual HTTP status into a
    // local confirmation, input, discovery, or workspace-conflict error.
    let mut payload = if let Some(read) = error.downcast_ref::<ReadHttpStatusError>() {
        let status = read.status.as_u16();
        CliErrorPayload {
            code: "HTTP_STATUS_ERROR",
            message: read.to_string(),
            hint: None,
            retryable: status >= 500,
            details: json!({ "status": status }),
            exit_code: if status < 500 { 5 } else { 6 },
        }
    } else if let Some(read) = error.downcast_ref::<ReadRequestError>() {
        CliErrorPayload {
            code: "CLI_ERROR",
            message: read.to_string(),
            hint: None,
            retryable: false,
            details: json!({}),
            exit_code: 1,
        }
    } else if message.contains("requires --dry-run or --yes") {
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
                || payload.message.contains("failed to PATCH")
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
mod label_rule_tests {
    // The server applies the rule again to what the CLI sends, and the CLI then
    // compares the saved label with its own result.
    #[test]
    fn the_tab_label_rule_gives_the_same_label_when_applied_again() {
        let label = super::normalize_replay_tab_label(&format!("{} tail", "a".repeat(79)));
        assert_eq!(label, "a".repeat(79));
        assert_eq!(super::normalize_replay_tab_label(&label), label);
    }
}

#[cfg(test)]
mod tests {
    use super::validate_saved_response_binding;
    use super::{
        active_session_id_from_summaries, adopt_target_scheme_for_uncaptured_request,
        api_failure_detail, api_url, attach_session_id, attach_workspace_save_error,
        auto_replace_write_session_id, browser_choices, browser_open_body,
        build_annotations_payload, build_editable_raw_request,
        build_editable_raw_request_with_version, build_oast_configure_update, clap_error_payload,
        cli_data_dir, cli_error_payload, cli_output_format_from_raw_args,
        cli_parse_error_long_option, cli_parse_error_operation, cli_partial_apply_error,
        command_from_call_args, command_from_operation_input, command_input_preview,
        default_cli_data_dir, default_editable_request, discover_api_base_url,
        discover_api_base_url_from_data_dir, dry_run_command, ensure_http_replay_tab,
        explicit_or_active_session_id, failed_record_output, fuzzer_active_target_for_request,
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

    fn assert_supplement_invalid_response(
        error: anyhow::Error,
        operation: &str,
        message: &str,
        reason: &str,
    ) {
        let payload = cli_error_payload(operation, &error);
        assert_eq!(payload.code, "INVALID_RESPONSE");
        assert_eq!(payload.message, message);
        assert_eq!(payload.details, json!({"status":null}));
        assert_eq!(payload.exit_code, 5);
        assert!(!payload.retryable);
        assert!(!serde_json::to_string(&payload).unwrap().contains(reason));
    }

    #[test]
    fn service_map_html_supplement_status_reason_contract() {
        use sniper::service_map_html::{ServiceMapHtmlGenerators, ACQUISITION_REASONS};
        let session_id = Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap();
        let args = super::ServiceMapHtmlGeneratorsArgs {
            session_id,
            evidence_id: format!("v1.{session_id}.22222222-2222-4222-8222-222222222222.9007199254740993.44444444-4444-4444-8444-444444444444.33333333-3333-4333-8333-333333333333"),
        };
        let unsupported = [
            "metadata_limit",
            "unsupported_content_type",
            "unsupported_body_encoding",
            "unsupported_content_encoding",
            "unsupported_metadata",
        ];
        for reason in ACQUISITION_REASONS.iter().copied().chain([
            "unsupported_source_context",
            "malformed_tag",
            "PRIVATE_CONTENT_SENTINEL",
        ]) {
            for status in [
                "unavailable",
                "unsupported",
                "scanned",
                "partial",
                "UNSUPPORTED",
            ] {
                let mut result =
                    ServiceMapHtmlGenerators::missing(session_id, args.evidence_id.clone(), reason);
                // The constructor sanitizes unknown input; simulate the wire value directly.
                result.reasons = vec![reason.into()];
                result.status = status.into();
                let valid = match status {
                    "unavailable" => ACQUISITION_REASONS.contains(&reason),
                    "unsupported" => unsupported.contains(&reason),
                    _ => false,
                };
                let outcome = super::validate_service_map_html_generators_response(&result, &args);
                assert_eq!(outcome.is_ok(), valid, "{status}/{reason}");
                if !valid {
                    assert_supplement_invalid_response(
                        outcome.unwrap_err(),
                        "target.service_map.html_generators.get",
                        "HTML generator inspection does not match the requested session, exact-row token, fixed catalog, bounds, or safe declaration contract",
                        reason,
                    );
                }
            }
        }
    }

    #[test]
    fn service_map_link_supplement_status_reason_contract() {
        use sniper::service_map_links::{ServiceMapLinkDeclarations, ACQUISITION_REASONS};
        let session_id = Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap();
        let args = super::ServiceMapLinkDeclarationsArgs {
            session_id,
            evidence_id: format!("v1.{session_id}.22222222-2222-4222-8222-222222222222.9007199254740993.44444444-4444-4444-8444-444444444444.33333333-3333-4333-8333-333333333333"),
        };
        for reason in ACQUISITION_REASONS.iter().copied().chain([
            "metadata_limit",
            "unsupported_content_type",
            "unsupported_body_encoding",
            "unsupported_content_encoding",
            "unsupported_metadata",
            "malformed_field",
            "PRIVATE_CONTENT_SENTINEL",
        ]) {
            for status in [
                "unavailable",
                "unsupported",
                "scanned",
                "partial",
                "UNSUPPORTED",
            ] {
                let mut result = ServiceMapLinkDeclarations::missing(
                    session_id,
                    args.evidence_id.clone(),
                    reason,
                );
                result.reasons = vec![reason.into()];
                result.status = status.into();
                let valid = match status {
                    "unavailable" => ACQUISITION_REASONS.contains(&reason),
                    "unsupported" => reason == "unsupported_source_context",
                    _ => false,
                };
                let outcome =
                    super::validate_service_map_link_declarations_response(&result, &args);
                assert_eq!(outcome.is_ok(), valid, "{status}/{reason}");
                if !valid {
                    assert_supplement_invalid_response(
                        outcome.unwrap_err(),
                        "target.service_map.link_declarations.get",
                        "Link declaration inspection does not match the requested session, exact-row token, fixed catalog, bounds, or safe declaration contract",
                        reason,
                    );
                }
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
    fn saved_call_input_errors_discard_source_details_before_propagation() {
        let private = "SYNTHETIC_PRIVATE_SOURCE_PATH";
        let legacy = super::CallInputError::Source(private.into());
        assert_eq!(legacy.to_string(), private);
        let saved: anyhow::Error = legacy.for_saved_input().into();
        assert_eq!(saved.to_string(), "Could not read saved-data input source");
        assert!(!format!("{saved:#}").contains(private));
        assert!(!format!("{saved:?}").contains(private));
        let syntax = super::CallInputError::JsonSyntax.for_saved_input();
        assert_eq!(syntax.to_string(), "failed to parse call input JSON");
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
    fn raw_request_parser_preserves_absolute_target_bytes() {
        for suffix in [
            "/a/../b",
            "/a/./b",
            "/a/%2e%2E/b",
            "/a/.%2e/b",
            "/a/%2E./b",
            "//a//b",
            "/a//b/",
            "/a?",
            "/a?x=%2f%2F",
            "/a@b?x=@example.com",
            "/a/%2f%2F?x=/../%2e&x=",
            "",
            "?",
            "?x=%2f%2F",
        ] {
            let raw = format!(
                "GET HtTp://example.com:8080{suffix} HTTP/1.1\r\nHost: example.com:8080\r\n\r\n"
            );
            let parsed = parse_editable_raw_request_with_version(&raw, None).unwrap();
            let expected = if suffix.starts_with('/') {
                suffix.to_string()
            } else {
                format!("/{suffix}")
            };
            assert_eq!(parsed.request.path, expected, "target suffix: {suffix:?}");
            assert_eq!(parsed.request.scheme, "http");
            assert_eq!(parsed.request.host, "example.com:8080");
            assert_eq!(parsed.http_version.as_deref(), Some("HTTP/1.1"));
        }
    }

    #[test]
    fn raw_request_parser_preserves_origin_target_bytes() {
        for target in ["/a/../b", "/a/.%2e/b", "//a//b?", "/a/%2f%2F?x=%2e"] {
            let raw = format!("GET {target} HTTP/1.1\r\nHost: example.com\r\n\r\n");
            let request = parse_editable_raw_request(&raw, None).unwrap();
            assert_eq!(request.path, target);
            assert_eq!(request.scheme, "https");
        }
    }

    #[test]
    fn raw_request_parser_rejects_malformed_absolute_target() {
        for target in [
            "http:///example.com/a",
            "http://?q",
            "http://example.com:bad/a",
            "http://[::1/a",
            "http://example.com\\other/a",
            "http://example.com/a\0b",
            "http://@example.com/a",
            "http://user:pass@example.com/a",
            "http://example.com/a#",
            "http://example.com/a#fragment",
        ] {
            let raw = format!("GET {target} HTTP/1.1\r\nHost: example.com\r\n\r\n");
            assert!(
                parse_editable_raw_request(&raw, None).is_err(),
                "accepted {target:?}"
            );
        }
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
    fn only_an_uncaptured_request_adopts_the_target_scheme() {
        let mut typed = default_editable_request();
        adopt_target_scheme_for_uncaptured_request(Some(&mut typed), None, "http");
        assert_eq!(typed.scheme, "http");
        adopt_target_scheme_for_uncaptured_request(Some(&mut typed), None, "");
        assert_eq!(
            typed.scheme, "http",
            "an unset target scheme changes nothing"
        );

        let mut captured = default_editable_request();
        let scheme = captured.scheme.clone();
        adopt_target_scheme_for_uncaptured_request(
            Some(&mut captured),
            Some(Uuid::new_v4()),
            "http",
        );
        assert_eq!(
            captured.scheme, scheme,
            "a captured request keeps its scheme; a change stays an override"
        );
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
    fn fuzzer_run_and_stop_take_the_attack_options_from_flags_and_calls() {
        let Cli {
            command:
                Command::Fuzzer {
                    command: FuzzerCommand::Run(args),
                },
            ..
        } = Cli::try_parse_from([
            "sniper-cli",
            "fuzzer",
            "run",
            "--attack-type",
            "sniper",
            "--raw-payloads",
            "--concurrency",
            "4",
        ])
        .unwrap()
        else {
            panic!("expected fuzzer run");
        };
        assert_eq!(args.attack_type, super::FuzzerAttackTypeArg::Sniper);
        assert!(args.raw_payloads);
        assert_eq!(args.concurrency, 4);
        assert!(
            Cli::try_parse_from(["sniper-cli", "fuzzer", "run", "--concurrency", "17"]).is_err()
        );

        let Command::Fuzzer {
            command: FuzzerCommand::Run(args),
        } = command_from_operation_input("fuzzer.run", &json!({})).unwrap()
        else {
            panic!("expected fuzzer run");
        };
        assert_eq!(
            (args.attack_type, args.raw_payloads, args.concurrency),
            (super::FuzzerAttackTypeArg::BatteringRam, false, 1),
            "a call without options keeps the attack the API ran before Sniper"
        );
        assert!(command_from_operation_input("fuzzer.run", &json!({"concurrency":0})).is_err());
        assert!(
            command_from_operation_input("fuzzer.run", &json!({"attack_type":"pitchfork"}))
                .is_err()
        );

        let id = "22222222-2222-2222-2222-222222222222";
        let Command::Fuzzer {
            command: FuzzerCommand::Stop(args),
        } = command_from_operation_input("fuzzer.stop", &json!({ "id": id })).unwrap()
        else {
            panic!("expected fuzzer stop");
        };
        assert_eq!(args.id.to_string(), id);
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
    fn service_map_commands_are_read_only_and_match_manifest() {
        let session = "11111111-1111-1111-1111-111111111111";
        for (operation, args, input, endpoint) in [
            (
                "target.service_map.get",
                vec!["scope", "service-map", "--session-id", session, "--in-scope-only", "--max-records", "25"],
                json!({"session_id":session,"in_scope_only":true,"max_records":25}),
                format!("/api/target/service-map?in_scope_only=true&max_records=25&session_id={session}"),
            ),
            (
                "target.service_map.evidence.get",
                vec!["target", "service-map-evidence", "--session-id", session, "--evidence-id", "v1.11111111-1111-1111-1111-111111111111.22222222-2222-2222-2222-222222222222.9007199254740993.33333333-3333-3333-3333-333333333333.44444444-4444-4444-4444-444444444444"],
                json!({"session_id":session,"evidence_id":"v1.11111111-1111-1111-1111-111111111111.22222222-2222-2222-2222-222222222222.9007199254740993.33333333-3333-3333-3333-333333333333.44444444-4444-4444-4444-444444444444"}),
                format!("/api/target/service-map/evidence?evidence_id=v1.11111111-1111-1111-1111-111111111111.22222222-2222-2222-2222-222222222222.9007199254740993.33333333-3333-3333-3333-333333333333.44444444-4444-4444-4444-444444444444&session_id={session}"),
            ),
            (
                "target.service_map.body_references.get",
                vec!["target", "service-map", "body-references", "--session-id", session, "--evidence-id", "v1.11111111-1111-1111-1111-111111111111.22222222-2222-2222-2222-222222222222.9007199254740993.33333333-3333-3333-3333-333333333333.44444444-4444-4444-4444-444444444444"],
                json!({"session_id":session,"evidence_id":"v1.11111111-1111-1111-1111-111111111111.22222222-2222-2222-2222-222222222222.9007199254740993.33333333-3333-3333-3333-333333333333.44444444-4444-4444-4444-444444444444"}),
                format!("/api/target/service-map/body-references?evidence_id=v1.11111111-1111-1111-1111-111111111111.22222222-2222-2222-2222-222222222222.9007199254740993.33333333-3333-3333-3333-333333333333.44444444-4444-4444-4444-444444444444&session_id={session}"),
            ),
        ] {
            let mut argv = vec!["sniper-cli"];
            argv.extend(args);
            let direct = Cli::try_parse_from(argv).unwrap().command;
            let call = command_from_operation_input(operation, &input).unwrap();
            assert_eq!(direct.operation_name(), operation);
            assert_eq!(call.operation_name(), operation);
            assert_eq!(command_input_preview(&direct), command_input_preview(&call));
            assert!(!direct.requires_confirmation());
            let plan = dry_run_command(&direct).unwrap();
            assert_eq!(plan["side_effect"], "read");
            assert_eq!(plan["api"]["method"], "GET");
            assert_eq!(plan["api"]["path"], endpoint);
            assert!(plan["api"]["body"].is_null());
            let spec = operation_spec(operation).unwrap();
            assert_eq!(spec.input_schema["additionalProperties"], false);
        }
    }

    // Turning passive templates on takes exactly one selection, so a missing
    // filter can never mean "all of them".
    #[test]
    fn templates_commands_validate_before_contacting_sniper() {
        let passive =
            |input: Value| command_from_operation_input("templates.passive.set_enabled", &input);
        assert!(passive(json!({"enabled":true})).is_err());
        assert!(passive(json!({"enabled":true,"ids":["tech-detect"],"all":true})).is_err());
        assert!(passive(json!({"enabled":true,"ids":["../x"]})).is_err());
        let by_tag = passive(json!({"enabled":false,"tag":"waf"})).unwrap();
        assert_eq!(
            super::command_api_preview(&by_tag).unwrap()["body"],
            json!({"filter":{"tag":"waf","support":"passive"},"enabled":false})
        );
        assert!(command_from_operation_input("templates.get", &json!({"id":"a/b"})).is_err());
        assert!(command_from_operation_input("templates.list", &json!({"limit":0})).is_err());
        let list = command_from_operation_input(
            "templates.list",
            &json!({"search":"a b&c","support":"passive"}),
        )
        .unwrap();
        assert_eq!(
            super::command_api_preview(&list).unwrap()["path"],
            "/api/templates?search=a+b%26c&support=passive&limit=200&offset=0"
        );
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "templates",
            "passive",
            "set-enabled",
            "--enabled",
            "true",
            "--all"
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["sniper-cli", "templates", "list", "--limit", "0"]).is_err());
        let download =
            command_from_operation_input("templates.library.download", &json!({})).unwrap();
        assert!(download.requires_confirmation());
        assert!(super::dry_run_notes(&download)
            .iter()
            .any(|note| note.contains("Contacts GitHub")));
    }

    // A scan names its targets and exactly one selection; starting one is a
    // confirmed write, and the body the server gets carries that confirmation.
    #[test]
    fn template_scans_need_targets_one_selection_and_confirmation() {
        let scan = |operation: &str, input: Value| command_from_operation_input(operation, &input);
        let target = json!(["https://app.example.com"]);
        assert!(scan("templates.scan.start", json!({"ids":["git-config"]})).is_err());
        assert!(scan("templates.scan.start", json!({"targets":target})).is_err());
        assert!(scan(
            "templates.scan.start",
            json!({"targets":target,"ids":["git-config"],"tag":"cve"})
        )
        .is_err());
        assert!(scan(
            "templates.scan.start",
            json!({"targets":target,"ids":["git-config"],"rate":51})
        )
        .is_err());
        let start = scan(
            "templates.scan.start",
            json!({"targets":target,"severity":"high","allow_risks":["intrusive"]}),
        )
        .unwrap();
        assert!(start.requires_confirmation());
        assert_eq!(
            super::command_api_preview(&start).unwrap()["body"],
            json!({
                "session_id":null,"targets":["https://app.example.com"],"allow_risks":["intrusive"],
                "rate":10,"concurrency":4,"max_requests":10000,"apply_match_replace":false,
                "filter":{"severity":"high"},"acknowledged":true
            })
        );
        let preview = scan(
            "templates.scan.preview",
            json!({"targets":target,"ids":["git-config"]}),
        )
        .unwrap();
        assert!(!preview.requires_confirmation());
        assert_eq!(
            super::command_api_preview(&preview).unwrap()["body"]["preview"],
            json!(true)
        );
        let id = "22222222-2222-2222-2222-222222222222";
        let stop = scan("templates.scan.stop", json!({"id":id})).unwrap();
        assert!(stop.requires_confirmation());
        assert_eq!(
            super::command_api_preview(&stop).unwrap()["path"],
            format!("/api/templates/scans/{id}/stop")
        );
        let direct = Cli::try_parse_from([
            "sniper-cli",
            "templates",
            "scan",
            "start",
            "--target",
            "https://app.example.com",
            "--id",
            "git-config",
            "--allow-risk",
            "method:put",
        ])
        .unwrap()
        .command;
        assert_eq!(direct.operation_name(), "templates.scan.start");
        assert!(
            Cli::try_parse_from(["sniper-cli", "templates", "scan", "start", "--id", "x"]).is_err()
        );
    }

    // The desktop map reads every retained row; the CLI can too, without a
    // row window, and never with one.
    #[test]
    fn service_map_all_rows_reads_without_a_window() {
        let command =
            command_from_operation_input("target.service_map.get", &json!({"all_rows":true}))
                .unwrap();
        assert_eq!(
            command_input_preview(&command),
            json!({"session_id":null,"origin":null,"in_scope_only":false,"all_rows":true,"technology_catalog_version":2})
        );
        let path = super::command_api_preview(&command).unwrap()["path"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(
            path.contains("all_rows=true") && !path.contains("max_records"),
            "{path}"
        );
        let error = command_from_operation_input(
            "target.service_map.get",
            &json!({"all_rows":true,"max_records":500}),
        )
        .unwrap_err();
        assert_eq!(
            cli_error_payload("target.service_map.get", &error).code,
            "INVALID_INPUT"
        );
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "scope",
            "service-map",
            "--all-rows",
            "--max-records",
            "500"
        ])
        .is_err());
        assert!(Cli::try_parse_from(["sniper-cli", "scope", "service-map", "--all-rows"]).is_ok());
        // The schema says so too, so an agent learns it before calling.
        let forbidden = &super::service_map_input_schema("target.service_map.get").unwrap()["not"];
        assert_eq!(forbidden["required"], json!(["all_rows", "max_records"]));
        assert_eq!(forbidden["properties"]["all_rows"]["const"], true);
        assert!(command_from_operation_input(
            "target.service_map.get",
            &json!({"all_rows":true,"max_records":null})
        )
        .is_ok());
    }

    #[test]
    fn service_map_method_input_schema_matches_http_tokens() {
        let schema = super::service_map_input_schema("target.service_map.parameters.get").unwrap();
        let schema = &schema["properties"]["method"];
        assert_eq!(schema["type"], "string");
        let forbidden = regex::Regex::new(schema["not"]["pattern"].as_str().unwrap()).unwrap();
        let mut values: Vec<String> = (0..=127u8)
            .map(|byte| format!("X{}Y", char::from(byte)))
            .collect();
        values.extend([
            "".into(),
            "X".repeat(64),
            "X".repeat(65),
            "GÉT".into(),
            "GET\u{a0}".into(),
            "GET\u{2028}".into(),
            "GET\u{2029}".into(),
        ]);
        for value in values {
            let valid = value.len() <= 64 && http::Method::from_bytes(value.as_bytes()).is_ok();
            assert_eq!(
                super::parse_service_map_parameters_method(&value).is_ok(),
                valid,
                "{value:?}"
            );
            let length = value.chars().count() as u64;
            let schema_valid = length >= schema["minLength"].as_u64().unwrap()
                && length <= schema["maxLength"].as_u64().unwrap()
                && !forbidden.is_match(&value);
            assert_eq!(schema_valid, valid, "schema: {value:?}");
        }
    }

    // An endpoint's parameters: an exact endpoint in, the endpoint asked about
    // and the server's own bounds out.
    #[test]
    fn service_map_parameters_read_one_endpoint_and_check_the_answer() {
        use sniper::service_map_parameters::{EndpointParameter, EndpointParameters};
        let session = "00000000-0000-0000-0000-000000000001";
        let input = json!({"session_id":session,"origin":"https://example.com","method":"POST","path":"/v1/items"});
        let command =
            command_from_operation_input("target.service_map.parameters.get", &input).unwrap();
        assert_eq!(
            command.operation_name(),
            "target.service_map.parameters.get"
        );
        let path = super::command_api_preview(&command).unwrap()["path"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(
            path.starts_with("/api/target/service-map/parameters?")
                && path.contains("method=POST")
                && path.contains("path=%2Fv1%2Fitems"),
            "{path}"
        );
        for bad in [
            json!({"session_id":session,"origin":"https://example.com/x","method":"GET","path":"/"}),
            json!({"session_id":session,"origin":"https://example.com","method":"GET POST","path":"/"}),
            json!({"session_id":session,"origin":"https://example.com","method":"GET","path":"/?q=1"}),
            json!({"session_id":session,"origin":"https://example.com","method":"GET","path":"items"}),
            json!({"session_id":session,"origin":"https://example.com","method":"GET"}),
        ] {
            assert!(
                command_from_operation_input("target.service_map.parameters.get", &bad).is_err(),
                "{bad}"
            );
        }
        let args = super::ServiceMapParametersArgs {
            session_id: session.parse().unwrap(),
            origin: "https://example.com".into(),
            method: "POST".into(),
            path: "/v1/items".into(),
        };
        let mut result = EndpointParameters::new(
            args.session_id,
            args.origin.clone(),
            args.method.clone(),
            args.path.clone(),
        );
        result.rows = 2;
        result.parameters.push(EndpointParameter {
            name: "q".into(),
            location: "query".into(),
            rows: 2,
            examples: vec!["shoes".into()],
        });
        assert!(super::validate_service_map_parameters_response(&result, &args).is_ok());
        let mut other = result.clone();
        other.path = "/v1/other".into();
        assert!(
            super::validate_service_map_parameters_response(&other, &args).is_err(),
            "another endpoint"
        );
        let mut overcounted = result.clone();
        overcounted.parameters[0].rows = 3;
        assert!(
            super::validate_service_map_parameters_response(&overcounted, &args).is_err(),
            "more rows than were read"
        );
        let mut located = result.clone();
        located.parameters[0].location = "cookie".into();
        assert!(super::validate_service_map_parameters_response(&located, &args).is_err());
        let unavailable = EndpointParameters::unavailable(
            args.session_id,
            args.origin.clone(),
            args.method.clone(),
            args.path.clone(),
            "inactive_session",
        );
        assert!(super::validate_service_map_parameters_response(&unavailable, &args).is_ok());
    }

    // What no rule names: gathered across origins, most widespread first,
    // with a few origins and evidence tokens each.
    #[test]
    fn service_map_unnamed_gathers_signals_across_origins() {
        let input = json!({"kind":"headers","limit":2});
        let command =
            command_from_operation_input("target.service_map.unnamed.get", &input).unwrap();
        assert_eq!(command.operation_name(), "target.service_map.unnamed.get");
        let preview = super::command_api_preview(&command).unwrap();
        let path = preview["path"].as_str().unwrap();
        assert!(
            path.starts_with("/api/target/service-map?") && path.contains("all_rows=true"),
            "{path}"
        );
        for bad in [
            json!({"kind":"values"}),
            json!({"limit":0}),
            json!({"limit":1001}),
            json!({"origin":"https://example.com"}),
        ] {
            assert!(
                command_from_operation_input("target.service_map.unnamed.get", &bad).is_err(),
                "{bad}"
            );
        }
        let origin = |id: &str,
                      headers: &[(&str, usize)],
                      banners: &[(&str, usize)],
                      named: &[&str]| {
            let signal = |(value, rows): &(&str, usize)| json!({"value": value, "row_count": rows, "evidence": [format!("token-{id}-{value}")]});
            let product = |name: &&str| json!({"product_id": name.to_ascii_lowercase(), "name": name, "category": "edge", "signals": ["header"], "row_count": 1, "evidence": []});
            json!({
                "origin": id, "host": id.trim_start_matches("https://"), "scheme": "https", "port": 443,
                "in_scope": true, "request_count": 1, "first_seen": "2026-10-17T00:00:00Z", "last_seen": "2026-10-17T00:00:00Z",
                "endpoints": [], "technology_clues": [], "redirects": [], "header_links": [],
                "server_technologies": named.iter().map(product).collect::<Vec<_>>(),
                "unnamed": {
                    "banners": banners.iter().map(signal).collect::<Vec<_>>(),
                    "headers": headers.iter().map(signal).collect::<Vec<_>>(),
                    "cookies": [],
                }
            })
        };
        let origins: Vec<sniper::service_map::ServiceOrigin> = [
            origin(
                "https://a.example.com",
                &[("x-cdn-pop", 3), ("x-trace", 1)],
                &[("server: HeRay", 2)],
                &["HeRayCDN", "Envoy"],
            ),
            origin(
                "https://b.example.com",
                &[("x-cdn-pop", 4)],
                &[],
                &["HeRayCDN"],
            ),
            origin("https://c.example.com", &[], &[], &["HeRayCDN"]),
        ]
        .into_iter()
        .map(|value| serde_json::from_value(value).unwrap())
        .collect();
        let session: Uuid = "00000000-0000-0000-0000-000000000001".parse().unwrap();
        let mut limits = serde_json::Map::new();
        for name in [
            "max_records",
            "metadata_bytes",
            "origins",
            "endpoints",
            "endpoints_per_origin",
            "evidence_per_item",
            "redirects_per_origin",
            "header_links_per_origin",
            "technology_clues_per_row",
            "statuses_per_endpoint",
            "content_types_per_endpoint",
            "path_bytes",
            "host_bytes",
            "method_bytes",
            "headers_per_row",
            "header_bytes_per_row",
            "header_value_bytes",
        ] {
            limits.insert(name.into(), json!(100));
        }
        let mut map: sniper::service_map::ServiceMap = serde_json::from_value(json!({
            "schema_version":1, "session_id":session, "origins":origins,
            "snapshot":{
                "id":Uuid::nil(), "generation":Uuid::nil(), "captured_at":"2026-10-17T00:00:00Z",
                "first_retained_started_at":null, "last_retained_started_at":null,
                "oldest_considered_at":null, "latest_considered_at":null,
                "window_order":"newest_capture_sequence", "retained_rows":8, "considered_rows":8,
                "non_http_rows":0, "projected_rows":8, "included_rows":8, "excluded_rows":0,
                "omitted_rows":0, "origin_count":3, "endpoint_count":0,
                "complete":true, "stopped_by":[], "limits":limits
            },
            "in_scope_only":false, "origin_filter":null, "unavailable":[], "deferred":[], "warnings":[]
        })).unwrap();
        let all = super::summarize_unnamed(&map, None, 10);
        assert_eq!(
            (
                all.origins_read,
                all.origins_with_unnamed,
                all.distinct_signals
            ),
            (3, 2, 3)
        );
        assert_eq!(all.signals[0].value, "x-cdn-pop", "most widespread first");
        assert_eq!((all.signals[0].origins, all.signals[0].rows), (2, 7));
        assert_eq!(
            all.signals[0].sample_origins,
            ["https://a.example.com", "https://b.example.com"]
        );
        assert_eq!(all.signals[0].evidence.len(), 2);
        // Only the carrying origins count: c names HeRayCDN but carries none.
        assert_eq!(
            all.signals[0]
                .named_alongside
                .iter()
                .map(|named| (named.name.as_str(), named.origins))
                .collect::<Vec<_>>(),
            [("HeRayCDN", 2), ("Envoy", 1)]
        );
        let serialized = serde_json::to_value(&all.signals[0]).unwrap();
        assert!(serialized.get("alongside").is_none(), "{serialized}");
        assert_eq!(
            serialized["named_alongside"][0],
            json!({"name": "HeRayCDN", "origins": 2})
        );
        let headers = super::summarize_unnamed(&map, Some("headers"), 1);
        assert_eq!(
            (
                headers.distinct_signals,
                headers.omitted_signals,
                headers.signals.len()
            ),
            (2, 1, 1)
        );
        assert!(headers
            .signals
            .iter()
            .all(|signal| signal.kind == "headers"));

        // Summary filtering must not overwrite source coverage or count source
        // losses as if they were a known number of distinct omitted signals.
        for reasons in [
            vec![],
            vec!["unnamed_signals_per_origin_limit"],
            vec!["header_value_limit", "origins_limit"],
        ] {
            map.snapshot.stopped_by = reasons.into_iter().map(str::to_string).collect();
            map.snapshot.complete = map.snapshot.stopped_by.is_empty();
            map.snapshot.omitted_rows = usize::from(map.snapshot.stopped_by.len() == 2);
            for kind in [None, Some("headers"), Some("cookies")] {
                for limit in [1, 100] {
                    let summary = super::summarize_unnamed(&map, kind, limit);
                    let output = serde_json::to_value(&summary).unwrap();
                    assert_eq!(
                        output["snapshot"],
                        serde_json::to_value(&map.snapshot).unwrap()
                    );
                    assert_eq!(
                        summary.omitted_signals,
                        summary.distinct_signals.saturating_sub(limit)
                    );
                    assert_eq!(
                        summary.signals.len() + summary.omitted_signals,
                        summary.distinct_signals
                    );
                }
            }
        }
        let summary_schema = super::service_map_unnamed_output_schema();
        let map_schema = super::service_map_output_schema("target.service_map.get").unwrap();
        assert_eq!(
            summary_schema["properties"]["snapshot"],
            map_schema["properties"]["snapshot"]
        );
        assert!(summary_schema["required"]
            .as_array()
            .unwrap()
            .contains(&json!("snapshot")));
    }

    // An origin's OpenAPI document: an exact origin in, a document for that
    // origin within the server's bounds out.
    #[test]
    fn service_map_openapi_reads_one_origin_and_checks_the_answer() {
        let session = "00000000-0000-0000-0000-000000000001";
        let input = json!({"session_id":session,"origin":"https://example.com"});
        let command =
            command_from_operation_input("target.service_map.openapi.get", &input).unwrap();
        assert_eq!(command.operation_name(), "target.service_map.openapi.get");
        let path = super::command_api_preview(&command).unwrap()["path"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(
            path.starts_with("/api/target/service-map/openapi?")
                && path.contains("origin=https%3A%2F%2Fexample.com"),
            "{path}"
        );
        for bad in [
            json!({"session_id":session,"origin":"https://example.com/x"}),
            json!({"session_id":session}),
            json!({"session_id":session,"origin":"https://example.com","path":"/"}),
        ] {
            assert!(
                command_from_operation_input("target.service_map.openapi.get", &bad).is_err(),
                "{bad}"
            );
        }
        let args = super::ServiceMapOpenApiArgs {
            session_id: session.parse().unwrap(),
            origin: "https://example.com".into(),
        };
        let document = json!({
            "openapi":"3.1.0",
            "info":{"title":"https://example.com","version":"observed","description":""},
            "servers":[{"url":"https://example.com"}],
            "paths":{"/v1/items":{"get":{"responses":{"200":{"description":"OK"}}}}},
        });
        assert!(super::validate_service_map_openapi_response(&document, &args).is_ok());
        let mut other = document.clone();
        other["servers"] = json!([{"url":"https://other.example.com"}]);
        assert!(
            super::validate_service_map_openapi_response(&other, &args).is_err(),
            "another origin"
        );
        let mut relative = document.clone();
        relative["paths"] = json!({"v1/items":{}});
        assert!(super::validate_service_map_openapi_response(&relative, &args).is_err());
    }

    // An origin's flow: an exact origin in, a flow for that origin and session
    // within the server's bounds out.
    #[test]
    fn service_map_flow_reads_one_origin_and_checks_the_answer() {
        let session = "00000000-0000-0000-0000-000000000001";
        let input =
            json!({"origin":"https://example.com","max_records":50000,"in_scope_only":true});
        let command = command_from_operation_input("target.service_map.flow.get", &input).unwrap();
        assert_eq!(command.operation_name(), "target.service_map.flow.get");
        let path = super::command_api_preview(&command).unwrap()["path"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(
            path.starts_with("/api/target/service-map/flow?")
                && path.contains("origin=https%3A%2F%2Fexample.com")
                && path.contains("max_records=50000")
                && path.contains("in_scope_only=true"),
            "{path}"
        );
        for bad in [
            json!({"origin":"https://example.com/x"}),
            json!({}),
            json!({"origin":"https://example.com","max_records":50001}),
            json!({"origin":"https://example.com","path":"/"}),
        ] {
            assert!(
                command_from_operation_input("target.service_map.flow.get", &bad).is_err(),
                "{bad}"
            );
        }
        let args = super::ServiceMapFlowArgs {
            session_id: Some(session.parse().unwrap()),
            origin: "https://example.com".into(),
            in_scope_only: false,
            max_records: 10_000,
        };
        let step = json!({"origin":"https://api.example.com","method":"GET","path":"/v1/items","status":200,
            "request_kind":"api","count":2,"first_seen":"2026-10-20T00:00:00Z","last_seen":"2026-10-20T00:00:01Z",
            "evidence":["v1.a","v1.b"],"record_id":"00000000-0000-0000-0000-000000000002"});
        let flow = json!({"schema_version":1,"session_id":session,"origin":"https://example.com",
            "lanes":["https://example.com","https://api.example.com"],
            "phases":[{"page":{"origin":"https://example.com","path":"/"},"steps":[step]}],
            "considered_rows":2,"flow_rows":2,"complete":true});
        assert_eq!(
            super::validate_service_map_flow_response(&flow, &args).unwrap(),
            session.parse::<Uuid>().unwrap()
        );
        let mut other_session = flow.clone();
        other_session["session_id"] = json!("00000000-0000-0000-0000-000000000009");
        let mut stray_lane = flow.clone();
        stray_lane["phases"][0]["steps"][0]["origin"] = json!("https://other.example.com");
        let mut other_origin = flow.clone();
        other_origin["lanes"][0] = json!("https://other.example.com");
        for bad in [other_session, stray_lane, other_origin] {
            assert!(
                super::validate_service_map_flow_response(&bad, &args).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn service_map_rejects_active_operations_and_invalid_limits() {
        for input in [
            json!({"max_records":0}),
            json!({"max_records":50001}),
            json!({"max_records":-1}),
            json!({"max_records":1.5}),
            json!({"max_records":"10"}),
            json!({"in_scope_only":"true"}),
            json!({"session_id":"invalid"}),
            json!({"url":"https://example.com"}),
            json!({"scan":true}),
            json!({"crawl":true}),
            json!({"follow_redirects":true}),
            json!({"offset":1}),
            Value::Null,
        ] {
            let error = command_from_operation_input("target.service_map.get", &input).unwrap_err();
            assert_eq!(
                cli_error_payload("target.service_map.get", &error).code,
                "INVALID_INPUT"
            );
        }

        for origin in [
            "https://example.com/",
            "https://example.com?token=secret",
            "https://user:secret@example.com",
            "https://example.com:443",
            "ftp://example.com",
            "https://EXAMPLE.COM",
        ] {
            assert!(command_from_operation_input(
                "target.service_map.get",
                &json!({"origin":origin})
            )
            .is_err());
            assert!(Cli::try_parse_from([
                "sniper-cli",
                "scope",
                "service-map",
                "--origin",
                origin
            ])
            .is_err());
        }
        for limit in ["0", "50001", "-1", "1.5"] {
            assert!(Cli::try_parse_from([
                "sniper-cli",
                "scope",
                "service-map",
                "--max-records",
                limit
            ])
            .is_err());
        }
        let defaults = command_from_operation_input("target.service_map.get", &json!({})).unwrap();
        assert_eq!(
            command_input_preview(&defaults),
            json!({"session_id":null,"origin":null,"in_scope_only":false,"max_records":10000,"technology_catalog_version":2})
        );
        let nulls = command_from_operation_input(
            "target.service_map.get",
            &json!({"session_id":null,"in_scope_only":null,"max_records":null}),
        )
        .unwrap();
        assert_eq!(
            command_input_preview(&defaults),
            command_input_preview(&nulls)
        );
        for operation in [
            "target.service_map.scan",
            "target.service_map.crawl",
            "target.service_map.follow",
            "target.service_map.refresh",
        ] {
            assert!(operation_spec(operation).is_none());
            assert!(command_from_operation_input(operation, &json!({})).is_err());
        }
    }

    #[test]
    fn service_map_evidence_requires_explicit_session_and_opaque_token() {
        let session = "11111111-1111-1111-1111-111111111111";
        for input in [
            json!({}),
            json!({"session_id":session}),
            json!({"evidence_id":"token"}),
            json!({"session_id":null,"evidence_id":"token"}),
            json!({"session_id":session,"evidence_id":""}),
            json!({"session_id":session,"evidence_id":"line\nbreak"}),
            json!({"session_id":session,"evidence_id":"x".repeat(513)}),
            json!({"session_id":session,"evidence_id":42}),
            json!({"session_id":session,"evidence_id":"token","id":session}),
        ] {
            assert!(
                command_from_operation_input("target.service_map.evidence.get", &input).is_err(),
                "{input}"
            );
        }
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "scope",
            "service-map-evidence",
            "--evidence-id",
            "token"
        ])
        .is_err());
        assert!(command_from_operation_input(
            "target.service_map.evidence.get",
            &json!({"session_id":session,"evidence_id":"opaque&query=not-a-field"}),
        )
        .is_err());
    }

    #[test]
    fn service_map_body_references_require_one_explicit_row_and_reject_batch_or_map_options() {
        let session = "11111111-1111-1111-1111-111111111111";
        let token = "v1.11111111-1111-1111-1111-111111111111.22222222-2222-2222-2222-222222222222.9007199254740993.33333333-3333-3333-3333-333333333333.44444444-4444-4444-4444-444444444444";
        for input in [
            json!({}),
            json!({"session_id":session}),
            json!({"evidence_id":token}),
            json!({"session_id":null,"evidence_id":token}),
            json!({"session_id":session,"evidence_id":null}),
            json!({"session_id":session,"evidence_id":session}),
            json!({"session_id":session,"evidence_id":[token]}),
            json!({"session_id":session,"evidence_id":token,"max_records":1}),
            json!({"session_id":session,"evidence_id":token,"origin":"https://example.com"}),
            json!({"session_id":session,"evidence_id":token,"activate":true}),
            json!({"session_id":session,"evidence_id":token,"automatic":true}),
            json!({"session_id":session,"evidence_id":token,"body":true}),
            json!({"session_id":session,"evidence_id":token,"follow_redirects":true}),
        ] {
            assert!(
                command_from_operation_input("target.service_map.body_references.get", &input)
                    .is_err(),
                "{input}"
            );
        }
        for args in [
            vec![
                "scope",
                "service-map",
                "body-references",
                "--evidence-id",
                token,
            ],
            vec![
                "scope",
                "service-map",
                "--session-id",
                session,
                "body-references",
                "--session-id",
                session,
                "--evidence-id",
                token,
            ],
            vec![
                "scope",
                "service-map",
                "body-references",
                "--session-id",
                session,
                "--evidence-id",
                token,
                "--max-records",
                "2",
            ],
        ] {
            let mut argv = vec!["sniper-cli"];
            argv.extend(args);
            assert!(Cli::try_parse_from(argv).is_err());
        }
        for map_flags in [
            vec!["--origin", "https://example.com"],
            vec!["--in-scope-only"],
            vec!["--max-records", "25"],
            vec!["--technology-catalog-version", "1"],
            vec!["--session-id", session],
        ] {
            let mut map = vec!["sniper-cli", "scope", "service-map"];
            map.extend(map_flags.iter().copied());
            assert!(Cli::try_parse_from(map.clone()).is_ok(), "{map_flags:?}");
            map.extend([
                "body-references",
                "--session-id",
                session,
                "--evidence-id",
                token,
            ]);
            assert!(
                Cli::try_parse_from(map).is_err(),
                "parent map flags must not be ignored: {map_flags:?}"
            );
        }
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "target",
            "service-map",
            "body-references",
            "--session-id",
            session,
            "--evidence-id",
            token,
        ])
        .is_ok());
        let help = Cli::try_parse_from([
            "sniper-cli",
            "scope",
            "service-map",
            "body-references",
            "--help",
        ])
        .unwrap_err()
        .to_string();
        assert!(help.contains("active session"), "{help}");
        assert!(help.contains("never loads or activates"), "{help}");
        assert!(help.contains("not wire bytes"), "{help}");
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
            let session_id_schema = &spec.input_schema["properties"]["session_id"];
            assert!(session_id_schema.get("format").is_none());
            assert_eq!(session_id_schema["type"], json!(["string", "null"]));
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
    fn parse_error_helpers_accept_os_strings_without_changing_unicode_behavior() {
        use std::ffi::{OsStr, OsString};

        let args: Vec<OsString> = [
            "--output=compact",
            "call",
            "--input",
            "@synthetic-\u{96ea}.json",
            "manifest",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        assert_eq!(cli_parse_error_operation(&args), "manifest");
        assert_eq!(
            cli_output_format_from_raw_args(&args),
            OutputFormat::Compact
        );
        assert_eq!(
            cli_parse_error_long_option(OsStr::new("--input=synthetic-\u{96ea}")),
            Some(("input", true))
        );
        assert_eq!(
            cli_parse_error_operation(&[OsStr::new("call"), OsStr::new("unknown.\u{96ea}")]),
            "unknown.\u{96ea}"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn parse_error_os_strings_preserve_non_unicode_operand_boundaries() {
        use std::ffi::OsString;
        #[cfg(unix)]
        let invalid = {
            use std::os::unix::ffi::OsStringExt;
            OsString::from_vec(vec![0xff])
        };
        #[cfg(windows)]
        let invalid = {
            use std::os::windows::ffi::OsStringExt;
            OsString::from_wide(&[0xd800])
        };
        let mut inline = OsString::from("--input=");
        inline.push(&invalid);
        assert_eq!(cli_parse_error_long_option(&inline), Some(("input", true)));
        for (args, expected) in [
            (
                vec![
                    "call".into(),
                    "--input".into(),
                    invalid.clone(),
                    "manifest".into(),
                ],
                "manifest",
            ),
            (vec!["call".into(), inline, "manifest".into()], "manifest"),
            (
                vec![
                    "skills".into(),
                    "--codex-dir".into(),
                    invalid.clone(),
                    "status".into(),
                ],
                "skills.status",
            ),
            (vec!["call".into(), invalid.clone()], "call"),
            (vec![invalid.clone()], "parse"),
        ] {
            assert_eq!(cli_parse_error_operation(&args), expected);
        }
        assert_eq!(
            cli_output_format_from_raw_args(&[OsString::from("--output"), invalid.clone()]),
            OutputFormat::Pretty
        );
        // The fallback must not change clap's acceptance of OS-native path
        // operands; only the rejected-argument diagnostic path is altered.
        assert!(Cli::try_parse_from([
            OsString::from("sniper-cli"),
            "--dry-run".into(),
            "skills".into(),
            "status".into(),
            "--codex".into(),
            "--codex-dir".into(),
            invalid,
        ])
        .is_ok());
    }

    #[test]
    fn parse_error_option_definitions_have_consistent_single_value_arity() {
        fn check(command: &clap::Command, seen: &mut std::collections::BTreeMap<String, bool>) {
            for arg in command
                .get_arguments()
                .filter(|arg| arg.get_long().is_some())
            {
                let takes_value = arg.get_action().takes_values();
                assert!(!arg.is_allow_hyphen_values_set(), "{}", arg.get_id());
                assert!(!arg.is_allow_negative_numbers_set(), "{}", arg.get_id());
                if let Some(range) = arg.get_num_args() {
                    assert_eq!(
                        range.min_values(),
                        usize::from(takes_value),
                        "{}",
                        arg.get_id()
                    );
                    assert_eq!(
                        range.max_values(),
                        usize::from(takes_value),
                        "{}",
                        arg.get_id()
                    );
                }
                for name in arg
                    .get_long()
                    .into_iter()
                    .chain(arg.get_all_aliases().unwrap_or_default())
                {
                    if let Some(previous) = seen.insert(name.to_owned(), takes_value) {
                        assert_eq!(previous, takes_value, "conflicting arity for --{name}");
                    }
                }
            }
            for child in command.get_subcommands() {
                check(child, seen);
            }
        }
        check(
            &<Cli as clap::CommandFactory>::command(),
            &mut std::collections::BTreeMap::new(),
        );
    }

    #[test]
    fn parse_error_operation_matches_unique_direct_manifest_commands() {
        for spec in manifest_operations() {
            let raw_args = spec
                .command
                .split_ascii_whitespace()
                .take_while(|token| !token.starts_with(['-', '<', '[']))
                .map(str::to_owned)
                .collect::<Vec<_>>();
            if raw_args.first().is_some_and(|command| command == "call") {
                continue;
            }
            let expected = if spec.operation.starts_with("capture.proxy.") {
                "capture"
            } else {
                spec.operation
            };
            assert_eq!(
                cli_parse_error_operation(&raw_args),
                expected,
                "{}",
                spec.command
            );
        }
    }

    #[test]
    fn parse_error_operation_uses_only_trusted_direct_command_tokens() {
        for (args, expected) in [
            (
                vec!["--dry-run", "skills", "status", "--unknown"],
                "skills.status",
            ),
            (
                vec!["--yes", "skills", "status", "--unknown"],
                "skills.status",
            ),
            (
                vec!["repeater", "set-pinned", "--unknown"],
                "replay.set_pinned",
            ),
            (
                vec!["capture", "history", "list", "--unknown"],
                "capture.http.list",
            ),
            (
                vec!["capture", "websocket", "list", "--unknown"],
                "capture.websocket.list",
            ),
            (
                vec!["web-socket", "list", "--unknown"],
                "capture.websocket.list",
            ),
            (
                vec!["match-replace", "list", "--unknown"],
                "capture.auto_replace.list",
            ),
            (vec!["target", "get-scope", "--unknown"], "scope.get"),
            (
                vec!["skills", "--codex-dir", "SYNTHETIC_PRIVATE_PATH", "status"],
                "skills.status",
            ),
            (vec!["skills", "--codex-dir", "status"], "skills"),
            (vec!["skills", "--codex-dir=status"], "skills"),
            (
                vec!["skills", "--codex-dir", "status", "install"],
                "skills.install",
            ),
            (vec!["capture", "--browser", "browser", "list"], "capture"),
            (vec!["skills", "--unknown", "status"], "skills"),
            (vec!["skills", "--unknown=status", "install"], "skills"),
            (vec!["skills", "SYNTHETIC_PRIVATE_ACTION"], "skills"),
            (vec!["SYNTHETIC_PRIVATE_ACTION"], "parse"),
            (vec!["skills", "--", "status"], "skills"),
            (vec!["--", "skills", "status"], "parse"),
            (vec!["capture", "proxy", "--stdin", "--unknown"], "capture"),
            (
                vec!["call", "unknown.operation", "--unknown"],
                "unknown.operation",
            ),
        ] {
            let raw_args = args
                .iter()
                .map(|arg| (*arg).to_string())
                .collect::<Vec<_>>();
            assert_eq!(cli_parse_error_operation(&raw_args), expected, "{args:?}");
        }
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
    fn session_metadata_status_errors_ignore_misleading_outer_context() {
        for status in [303, 400, 409, 503] {
            let status = reqwest::StatusCode::from_u16(status).unwrap();
            let typed = anyhow::Error::new(super::SessionMetadataHttpStatusError { status })
                .context(
                "synthetic-private-diagnostic requires --dry-run or --yes failed (599 Synthetic)",
            );
            for operation in [
                "session.create",
                "session.rename",
                "session.switch",
                "session.delete",
            ] {
                let payload = cli_error_payload(operation, &typed);
                assert_eq!(payload.code, "HTTP_STATUS_ERROR");
                assert_eq!(payload.exit_code, if status.as_u16() < 500 { 5 } else { 6 });
                assert!(!payload.retryable);
                assert_eq!(
                    payload.message,
                    format!(
                        "Session metadata write failed ({status}); mutation outcome is unknown"
                    )
                );
                assert_eq!(
                    payload.details,
                    json!({
                        "status":status.as_u16(),"idempotent":false,"outcome":"unknown"
                    })
                );
                assert_eq!(payload.hint, Some(
                    "Inspect session list and current state before deliberately issuing another write; never automatically retry."
                ));
            }
        }
    }

    #[test]
    fn read_http_status_errors_keep_write_retry_guards_and_safe_messages() {
        let typed = anyhow::Error::new(super::ReadHttpStatusError {
            status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
        })
        .context("synthetic diagnostic requires --dry-run or --yes");
        let read = cli_error_payload("session.list", &typed);
        assert_eq!(read.code, "HTTP_STATUS_ERROR");
        assert_eq!(read.message, "API read failed (503 Service Unavailable)");
        assert_eq!(read.details, json!({"status":503}));
        assert_eq!(read.exit_code, 6);
        assert!(read.retryable);

        let legacy = anyhow::anyhow!(
            "request to /api/sessions failed (503 Service Unavailable): synthetic failure"
        );
        for operation in manifest_operations()
            .into_iter()
            .filter(|spec| spec.side_effect == CliSideEffect::Write && spec.requires_confirmation)
        {
            for error in [&typed, &legacy] {
                let payload = cli_error_payload(operation.operation, error);
                assert_eq!(payload.code, "HTTP_STATUS_ERROR");
                assert!(!payload.retryable, "{}", operation.operation);
                assert_eq!(payload.details["status"], 503);
                assert_eq!(payload.details["idempotent"], false);
                assert!(payload.hint.unwrap().contains("partially applied"));
            }
        }
    }

    #[test]
    fn read_request_errors_keep_their_context_without_using_query_words_as_error_kinds() {
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let message = "failed to GET /api/transactions-search?value=invalid";
        for method in [
            reqwest::Method::GET,
            reqwest::Method::POST,
            reqwest::Method::PATCH,
            reqwest::Method::DELETE,
        ] {
            // A builder error supplies a reqwest source without making a request.
            let source = client.get("://").build().unwrap_err();
            let legacy =
                anyhow::Error::new(client.get("://").build().unwrap_err()).context(message);
            let expected_chain = format!("{legacy:#}");
            let error = super::api_request_error(source, &method, message.to_owned());
            assert_eq!(error.to_string(), message);
            assert_eq!(format!("{error:#}"), expected_chain);
            assert!(error.downcast_ref::<reqwest::Error>().is_some());
            assert_eq!(
                error.downcast_ref::<super::ReadRequestError>().is_some(),
                method == reqwest::Method::GET
            );
            if method == reqwest::Method::GET {
                let error = error.context("requires --dry-run or --yes");
                let payload = cli_error_payload("capture.http.search", &error);
                assert_eq!(payload.code, "CLI_ERROR");
                assert_eq!(payload.exit_code, 1);
                assert_eq!(payload.message, message);
                assert!(!payload.retryable);
                assert_eq!(payload.details, json!({}));
                assert!(payload.hint.is_none());
            }
        }

        let invalid = cli_error_payload("capture.http.search", &anyhow::anyhow!("invalid input"));
        assert_eq!(invalid.code, "INVALID_INPUT");
        assert_eq!(invalid.exit_code, 2);
    }

    #[test]
    fn legacy_workspace_conflict_classification_remains_unchanged() {
        let error = anyhow::anyhow!(
            "workspace state revision conflict: current revision 2; reload workspace state"
        );
        let payload = cli_error_payload("session.create", &error);
        assert_eq!(payload.code, "WORKSPACE_CONFLICT");
        assert_eq!(payload.exit_code, 5);
        assert!(!payload.retryable);
        assert_eq!(payload.details, json!({}));
        assert_eq!(
            payload.hint,
            Some("Refresh workspace state and retry deliberately.")
        );
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

    // The fixture only serves synthetic settings responses over loopback. A stalled
    // connection stays open until the probe's own timeout closes it.
    async fn assert_discovery_response_cleanup(
        response: &'static [u8],
        stall: bool,
        live_owner: bool,
        preserve: bool,
        expected_message: &str,
    ) {
        let root = std::env::temp_dir().join(format!("sniper-cli-probe-body-{}", Uuid::new_v4()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut snapshot = RuntimeStateSnapshot::with_proxy_status(
            "127.0.0.1:18080".parse().unwrap(),
            listener.local_addr().unwrap(),
            true,
        );
        if !live_owner {
            snapshot.pid = None;
        }
        persist_runtime_state(&root, &snapshot).unwrap();
        let original = fs::read(runtime_state_path(&root)).unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..=SNIPER_API_PROBE_RETRY_DELAYS.len() {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(stream.read_u8().await.unwrap());
                }
                assert!(request.starts_with(b"GET /api/settings HTTP/1.1\r\n"));
                stream.write_all(response).await.unwrap();
                if stall {
                    let mut rest = Vec::new();
                    // EOF or a reset both mean that the timed-out client closed.
                    let _ = stream.read_to_end(&mut rest).await;
                }
            }
        });
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            discover_api_base_url_from_data_dir(&client, root.clone()),
        )
        .await
        .expect("discovery should finish after its bounded retries")
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains(expected_message), "{message}");
        assert_eq!(runtime_state_path(&root).exists(), preserve, "{message}");
        if preserve {
            assert_eq!(fs::read(runtime_state_path(&root)).unwrap(), original);
        } else {
            assert!(
                message.contains("Removed the stale runtime-state"),
                "{message}"
            );
        }
        server.await.unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn discovery_preserves_live_owner_on_timeout_before_headers() {
        assert_discovery_response_cleanup(b"", true, true, true, "Leaving runtime-state intact")
            .await;
    }

    #[tokio::test]
    async fn discovery_preserves_live_owner_on_timeout_after_headers() {
        assert_discovery_response_cleanup(
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{",
            true,
            true,
            true,
            "Leaving runtime-state intact",
        )
        .await;
    }

    #[tokio::test]
    async fn discovery_preserves_live_owner_on_truncated_response_body() {
        assert_discovery_response_cleanup(
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{",
            false,
            true,
            true,
            "Leaving runtime-state intact",
        )
        .await;
    }

    #[tokio::test]
    async fn discovery_removes_stale_owner_on_truncated_response_body() {
        assert_discovery_response_cleanup(
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{",
            false,
            false,
            false,
            "is not responding",
        )
        .await;
    }

    #[tokio::test]
    async fn discovery_rejects_complete_invalid_json_with_live_owner() {
        assert_discovery_response_cleanup(
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n{",
            false,
            true,
            false,
            "response was not JSON",
        )
        .await;
    }

    #[tokio::test]
    async fn discovery_rejects_complete_invalid_schema_with_live_owner() {
        assert_discovery_response_cleanup(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
            false,
            true,
            false,
            "did not match the expected /api/settings schema",
        )
        .await;
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
            if operation == "session.rename" {
                let id_schema = &spec.input_schema["properties"]["id"];
                assert!(id_schema.get("format").is_none());
                assert_eq!(id_schema["type"], "string");
            } else {
                assert_eq!(
                    spec.input_schema["properties"]["session_id"]["format"],
                    "uuid"
                );
            }
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
            &json!({"session_id":second,"limit":50,"items":[]})
        )
        .is_ok());
    }

    #[test]
    fn saved_response_binding_matches_explicit_selection_uuid_sets() {
        let first = Uuid::from_u128(0xabcdef);
        let second = Uuid::from_u128(0xabcdee);
        let input = json!({"session_id":first,"ids":[first,second]});
        let data = json!({"session_id":first,"ids":[second,first.to_string().to_uppercase()]});
        assert!(validate_saved_response_binding("saved.v1.http.select", &input, &data).is_ok());
        for ids in [
            json!([]),
            json!([first]),
            json!([first, Uuid::nil()]),
            json!([first, second, Uuid::nil()]),
        ] {
            assert!(validate_saved_response_binding(
                "saved.v1.http.select",
                &input,
                &json!({"session_id":first,"ids":ids})
            )
            .is_err());
        }
        assert!(validate_saved_response_binding(
            "saved.v1.http.select",
            &json!({"session_id":first,"host":"example.com"}),
            &json!({"session_id":first,"ids":[]})
        )
        .is_ok());
    }

    #[test]
    fn saved_response_binding_checks_limits_even_on_empty_terminal_pages() {
        for operation in ["saved.v1.http.list", "saved.v1.session.list"] {
            for (input, expected) in [
                (json!({}), 50),
                (json!({"limit":1}), 1),
                (json!({"limit":200}), 200),
            ] {
                for limit in [1, 50, 200] {
                    let data = json!({"session_id":Uuid::nil(),"limit":limit,"items":[],"continuation":null});
                    assert_eq!(
                        validate_saved_response_binding(operation, &input, &data).is_ok(),
                        limit == expected
                    );
                }
            }
        }
    }

    #[test]
    fn saved_response_binding_checks_http_cursor_even_on_terminal_pages() {
        let sid = Uuid::from_u128(0xabcdef);
        let generation = Uuid::from_u128(0xabcdee);
        let input = json!({"continuation":{"session_id":sid,"store_generation":generation,"before_sequence":10,"limit":1}});
        for (sequence, valid) in [(9, true), (10, false), (11, false)] {
            let data = json!({"session_id":sid,"limit":1,"items":[{"sequence":sequence}],"continuation":null});
            assert_eq!(
                validate_saved_response_binding("saved.v1.http.list", &input, &data).is_ok(),
                valid
            );
        }
        let mut data = json!({"session_id":sid,"limit":1,"items":[],"continuation":null});
        assert!(validate_saved_response_binding("saved.v1.http.list", &input, &data).is_ok());
        data["limit"] = json!(2);
        assert!(validate_saved_response_binding("saved.v1.http.list", &input, &data).is_err());
        data["limit"] = json!(1);
        for (returned, valid) in [
            (generation.to_string().to_uppercase(), true),
            (Uuid::nil().to_string(), false),
        ] {
            data["continuation"] = json!({"store_generation":returned});
            assert_eq!(
                validate_saved_response_binding("saved.v1.http.list", &input, &data).is_ok(),
                valid
            );
        }
    }

    #[test]
    fn saved_response_binding_checks_session_cursor_as_uuid() {
        let after = Uuid::from_u128(0xabcdef);
        let input = json!({"after_id":after.to_string().to_uppercase(),"limit":1});
        for (id, valid) in [
            (after.as_u128() - 1, false),
            (after.as_u128(), false),
            (after.as_u128() + 1, true),
        ] {
            let data = json!({"limit":1,"items":[{"id":Uuid::from_u128(id)}],"continuation":null});
            assert_eq!(
                validate_saved_response_binding("saved.v1.session.list", &input, &data).is_ok(),
                valid
            );
        }
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

    #[test]
    fn saved_response_diagnostics_distinguish_metadata_reads_from_receipts() {
        for operation in [
            "saved.v1.http.list",
            "saved.v1.http.select",
            "saved.v1.session.list",
        ] {
            assert_eq!(
                super::saved_response_diagnostic(
                    operation,
                    "read diagnostic",
                    "receipt diagnostic"
                ),
                "read diagnostic"
            );
        }
        for operation in [
            "saved.v1.http.delete",
            "saved.v1.http.clear",
            "saved.v1.session.rename",
            "saved.v1.operation.get",
            "saved.v1.future",
        ] {
            assert_eq!(
                super::saved_response_diagnostic(
                    operation,
                    "read diagnostic",
                    "receipt diagnostic"
                ),
                "receipt diagnostic"
            );
        }
    }

    #[test]
    fn saved_mutation_errors_keep_receipt_guidance() {
        for operation in [
            "saved.v1.http.delete",
            "saved.v1.http.clear",
            "saved.v1.session.rename",
        ] {
            for (code, outcome) in [
                ("INVALID_INPUT", "not_applied"),
                ("INVALID_RESPONSE", "unknown"),
                ("API_UNAVAILABLE", "unknown"),
            ] {
                let error = super::saved_cli_error(
                    code,
                    "synthetic failure",
                    outcome,
                    &json!({"operation_id":"aabbccdd-0011-2233-4455-66778899aabb"}),
                );
                let payload = cli_error_payload(operation, &error);
                assert_eq!(payload.code, code);
                assert_eq!(payload.details["outcome"], outcome);
                assert_eq!(
                    payload.details["operation_id"],
                    "aabbccdd-0011-2233-4455-66778899aabb"
                );
                assert!(!payload.retryable);
                assert!(payload.hint.unwrap().contains("original operation_id"));
                assert!(payload.hint.unwrap().contains("never automatically retry"));
                assert_eq!(
                    payload.exit_code,
                    if code == "INVALID_INPUT" { 2 } else { 5 }
                );
            }
        }
    }

    #[test]
    fn saved_read_hint_keeps_receipt_guidance_for_unknown_outcomes_and_operations() {
        for (operation, outcome) in [
            ("saved.v1.http.list", "unknown"),
            ("saved.v1.future", "not_applied"),
        ] {
            let error =
                super::saved_cli_error("INVALID_INPUT", "synthetic failure", outcome, &json!({}));
            let payload = cli_error_payload(operation, &error);
            assert!(payload.hint.unwrap().contains("original operation_id"));
            assert_eq!(payload.details["outcome"], outcome);
        }
    }
}
