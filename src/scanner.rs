use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use regex::Regex;
use rsa::sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

use crate::model::{BodyEncoding, MessageRecord, TransactionRecord};

const MAX_SCANNER_BROADCAST_CAPACITY: usize = 4096;
pub const MAX_SCANNER_CUSTOM_RULES: usize = 250;
pub const MAX_SCANNER_FIELD_BYTES: usize = 64 * 1024;
pub const MAX_SCANNER_CONFIG_BYTES: usize = 4 * 1024 * 1024;

// ── Scanner config ──

/// Built-in rule identifiers.
pub const BUILTIN_RULES: &[(&str, &str)] = &[
    ("jwt", "JWT Analysis"),
    ("header", "Security Headers"),
    ("cookie", "Cookie Flags"),
    ("disclosure", "Sensitive Data Exposure"),
    ("cors", "CORS Misconfiguration"),
    ("server", "Server Disclosure"),
    ("error", "Error Messages"),
    ("misconfig", "Security Misconfiguration"),
    ("info", "Information Disclosure"),
    ("auth", "Authentication Issues"),
];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CustomRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    /// Where to search: "response_body", "response_header", "request_header"
    pub target: String,
    /// For header targets, the header name to check.
    #[serde(default)]
    pub header_name: String,
    pub pattern: String,
    pub severity: Severity,
    pub category: String,
    pub description: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScannerConfig {
    #[serde(default = "default_scanner_enabled")]
    pub enabled: bool,
    /// Per-rule toggle. Key = rule id (e.g. "jwt", "header"), value = enabled.
    #[serde(default = "default_rule_toggles")]
    pub rules: HashMap<String, bool>,
    #[serde(default)]
    pub custom_rules: Vec<CustomRule>,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rules: default_rule_toggles(),
            custom_rules: Vec::new(),
        }
    }
}

/// A read snapshot and compare-and-swap precondition for one session's settings.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScannerConfigSnapshot {
    pub session_id: Uuid,
    pub config_token: String,
    #[serde(flatten)]
    pub config: ScannerConfig,
}

impl ScannerConfigSnapshot {
    pub fn new(session_id: Uuid, config: ScannerConfig) -> Self {
        Self {
            session_id,
            config_token: scanner_config_token(session_id, &config),
            config,
        }
    }
}

pub fn scanner_config_token(session_id: Uuid, config: &ScannerConfig) -> String {
    // Value sorts object keys; custom-rule order remains significant. Binding the
    // content to the session prevents a copied token from authorizing another one.
    let value = serde_json::to_value(config).expect("scanner config is serializable");
    let bytes = serde_json::to_vec(&(session_id, value)).expect("scanner snapshot is serializable");
    let mut hash = Sha256::new();
    hash.update(b"sniper-scanner-config-v1\0");
    hash.update(bytes);
    format!("{:x}", hash.finalize())
}

pub fn validate_scanner_config(config: &ScannerConfig) -> Result<(), String> {
    let bytes =
        serde_json::to_vec(config).map_err(|_| "failed to measure scanner config".to_string())?;
    if bytes.len() > MAX_SCANNER_CONFIG_BYTES {
        return Err(format!(
            "scanner config cannot exceed {MAX_SCANNER_CONFIG_BYTES} stored bytes"
        ));
    }
    if config.custom_rules.len() > MAX_SCANNER_CUSTOM_RULES {
        return Err(format!(
            "scanner config cannot contain more than {MAX_SCANNER_CUSTOM_RULES} custom rules"
        ));
    }
    let mut ids = HashSet::new();
    for rule in &config.custom_rules {
        validate_custom_rule(rule)?;
        if !ids.insert(rule.id.trim()) {
            return Err(format!(
                "custom scanner rule {} id is duplicated",
                rule.id.trim()
            ));
        }
    }
    Ok(())
}

pub fn validate_custom_rule(rule: &CustomRule) -> Result<(), String> {
    for (label, value) in [
        ("id", &rule.id),
        ("name", &rule.name),
        ("target", &rule.target),
        ("header name", &rule.header_name),
        ("pattern", &rule.pattern),
        ("category", &rule.category),
        ("description", &rule.description),
    ] {
        if value.len() > MAX_SCANNER_FIELD_BYTES {
            return Err(format!(
                "custom scanner rule {label} cannot exceed {MAX_SCANNER_FIELD_BYTES} bytes"
            ));
        }
    }
    if rule.id.trim().is_empty() {
        return Err("custom scanner rule id is required".to_string());
    }
    if rule.name.trim().is_empty() {
        return Err(format!("custom scanner rule {} name is required", rule.id));
    }
    if rule.pattern.trim().is_empty() {
        return Err(format!(
            "custom scanner rule {} pattern is required",
            rule.id
        ));
    }
    if !matches!(
        rule.target.as_str(),
        "response_body" | "response_header" | "request_header"
    ) {
        return Err(format!(
            "custom scanner rule {} has invalid target",
            rule.id
        ));
    }
    // Regex's diagnostic includes the source pattern. Keep it out of API errors,
    // since patterns can contain private captured values.
    Regex::new(&rule.pattern)
        .map_err(|_| format!("custom scanner rule {} has invalid regex", rule.id))?;
    Ok(())
}

pub fn sanitize_scanner_config(mut config: ScannerConfig) -> ScannerConfig {
    let mut seen_rule_ids = HashSet::new();
    config.custom_rules = config
        .custom_rules
        .into_iter()
        .filter(|rule| valid_restored_custom_rule(rule, &mut seen_rule_ids))
        .take(MAX_SCANNER_CUSTOM_RULES)
        .collect();
    while serde_json::to_vec(&config)
        .map(|bytes| bytes.len() > MAX_SCANNER_CONFIG_BYTES)
        .unwrap_or(true)
    {
        if config.custom_rules.pop().is_none() {
            config = ScannerConfig::default();
            break;
        }
    }
    config
}

fn valid_restored_custom_rule(rule: &CustomRule, seen_rule_ids: &mut HashSet<String>) -> bool {
    if rule.id.len() > MAX_SCANNER_FIELD_BYTES
        || rule.name.len() > MAX_SCANNER_FIELD_BYTES
        || rule.target.len() > MAX_SCANNER_FIELD_BYTES
        || rule.header_name.len() > MAX_SCANNER_FIELD_BYTES
        || rule.pattern.len() > MAX_SCANNER_FIELD_BYTES
        || rule.category.len() > MAX_SCANNER_FIELD_BYTES
        || rule.description.len() > MAX_SCANNER_FIELD_BYTES
    {
        return false;
    }
    let id = rule.id.trim();
    if id.is_empty() || !seen_rule_ids.insert(id.to_string()) {
        return false;
    }
    if rule.name.trim().is_empty() || rule.pattern.trim().is_empty() {
        return false;
    }
    if !matches!(
        rule.target.as_str(),
        "response_body" | "response_header" | "request_header"
    ) {
        return false;
    }
    Regex::new(&rule.pattern).is_ok()
}

fn default_scanner_enabled() -> bool {
    true
}

fn default_rule_toggles() -> HashMap<String, bool> {
    let mut rules = HashMap::new();
    for &(id, _) in BUILTIN_RULES {
        rules.insert(id.to_string(), true);
    }
    rules
}

impl ScannerConfig {
    pub fn is_rule_enabled(&self, rule_id: &str) -> bool {
        self.enabled && *self.rules.get(rule_id).unwrap_or(&true)
    }
}

// ── Finding model ──

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScannerFinding {
    pub id: Uuid,
    pub record_id: Uuid,
    pub found_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rule_id: String,
    pub severity: Severity,
    pub category: String,
    pub title: String,
    pub detail: String,
    pub evidence: String,
    pub host: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<FindingLocation>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FindingSummary {
    pub id: Uuid,
    pub record_id: Uuid,
    pub found_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rule_id: String,
    pub severity: Severity,
    pub category: String,
    pub title: String,
    pub host: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<FindingLocation>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingLocation {
    pub side: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub section: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
}

impl ScannerFinding {
    pub fn summary(&self) -> FindingSummary {
        FindingSummary {
            id: self.id,
            record_id: self.record_id,
            found_at: self.found_at,
            rule_id: self.rule_id.clone(),
            severity: self.severity.clone(),
            category: self.category.clone(),
            title: self.title.clone(),
            host: self.host.clone(),
            path: self.path.clone(),
            location: self.location.clone(),
        }
    }
}

// ── Finding store ──

pub struct ScannerStore {
    max_entries: usize,
    entries: RwLock<VecDeque<ScannerFinding>>,
    events: broadcast::Sender<FindingSummary>,
    config: RwLock<ScannerConfig>,
    seen: RwLock<HashSet<FindingDedupKey>>,
    clear_generation: AtomicU64,
    rescanning: AtomicBool,
}

/// Held while a rescan runs; dropping it lets the next one start.
pub struct RescanSlot<'a>(&'a AtomicBool);

impl Drop for RescanSlot<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl ScannerStore {
    pub fn new(max_entries: usize) -> Self {
        let (events, _) = broadcast::channel(max_entries.clamp(64, MAX_SCANNER_BROADCAST_CAPACITY));
        Self {
            max_entries,
            entries: RwLock::new(VecDeque::new()),
            events,
            config: RwLock::new(ScannerConfig::default()),
            seen: RwLock::new(HashSet::new()),
            clear_generation: AtomicU64::new(0),
            rescanning: AtomicBool::new(false),
        }
    }

    /// One rescan per session at a time.
    pub fn begin_rescan(&self) -> Option<RescanSlot<'_>> {
        (!self.rescanning.swap(true, Ordering::AcqRel)).then_some(RescanSlot(&self.rescanning))
    }

    /// Push a finding unless the same issue is already listed (see `finding_scope`).
    pub async fn push(&self, finding: ScannerFinding) -> bool {
        self.push_inner(finding, None).await
    }

    pub fn clear_generation(&self) -> u64 {
        self.clear_generation.load(Ordering::Acquire)
    }

    pub fn restore_clear_generation(&self, generation: u64) {
        self.clear_generation.store(generation, Ordering::Release);
    }

    pub async fn push_if_generation(&self, finding: ScannerFinding, generation: u64) -> bool {
        self.push_inner(finding, Some(generation)).await
    }

    async fn push_inner(&self, finding: ScannerFinding, generation: Option<u64>) -> bool {
        let dedup_key = finding_dedup_key(&finding);
        let summary = finding.summary();
        let mut entries = self.entries.write().await;
        let mut seen = self.seen.write().await;
        if generation.is_some_and(|expected| self.clear_generation() != expected) {
            return false;
        }
        if !seen.insert(dedup_key) {
            return false; // duplicate — skip
        }
        entries.push_front(finding);
        while entries.len() > self.max_entries {
            if let Some(evicted) = entries.pop_back() {
                seen.remove(&finding_dedup_key(&evicted));
            }
        }
        let _ = self.events.send(summary);
        true
    }

    pub async fn list(&self, limit: Option<usize>) -> Vec<FindingSummary> {
        let entries = self.entries.read().await;
        entries
            .iter()
            .take(limit.unwrap_or(self.max_entries).min(self.max_entries))
            .map(ScannerFinding::summary)
            .collect()
    }

    pub async fn get(&self, id: Uuid) -> Option<ScannerFinding> {
        let entries = self.entries.read().await;
        entries.iter().find(|f| f.id == id).cloned()
    }

    /// Each record's most severe finding, which is what HTTP history tints it by.
    pub async fn worst_severity_by_record(&self) -> HashMap<Uuid, Severity> {
        let entries = self.entries.read().await;
        let mut worst: HashMap<Uuid, Severity> = HashMap::new();
        for finding in entries.iter() {
            worst
                .entry(finding.record_id)
                .and_modify(|severity| {
                    if finding.severity > *severity {
                        *severity = finding.severity.clone();
                    }
                })
                .or_insert_with(|| finding.severity.clone());
        }
        worst
    }

    pub async fn clear(&self) {
        self.clear_generation.fetch_add(1, Ordering::AcqRel);
        self.entries.write().await.clear();
        self.seen.write().await.clear();
    }

    pub async fn replace_all(&self, findings: Vec<ScannerFinding>) {
        let mut entries = self.entries.write().await;
        let mut seen = self.seen.write().await;
        entries.clear();
        seen.clear();
        for finding in distinct_findings(findings)
            .into_iter()
            .take(self.max_entries)
        {
            seen.insert(finding_dedup_key(&finding));
            entries.push_back(finding);
        }
    }

    pub async fn count(&self) -> usize {
        self.entries.read().await.len()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<FindingSummary> {
        self.events.subscribe()
    }

    pub async fn get_config(&self) -> ScannerConfig {
        self.config.read().await.clone()
    }

    pub async fn update_config(&self, new_config: ScannerConfig) {
        *self.config.write().await = sanitize_scanner_config(new_config);
    }

    /// Create a store pre-populated with persisted findings.
    pub fn from_findings(max_entries: usize, findings: Vec<ScannerFinding>) -> Self {
        Self::from_findings_with_config(max_entries, findings, ScannerConfig::default())
    }

    pub fn from_findings_with_config(
        max_entries: usize,
        findings: Vec<ScannerFinding>,
        config: ScannerConfig,
    ) -> Self {
        let (events, _) = broadcast::channel(max_entries.clamp(64, MAX_SCANNER_BROADCAST_CAPACITY));
        let findings: Vec<_> = distinct_findings(findings)
            .into_iter()
            .take(max_entries)
            .collect();
        let seen = findings.iter().map(finding_dedup_key).collect();
        Self {
            max_entries,
            entries: RwLock::new(VecDeque::from(findings)),
            events,
            config: RwLock::new(sanitize_scanner_config(config)),
            seen: RwLock::new(seen),
            clear_generation: AtomicU64::new(0),
            rescanning: AtomicBool::new(false),
        }
    }

    /// Take a snapshot of all findings for persistence.
    pub async fn snapshot(&self, limit: Option<usize>) -> Vec<ScannerFinding> {
        let entries = self.entries.read().await;
        entries
            .iter()
            .take(limit.unwrap_or(self.max_entries).min(self.max_entries))
            .cloned()
            .collect()
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct FindingDedupKey {
    host: String,
    rule_id: String,
    category: String,
    title: String,
    scope: String,
}

fn finding_dedup_key(finding: &ScannerFinding) -> FindingDedupKey {
    FindingDedupKey {
        host: finding.host.to_ascii_lowercase(),
        rule_id: finding.rule_id.clone(),
        category: finding.category.clone(),
        title: finding.title.clone(),
        scope: finding_scope(finding),
    }
}

/// One finding per issue, not per request. A missing header or a cookie's
/// flags belong to the host; an open redirect, an error page, an exposed
/// document or endpoint, or a caching policy to one endpoint, with ID segments
/// grouped as the map groups them; a secret, a token, an address, a version
/// banner, a CORS policy or a comment to its own value. Each request used to
/// add a finding, on every path the host served.
fn finding_scope(finding: &ScannerFinding) -> String {
    let endpoint = || {
        let path = finding.path.split(['?', '#']).next().unwrap_or("");
        crate::service_map::path_group(path).unwrap_or_else(|| path.to_string())
    };
    // A scan's evidence can be a random value it sent and saw reflected; the
    // template and the endpoint it matched are the issue.
    if finding
        .rule_id
        .starts_with(crate::templates::ACTIVE_RULE_PREFIX)
    {
        return endpoint();
    }
    if !finding.rule_id.is_empty() {
        return finding.evidence.clone();
    }
    match (finding.category.as_str(), finding.title.as_str()) {
        ("disclosure" | "jwt", _) | ("info", "Email address in response") => {
            finding.evidence.clone()
        }
        // A host may run more than one stack, one behind each path; a CORS
        // policy may trust more than one origin, and a site may leave more
        // than one comment.
        ("server", title) if title.ends_with("version disclosure") => finding.evidence.clone(),
        ("cors", _) => finding.evidence.clone(),
        ("info", title) if title.starts_with("HTML comment") => finding.evidence.clone(),
        // A SQL error or a stack trace on `/search` and on `/login` are two leads.
        ("error", _) => endpoint(),
        ("auth", "Possible open redirect") => endpoint(),
        ("misconfig", title) if title.contains("Cache-Control") => endpoint(),
        ("info", title) if ENDPOINT_INFO_TITLES.contains(&title) => endpoint(),
        // A page the map names as exposed carries no evidence; one named from
        // a header or a cookie is on every answer of the host.
        ("info", title) if title.ends_with(" exposed") && finding.evidence.is_empty() => endpoint(),
        _ => String::new(),
    }
}

/// Information findings an endpoint gives away by answering, not the host.
const ENDPOINT_INFO_TITLES: &[&str] = &[
    "Directory listing enabled",
    "Git commit metadata exposed",
    "GraphQL introspection enabled",
    "Swagger/OpenAPI spec exposed",
    "WSDL service definition exposed",
];

/// Scans retained records again with the current rules, for a session whose
/// findings came from older ones. Keeps the first finding of each issue in the
/// order the records come, oldest first, as live capture keeps the first it sees.
pub struct Rescan {
    config: ScannerConfig,
    seen: HashSet<FindingDedupKey>,
    findings: Vec<ScannerFinding>,
    scanned: HashSet<Uuid>,
    templates: Option<RescanTemplates>,
}

/// The passive Nuclei templates a rescan runs, with the scope they apply to,
/// read once when it starts.
pub struct RescanTemplates {
    pub set: std::sync::Arc<crate::templates::engine::PassiveSet>,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

impl Rescan {
    pub fn new(config: ScannerConfig) -> Self {
        Self {
            config,
            seen: HashSet::new(),
            findings: Vec::new(),
            scanned: HashSet::new(),
            templates: None,
        }
    }

    pub fn with_templates(mut self, templates: Option<RescanTemplates>) -> Self {
        self.templates = templates;
        self
    }

    pub fn scan(&mut self, record: &TransactionRecord) {
        self.scanned.insert(record.id);
        // A rule that panics on one row must not end the rescan; that row just
        // gets no findings.
        let Ok(mut found) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            scan_transaction(record, &self.config)
        })) else {
            return;
        };
        if let Some(templates) = self.templates.as_ref().filter(|_| self.config.enabled) {
            if crate::templates::passive_applies(record, &templates.include, &templates.exclude) {
                if let Ok(more) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    crate::templates::passive_findings(&templates.set, record)
                })) {
                    found.extend(more);
                }
            }
        }
        for finding in found {
            if self.seen.insert(finding_dedup_key(&finding)) {
                self.findings.push(finding);
            }
        }
    }

    /// The findings newest first, as the store lists them, and the records scanned.
    pub fn finish(self) -> (Vec<ScannerFinding>, HashSet<Uuid>) {
        let mut findings = self.findings;
        findings.reverse();
        (findings, self.scanned)
    }
}

/// Keeps the first of each issue, newest first, as a store built before
/// findings were grouped by issue may hold one per request.
fn distinct_findings(findings: Vec<ScannerFinding>) -> Vec<ScannerFinding> {
    let mut seen = HashSet::new();
    findings
        .into_iter()
        .filter(|finding| seen.insert(finding_dedup_key(finding)))
        .collect()
}

// ── Scanner engine ──

/// Returns true when the message body is binary (base64-encoded).
/// Binary bodies (images, fonts, wasm, etc.) should be skipped by pattern-matching
/// rules because regex hits on raw base64 are almost always false positives.
fn is_binary_body(msg: &MessageRecord) -> bool {
    msg.body_encoding == BodyEncoding::Base64
}

/// Returns true if the regex match appears to be embedded inside a larger base64
/// string (e.g., base64-encoded ad payloads in JSON responses). Such matches are
/// almost always false positives — the token pattern coincidentally appears within
/// base64-encoded binary data.
fn is_embedded_in_base64(body: &str, m: &regex::Match) -> bool {
    is_span_embedded_in_base64(body, m.start(), m.end())
}

fn is_span_embedded_in_base64(body: &str, start: usize, end: usize) -> bool {
    let bytes = body.as_bytes();

    // Count continuous base64 chars before the match
    let pre = (0..start)
        .rev()
        .take_while(|&i| is_base64_char(bytes[i]))
        .count();

    // Count continuous base64 chars after the match
    let post = (end..bytes.len())
        .take_while(|&i| is_base64_char(bytes[i]))
        .count();

    // If 20+ base64 chars on each side, the match is embedded in base64 data
    pre >= 20 && post >= 20
}

#[inline]
fn is_base64_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='
}

/// Run all passive scan rules against a transaction record, respecting config.
pub fn scan_transaction(record: &TransactionRecord, config: &ScannerConfig) -> Vec<ScannerFinding> {
    if !config.enabled {
        return Vec::new();
    }

    let mut findings = Vec::new();

    if config.is_rule_enabled("jwt") {
        check_jwt(record, &mut findings);
    }
    if config.is_rule_enabled("header") {
        check_security_headers(record, &mut findings);
    }
    if config.is_rule_enabled("cookie") {
        check_cookie_flags(record, &mut findings);
    }
    if config.is_rule_enabled("disclosure") {
        check_sensitive_data(record, &mut findings);
    }
    if config.is_rule_enabled("cors") {
        check_cors(record, &mut findings);
    }
    if config.is_rule_enabled("server") {
        check_server_disclosure(record, &mut findings);
    }
    if config.is_rule_enabled("error") {
        check_error_messages(record, &mut findings);
    }
    if config.is_rule_enabled("misconfig") {
        check_security_misconfig(record, &mut findings);
    }
    if config.is_rule_enabled("info") {
        check_info_disclosure(record, &mut findings);
        check_exposures(record, &mut findings);
    }
    if config.is_rule_enabled("auth") {
        check_auth_issues(record, &mut findings);
    }

    // Run enabled custom rules
    for rule in &config.custom_rules {
        if rule.enabled {
            check_custom_rule(record, rule, &mut findings);
        }
    }

    for finding in &mut findings {
        if finding.location.is_none() {
            finding.location = infer_finding_location(record, finding);
        }
    }

    findings
}

/// Execute a single custom regex rule against the transaction.
fn check_custom_rule(
    record: &TransactionRecord,
    rule: &CustomRule,
    findings: &mut Vec<ScannerFinding>,
) {
    let re = match Regex::new(&rule.pattern) {
        Ok(re) => re,
        Err(_) => return, // invalid pattern — skip silently
    };

    let targets: Vec<(String, Option<FindingLocation>)> = match rule.target.as_str() {
        "response_body" => {
            if let Some(response) = &record.response {
                if is_binary_body(response) {
                    vec![]
                } else {
                    vec![(response.body_preview.clone(), None)]
                }
            } else {
                vec![]
            }
        }
        "response_header" => {
            if let Some(response) = &record.response {
                response
                    .headers
                    .iter()
                    .enumerate()
                    .filter(|h| {
                        let header = h.1;
                        rule.header_name.is_empty()
                            || header.name.eq_ignore_ascii_case(&rule.header_name)
                    })
                    .map(|(index, header)| {
                        (
                            header.value.clone(),
                            Some(FindingLocation {
                                side: "response".to_string(),
                                section: "header".to_string(),
                                line: Some(index + 2),
                            }),
                        )
                    })
                    .collect::<Vec<_>>()
            } else {
                vec![]
            }
        }
        "request_header" => record
            .request
            .headers
            .iter()
            .enumerate()
            .filter(|h| {
                let header = h.1;
                rule.header_name.is_empty() || header.name.eq_ignore_ascii_case(&rule.header_name)
            })
            .map(|(index, header)| {
                (
                    header.value.clone(),
                    Some(FindingLocation {
                        side: "request".to_string(),
                        section: "header".to_string(),
                        line: Some(
                            index + 2 + usize::from(request_finding_synthesizes_host(record)),
                        ),
                    }),
                )
            })
            .collect(),
        _ => vec![],
    };

    for (text, location) in targets {
        if let Some(m) = re.find(&text) {
            let mut finding = make_finding(
                record,
                rule.severity.clone(),
                &rule.category,
                &rule.name,
                &rule.description,
                truncate_evidence(m.as_str(), 120),
            );
            finding.rule_id = rule.id.clone();
            finding.location = location;
            findings.push(finding);
            break; // one match per rule per request is enough
        }
    }
}

fn make_finding(
    record: &TransactionRecord,
    severity: Severity,
    category: &str,
    title: impl Into<String>,
    detail: impl Into<String>,
    evidence: impl Into<String>,
) -> ScannerFinding {
    ScannerFinding {
        id: Uuid::new_v4(),
        record_id: record.id,
        found_at: Utc::now(),
        rule_id: String::new(),
        severity,
        category: category.to_string(),
        title: title.into(),
        detail: detail.into(),
        evidence: evidence.into(),
        host: record.host.clone(),
        path: record.path.clone(),
        location: None,
    }
}

pub(crate) fn infer_finding_location(
    record: &TransactionRecord,
    finding: &ScannerFinding,
) -> Option<FindingLocation> {
    let response_text = raw_response_text_for_finding(record);
    let request_text = raw_request_text_for_finding(record);
    let prefer_request = finding.category == "auth"
        || finding
            .evidence
            .to_ascii_lowercase()
            .starts_with("authorization:");

    let mut sides = if prefer_request {
        vec![
            ("request", Some(request_text.as_str())),
            ("response", response_text.as_deref()),
        ]
    } else {
        vec![
            ("response", response_text.as_deref()),
            ("request", Some(request_text.as_str())),
        ]
    };

    if let Some(query) = finding_evidence_query(&finding.evidence, finding) {
        for (side, text) in &sides {
            let Some(text) = text else {
                continue;
            };
            if let Some(line) = line_number_for_query(text, &query) {
                return Some(location_for_line(record, side, line));
            }
        }
    }

    for keyword in finding_location_keywords(finding) {
        for (side, text) in &sides {
            let Some(text) = text else {
                continue;
            };
            if let Some(line) = line_number_for_query(text, keyword) {
                return Some(location_for_line(record, side, line));
            }
        }
    }

    sides.clear();
    if finding.title.starts_with("Missing ")
        && matches!(finding.category.as_str(), "header" | "misconfig")
    {
        return Some(FindingLocation {
            side: "response".to_string(),
            section: "headers".to_string(),
            line: None,
        });
    }

    None
}

fn raw_request_text_for_finding(record: &TransactionRecord) -> String {
    let start_line = if matches!(&record.kind, &crate::model::TrafficKind::Tunnel) {
        format!(
            "CONNECT {} {}",
            record.host,
            record.http_version.as_deref().unwrap_or("HTTP/1.1")
        )
    } else {
        format!(
            "{} {} {}",
            record.method,
            if record.path.is_empty() {
                "/"
            } else {
                &record.path
            },
            record.http_version.as_deref().unwrap_or("HTTP/1.1")
        )
    };
    let headers = request_headers_for_finding(record);
    raw_message_text(start_line, &headers, &record.request.body_preview)
}

fn request_headers_for_finding(record: &TransactionRecord) -> Vec<crate::model::HeaderRecord> {
    let mut headers = Vec::new();
    if request_finding_synthesizes_host(record) {
        headers.push(crate::model::HeaderRecord {
            name: "Host".to_string(),
            value: record.host.clone(),
        });
    }
    headers.extend(record.request.headers.iter().cloned());
    headers
}

fn request_finding_synthesizes_host(record: &TransactionRecord) -> bool {
    !record.host.trim().is_empty()
        && !record
            .request
            .headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("host"))
}

fn raw_response_text_for_finding(record: &TransactionRecord) -> Option<String> {
    let response = record.response.as_ref()?;
    let start_line = format!(
        "{} {}",
        record
            .response_http_version
            .as_deref()
            .or(record.http_version.as_deref())
            .unwrap_or("HTTP/1.1"),
        record.status.unwrap_or(0)
    );
    Some(raw_message_text(
        start_line,
        &response.headers,
        &response.body_preview,
    ))
}

fn raw_message_text(
    start_line: String,
    headers: &[crate::model::HeaderRecord],
    body: &str,
) -> String {
    let mut text = start_line;
    for header in headers {
        text.push('\n');
        text.push_str(&header.name);
        text.push_str(": ");
        text.push_str(&header.value);
    }
    if !body.is_empty() {
        text.push_str("\n\n");
        text.push_str(body);
    }
    text
}

fn finding_evidence_query(evidence: &str, finding: &ScannerFinding) -> Option<String> {
    let keywords = finding_location_keywords(finding);
    let line = evidence
        .lines()
        .map(str::trim)
        .find(|line| {
            let line_lower = line.to_ascii_lowercase();
            line.len() >= 3
                && keywords
                    .iter()
                    .any(|keyword| line_lower.contains(keyword.trim_end_matches(':')))
        })
        .or_else(|| evidence.lines().map(str::trim).find(|line| line.len() >= 3))?;
    let line = line.trim_end_matches("...").trim();
    (line.len() >= 3).then(|| line.to_string())
}

fn line_number_for_query(text: &str, query: &str) -> Option<usize> {
    let needle = query.trim();
    if needle.len() < 3 {
        return None;
    }
    let haystack = text.to_ascii_lowercase();
    let needle = needle.to_ascii_lowercase();
    let index = haystack.find(&needle)?;
    Some(text[..index].bytes().filter(|byte| *byte == b'\n').count() + 1)
}

fn location_for_line(record: &TransactionRecord, side: &str, line: usize) -> FindingLocation {
    let header_count = if side == "request" {
        record.request.headers.len() + usize::from(request_finding_synthesizes_host(record))
    } else {
        record
            .response
            .as_ref()
            .map(|response| response.headers.len())
            .unwrap_or(0)
    };
    let section = if line == 1 {
        "start_line"
    } else if line <= header_count + 1 {
        "header"
    } else {
        "body"
    };
    FindingLocation {
        side: side.to_string(),
        section: section.to_string(),
        line: Some(line),
    }
}

fn finding_location_keywords(finding: &ScannerFinding) -> Vec<&'static str> {
    let title = finding.title.to_ascii_lowercase();
    let mut keywords = Vec::new();
    if title.contains("content-security-policy") {
        keywords.push("content-security-policy:");
    }
    if title.contains("strict-transport-security") {
        keywords.push("strict-transport-security:");
    }
    if title.contains("x-content-type-options") {
        keywords.push("x-content-type-options:");
    }
    if title.contains("x-frame-options") {
        keywords.push("x-frame-options:");
        keywords.push("frame-ancestors");
    }
    if title.contains("httponly") || title.contains("secure flag") || title.contains("samesite") {
        keywords.push("set-cookie:");
    }
    if title.contains("cors") {
        keywords.push("access-control-allow-origin:");
        keywords.push("access-control-allow-credentials:");
        keywords.push("access-control-allow-methods:");
    }
    if title.contains("server version") || title.contains("header exposed") {
        keywords.push("server:");
        keywords.push("x-powered-by:");
    }
    if title.contains("jwt") || title.contains("basic authentication") {
        keywords.push("authorization:");
        keywords.push("bearer");
    }
    if title.contains("open redirect") {
        keywords.push("location:");
    }
    if title.contains("cache-control") {
        keywords.push("cache-control:");
    }
    if title.contains("source map header") {
        keywords.push("sourcemap:");
        keywords.push("x-sourcemap:");
    }
    if title.contains("sql") {
        keywords.push("sql syntax");
        keywords.push("mysql");
        keywords.push("postgresql");
    }
    if title.contains("syntax error") {
        keywords.push("syntax error");
    }
    keywords
}

// ── Rule 1: JWT Analysis ──

fn check_jwt(record: &TransactionRecord, findings: &mut Vec<ScannerFinding>) {
    let mut jwt_sources: Vec<(&str, String)> = Vec::new();

    // Check Authorization header in request
    if let Some(auth) = record.request.header_value("authorization") {
        if let Some(token) = authorization_bearer_token(auth) {
            let token = normalize_jwt_token_candidate(token);
            if looks_like_jwt(&token) {
                jwt_sources.push(("Authorization header", token));
            }
        }
    }

    // Check cookies for JWTs
    for header in &record.request.headers {
        if header.name.eq_ignore_ascii_case("cookie") {
            for part in header.value.split(';') {
                let part = part.trim();
                if let Some((_name, value)) = part.split_once('=') {
                    let token = normalize_jwt_token_candidate(value);
                    if looks_like_jwt(&token) {
                        jwt_sources.push(("Cookie", token));
                    }
                }
            }
        }
    }

    // Check response Set-Cookie for JWTs
    if let Some(response) = &record.response {
        for header in &response.headers {
            if header.name.eq_ignore_ascii_case("set-cookie") {
                if let Some(value) = header.value.split(';').next() {
                    if let Some((_name, val)) = value.split_once('=') {
                        let token = normalize_jwt_token_candidate(val);
                        if looks_like_jwt(&token) {
                            jwt_sources.push(("Set-Cookie", token));
                        }
                    }
                }
            }
        }
    }

    // Check response body for JWTs (skip binary bodies)
    if let Some(response) = &record.response {
        if !is_binary_body(response) {
            let body = &response.body_preview;
            for token in extract_jwt_from_text(body) {
                jwt_sources.push(("Response body", token));
            }
        }
    }

    for (source, token) in jwt_sources {
        analyze_jwt(record, findings, source, &token);
    }
}

fn looks_like_jwt(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    // Each part should be valid base64url, and the first a JOSE header: any
    // three dotted words passed before, so a BIG-IP cookie
    // (`1677787402.20480.0000`) read as a session token.
    parts[0..2].iter().all(|part| is_non_empty_base64url(part))
        && parts[2]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=')
        && decode_jwt_part(parts[0]).is_some_and(|header| jwt_alg_from_header(&header).is_some())
}

fn normalize_jwt_token_candidate(value: &str) -> String {
    let trimmed = value.trim().trim_matches(|ch| ch == '"' || ch == '\'');
    percent_decode(trimmed)
        .trim()
        .trim_matches(|ch| ch == '"' || ch == '\'')
        .to_string()
}

fn authorization_bearer_token(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    let (scheme, token) = trimmed.split_once(char::is_whitespace)?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then_some(token.trim())
        .filter(|token| !token.is_empty())
}

fn is_non_empty_base64url(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=')
}

fn extract_jwt_from_text(text: &str) -> Vec<String> {
    // Simple pattern: JWT-looking base64url segments with a JSON-looking header.
    let re = Regex::new(r"eyJ[A-Za-z0-9_-]*(?:\.|%2[eE])[A-Za-z0-9_-]+(?:\.|%2[eE])[A-Za-z0-9_-]*")
        .unwrap();
    re.find_iter(text)
        .filter(|m| jwt_body_match_has_token_context(text, m))
        .map(|m| normalize_jwt_token_candidate(m.as_str()))
        .filter(|token| looks_like_jwt(token))
        .collect()
}

fn jwt_body_match_has_token_context(text: &str, m: &regex::Match<'_>) -> bool {
    let start = previous_char_boundary(text, m.start().saturating_sub(96));
    let context = text[start..m.start()].to_ascii_lowercase();
    [
        "token",
        "jwt",
        "authorization",
        "bearer",
        "session",
        "access",
        "refresh",
        "id_token",
        "auth",
    ]
    .iter()
    .any(|needle| context.contains(needle))
}

fn decode_jwt_part(part: &str) -> Option<String> {
    // JWT uses base64url encoding (no padding)
    let padded = match part.len() % 4 {
        2 => format!("{part}=="),
        3 => format!("{part}="),
        _ => part.to_string(),
    };
    let decoded = STANDARD
        .decode(padded.replace('-', "+").replace('_', "/"))
        .ok()?;
    String::from_utf8(decoded).ok()
}

fn analyze_jwt(
    record: &TransactionRecord,
    findings: &mut Vec<ScannerFinding>,
    source: &str,
    token: &str,
) {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return;
    }

    let header_json = match decode_jwt_part(parts[0]) {
        Some(json) => json,
        None => return,
    };
    let Some(payload_json) = decode_jwt_part(parts[1]) else {
        return;
    };

    let Some(jwt_alg) = jwt_alg_from_header(&header_json) else {
        return;
    };
    let Ok(payload) = serde_json::from_str::<serde_json::Value>(&payload_json) else {
        return;
    };

    // Check alg:none
    if jwt_alg == "none" {
        findings.push(make_finding(
            record,
            Severity::High,
            "jwt",
            "JWT with alg:none",
            format!("JWT token in {source} uses algorithm \"none\", which means no signature verification. This is a critical vulnerability if the server accepts this token."),
            truncate_evidence(token, 120),
        ));
    }

    // Check expiration
    if payload.get("exp").is_none() {
        findings.push(make_finding(
            record,
            Severity::Medium,
            "jwt",
            "JWT without expiration",
            format!("JWT token in {source} has no 'exp' claim, so it does not declare an expiration time. Server-side session expiry, revocation, or other validation may still limit its lifetime; this capture does not establish indefinite reuse."),
            truncate_evidence(token, 120),
        ));
    }
}

fn jwt_alg_from_header(header_json: &str) -> Option<String> {
    let header = serde_json::from_str::<serde_json::Value>(header_json).ok()?;
    header
        .get("alg")?
        .as_str()
        .map(|alg| alg.to_ascii_lowercase())
}

// ── Rule 2: Security Headers ──

fn check_security_headers(record: &TransactionRecord, findings: &mut Vec<ScannerFinding>) {
    let response = match &record.response {
        Some(r) => r,
        None => return,
    };

    let header_value = |name: &str| -> Option<&str> {
        response
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    };

    // Only documents a browser navigates to or frames: browsers act on these
    // headers there, not on the scripts, images, API answers and fragments a
    // page loads. Checking every HTTPS answer for HSTS listed every CDN, API
    // and tracker host the pages used.
    let document = match crate::service_map::request_kind(record) {
        "navigation" | "frame" => true,
        // Neither Sec-Fetch-Dest nor a type to go by.
        "other" => is_html_page_response(response),
        _ => false,
    };
    if !document {
        return;
    }

    // Redirects too: an apex that only redirects to `www` still needs HSTS, or
    // the first visit to it can be downgraded. RFC 6797 excludes IP literals
    // from HSTS hosts; their missing header is not an actionable HSTS finding.
    if record.scheme.eq_ignore_ascii_case("https")
        && !host_is_ip_literal(&record.host)
        && matches!(record.status, Some(200..=399))
        && !header_value("strict-transport-security").is_some_and(valid_hsts_header_value)
    {
        findings.push(make_finding(
            record,
            Severity::Low,
            "header",
            "Missing Strict-Transport-Security",
            "HTTPS response lacks HSTS header. Browsers may allow HTTP downgrade attacks.",
            "",
        ));
    }

    // Error pages and fallback HTML snippets create noisy checklist findings.
    if !is_success_html_page_response(record, response) {
        return;
    }

    if header_value("content-security-policy").is_none_or(|value| value.trim().is_empty()) {
        findings.push(make_finding(
            record,
            Severity::Low,
            "header",
            "Missing Content-Security-Policy",
            "No CSP header found. CSP helps prevent XSS and data injection attacks.",
            "",
        ));
    }

    if !header_value("x-content-type-options")
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("nosniff"))
    {
        findings.push(make_finding(
            record,
            Severity::Info,
            "header",
            "Missing X-Content-Type-Options",
            "No X-Content-Type-Options: nosniff header. Browsers may MIME-sniff the response.",
            "",
        ));
    }

    if !header_value("x-frame-options").is_some_and(valid_x_frame_options_value)
        && !has_csp_frame_ancestors(response)
    {
        findings.push(make_finding(
            record,
            Severity::Low,
            "header",
            "Missing X-Frame-Options",
            "No X-Frame-Options or CSP frame-ancestors. Page may be framed for clickjacking.",
            "",
        ));
    }
}

fn host_is_ip_literal(host: &str) -> bool {
    // Stored hosts can also retain an authority's explicit port.
    host.parse::<std::net::IpAddr>().is_ok()
        || host.parse::<std::net::SocketAddr>().is_ok()
        || host
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .is_some_and(|value| value.parse::<std::net::Ipv6Addr>().is_ok())
}

fn valid_hsts_header_value(value: &str) -> bool {
    value.split(';').any(|directive| {
        let Some((name, value)) = directive.trim().split_once('=') else {
            return false;
        };
        name.trim().eq_ignore_ascii_case("max-age")
            && value.trim().parse::<u64>().is_ok_and(|max_age| max_age > 0)
    })
}

fn valid_x_frame_options_value(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "deny" | "sameorigin"
    )
}

fn has_csp_frame_ancestors(response: &crate::model::MessageRecord) -> bool {
    response.headers.iter().any(|h| {
        if !h.name.eq_ignore_ascii_case("content-security-policy") {
            return false;
        }
        h.value.split(';').any(|directive| {
            let mut tokens = directive.split_whitespace();
            matches!(tokens.next(), Some(name) if name.eq_ignore_ascii_case("frame-ancestors"))
                && tokens.next().is_some()
        })
    })
}

fn is_html_page_response(response: &crate::model::MessageRecord) -> bool {
    if let Some(content_type) = response.content_type.as_deref() {
        let ct = content_type.trim();
        if !ct.is_empty() {
            return ct.to_ascii_lowercase().contains("text/html");
        }
    }

    if !matches!(response.body_encoding, BodyEncoding::Utf8) {
        return false;
    }

    let body = response.body_preview.trim_start().to_ascii_lowercase();
    body.starts_with("<!doctype html")
        || body.starts_with("<html")
        || body.contains("<head")
        || body.contains("<body")
}

fn is_success_html_page_response(
    record: &TransactionRecord,
    response: &crate::model::MessageRecord,
) -> bool {
    matches!(record.status, Some(200..=299)) && is_html_page_response(response)
}

// ── Rule 3: Cookie Flags ──

fn check_cookie_flags(record: &TransactionRecord, findings: &mut Vec<ScannerFinding>) {
    let response = match &record.response {
        Some(r) => r,
        None => return,
    };

    for header in &response.headers {
        if !header.name.eq_ignore_ascii_case("set-cookie") {
            continue;
        }

        if set_cookie_is_deletion(&header.value) {
            continue;
        }

        let Some((cookie_name, cookie_value)) = set_cookie_name_value(&header.value) else {
            continue;
        };
        if !cookie_requires_security_flags(cookie_name, cookie_value) {
            continue;
        }
        let attributes = cookie_attribute_names(&header.value);

        if !attributes.contains("httponly") {
            findings.push(make_finding(
                record,
                Severity::Medium,
                "cookie",
                format!("Cookie '{cookie_name}' missing HttpOnly flag"),
                "Cookie accessible via JavaScript. If XSS exists, attacker can steal this cookie.",
                &header.value,
            ));
        }

        if !attributes.contains("secure") && record.scheme == "https" {
            findings.push(make_finding(
                record,
                Severity::Medium,
                "cookie",
                format!("Cookie '{cookie_name}' missing Secure flag"),
                "Cookie may be sent over unencrypted HTTP connections, exposing it to interception.",
                &header.value,
            ));
        }

        if !attributes.contains("samesite") {
            findings.push(make_finding(
                record,
                Severity::Low,
                "cookie",
                format!("Cookie '{cookie_name}' missing SameSite attribute"),
                "No SameSite attribute. Cookie may be sent in cross-site requests (CSRF risk).",
                &header.value,
            ));
        }
    }
}

fn cookie_attribute_names(value: &str) -> HashSet<String> {
    value
        .split(';')
        .skip(1)
        .filter_map(|attribute| attribute.trim().split('=').next())
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect()
}

fn set_cookie_name_value(value: &str) -> Option<(&str, &str)> {
    let pair = value.split(';').next()?.trim();
    let (name, value) = pair.split_once('=')?;
    let name = name.trim();
    let value = value.trim().trim_matches('"');
    if name.is_empty()
        || name.eq_ignore_ascii_case("null")
        || value.is_empty()
        || value.eq_ignore_ascii_case("null")
    {
        return None;
    }
    Some((name, value))
}

fn cookie_requires_security_flags(name: &str, value: &str) -> bool {
    cookie_looks_auth_sensitive(name, value)
}

fn cookie_looks_auth_sensitive(name: &str, value: &str) -> bool {
    let value = value.trim().trim_matches('"');
    if value.is_empty() || value.eq_ignore_ascii_case("null") {
        return false;
    }
    if !is_auth_cookie_name(name) && !looks_like_jwt(&normalize_jwt_token_candidate(value)) {
        return false;
    }
    // Use the same known analytics-cookie exclusion for cache checks as for
    // cookie flags. Their session identifiers do not authenticate this user.
    if crate::service_map_servers::detect_header("set-cookie", &format!("{name}={value}"))
        .iter()
        .any(|detection| detection.category == crate::service_map_libraries::ANALYTICS)
    {
        return false;
    }
    true
}

fn set_cookie_is_deletion(value: &str) -> bool {
    if set_cookie_attribute_value(value, "max-age")
        .and_then(|max_age| max_age.trim().parse::<i64>().ok())
        .is_some_and(|max_age| max_age <= 0)
    {
        return true;
    }

    set_cookie_attribute_value(value, "expires")
        .and_then(|expires| DateTime::parse_from_rfc2822(expires.trim()).ok())
        .is_some_and(|expires| expires.with_timezone(&Utc) <= Utc::now())
}

fn set_cookie_attribute_value<'a>(value: &'a str, name: &str) -> Option<&'a str> {
    value.split(';').skip(1).find_map(|attribute| {
        let (attribute_name, attribute_value) = attribute.trim().split_once('=')?;
        attribute_name
            .trim()
            .eq_ignore_ascii_case(name)
            .then_some(attribute_value.trim())
    })
}

// ── Rule 4: Sensitive Data Exposure ──

fn check_sensitive_data(record: &TransactionRecord, findings: &mut Vec<ScannerFinding>) {
    let response = match &record.response {
        Some(r) => r,
        None => return,
    };

    // Skip binary bodies — regex hits on base64-encoded images/fonts are false positives
    if is_binary_body(response) {
        return;
    }

    let body = &response.body_preview;
    if body.is_empty() {
        return;
    }
    let script = javascript_or_css_response(record, response);
    let page = response
        .header_value("content-type")
        .or(response.content_type.as_deref())
        .is_some_and(|value| value.to_ascii_lowercase().contains("html"));

    static PATTERNS: &[(&str, &str, Severity)] = &[
        // ── Cloud provider secrets ──
        (
            r#"(?i)\b(aws_secret_access_key|aws_secret)\b["']?\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}"#,
            "AWS Secret Access Key",
            Severity::High,
        ),
        // ── AI / ML tokens ──
        (
            r"sk-proj-[A-Za-z0-9_-]{74,}",
            "OpenAI Project API Key",
            Severity::Critical,
        ),
        (
            r"sk-svcacct-[A-Za-z0-9_-]{74,}",
            "OpenAI Service Account Key",
            Severity::Critical,
        ),
        (
            r"sk-ant-api03-[a-zA-Z0-9_\-]{93}",
            "Anthropic API Key",
            Severity::Critical,
        ),
        (
            r"sk-ant-admin01-[a-zA-Z0-9_\-]{80,}",
            "Anthropic Admin Key",
            Severity::Critical,
        ),
        (
            r"\bhf_[a-zA-Z0-9]{34}\b",
            "HuggingFace Token",
            Severity::High,
        ),
        (r"gsk_[a-zA-Z0-9]{48}", "Groq API Key", Severity::Critical),
        (
            r"pplx-[a-zA-Z0-9]{48}",
            "Perplexity API Key",
            Severity::Critical,
        ),
        (
            r"xai-[a-zA-Z0-9]{20,}",
            "xAI (Grok) API Key",
            Severity::Critical,
        ),
        (r"r8_[a-zA-Z0-9]{38}", "Replicate API Token", Severity::High),
        // ── VCS / DevOps tokens ──
        (
            r"ghp_[A-Za-z0-9]{36}",
            "GitHub Personal Access Token",
            Severity::High,
        ),
        (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth Token", Severity::High),
        (r"ghs_[A-Za-z0-9]{36}", "GitHub App Token", Severity::High),
        (
            r"ghr_[A-Za-z0-9]{36}",
            "GitHub Refresh Token",
            Severity::High,
        ),
        (
            r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}",
            "GitHub Fine-Grained PAT",
            Severity::High,
        ),
        (
            r"glpat-[A-Za-z0-9\-]{20,}",
            "GitLab Personal Access Token",
            Severity::High,
        ),
        (
            r"\b(?:glrt|glrtr|gloas|gldt|glcbt|glptt|glft|glimt|glagent|glwt|glsoat|glffct)-[A-Za-z0-9_\-]{20,}",
            "GitLab Token",
            Severity::High,
        ),
        (
            r"ATATT3[A-Za-z0-9_\-=]{100,}",
            "Atlassian/Jira API Token",
            Severity::High,
        ),
        (r"dop_v1_[a-f0-9]{64}", "DigitalOcean PAT", Severity::High),
        (r"dapi[a-f0-9]{32}", "Databricks API Token", Severity::High),
        (
            r"LTAI[a-z0-9]{20}",
            "Alibaba Cloud Access Key",
            Severity::High,
        ),
        (
            r"dckr_pat_[a-zA-Z0-9_-]{20,}",
            "Docker Hub PAT",
            Severity::High,
        ),
        (
            r"pscale_tkn_[a-zA-Z0-9_=-]{32,}",
            "PlanetScale Token",
            Severity::High,
        ),
        (r"sbp_[a-f0-9]{40,}", "Supabase PAT", Severity::High),
        (
            r"dt0c01\.[a-z0-9]{24}\.[a-z0-9]{64}",
            "Dynatrace API Token",
            Severity::High,
        ),
        (r"pul-[a-f0-9]{40}", "Pulumi API Token", Severity::High),
        (
            r"AKCp[A-Za-z0-9]{69}",
            "JFrog Artifactory Token",
            Severity::High,
        ),
        (r"ntn_[a-zA-Z0-9]{40,}", "Notion API Token", Severity::High),
        (r"figd_[a-zA-Z0-9_-]{40,}", "Figma PAT", Severity::High),
        (
            r"EAA[MC][a-zA-Z0-9]{100,}",
            "Facebook Page Access Token",
            Severity::High,
        ),
        // ── Chat / SaaS tokens ──
        (
            r"xox[bpras]-[A-Za-z0-9\-]{10,}",
            "Slack Token",
            Severity::High,
        ),
        (
            r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+",
            "Slack Webhook URL",
            Severity::High,
        ),
        // ── Generic secrets ──
        (
            r#"(?i)\b(?:api[_-]?key|apikey|api[_-]?secret)\b["']?\s*[:=]\s*["']?([A-Za-z0-9_\-]{20,})"#,
            "API Key/Secret pattern",
            Severity::Medium,
        ),
        // Only with key material after the header, as the map reads it: a PEM
        // parser in a script carries the bare header as a constant.
        (
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----(?:\\[rn]|\s)*[A-Za-z0-9+/]{40}",
            "Private Key",
            Severity::High,
        ),
        (
            r#"(?i)(?:\b|[_-])(?:password|passwd|pwd)\b\s*["']?\s*[:=]\s*(?:"([^"]{4,})"|'([^']{4,})'|([^\s"'<>{}]{4,}))"#,
            "Password in response",
            Severity::High,
        ),
        (
            r#"(?i)\b(?:secret[_-]?key|client[_-]?secret|auth[_-]?token|access[_-]?token)\b["']?\s*[:=]\s*["']?([A-Za-z0-9_\-/+=]{16,})"#,
            "Secret/Token pattern",
            Severity::Medium,
        ),
        // ── Payment / SaaS tokens ──
        (
            r"sk_live_[0-9a-zA-Z]{24,}",
            "Stripe Secret Key",
            Severity::Critical,
        ),
        (
            r"rk_live_[0-9a-zA-Z]{24,}",
            "Stripe Restricted Key",
            Severity::High,
        ),
        (
            r"sq0[a-z]{3}-[0-9A-Za-z\-_]{22,}",
            "Square Access Token",
            Severity::High,
        ),
        (
            r"shpat_[a-fA-F0-9]{32}",
            "Shopify Admin Token",
            Severity::High,
        ),
        (
            r"shpss_[a-fA-F0-9]{32}",
            "Shopify Shared Secret",
            Severity::High,
        ),
        // ── Communication / Messaging tokens ──
        (
            r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
            "SendGrid API Key",
            Severity::High,
        ),
        (r"key-[0-9a-zA-Z]{32}", "Mailgun API Key", Severity::High),
        (
            r"[0-9]+:AA[A-Za-z0-9_-]{33}",
            "Telegram Bot Token",
            Severity::High,
        ),
        (
            r"[MN][A-Za-z0-9]{23}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}",
            "Discord Bot Token",
            Severity::High,
        ),
        (
            r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+",
            "Discord Webhook URL",
            Severity::High,
        ),
        // ── Infrastructure / DevOps secrets ──
        (
            r"hvs\.[a-zA-Z0-9_-]{90,}",
            "Hashicorp Vault Token",
            Severity::High,
        ),
        (r"dp\.pt\.[a-z0-9]{43}", "Doppler API Token", Severity::High),
        (r"lin_api_[a-zA-Z0-9]{40}", "Linear API Key", Severity::High),
        // ── Monitoring / Observability ──
        (
            r"NRAK-[A-Z0-9]{27}",
            "New Relic User API Key",
            Severity::High,
        ),
        (
            r"NRII-[a-zA-Z0-9]{32}",
            "New Relic Insert Key",
            Severity::High,
        ),
        (
            r"glc_[A-Za-z0-9+/]{32,}",
            "Grafana Cloud Token",
            Severity::High,
        ),
        (
            r"glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}",
            "Grafana Service Account Token",
            Severity::High,
        ),
        // ── Database connection strings ──
        (
            r#"mongodb(?:\+srv)?://[^\s'"]{10,}"#,
            "MongoDB connection string",
            Severity::High,
        ),
        (
            r#"postgres(?:ql)?://[^\s'"]{10,}"#,
            "PostgreSQL connection string",
            Severity::High,
        ),
        (
            r#"mysql://[^\s'"]{10,}"#,
            "MySQL connection string",
            Severity::High,
        ),
        (
            r#"redis://[^\s'"]{10,}"#,
            "Redis connection string",
            Severity::High,
        ),
        // ── Package registry tokens ──
        (r"npm_[A-Za-z0-9]{36}", "npm Access Token", Severity::High),
        (r"pypi-[A-Za-z0-9_-]{50,}", "PyPI API Token", Severity::High),
        // ── Cloud / Infrastructure ──
        (
            r"(?i)heroku[a-z0-9_ .\-,]{0,25}[=:]\s*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "Heroku API Key",
            Severity::High,
        ),
        (
            r"(?i)(?:AccountKey|SharedAccessKey)\s*=\s*[A-Za-z0-9+/=]{40,}",
            "Azure Storage/SAS Key",
            Severity::High,
        ),
        // ── Sensitive file paths ──
        (
            r"(?i)/\.(?:env|git|svn|htpasswd|htaccess|DS_Store|aws/credentials|npmrc|dockerenv)\b",
            "Sensitive file path exposed",
            Severity::Medium,
        ),
        // ── Credit card patterns (basic) ──
        (
            r"\b4[0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b",
            "Possible Visa card number",
            Severity::High,
        ),
        (
            r"\b5[1-5][0-9]{2}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b",
            "Possible Mastercard number",
            Severity::High,
        ),
    ];

    for &(pattern, label, ref severity) in PATTERNS {
        if let Ok(re) = Regex::new(pattern) {
            if label == "Password in response" {
                if let Some(span) = password_response_match(body, script, &re) {
                    let mut finding = make_finding(
                        record,
                        severity.clone(),
                        "disclosure",
                        format!("{label} detected in response"),
                        format!("{label} found in response body. This may expose sensitive information to clients."),
                        truncate_evidence(&body[span.clone()], 80),
                    );
                    let line = response.headers.len()
                        + 3
                        + body[..span.start]
                            .bytes()
                            .filter(|byte| *byte == b'\n')
                            .count();
                    finding.location = Some(location_for_line(record, "response", line));
                    findings.push(finding);
                }
                continue;
            }
            for captures in re.captures_iter(body) {
                let Some(m) = captures.get(0) else {
                    continue;
                };
                if is_generic_secret_label(label)
                    && !generic_secret_candidate_looks_like_secret(&captures)
                {
                    continue;
                }
                // A page or a script hands its SDK keys to every visitor; there
                // only a key named a secret is worth a finding.
                if label == "API Key/Secret pattern"
                    && (script || page)
                    && !body[m.start()..captures.get(1).map_or(m.end(), |value| value.start())]
                        .to_ascii_lowercase()
                        .contains("secret")
                {
                    continue;
                }
                // A script's sixteen digits are an ID or a test number.
                if is_card_number_label(label)
                    && (script
                        || !luhn_valid(m.as_str())
                        || card_number_is_known_test(m.as_str())
                        || !card_number_match_has_payment_context(body, &m)
                        // The head of a UUID: `41234567-1234-1234-…`.
                        || body[m.end()..].starts_with('-')
                        || body[..m.start()].ends_with('-'))
                {
                    continue;
                }
                if is_database_connection_label(label)
                    && !database_connection_string_has_credentials(m.as_str())
                {
                    continue;
                }
                // A real token mixes cases and digits; a run of letters after
                // `EAA` is a minified identifier or part of a blob.
                if label == "Facebook Page Access Token"
                    && !token_mixes_cases_and_digits(m.as_str())
                {
                    continue;
                }
                if label == "Mailgun API Key" && !mailgun_key_match_has_context(body, &m) {
                    continue;
                }
                if label == "Replicate API Token" && !replicate_token_has_boundaries(body, &m) {
                    continue;
                }
                if label == "Sensitive file path exposed"
                    && sensitive_file_path_match_is_template(body, &m)
                {
                    continue;
                }
                // Skip matches embedded inside base64 strings (false positives from
                // base64-encoded ad payloads, tracking pixels, etc. in JSON responses)
                if is_embedded_in_base64(body, &m) {
                    continue;
                }
                let mut finding = make_finding(
                    record,
                    severity.clone(),
                    "disclosure",
                    format!("{label} detected in response"),
                    format!("{label} found in response body. This may expose sensitive information to clients."),
                    truncate_evidence(m.as_str(), 80),
                );
                if label == "Replicate API Token" {
                    // The same value may occur earlier inside a rejected opaque
                    // identifier or header. Navigate to this accepted body match.
                    let line = response.headers.len()
                        + 3
                        + body[..m.start()]
                            .bytes()
                            .filter(|byte| *byte == b'\n')
                            .count();
                    finding.location = Some(location_for_line(record, "response", line));
                }
                findings.push(finding);
                break;
            }
        }
    }

    check_internal_ip_disclosure(record, body, findings);
}

// A supported token can occur inside a longer URL-safe opaque identifier.
// Inspect adjacent bytes without consuming delimiters or slicing UTF-8. Unicode
// prose remains a delimiter; ASCII hyphens conservatively count as continuation,
// even when a genuine token happens to touch hyphen punctuation.
fn replicate_token_has_boundaries(body: &str, m: &regex::Match<'_>) -> bool {
    let bytes = body.as_bytes();
    let adjacent = [
        m.start().checked_sub(1).and_then(|index| bytes.get(index)),
        bytes.get(m.end()),
    ];
    !adjacent
        .into_iter()
        .flatten()
        .any(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-'))
}

fn check_internal_ip_disclosure(
    record: &TransactionRecord,
    body: &str,
    findings: &mut Vec<ScannerFinding>,
) {
    let re = Regex::new(r"\b(?:10\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)|172\.(?:1[6-9]|2\d|3[01])\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)|192\.168\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d))\b").unwrap();
    for m in re.find_iter(body) {
        if is_embedded_in_base64(body, &m) || !internal_ip_match_has_network_context(body, &m) {
            continue;
        }
        findings.push(make_finding(
            record,
            Severity::Low,
            "disclosure",
            "Internal IP address detected in response",
            "Internal IP address found in response body. This may expose sensitive information to clients.",
            truncate_evidence(m.as_str(), 80),
        ));
        break;
    }
}

fn internal_ip_match_has_network_context(body: &str, m: &regex::Match<'_>) -> bool {
    let before_start = previous_char_boundary(body, m.start().saturating_sub(96));
    let after_end = next_char_boundary(body, (m.end() + 32).min(body.len()));
    let before = body[before_start..m.start()].to_ascii_lowercase();
    let after = body[m.end()..after_end].to_ascii_lowercase();

    internal_ip_looks_like_url_endpoint(&before, &after)
        || internal_ip_has_labeled_network_context(&before)
}

fn internal_ip_looks_like_url_endpoint(before: &str, after: &str) -> bool {
    let before =
        before.trim_end_matches(|ch: char| ch.is_ascii_whitespace() || ch == '"' || ch == '\'');
    let after = after.trim_start();
    let has_url_prefix = ["http://", "https://", "ws://", "wss://", "ftp://", "//"]
        .iter()
        .any(|prefix| before.ends_with(prefix));
    if has_url_prefix {
        return true;
    }

    if let Some(rest) = after.strip_prefix(':') {
        return rest.chars().next().is_some_and(|ch| ch.is_ascii_digit());
    }
    after.starts_with('/') || after.starts_with('?')
}

fn internal_ip_has_labeled_network_context(before: &str) -> bool {
    let tokens = before
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'))
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    let recent = tokens.iter().rev().take(8).copied().collect::<Vec<_>>();
    if recent.iter().any(|token| {
        matches!(
            *token,
            "ip" | "addr"
                | "address"
                | "host"
                | "hostname"
                | "upstream"
                | "backend"
                | "proxy"
                | "gateway"
                | "endpoint"
                | "origin"
                | "dns"
                | "resolver"
                | "forwarded"
                | "remote"
                | "local"
                | "internal"
                | "private"
                | "intranet"
                | "listen"
                | "bind"
                | "target"
        )
    }) {
        return true;
    }

    let compact = recent
        .iter()
        .rev()
        .flat_map(|token| token.chars().filter(|ch| ch.is_ascii_alphanumeric()))
        .collect::<String>();
    [
        "internalip",
        "privateip",
        "ipaddress",
        "hostaddress",
        "serverip",
        "proxyip",
        "backendip",
        "upstreamip",
        "gatewayip",
        "remoteaddr",
        "localaddr",
    ]
    .iter()
    .any(|needle| compact.contains(needle))
}

fn captured_secret_value<'a>(captures: &regex::Captures<'a>) -> Option<&'a str> {
    captures
        .iter()
        .skip(1)
        .flatten()
        .map(|capture| capture.as_str().trim())
        .find(|value| !value.is_empty())
}

fn token_mixes_cases_and_digits(token: &str) -> bool {
    let body = token.get(4..).unwrap_or("");
    body.bytes().filter(u8::is_ascii_digit).count() >= 4
        && body.bytes().any(|byte| byte.is_ascii_uppercase())
        && body.bytes().any(|byte| byte.is_ascii_lowercase())
}

// Keep the old accepted candidates as a compatibility floor. Completing a
// quoted prefix can expose a suffix rejected by existing heuristics; that must
// improve evidence, not silently remove an already reported finding.
fn password_response_match(
    body: &str,
    script: bool,
    legacy: &Regex,
) -> Option<std::ops::Range<usize>> {
    let legacy_match = legacy.captures_iter(body).find_map(|captures| {
        let m = captures.get(0)?;
        if !password_candidate_looks_like_secret(&captures, script)
            || is_embedded_in_base64(body, &m)
        {
            return None;
        }
        let end = captures
            .get(1)
            .or(captures.get(2))
            .and_then(|value| password_quoted_end(body, value.start() - 1))
            .unwrap_or(m.end());
        Some(m.start()..end)
    });

    // Discover keys independently: a rejected or malformed earlier literal
    // must not consume a later key. Only quoted candidates are supplemented;
    // the unquoted signature and its filtering remain on the legacy path.
    let heads = Regex::new(r#"(?i)(?:\b|[_-])(?:password|passwd|pwd)\b\s*["']?\s*[:=]\s*["']"#)
        .expect("valid password key pattern");
    for head in heads.find_iter(body) {
        if legacy_match
            .as_ref()
            .is_some_and(|span| head.start() >= span.start)
        {
            break;
        }
        let Some(end) = password_quoted_end(body, head.end() - 1) else {
            continue;
        };
        let value = &body[head.end()..end - 1];
        // Preserve the regex's four raw Unicode scalars, then the existing
        // heuristic's eight raw UTF-8 bytes. Do not decode any escape spelling.
        if value.chars().take(4).count() == 4
            && password_value_looks_like_secret(value, true, script)
            && !is_span_embedded_in_base64(body, head.start(), end)
        {
            return Some(head.start()..end);
        }
    }
    legacy_match
}

// ASCII quote/backslash offsets are always UTF-8 boundaries. Each discovered
// opening quote follows ':'/'='/whitespace and is therefore unescaped. For
// either quote kind its next closing quote is no later than the next opener of
// that kind, so scans (including rejected/unterminated candidates) total O(n),
// rather than repeatedly scanning an unclosed suffix. No source is decoded.
fn password_quoted_end(body: &str, opening: usize) -> Option<usize> {
    let quote = body.as_bytes()[opening];
    let mut escaped = false;
    for (offset, &byte) in body.as_bytes()[opening + 1..].iter().enumerate() {
        if byte == quote && !escaped {
            return Some(opening + offset + 2);
        }
        escaped = byte == b'\\' && !escaped;
    }
    None
}

fn password_candidate_looks_like_secret(captures: &regex::Captures<'_>, script: bool) -> bool {
    let Some(value) = captured_secret_value(captures) else {
        return false;
    };
    let quoted = captures.get(1).or(captures.get(2)).is_some();
    password_value_looks_like_secret(value, quoted, script)
}

fn password_value_looks_like_secret(value: &str, quoted: bool, script: bool) -> bool {
    let value = value.trim();
    if value.len() < 8 {
        return false;
    }
    // Code, not a value: in a script anything unquoted (`e.password,text:…`);
    // anywhere an unquoted flag, comparison or call (`!0`, `==e.type`, `f(x)`),
    // or a quote closing a string before a concatenation (`"pw: "+e.pw`).
    if value.starts_with('+')
        || (!quoted && (script || value.starts_with(['!', '=']) || value.contains('(')))
    {
        return false;
    }
    // A label shown to users: words with spaces, or another script's letters
    // ("비밀번호"); a template variable (`%pass%`, `{{pass}}`, `${pass}`), a
    // selector (`[name=pw]`), a regex, a path or a URL; and a value naming the
    // field (`user_password`, the autocomplete token `new-password`).
    let lower = value.to_ascii_lowercase();
    let wrapped = |open: &str, close: &str| value.starts_with(open) && value.ends_with(close);
    if value.contains(char::is_whitespace)
        || value.chars().any(|ch| ch.is_alphabetic() && !ch.is_ascii())
        || wrapped("%", "%")
        || wrapped("{{", "}}")
        || wrapped("${", "}")
        || wrapped("<", ">")
        || wrapped("[", "]")
        || value.starts_with('/')
        || value.contains("://")
        || lower.contains("password")
        || lower.contains("passwd")
    {
        return false;
    }
    // A script's word is an identifier or a message key, not a password.
    if script
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphabetic() || ch == '_' || ch == '-')
    {
        return false;
    }

    if secret_candidate_is_masked(value) || secret_candidate_is_placeholder(value) {
        return false;
    }

    let normalized = normalize_secret_candidate(value);
    if normalized.is_empty() {
        return false;
    }
    if normalized == "password" || normalized == "passwd" {
        return false;
    }

    let collapsed = normalized.split_whitespace().collect::<Vec<_>>().join(" ");
    let validation_phrases = [
        "password is ",
        "password must ",
        "password cannot ",
        "password should ",
        "password do ",
        "password does ",
        "please ",
        "enter ",
        "confirm ",
        "at least ",
        "at most ",
        "minimum ",
        "maximum ",
        "min ",
        "max ",
        "too short",
        "too long",
        "required ",
        "invalid ",
        "missing ",
        "incorrect ",
        "wrong ",
        "authentication ",
        "login ",
        "failed ",
        "must ",
        "cannot ",
        "should ",
        "do not ",
        "don't ",
        "don’t ",
        "match ",
        "matches ",
    ];
    if validation_phrases
        .iter()
        .any(|phrase| collapsed.starts_with(phrase))
    {
        return false;
    }
    !matches!(
        collapsed.as_str(),
        "password required" | "confirm password" | "password confirmation"
    )
}

fn is_generic_secret_label(label: &str) -> bool {
    matches!(label, "API Key/Secret pattern" | "Secret/Token pattern")
}

fn generic_secret_candidate_looks_like_secret(captures: &regex::Captures<'_>) -> bool {
    let Some(value) = captured_secret_value(captures) else {
        return false;
    };
    let normalized = normalize_secret_candidate(value);
    if normalized.len() < 16 {
        return false;
    }
    if secret_candidate_is_masked(&normalized) || secret_candidate_is_placeholder(&normalized) {
        return false;
    }
    if secret_candidate_is_public_identifier(value) {
        return false;
    }
    if generic_secret_candidate_is_header_value_copy(&normalized) {
        return false;
    }
    if normalized.chars().collect::<HashSet<_>>().len() < 6 {
        return false;
    }

    let has_lower = normalized.chars().any(|ch| ch.is_ascii_lowercase());
    let has_upper = normalized.chars().any(|ch| ch.is_ascii_uppercase());
    let has_digit = normalized.chars().any(|ch| ch.is_ascii_digit());
    let has_symbol = normalized
        .chars()
        .any(|ch| matches!(ch, '_' | '-' | '/' | '+' | '='));
    let class_count = [has_lower, has_upper, has_digit, has_symbol]
        .into_iter()
        .filter(|present| *present)
        .count();

    class_count >= 2 && (has_digit || has_symbol)
}

fn generic_secret_candidate_is_header_value_copy(value: &str) -> bool {
    let compact = value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>();
    if compact.is_empty() {
        return false;
    }

    let header_marker = compact.contains("header")
        || compact.contains("authorization")
        || compact.contains("contenttype")
        || compact.contains("cookie");
    let metadata_marker = compact.contains("value")
        || compact.contains("request")
        || compact.contains("response")
        || compact.contains("example");

    header_marker && metadata_marker
}

fn normalize_secret_candidate(value: &str) -> String {
    value
        .trim()
        .trim_matches(|ch: char| matches!(ch, '"' | '\'' | '`'))
        .trim_matches(|ch: char| {
            ch.is_ascii_punctuation() && !matches!(ch, '_' | '-' | '/' | '+' | '=')
        })
        .trim()
        .to_ascii_lowercase()
}

fn secret_candidate_is_masked(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && trimmed.len() >= 4
        && trimmed
            .chars()
            .all(|ch| matches!(ch, '*' | 'x' | 'X' | '•' | '-' | '_' | '.'))
}

fn secret_candidate_is_placeholder(value: &str) -> bool {
    let normalized = normalize_secret_candidate(value);
    if normalized.is_empty() {
        return true;
    }
    if normalized
        .chars()
        .all(|ch| ch == normalized.chars().next().unwrap_or_default())
    {
        return true;
    }

    let collapsed = normalized
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("_");
    let placeholder_exact = [
        "api_key",
        "apikey",
        "access_token",
        "auth_token",
        "client_secret",
        "secret_key",
        "secret_token",
        "password",
        "passwd",
        "null",
        "none",
        "undefined",
        "true",
        "false",
        "secret",
        "token",
    ];
    let placeholder_fragments = [
        "placeholder",
        "changeme",
        "change_me",
        "replace_me",
        "example",
        "sample",
        "dummy",
        "redacted",
        "masked",
        "todo",
        "your_",
        "_here",
    ];
    placeholder_exact.contains(&collapsed.as_str())
        || placeholder_fragments
            .iter()
            .any(|fragment| collapsed.contains(fragment))
}

fn secret_candidate_is_public_identifier(value: &str) -> bool {
    let trimmed = value.trim().trim_matches(|ch: char| {
        matches!(ch, '"' | '\'' | '`') || (ch.is_ascii_punctuation() && ch != '_')
    });
    let lower = trimmed.to_ascii_lowercase();
    (trimmed.starts_with("AIza")
        && trimmed.len() == 39
        && trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'))
        || lower.starts_with("pk_live_")
        || lower.starts_with("pk_test_")
}

fn is_card_number_label(label: &str) -> bool {
    matches!(
        label,
        "Possible Visa card number" | "Possible Mastercard number"
    )
}

fn is_database_connection_label(label: &str) -> bool {
    matches!(
        label,
        "MongoDB connection string"
            | "PostgreSQL connection string"
            | "MySQL connection string"
            | "Redis connection string"
    )
}

fn database_connection_string_has_credentials(candidate: &str) -> bool {
    let Ok(url) = url::Url::parse(candidate) else {
        return false;
    };
    url.password().is_some_and(|password| {
        !password.is_empty()
            && !secret_candidate_is_masked(password)
            && !secret_candidate_is_placeholder(password)
    })
}

fn mailgun_key_match_has_context(body: &str, m: &regex::Match<'_>) -> bool {
    let start = previous_char_boundary(body, m.start().saturating_sub(96));
    let end = next_char_boundary(body, (m.end() + 64).min(body.len()));
    let context = body[start..end].to_ascii_lowercase();
    ["mailgun", "api.mailgun.net", "mg_api", "mailgun_api"]
        .iter()
        .any(|needle| context.contains(needle))
}

fn sensitive_file_path_match_is_template(body: &str, m: &regex::Match<'_>) -> bool {
    let end = next_char_boundary(body, (m.end() + 16).min(body.len()));
    let suffix = body[m.end()..end].to_ascii_lowercase();
    [".example", ".sample", ".template", ".dist"]
        .iter()
        .any(|template_suffix| suffix.starts_with(template_suffix))
}

fn card_number_match_has_payment_context(body: &str, m: &regex::Match<'_>) -> bool {
    let start = previous_char_boundary(body, m.start().saturating_sub(96));
    let end = next_char_boundary(body, (m.end() + 48).min(body.len()));
    let context = body[start..end].to_ascii_lowercase();
    [
        "card",
        "credit",
        "debit",
        "payment",
        "billing",
        "pan",
        "cc_number",
        "card_number",
        "visa",
        "mastercard",
    ]
    .iter()
    .any(|needle| context.contains(needle))
}

fn luhn_valid(candidate: &str) -> bool {
    let digits: Vec<u32> = candidate
        .chars()
        .filter(|ch| ch.is_ascii_digit())
        .filter_map(|ch| ch.to_digit(10))
        .collect();
    if digits.len() < 12 {
        return false;
    }

    let mut sum = 0u32;
    let mut double = false;
    for digit in digits.iter().rev() {
        let mut value = *digit;
        if double {
            value *= 2;
            if value > 9 {
                value -= 9;
            }
        }
        sum += value;
        double = !double;
    }
    sum.is_multiple_of(10)
}

fn card_number_is_known_test(candidate: &str) -> bool {
    let digits = candidate
        .chars()
        .filter(|ch| ch.is_ascii_digit())
        .collect::<String>();
    matches!(
        digits.as_str(),
        "4111111111111111"
            | "4242424242424242"
            | "4000000000000002"
            | "4000000000009995"
            | "5555555555554444"
            | "5105105105105100"
            | "2223003122003222"
    )
}

// ── Rule 5: CORS ──

fn check_cors(record: &TransactionRecord, findings: &mut Vec<ScannerFinding>) {
    let response = match &record.response {
        Some(r) => r,
        None => return,
    };

    // Fetch combines duplicate field lines, which cannot yield a singleton
    // ACAO origin or the exact ACAC token. Reading only the first line would
    // report browser access that the CORS check actually rejects.
    let Some(origin) = cors_single_header_value(response, "access-control-allow-origin") else {
        return;
    };
    if cors_single_header_value(response, "access-control-allow-credentials") != Some("true") {
        return;
    }

    if origin == "null" {
        findings.push(make_finding(
            record,
            Severity::Medium,
            "cors",
            "CORS: null origin with credentials",
            "Access-Control-Allow-Origin: null with Access-Control-Allow-Credentials: true can expose credentialed responses to sandboxed or file-origin contexts.",
            "ACAO: null, ACAC: true",
        ));
    } else if origin != "*" && is_serialized_cors_origin(origin) {
        let req_origin = cors_single_header_value(&record.request, "origin").unwrap_or("");
        if origin == req_origin && !origin_is_same_site(origin, &record.scheme, &record.host) {
            // One answer cannot show reflection: an allowlist answers its
            // own origins the same way. A site trusting its own hosts is
            // the usual setup and is left out above.
            findings.push(make_finding(
                record,
                Severity::Low,
                "cors",
                "CORS: another site allowed with credentials",
                format!("Response headers allow credentialed CORS access for {origin}, another site, if the browser's other checks pass. This capture does not establish that credentials were sent, sensitive data was returned, or another site actually read the response. One answer cannot distinguish an intentional allowlist from unrestricted origin reflection."),
                format!("ACAO: {origin}, ACAC: true"),
            ));
        }
    }
}

fn cors_single_header_value<'a>(message: &'a MessageRecord, name: &str) -> Option<&'a str> {
    let mut values = message
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name));
    let value = &values.next()?.value;
    if values.next().is_some() {
        return None;
    }
    // HTTP optional whitespace, not arbitrary Unicode whitespace.
    Some(value.trim_matches([' ', '\t']))
}

fn is_serialized_cors_origin(origin: &str) -> bool {
    url::Url::parse(origin).is_ok_and(|url| {
        let serialized = url.origin().ascii_serialization();
        serialized != "null" && serialized == origin
    })
}

/// Whether an origin is on the same site as the request, as browsers judge
/// it for cookies: the same scheme and registrable domain. `www.example.com`
/// and `api.example.com` are one site; an `http:` page on it is not, since
/// anyone on the network can write into it.
fn origin_is_same_site(origin: &str, request_scheme: &str, request_host: &str) -> bool {
    let parse = |url: &str| {
        let url = url::Url::parse(url).ok()?;
        Some((
            url.scheme().to_string(),
            url.host_str()?.to_ascii_lowercase(),
        ))
    };
    let (Some((origin_scheme, origin_host)), Some((scheme, host))) = (
        parse(origin),
        parse(&format!("{request_scheme}://{request_host}")),
    ) else {
        return false;
    };
    origin_scheme == scheme && site_of(&origin_host) == site_of(&host)
}

/// A host's registrable domain: its last two labels, or three under a suffix
/// whose names belong to different owners, a ccTLD's own second level
/// (`co.kr`, `com.mx`, `co.za`) or an app host that gives each customer a
/// subdomain (`herokuapp.com`). An address or a single label is its own site.
// ponytail: a heuristic and a short list, not the public suffix list; a
// missing shared host reads as one site and hides that host's CORS findings.
fn site_of(host: &str) -> &str {
    const COUNTRY_SECOND_LEVELS: &[&str] = &[
        "com", "net", "org", "edu", "gov", "mil", "co", "ac", "or", "ne", "go", "re", "pe", "gob",
    ];
    const SHARED_HOSTS: &[&str] = &[
        "herokuapp.com",
        "vercel.app",
        "netlify.app",
        "github.io",
        "gitlab.io",
        "pages.dev",
        "workers.dev",
        "web.app",
        "firebaseapp.com",
        "appspot.com",
        "azurewebsites.net",
        "cloudfront.net",
        "onrender.com",
        "fly.dev",
        "myshopify.com",
        "blogspot.com",
    ];
    let host = host.trim_end_matches('.');
    if host.starts_with('[') || host.parse::<std::net::Ipv4Addr>().is_ok() {
        return host;
    }
    // Where the last two labels start, then the last three.
    let mut starts = host.rmatch_indices('.').map(|(dot, _)| dot + 1).skip(1);
    let Some(two) = starts.next() else {
        return host;
    };
    let suffix = &host[two..];
    let shared = SHARED_HOSTS.contains(&suffix)
        || suffix
            .split_once('.')
            .is_some_and(|(second, top)| top.len() == 2 && COUNTRY_SECOND_LEVELS.contains(&second));
    if shared {
        return starts.next().map_or(host, |three| &host[three..]);
    }
    suffix
}

// ── Rule 6: Server / Version Disclosure ──

fn check_server_disclosure(record: &TransactionRecord, findings: &mut Vec<ScannerFinding>) {
    let response = match &record.response {
        Some(r) => r,
        None => return,
    };

    for (header_name, label) in &[
        ("server", "Server"),
        ("x-powered-by", "X-Powered-By"),
        ("x-aspnet-version", "X-AspNet-Version"),
    ] {
        if let Some(value) = response.header_value(header_name) {
            if header_discloses_stack_version(header_name, value) {
                findings.push(make_finding(
                    record,
                    Severity::Info,
                    "server",
                    format!("{label} version disclosure"),
                    format!("{label} header reveals server technology/version. This helps attackers fingerprint the stack."),
                    format!("{header_name}: {value}"),
                ));
            }
        }
    }

    // Debug / infrastructure headers that should not be in production
    for (header_name, label, severity) in &[
        (
            "x-backend-server",
            "X-Backend-Server header",
            Severity::Medium,
        ),
        (
            "x-chromelogger-data",
            "ChromeLogger debug data",
            Severity::Medium,
        ),
        ("x-chromephp-data", "ChromePHP debug data", Severity::Medium),
        (
            "x-debug-token-link",
            "Symfony debug profiler link",
            Severity::Medium,
        ),
    ] {
        if let Some(value) = response.header_value(header_name) {
            findings.push(make_finding(
                record,
                severity.clone(),
                "server",
                format!("{label} exposed"),
                format!("{label} found in response. This debug/infrastructure header should not be present in production."),
                format!("{header_name}: {}", truncate_evidence(value, 80)),
            ));
        }
    }
}

/// A dotted version of the target's own stack: `nginx/1.25.3`, `PHP/8.2.12`,
/// `4.0.30319`. Any digit used to count, so a CDN node (`BunnyCDN-KR1-1192`),
/// a build hash (`Fly/42494bfe9c`) or `AmazonS3` read as a version, and a bare
/// `PHP` as one. A banner the map names as an edge, a gateway or a host is
/// theirs, not the target's stack.
fn header_discloses_stack_version(header_name: &str, value: &str) -> bool {
    use crate::service_map_servers::{EDGE, GATEWAY, PLATFORM};
    let dotted = value.as_bytes().windows(3).any(|window| {
        window[0].is_ascii_digit() && window[1] == b'.' && window[2].is_ascii_digit()
    });
    dotted
        && !crate::service_map_servers::detect_header(header_name, value)
            .iter()
            .any(|detection| [EDGE, GATEWAY, PLATFORM].contains(&detection.category))
}

// ── Rule 7: Error Messages ──

fn check_error_messages(record: &TransactionRecord, findings: &mut Vec<ScannerFinding>) {
    let response = match &record.response {
        Some(r) => r,
        None => return,
    };

    if is_binary_body(response) {
        return;
    }

    // Only check 4xx/5xx responses
    let status = record.status.unwrap_or(0);
    if status < 400 {
        return;
    }

    let body = &response.body_preview;
    if body.is_empty() {
        return;
    }

    let body_lower = body.to_ascii_lowercase();

    static ERROR_PATTERNS: &[(&str, &str, Severity)] = &[
        // ── SQL / Database ──
        ("sql syntax", "SQL error message", Severity::Medium),
        ("mysql", "MySQL error disclosure", Severity::Medium),
        (
            "postgresql",
            "PostgreSQL error disclosure",
            Severity::Medium,
        ),
        ("ora-", "Oracle DB error disclosure", Severity::Medium),
        ("sqlite", "SQLite error disclosure", Severity::Medium),
        ("mongodb", "MongoDB error disclosure", Severity::Medium),
        ("mongoose", "Mongoose (MongoDB) error", Severity::Medium),
        ("redis", "Redis error disclosure", Severity::Low),
        ("mariadb", "MariaDB error disclosure", Severity::Medium),
        (
            "microsoft sql server",
            "MSSQL error disclosure",
            Severity::Medium,
        ),
        (
            "unclosed quotation mark",
            "SQL injection indicator",
            Severity::High,
        ),
        (
            "unterminated string",
            "SQL injection indicator",
            Severity::High,
        ),
        (
            "column count doesn't match",
            "SQL column mismatch error",
            Severity::Medium,
        ),
        (
            "incorrect column name",
            "SQL column error",
            Severity::Medium,
        ),
        ("unknown table", "SQL unknown table error", Severity::Medium),
        // ── DB2 / Informix / Access / JDBC (ZAP) ──
        ("db2 driver", "DB2 error disclosure", Severity::Medium),
        ("db2 error", "DB2 error disclosure", Severity::Medium),
        ("odbc db2", "DB2 ODBC error", Severity::Medium),
        ("[cli driver][db2", "DB2 CLI error", Severity::Medium),
        ("[informix]", "Informix DB error", Severity::Medium),
        (
            "odbc microsoft access",
            "MS Access ODBC error",
            Severity::Medium,
        ),
        ("jdbc driver", "JDBC driver error", Severity::Medium),
        ("jdbc error", "JDBC error disclosure", Severity::Medium),
        ("ole db provider", "OLE DB error", Severity::Medium),
        // ── Generic errors ──
        ("syntax error", "Syntax error in response", Severity::Low),
        ("stack trace", "Stack trace disclosure", Severity::Medium),
        (
            "internal server error",
            "Internal server error detail",
            Severity::Low,
        ),
        // ── Language-specific stack traces ──
        (
            "traceback (most recent",
            "Python traceback",
            Severity::Medium,
        ),
        ("at java.", "Java stack trace", Severity::Medium),
        ("at system.", ".NET stack trace", Severity::Medium),
        ("exception in thread", "Java exception", Severity::Medium),
        ("runtime error", "Runtime error disclosure", Severity::Low),
        ("fatal error", "Fatal error disclosure", Severity::Medium),
        // ── PHP ──
        ("parse error:", "PHP parse error", Severity::Medium),
        ("fatal error:", "PHP fatal error", Severity::Medium),
        ("warning:</b>", "PHP warning (HTML)", Severity::Medium),
        ("notice:</b>", "PHP notice (HTML)", Severity::Low),
        (
            "warning: mysql_query()",
            "PHP MySQL warning",
            Severity::Medium,
        ),
        (
            "warning: pg_connect()",
            "PHP PostgreSQL warning",
            Severity::Medium,
        ),
        (
            "warning: cannot modify header information",
            "PHP header warning",
            Severity::Low,
        ),
        // ── Node.js / JavaScript ──
        ("syntaxerror:", "JavaScript SyntaxError", Severity::Medium),
        (
            "referenceerror:",
            "JavaScript ReferenceError",
            Severity::Medium,
        ),
        ("typeerror:", "JavaScript TypeError", Severity::Low),
        ("node_modules/", "Node.js path disclosure", Severity::Low),
        // ── ASP / VBScript / ColdFusion ──
        ("microsoft vbscript", "VBScript error", Severity::Medium),
        (
            "active server pages error",
            "Classic ASP error",
            Severity::Medium,
        ),
        ("adodb.field error", "ASP ADODB error", Severity::Medium),
        (
            "server error in '/' application",
            "ASP.NET application error",
            Severity::Medium,
        ),
        (
            "error occurred while processing request",
            "ColdFusion error",
            Severity::Medium,
        ),
        ("jrun servlet error", "JRun servlet error", Severity::Medium),
        ("disallowed parent path", "IIS path error", Severity::Medium),
        // ── Framework debug ──
        ("debug mode", "Debug mode enabled", Severity::Medium),
        ("django.core", "Django debug info", Severity::Medium),
        ("laravel", "Laravel framework error", Severity::Medium),
        ("spring boot", "Spring Boot error page", Severity::Low),
        (
            "whitelabel error page",
            "Spring Boot default error page",
            Severity::Low,
        ),
        (
            "werkzeug debugger",
            "Flask/Werkzeug debugger exposed",
            Severity::High,
        ),
        ("x-debug-token", "Symfony debug token", Severity::Medium),
    ];

    for &(pattern, label, ref severity) in ERROR_PATTERNS {
        let matched = match pattern {
            "ora-" => {
                oracle_error_code_match(&body_lower).map(|(index, length)| (index, length, None))
            }
            "error occurred while processing request" => coldfusion_error_phrase_match(&body_lower)
                .map(|(index, marker_start, marker_len)| {
                    (index, pattern.len(), Some((marker_start, marker_len)))
                }),
            _ => body_lower
                .find(pattern)
                .filter(|_| !error_pattern_is_too_generic(pattern, &body_lower))
                .map(|index| (index, pattern.len(), None)),
        };
        if let Some((evidence_start, evidence_len, corroborator)) = matched {
            let evidence = error_match_evidence(body, evidence_start, evidence_len, corroborator);
            let mut finding = make_finding(
                record,
                severity.clone(),
                "error",
                format!("{label} in error response"),
                format!("HTTP {status} response contains {label}. Detailed error messages help attackers understand the backend stack."),
                evidence,
            );
            if pattern == "ora-" || corroborator.is_some() {
                // Searching the excerpt again can jump to an earlier repeated
                // prefix or a lookalike that failed the contextual predicate.
                let offset = corroborator.map_or(evidence_start, |(start, _)| start);
                let line = response.headers.len()
                    + 3
                    + body[..offset].bytes().filter(|byte| *byte == b'\n').count();
                finding.location = Some(location_for_line(record, "response", line));
            }
            findings.push(finding);
            break; // One finding per response is enough
        }
    }
}

fn oracle_error_code_match(body_lower: &str) -> Option<(usize, usize)> {
    // Oracle's displayed ORA code is five digits. Bare prefixes also occur in
    // ordinary words such as "flora-guide"; an excerpt must use the qualifying
    // occurrence, not an earlier prefix that failed these checks.
    body_lower.match_indices("ora-").find_map(|(index, _)| {
        let end = index + 9;
        let digits = body_lower.as_bytes().get(index + 4..end)?;
        let before = body_lower[..index].chars().next_back();
        let after = body_lower.get(end..)?.chars().next();
        (digits.iter().all(u8::is_ascii_digit)
            && before.is_none_or(|ch| !ch.is_alphanumeric() && ch != '_')
            && after.is_none_or(|ch| !ch.is_alphanumeric() && ch != '_'))
        .then_some((index, 9))
    })
}

fn coldfusion_error_phrase_match(body_lower: &str) -> Option<(usize, usize, usize)> {
    const PHRASE: &str = "error occurred while processing request";
    // The heading is generic. Return its offset plus the corroborator's offset
    // and length so the bounded excerpt can display both pieces of evidence.
    body_lower.match_indices(PHRASE).find_map(|(index, _)| {
        let context_start = previous_char_boundary(body_lower, index.saturating_sub(512));
        let context_end = next_char_boundary(
            body_lower,
            (index + PHRASE.len() + 512).min(body_lower.len()),
        );
        let context = &body_lower[context_start..context_end];
        [
            "coldfusion.runtime.",
            "coldfusion.tagext.",
            "coldfusion.filter.",
            "coldfusion.sql.",
            "coldfusion.compiler.",
            "check the coldfusion documentation",
            "enable robust exception information",
        ]
        .iter()
        .find_map(|marker| {
            context.match_indices(marker).find_map(|(start, _)| {
                let marker_start = context_start + start;
                // A cropped window must not invent a boundary inside a word.
                body_lower[..marker_start]
                    .chars()
                    .next_back()
                    .is_none_or(|ch| !ch.is_alphanumeric() && ch != '_')
                    .then_some((index, marker_start, marker.len()))
            })
        })
    })
}

fn error_match_evidence(
    body: &str,
    match_start: usize,
    match_len: usize,
    corroborator: Option<(usize, usize)>,
) -> String {
    if let Some((marker_start, marker_len)) = corroborator {
        // A generic heading alone cannot explain vendor attribution. Keep both
        // matches visible even when their local context is too far apart for
        // one excerpt. Put the real marker excerpt on its own first line so
        // finding-location lookup can still locate the corroborating text.
        truncate_evidence(
            &format!(
                "{}\n{}",
                evidence_window(body, marker_start, marker_len, 0, 32),
                &body[match_start..match_start + match_len],
            ),
            120,
        )
    } else {
        truncate_evidence(evidence_window(body, match_start, match_len, 20, 60), 120)
    }
}

fn error_pattern_is_too_generic(pattern: &str, body_lower: &str) -> bool {
    match pattern {
        "syntax error" => ![
            "sql", "mysql", "postgres", "sqlite", "oracle", "mariadb", "odbc", "jdbc", "database",
            "sqlstate",
        ]
        .iter()
        .any(|marker| body_lower.contains(marker)),
        "unclosed quotation mark" | "unterminated string" => {
            !sql_error_indicator_has_database_context(body_lower)
        }
        "stack trace" => stack_trace_pattern_is_suppressed(body_lower),
        "internal server error" => !internal_server_error_has_details(body_lower),
        "mysql"
        | "postgresql"
        | "sqlite"
        | "mongodb"
        | "mongoose"
        | "redis"
        | "mariadb"
        | "microsoft sql server" => {
            !error_pattern_has_token_boundary(pattern, body_lower)
                || !database_error_pattern_has_context(pattern, body_lower)
        }
        "runtime error" | "fatal error" | "node_modules/" | "debug mode" | "django.core"
        | "laravel" | "spring boot" => !framework_error_pattern_has_context(pattern, body_lower),
        _ => false,
    }
}

fn error_pattern_has_token_boundary(pattern: &str, body_lower: &str) -> bool {
    let Some(index) = body_lower.find(pattern) else {
        return false;
    };
    let before = body_lower[..index].chars().next_back();
    let after = body_lower[index + pattern.len()..].chars().next();
    before.is_none_or(|ch| !ch.is_ascii_alphanumeric())
        && after.is_none_or(|ch| !ch.is_ascii_alphanumeric())
}

fn stack_trace_pattern_is_suppressed(body_lower: &str) -> bool {
    let Some(index) = body_lower.find("stack trace") else {
        return false;
    };
    let start = previous_char_boundary(body_lower, index.saturating_sub(32));
    let end = next_char_boundary(body_lower, (index + 96).min(body_lower.len()));
    let context = &body_lower[start..end];
    [
        "no stack trace",
        "stack trace disabled",
        "stack trace unavailable",
        "stack trace not available",
        "stack trace suppressed",
        "stack trace hidden",
        "stack trace omitted",
        "stack trace redacted",
    ]
    .iter()
    .any(|marker| context.contains(marker))
}

fn internal_server_error_has_details(body_lower: &str) -> bool {
    [
        "exception",
        "stack trace",
        "traceback",
        "caused by",
        "\n    at ",
        "\n at ",
        " in /",
        ".php on line",
        ".js:",
        ".py:",
        ".rb:",
        ".java:",
        "line ",
        "file ",
    ]
    .iter()
    .any(|marker| body_lower.contains(marker))
}

fn sql_error_indicator_has_database_context(body_lower: &str) -> bool {
    [
        "sql",
        "sqlstate",
        "database",
        "mysql",
        "postgres",
        "sqlite",
        "oracle",
        "mariadb",
        "odbc",
        "jdbc",
        "microsoft sql server",
    ]
    .iter()
    .any(|marker| body_lower.contains(marker))
}

fn database_error_pattern_has_context(pattern: &str, body_lower: &str) -> bool {
    let Some(index) = body_lower.find(pattern) else {
        return false;
    };
    let start = previous_char_boundary(body_lower, index.saturating_sub(96));
    let end = next_char_boundary(
        body_lower,
        (index + pattern.len() + 128).min(body_lower.len()),
    );
    let context = &body_lower[start..end];
    [
        "error",
        "exception",
        "syntax",
        "query",
        "driver",
        "odbc",
        "jdbc",
        "database",
        "sqlstate",
        "constraint",
        "table",
        "column",
        "connect",
        "connection",
        "stack",
        "trace",
        "failed",
    ]
    .iter()
    .any(|marker| context.contains(marker))
}

fn framework_error_pattern_has_context(pattern: &str, body_lower: &str) -> bool {
    let Some(index) = body_lower.find(pattern) else {
        return false;
    };
    let start = previous_char_boundary(body_lower, index.saturating_sub(128));
    let end = next_char_boundary(
        body_lower,
        (index + pattern.len() + 192).min(body_lower.len()),
    );
    let context = &body_lower[start..end];

    match pattern {
        "debug mode" => {
            if context.contains("disabled") || context.contains("disable debug mode") {
                return false;
            }
            let tokens = context
                .split(|ch: char| !ch.is_ascii_alphanumeric())
                .filter(|token| !token.is_empty())
                .collect::<Vec<_>>();
            tokens
                .iter()
                .any(|token| matches!(*token, "enabled" | "true" | "on"))
                || ["traceback", "stack trace", "debugger", "exception", "error"]
                    .iter()
                    .any(|marker| context.contains(marker))
        }
        "laravel" => [
            "whoops",
            "illuminate\\",
            "laravel/framework",
            "vendor/laravel",
            "queryexception",
            "stack trace",
            "exception",
            " in /",
            ".php on line",
        ]
        .iter()
        .any(|marker| context.contains(marker)),
        "spring boot" => [
            "whitelabel error page",
            "exception",
            "stack trace",
            "trace",
            "org.springframework",
            "java.lang.",
        ]
        .iter()
        .any(|marker| context.contains(marker)),
        "django.core" => [
            "traceback",
            "exception",
            "settings.py",
            "urls.py",
            "wsgi.py",
            "django.views",
        ]
        .iter()
        .any(|marker| context.contains(marker)),
        "node_modules/" => [
            "typeerror:",
            "referenceerror:",
            "syntaxerror:",
            "stack",
            "trace",
            "\n    at ",
            "\n at ",
            ".js:",
        ]
        .iter()
        .any(|marker| context.contains(marker)),
        "runtime error" | "fatal error" => [
            "exception",
            "stack trace",
            "traceback",
            " in /",
            ".php on line",
            ".js:",
            ".rb:",
            ".py:",
            ".java:",
            "line ",
            " at ",
        ]
        .iter()
        .any(|marker| context.contains(marker)),
        _ => true,
    }
}

// ── Rule 8: Security Misconfiguration ──

fn check_security_misconfig(record: &TransactionRecord, findings: &mut Vec<ScannerFinding>) {
    let response = match &record.response {
        Some(r) => r,
        None => return,
    };

    let has_header = |name: &str| -> bool {
        response
            .headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case(name))
    };

    // All enforced policies apply independently. A permissive policy cannot
    // override a restrictive one, and report-only headers impose no limit.
    let policies: Vec<_> = response
        .headers
        .iter()
        .enumerate()
        .filter(|(_, header)| header.name.eq_ignore_ascii_case("content-security-policy"))
        .flat_map(|(index, header)| {
            header
                .value
                .split(',')
                .map(move |policy| CspScriptPolicy::parse(policy, index + 2))
        })
        .collect();
    if let Some((evidence, location)) = [CspScriptContext::Element, CspScriptContext::Attribute]
        .into_iter()
        .find_map(|context| csp_finding_evidence(&policies, context))
    {
        let mut finding = make_finding(
            record,
            Severity::Medium,
            "misconfig",
            "CSP allows unsafe-inline",
            "Content-Security-Policy contains 'unsafe-inline', which undermines XSS protection by allowing inline scripts.",
            evidence,
        );
        finding.location = Some(location);
        findings.push(finding);
    }
    if let Some((evidence, location)) = csp_finding_evidence(&policies, CspScriptContext::Eval) {
        let mut finding = make_finding(
            record,
            Severity::Medium,
            "misconfig",
            "CSP allows unsafe-eval",
            "Content-Security-Policy contains 'unsafe-eval', which allows eval() and similar dynamic code execution.",
            evidence,
        );
        finding.location = Some(location);
        findings.push(finding);
    }

    // Session or authorization indicators need not mean an authenticated user.
    // Browsers send cookies with images, styles and scripts too, whose public
    // caching is right.
    let has_auth = has_authenticated_cache_context(record, response)
        && !matches!(
            crate::service_map::request_kind(record),
            "script" | "static"
        );
    if has_auth && !has_header("cache-control") {
        findings.push(make_finding(
            record,
            Severity::Low,
            "misconfig",
            "Missing Cache-Control with session or authorization indicators",
            "An Authorization header or session-like cookie was observed. This does not establish an authenticated user. The response lacks Cache-Control, so any sensitive content may be cached by browsers or proxies.",
            "",
        ));
    }

    // A directive name is significant, not a substring inside an extension
    // or a quoted field-name list. Multiple field lines form one policy.
    if has_auth {
        let cache_control: Vec<_> = response
            .headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case("cache-control"))
            .map(|header| header.value.as_str())
            .collect();
        let directives: Vec<_> = cache_control
            .iter()
            .flat_map(|value| header_list_members(value))
            .map(str::trim)
            .collect();
        if directives
            .iter()
            .any(|value| value.eq_ignore_ascii_case("public"))
            && !directives.iter().any(|value| {
                value.eq_ignore_ascii_case("no-store") || value.eq_ignore_ascii_case("private")
            })
        {
            findings.push(make_finding(
                record,
                Severity::Medium,
                "misconfig",
                "Cache-Control: public with session or authorization indicators",
                "An Authorization header or session-like cookie was observed. This does not establish an authenticated user. Cache-Control: public may allow shared caching of any sensitive content in this response.",
                format!("Cache-Control: {}", cache_control.join(", ")),
            ));
        }
    }
}

#[derive(Clone, Copy)]
enum CspScriptContext {
    Element,
    Attribute,
    Eval,
}

struct CspScriptDirective {
    raw: String,
    sources: Vec<String>,
}

impl CspScriptDirective {
    fn evidence(&self, context: CspScriptContext) -> String {
        if self.raw.len() <= 120 {
            return self.raw.clone();
        }
        // A long source list can hide the unsafe keyword even after selecting
        // the operative directive. Keep both visible; location retains the
        // exact original header when this abbreviated excerpt is not contiguous.
        let keyword = match context {
            CspScriptContext::Eval => "'unsafe-eval'",
            CspScriptContext::Element | CspScriptContext::Attribute => "'unsafe-inline'",
        };
        let name = self.raw.split_ascii_whitespace().next().unwrap_or_default();
        let source = self
            .raw
            .split_ascii_whitespace()
            .find(|source| source.eq_ignore_ascii_case(keyword))
            .unwrap_or(keyword);
        format!("{name} ... {source}")
    }
}

#[derive(Default)]
struct CspScriptPolicy {
    header_line: usize,
    default: Option<CspScriptDirective>,
    script: Option<CspScriptDirective>,
    element: Option<CspScriptDirective>,
    attribute: Option<CspScriptDirective>,
}

impl CspScriptPolicy {
    fn parse(policy: &str, header_line: usize) -> Self {
        let mut parsed = Self {
            header_line,
            ..Self::default()
        };
        for directive in policy.split(';') {
            // CSP parsing discards non-ASCII directives rather than allowing
            // Unicode whitespace to create a browser-inert source restriction.
            if !directive.is_ascii() {
                continue;
            }
            let mut parts = directive.split_ascii_whitespace();
            let Some(name) = parts.next() else {
                continue;
            };
            let slot = match name.to_ascii_lowercase().as_str() {
                "default-src" => &mut parsed.default,
                "script-src" => &mut parsed.script,
                "script-src-elem" => &mut parsed.element,
                "script-src-attr" => &mut parsed.attribute,
                _ => continue,
            };
            // Browsers ignore a repeated directive after its first occurrence.
            if slot.is_none() {
                *slot = Some(CspScriptDirective {
                    raw: directive.trim().to_string(),
                    sources: parts.map(str::to_ascii_lowercase).collect(),
                });
            }
        }
        parsed
    }

    fn directive(&self, context: CspScriptContext) -> Option<&CspScriptDirective> {
        let script = self.script.as_ref().or(self.default.as_ref());
        match context {
            CspScriptContext::Element => self.element.as_ref().or(script),
            CspScriptContext::Attribute => self.attribute.as_ref().or(script),
            // script-src-elem/attr do not govern eval(), even when present.
            CspScriptContext::Eval => script,
        }
    }

    fn sources(&self, context: CspScriptContext) -> Option<&[String]> {
        self.directive(context)
            .map(|directive| directive.sources.as_slice())
    }
}

fn csp_finding_evidence(
    policies: &[CspScriptPolicy],
    context: CspScriptContext,
) -> Option<(String, FindingLocation)> {
    if !csp_policies_allow(policies, context) {
        return None;
    }
    // Select a representative directive only after every enforced policy has
    // allowed this same context, preserving intersection and fallback semantics.
    policies.iter().find_map(|policy| {
        let directive = policy.directive(context)?;
        Some((
            directive.evidence(context),
            FindingLocation {
                side: "response".to_string(),
                section: "header".to_string(),
                line: Some(policy.header_line),
            },
        ))
    })
}

fn csp_policies_allow(policies: &[CspScriptPolicy], context: CspScriptContext) -> bool {
    let mut explicitly_allowed = false;
    for policy in policies {
        let Some(sources) = policy.sources(context) else {
            continue; // This policy does not constrain this script context.
        };
        let allowed = match context {
            CspScriptContext::Eval => csp_sources_contain(sources, "'unsafe-eval'"),
            CspScriptContext::Element | CspScriptContext::Attribute => {
                csp_sources_contain(sources, "'unsafe-inline'")
                    && !csp_sources_have_nonce_or_hash(sources)
                    && !csp_sources_contain(sources, "'strict-dynamic'")
            }
        };
        if !allowed {
            return false;
        }
        explicitly_allowed = true;
    }
    explicitly_allowed
}

fn csp_sources_contain(sources: &[String], token: &str) -> bool {
    sources.iter().any(|source| source == token)
}

fn csp_sources_have_nonce_or_hash(sources: &[String]) -> bool {
    sources.iter().any(|source| {
        let Some(source) = source.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) else {
            return false;
        };
        let Some((kind, value)) = source.split_once('-') else {
            return false;
        };
        let unpadded = value.trim_end_matches('=');
        matches!(kind, "nonce" | "sha256" | "sha384" | "sha512")
            && !unpadded.is_empty()
            && value.len() - unpadded.len() <= 2
            && unpadded.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'-' | b'_')
            })
    })
}

fn has_authenticated_cache_context(
    record: &TransactionRecord,
    response: &crate::model::MessageRecord,
) -> bool {
    record.request.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("authorization") && !header.value.trim().is_empty()
    }) || request_has_auth_cookie(record)
        || response_sets_auth_cookie(response)
}

fn request_has_auth_cookie(record: &TransactionRecord) -> bool {
    record.request.headers.iter().any(|header| {
        if !header.name.eq_ignore_ascii_case("cookie") {
            return false;
        }
        header.value.split(';').any(|part| {
            part.split_once('=')
                .is_some_and(|(name, value)| cookie_looks_auth_sensitive(name, value))
        })
    })
}

fn response_sets_auth_cookie(response: &crate::model::MessageRecord) -> bool {
    response.headers.iter().any(|header| {
        if !header.name.eq_ignore_ascii_case("set-cookie") {
            return false;
        }
        if set_cookie_is_deletion(&header.value) {
            return false;
        }
        header
            .value
            .split(';')
            .next()
            .and_then(|pair| pair.split_once('='))
            .is_some_and(|(name, value)| cookie_looks_auth_sensitive(name, value))
    })
}

fn is_auth_cookie_name(name: &str) -> bool {
    let normalized = name.trim().trim_start_matches('$').to_ascii_lowercase();
    let compact = normalized
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>();
    if compact.contains("csrf") || compact.contains("xsrf") {
        return false;
    }
    if matches!(
        compact.as_str(),
        "sid"
            | "jwt"
            | "token"
            | "access"
            | "refresh"
            | "auth"
            | "session"
            | "sessionid"
            | "phpsessid"
            | "jsessionid"
            | "aspsessionid"
            | "authtoken"
            | "accesstoken"
            | "refreshtoken"
            | "idtoken"
            | "sessiontoken"
            | "rememberme"
            | "remembertoken"
            | "logintoken"
    ) {
        return true;
    }

    let tokens = normalized
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    if tokens
        .iter()
        .any(|token| matches!(*token, "sid" | "jwt" | "auth" | "session"))
    {
        return true;
    }
    matches!(
        tokens.as_slice(),
        ["access", "token"]
            | ["refresh", "token"]
            | ["id", "token"]
            | ["auth", "token"]
            | ["session", "token"]
    )
}

// ── Rule 9: Information Disclosure ──

fn check_info_disclosure(record: &TransactionRecord, findings: &mut Vec<ScannerFinding>) {
    let response = match &record.response {
        Some(r) => r,
        None => return,
    };

    push_source_map_header_finding(record, response, findings);

    if is_binary_body(response) {
        return;
    }

    let body = &response.body_preview;
    if body.is_empty() {
        return;
    }

    let body_lower = body.to_ascii_lowercase();

    // Directory listing detection
    if (body_lower.contains("index of /") || body_lower.contains("directory listing for"))
        && (body_lower.contains("parent directory") || body_lower.contains("last modified"))
    {
        findings.push(make_finding(
            record,
            Severity::Medium,
            "info",
            "Directory listing enabled",
            "Server is exposing directory contents. This reveals file structure and may expose sensitive files.",
            truncate_evidence(evidence_prefix(body, 120), 120),
        ));
    }

    // Source map references
    if javascript_or_css_response(record, response) {
        let sourcemap_re =
            Regex::new(r"(?m)(?://[#@]|/\*[#@])\s*sourceMappingURL\s*=\s*[^\s*]+\.map\s*(?:\*/)?")
                .unwrap();
        if let Some(m) = sourcemap_re.find(body) {
            findings.push(make_finding(
                record,
                Severity::Low,
                "info",
                "JavaScript source map reference",
                "Source map file referenced in response. Source maps can expose original source code, making it easier for attackers to understand application logic.",
                truncate_evidence(m.as_str(), 120),
            ));
        }
    }

    // GraphQL Introspection enabled
    if graphql_introspection_response_detected(body) {
        findings.push(make_finding(
            record,
            Severity::Medium,
            "info",
            "GraphQL introspection enabled",
            "GraphQL introspection query response detected. Introspection exposes the entire API schema to attackers.",
            "__schema { queryType { ... } }",
        ));
    }

    // HTML comments with sensitive keywords
    if response_can_contain_html_comments(record, response) {
        let comment_re = Regex::new(r"<!--[\s\S]{0,500}?-->").unwrap();
        for m in comment_re.find_iter(body) {
            let comment = m.as_str().to_ascii_lowercase();
            if let Some(keyword) = sensitive_html_comment_keyword(&comment) {
                findings.push(make_finding(
                    record,
                    Severity::Info,
                    "info",
                    format!("HTML comment contains '{keyword}'"),
                    "HTML comments may reveal developer notes, internal paths, or sensitive information to users.",
                    truncate_evidence(m.as_str(), 120),
                ));
            }
        }
    }

    if let Some(email) = structured_email_disclosure(body) {
        findings.push(make_finding(
            record,
            Severity::Low,
            "info",
            "Email address in response",
            "Email address found in a structured response field. This may expose user or account data.",
            truncate_evidence(&email, 80),
        ));
    }

    // Version control metadata exposure
    if git_commit_metadata_response_detected(body) {
        findings.push(make_finding(
            record,
            Severity::Low,
            "info",
            "Git commit metadata exposed",
            "Response contains git commit metadata (sha, author). This may reveal internal development details.",
            "",
        ));
    }

    // Swagger/OpenAPI exposure
    if openapi_spec_response_detected(body) {
        findings.push(make_finding(
            record,
            Severity::Low,
            "info",
            "Swagger/OpenAPI spec exposed",
            "Swagger or OpenAPI specification found in response. This reveals the full API structure to potential attackers.",
            "",
        ));
    }

    // WSDL exposure
    if wsdl_definition_response_detected(&body_lower) {
        findings.push(make_finding(
            record,
            Severity::Low,
            "info",
            "WSDL service definition exposed",
            "WSDL document found in response. This reveals web service endpoints and data types.",
            "",
        ));
    }
}

fn graphql_introspection_response_detected(body: &str) -> bool {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    json.pointer("/data/__schema/queryType")
        .is_some_and(|value| value.is_object())
}

fn javascript_or_css_response(
    record: &TransactionRecord,
    response: &crate::model::MessageRecord,
) -> bool {
    let content_type = response
        .header_value("content-type")
        .or(response.content_type.as_deref())
        .unwrap_or("")
        .to_ascii_lowercase();
    content_type.contains("javascript")
        || content_type.contains("ecmascript")
        || content_type.contains("text/css")
        || record.path.ends_with(".js")
        || record.path.ends_with(".css")
}

fn git_commit_metadata_response_detected(body: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    match value {
        serde_json::Value::Array(items) => items.iter().any(json_value_looks_like_git_commit),
        ref item => json_value_looks_like_git_commit(item),
    }
}

fn json_value_looks_like_git_commit(value: &serde_json::Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    let sha = object
        .get("sha")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let plausible_sha =
        (7..=64).contains(&sha.len()) && sha.chars().all(|ch| ch.is_ascii_hexdigit());
    plausible_sha
        && object
            .get("commit")
            .is_some_and(|commit| commit.is_object())
        && (object.get("author").is_some() || value.pointer("/commit/author").is_some())
}

fn openapi_spec_response_detected(body: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    let Some(object) = value.as_object() else {
        return false;
    };
    let has_version = object
        .get("openapi")
        .and_then(|value| value.as_str())
        .is_some()
        || object
            .get("swagger")
            .and_then(|value| value.as_str())
            .is_some();
    has_version
        && object.get("paths").is_some_and(|value| value.is_object())
        && object.get("info").is_some_and(|value| value.is_object())
}

fn wsdl_definition_response_detected(body_lower: &str) -> bool {
    (body_lower.contains("<wsdl:definitions") || body_lower.contains("<definitions"))
        && body_lower.contains("xmlns")
        && body_lower.contains("wsdl")
}

fn structured_email_disclosure(body: &str) -> Option<String> {
    let json = serde_json::from_str::<serde_json::Value>(body).ok()?;
    let email_re = Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap();
    find_structured_email(&json, &mut Vec::new(), &email_re)
}

fn find_structured_email(
    value: &serde_json::Value,
    path: &mut Vec<String>,
    email_re: &Regex,
) -> Option<String> {
    match value {
        serde_json::Value::String(text) => {
            if !json_path_has_email_context(path) {
                return None;
            }
            email_re.find(text).and_then(|m| {
                let email = m.as_str();
                (!should_ignore_structured_email(email)).then(|| email.to_string())
            })
        }
        serde_json::Value::Array(items) => {
            for item in items {
                if let Some(email) = find_structured_email(item, path, email_re) {
                    return Some(email);
                }
            }
            None
        }
        serde_json::Value::Object(object) => {
            for (key, child) in object {
                path.push(key.to_string());
                let result = find_structured_email(child, path, email_re);
                path.pop();
                if result.is_some() {
                    return result;
                }
            }
            None
        }
        _ => None,
    }
}

fn json_path_has_email_context(path: &[String]) -> bool {
    let Some(key) = path.last() else {
        return false;
    };
    let normalized = key
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase();
    if !normalized.contains("email") && !normalized.contains("mail") {
        return false;
    }
    ![
        "support",
        "contact",
        "sales",
        "marketing",
        "help",
        "abuse",
        "privacy",
        "noreply",
        "replyto",
        "from",
        "sender",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

fn should_ignore_structured_email(email: &str) -> bool {
    let Some((local, domain)) = email.rsplit_once('@') else {
        return true;
    };
    let local = local.to_ascii_lowercase();
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    if matches!(
        domain.as_str(),
        "example.com" | "example.org" | "example.net" | "schema.org" | "w3.org"
    ) || domain.ends_with(".example.com")
        || domain.ends_with(".example.org")
        || domain.ends_with(".example.net")
        || domain.ends_with(".schema.org")
        || domain.ends_with(".w3.org")
    {
        return true;
    }
    matches!(
        local.as_str(),
        "support"
            | "contact"
            | "security"
            | "sales"
            | "help"
            | "info"
            | "noreply"
            | "no-reply"
            | "abuse"
            | "privacy"
            | "postmaster"
            | "webmaster"
            | "admin"
    )
}

fn push_source_map_header_finding(
    record: &TransactionRecord,
    response: &crate::model::MessageRecord,
    findings: &mut Vec<ScannerFinding>,
) {
    if !javascript_or_css_response(record, response) {
        return;
    }
    if let Some(sm) = response
        .header_value("sourcemap")
        .or_else(|| response.header_value("x-sourcemap"))
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        findings.push(make_finding(
            record,
            Severity::Low,
            "info",
            "Source map header present",
            "SourceMap HTTP header found. Source maps can expose original source code.",
            format!("SourceMap: {sm}"),
        ));
    }
}

fn response_can_contain_html_comments(
    record: &TransactionRecord,
    response: &MessageRecord,
) -> bool {
    if let Some(content_type) = response
        .header_value("content-type")
        .or(response.content_type.as_deref())
        .filter(|value| !value.trim().is_empty())
    {
        let essence = content_type.split(';').next().unwrap_or("").trim();
        // An HTML error page can be served at a .js path; conversely a MIME
        // parameter containing "text/html" does not make JSON into HTML.
        return essence.eq_ignore_ascii_case("text/html")
            || essence.eq_ignore_ascii_case("application/xhtml+xml");
    }
    !javascript_or_css_response(record, response) && is_html_page_response(response)
}

fn sensitive_html_comment_keyword(comment_lower: &str) -> Option<&'static str> {
    const SENSITIVE_KEYWORDS: &[&str] = &[
        "password",
        "secret",
        "credential",
        "token",
        "api_key",
        "apikey",
        "admin",
        "internal",
        "debug",
    ];
    for keyword in SENSITIVE_KEYWORDS {
        if contains_comment_keyword(comment_lower, keyword) {
            return Some(*keyword);
        }
    }

    const DEV_NOTE_KEYWORDS: &[&str] =
        &["todo", "fixme", "hack", "bug", "temporary", "remove before"];
    DEV_NOTE_KEYWORDS
        .iter()
        .find(|keyword| contains_comment_keyword(comment_lower, keyword))
        .copied()
        .filter(|_| {
            ["auth", "login", "session", "role", "permission", "prod"]
                .iter()
                .any(|context| contains_comment_keyword(comment_lower, context))
        })
}

fn contains_comment_keyword(comment: &str, keyword: &str) -> bool {
    let aliases: &[&str] = match keyword {
        "password" => &["password", "passwords"],
        "secret" => &["secret", "secrets"],
        "credential" => &["credential", "credentials"],
        "token" => &["token", "tokens"],
        "auth" => &["auth", "authentication", "authorization"],
        "role" => &["role", "roles"],
        "permission" => &["permission", "permissions"],
        "prod" => &["prod", "production"],
        _ => &[keyword],
    };
    aliases.iter().any(|keyword| {
        comment.match_indices(keyword).any(|(index, _)| {
            // Underscores delimit names such as access_token or db_password.
            let is_word = |ch: char| ch.is_alphanumeric();
            comment[..index]
                .chars()
                .next_back()
                .is_none_or(|ch| !is_word(ch))
                && comment[index + keyword.len()..]
                    .chars()
                    .next()
                    .is_none_or(|ch| !is_word(ch))
        })
    })
}

// ── Exposures the Service Map names ──

/// What the map names as exposed (`service_map_servers`) that no rule above
/// reads: a management or debug endpoint answering, a configuration file
/// served, a backend address in a load balancer's cookie or in a header. Error
/// pages, stack traces, SQL errors, source maps and secrets are the rules above.
fn check_exposures(record: &TransactionRecord, findings: &mut Vec<ScannerFinding>) {
    let Some(response) = &record.response else {
        return;
    };
    let mut push = |detection: &crate::service_map_libraries::Detection, evidence: String| {
        let Some(severity) = map_exposure_severity(&detection.product_id) else {
            return;
        };
        let title = if detection.product_id == "backend_address" {
            detection.name.clone()
        } else {
            format!("{} exposed", detection.name)
        };
        if findings.iter().any(|finding| finding.title == title) {
            return;
        }
        let detail = if evidence.is_empty() {
            format!("Found {} at this path. It shows how the server is run or configured, and should not be reachable from outside.", detection.name)
        } else {
            format!("{evidence} gives away the name or address of a server behind the one that answered.")
        };
        findings.push(make_finding(
            record, severity, "info", title, detail, evidence,
        ));
    };
    // A management page or a configuration file is text, never a script.
    if !response.body_preview.is_empty()
        && !is_binary_body(response)
        && !javascript_or_css_response(record, response)
    {
        let html = is_html_page_response(response);
        // These pages say what they are at the top, and this runs on every
        // captured response: the rules' long bounded gaps cost time on
        // megabytes of text.
        let body = &response.body_preview;
        let head = &body[..previous_char_boundary(body, body.len().min(EXPOSURE_BODY_BYTES))];
        for detection in crate::service_map_servers::detect_body(head) {
            // A page about a project quotes these files in its code blocks; the
            // files themselves are served as text.
            if html && matches!(detection.product_id.as_str(), "git_config" | "dotenv") {
                continue;
            }
            push(&detection, String::new());
        }
    }
    for header in &response.headers {
        let name = header.name.to_ascii_lowercase();
        // The server rule reports this header with its value.
        if name == "x-backend-server" {
            continue;
        }
        for detection in crate::service_map_servers::detect_header(&name, &header.value) {
            // Only the cookie's or the header's name: the map never reports the
            // address or the host either.
            let evidence = match name.as_str() {
                "set-cookie" => format!(
                    "Set-Cookie: {}",
                    header.value.split(['=', ';']).next().unwrap_or("").trim()
                ),
                _ => header.name.clone(),
            };
            push(&detection, evidence);
        }
    }
}

const EXPOSURE_BODY_BYTES: usize = 64 * 1024;

/// The map's exposures this rule reports, by how much each gives away.
fn map_exposure_severity(product_id: &str) -> Option<Severity> {
    Some(match product_id {
        "git_config" | "dotenv" | "h2_console" | "jolokia" => Severity::High,
        "spring_actuator"
        | "phpinfo"
        | "go_pprof"
        | "go_expvar"
        | "apache_server_status"
        | "apache_server_info"
        | "elasticsearch_root"
        | "backend_address"
        | "backend_host_header" => Severity::Medium,
        "nginx_status" | "prometheus_metrics" | "graphql_ide" => Severity::Low,
        _ => return None,
    })
}

// ── Rule 10: Authentication Issues ──

fn check_auth_issues(record: &TransactionRecord, findings: &mut Vec<ScannerFinding>) {
    // Session token in URL
    if let Some(param) = session_token_parameter_in_url(record) {
        findings.push(make_finding(
                record,
                Severity::Medium,
                "auth",
            format!("Session/token parameter in URL: {param}"),
                "Session token or credentials found in URL. URLs are logged in browser history, server logs, and referer headers, exposing the token.",
                truncate_evidence(&record.path, 120),
            ));
    }

    // Basic authentication over HTTP (not HTTPS)
    if record.scheme == "http" {
        if let Some(auth) = record.request.header_value("authorization") {
            if auth.to_ascii_lowercase().starts_with("basic ") {
                findings.push(make_finding(
                    record,
                    Severity::High,
                    "auth",
                    "Basic authentication over HTTP",
                    "HTTP Basic authentication is used over unencrypted HTTP. Credentials are Base64-encoded (not encrypted) and can be intercepted.",
                    "Authorization: Basic ***",
                ));
            }
        }
    }

    // Credentials in URL (userinfo component)
    if let Ok(cred_re) = Regex::new(r"https?://[^@/\s]+:[^@/\s]+@") {
        // Check request path / referer for credentials
        if cred_re.is_match(&record.path) {
            findings.push(make_finding(
                record,
                Severity::High,
                "auth",
                "Credentials in URL",
                "URL contains user:password credentials. This exposes credentials in logs, browser history, and referer headers.",
                "https://user:pass@...",
            ));
        }
        // Also check Referer header
        for h in &record.request.headers {
            if h.name.eq_ignore_ascii_case("referer") && cred_re.is_match(&h.value) {
                findings.push(make_finding(
                    record,
                    Severity::High,
                    "auth",
                    "Credentials in Referer header",
                    "Referer header contains URL with embedded credentials, leaking authentication data to third parties.",
                    truncate_evidence(&h.value, 80),
                ));
            }
        }
    }

    // Weak authentication: no Secure flag on session cookies over HTTPS
    // (Handled in cookie rule, skip here)

    // Open redirect indicators in response headers
    if let Some(response) = &record.response {
        let status = record.status.unwrap_or(0);
        if (300..=399).contains(&status) {
            if let Some(loc) = response.header_value("location") {
                // Check if Location contains user-controlled input (common open redirect patterns)
                let path_params: Vec<&str> = record.path.split('?').collect();
                if path_params.len() > 1 {
                    let query = path_params[1];
                    let redirect_params = [
                        "redirect",
                        "url",
                        "next",
                        "return",
                        "goto",
                        "redir",
                        "redirect_uri",
                        "return_url",
                        "continue",
                        "dest",
                        "destination",
                    ];
                    let matched_param = query.split('&').find_map(|pair| {
                        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
                        let key = key.replace('+', " ");
                        let decoded_key = percent_decode(&key).to_ascii_lowercase();
                        if !redirect_params.contains(&decoded_key.as_str()) {
                            return None;
                        }
                        let value = value.replace('+', " ");
                        let decoded_value = percent_decode(&value);
                        redirect_parameter_controls_location(
                            &decoded_value,
                            loc,
                            &record.scheme,
                            &record.host,
                        )
                        .then_some(decoded_key)
                    });
                    if let Some(param) = matched_param {
                        // Check if Location points to an external origin.
                        if is_external_redirect_location(loc, &record.scheme, &record.host) {
                            findings.push(make_finding(
                                record,
                                Severity::Medium,
                                "auth",
                                "Possible open redirect",
                                format!("Redirect to external URL based on user-controlled parameter. Query contains '{param}' and Location points to a different host."),
                                format!("Location: {}", truncate_evidence(loc, 80)),
                            ));
                        }
                    }
                }
            }
        }
    }

    if record.scheme == "http" {
        if let Some(response) = &record.response {
            for header in &response.headers {
                if !header.name.eq_ignore_ascii_case("www-authenticate")
                    || !header_list_members(&header.value).iter().any(|member| {
                        let (scheme, rest) = member
                            .split_once(char::is_whitespace)
                            .unwrap_or((member, ""));
                        scheme.eq_ignore_ascii_case("basic") && !rest.trim_start().starts_with('=')
                    })
                {
                    continue;
                }
                findings.push(make_finding(
                    record,
                    Severity::Medium,
                    "auth",
                    "Server requests Basic auth over HTTP",
                    "WWW-Authenticate header requests Basic authentication over unencrypted HTTP.",
                    format!("WWW-Authenticate: {}", header.value),
                ));
                break;
            }
        }
    }
}

/// Commas in quoted header parameters belong to that value, not to a new
/// challenge or directive (for example Digest realm="basic, account").
fn header_list_members(value: &str) -> Vec<&str> {
    let mut members = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, ch) in value.char_indices() {
        if escaped {
            escaped = false;
        } else if quoted && ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            quoted = !quoted;
        } else if ch == ',' && !quoted {
            members.push(value[start..index].trim());
            start = index + 1;
        }
    }
    members.push(value[start..].trim());
    members
}

fn is_external_redirect_location(location: &str, request_scheme: &str, request_host: &str) -> bool {
    let base = match url::Url::parse(&format!("{request_scheme}://{request_host}")) {
        Ok(base) => base,
        Err(_) => return false,
    };
    let redirect = match url::Url::parse(location).or_else(|_| base.join(location)) {
        Ok(redirect) => redirect,
        Err(_) => return false,
    };
    if !matches!(redirect.scheme(), "http" | "https") {
        return false;
    }
    let Some(base_host) = base.host_str() else {
        return false;
    };
    let Some(redirect_host) = redirect.host_str() else {
        return false;
    };
    !base.scheme().eq_ignore_ascii_case(redirect.scheme())
        || !base_host.eq_ignore_ascii_case(redirect_host)
        || base.port_or_known_default() != redirect.port_or_known_default()
}

fn redirect_parameter_controls_location(
    value: &str,
    location: &str,
    request_scheme: &str,
    request_host: &str,
) -> bool {
    let value = value.trim();
    if value.is_empty() {
        return false;
    }
    let base = match url::Url::parse(&format!("{request_scheme}://{request_host}")) {
        Ok(base) => base,
        Err(_) => return false,
    };
    let parameter_url = match url::Url::parse(value).or_else(|_| base.join(value)) {
        Ok(url) => url,
        Err(_) => return false,
    };
    if !is_external_redirect_location(parameter_url.as_str(), request_scheme, request_host) {
        return false;
    }
    let location_url = match url::Url::parse(location).or_else(|_| base.join(location)) {
        Ok(url) => url,
        Err(_) => return false,
    };
    parameter_url == location_url
}

// ── Utilities ──

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (hex_value(bytes[i + 1]), hex_value(bytes[i + 2])) {
                decoded.push((high << 4) | low);
                i += 3;
                continue;
            }
        }
        decoded.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn session_token_parameter_in_url(record: &TransactionRecord) -> Option<String> {
    let path = &record.path;
    let lower = path.to_ascii_lowercase();
    if lower.contains(";jsessionid=") || lower.contains(";phpsessid=") {
        return path.split(';').skip(1).find_map(|segment| {
            let (key, value) = segment.split_once('=').unwrap_or((segment, ""));
            let key = percent_decode(&key.replace('+', " ")).to_ascii_lowercase();
            (matches!(key.as_str(), "jsessionid" | "phpsessid")
                && session_token_value_looks_sensitive(&key, value))
            .then_some(key)
        });
    }

    let query = path.split_once('?')?.1;
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = key.replace('+', " ");
        let decoded = percent_decode(&key).to_ascii_lowercase();
        (is_session_token_parameter_name(&decoded)
            && (!session_token_name_needs_cookie(&decoded)
                || request_cookie_carries(record, value))
            && session_token_value_looks_sensitive(&decoded, value))
        .then_some(decoded)
    })
}

// Analytics, ad and bot beacons send their own ids as `sid`, `token` or
// `api_key`. Under these names only the request's own cookie copied into the
// URL is a session leaking.
fn session_token_name_needs_cookie(name: &str) -> bool {
    matches!(
        name,
        "sessionid" | "session_id" | "sid" | "token" | "api_key"
    )
}

fn request_cookie_carries(record: &TransactionRecord, value: &str) -> bool {
    let value = percent_decode(value);
    record
        .request
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("cookie"))
        .flat_map(|header| header.value.split(';'))
        .filter_map(|pair| pair.split_once('='))
        .any(|(_, cookie)| percent_decode(cookie.trim()) == value)
}

fn is_session_token_parameter_name(name: &str) -> bool {
    matches!(
        name,
        "jsessionid"
            | "phpsessid"
            | "sessionid"
            | "session_id"
            | "sid"
            | "aspsessionid"
            | "token"
            | "access_token"
            | "auth_token"
            | "api_key"
    )
}

fn session_token_value_looks_sensitive(name: &str, value: &str) -> bool {
    let decoded = percent_decode(&value.replace('+', " "));
    let trimmed = decoded.trim();
    if name == "api_key" && session_api_key_value_is_public_identifier(trimmed) {
        return false;
    }
    // A short number is a timestamp or a counter: analytics beacons send their
    // session start as `sid=1760000000`.
    if trimmed.len() < 16 && trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    !trimmed.is_empty()
        && !secret_candidate_is_masked(trimmed)
        && !secret_candidate_is_placeholder(trimmed)
        && session_token_value_has_enough_signal(trimmed)
}

fn session_api_key_value_is_public_identifier(value: &str) -> bool {
    (value.starts_with("AIza")
        && value.len() == 39
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'))
        || value.starts_with("pk_live_")
        || value.starts_with("pk_test_")
}

fn session_token_value_has_enough_signal(value: &str) -> bool {
    let compact = value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>();
    compact.len() >= 8 && compact.chars().collect::<HashSet<_>>().len() >= 4
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn truncate_evidence(value: &str, max: usize) -> String {
    if value.len() <= max {
        value.to_string()
    } else {
        let end = value
            .char_indices()
            .map(|(idx, _)| idx)
            .take_while(|idx| *idx <= max)
            .last()
            .unwrap_or(0);
        format!("{}...", &value[..end])
    }
}

fn evidence_window(
    value: &str,
    match_start: usize,
    match_len: usize,
    before: usize,
    after: usize,
) -> &str {
    let start = previous_char_boundary(value, match_start.saturating_sub(before));
    let end = next_char_boundary(value, (match_start + match_len + after).min(value.len()));
    &value[start..end]
}

fn evidence_prefix(value: &str, max: usize) -> &str {
    &value[..previous_char_boundary(value, value.len().min(max))]
}

fn previous_char_boundary(value: &str, mut index: usize) -> usize {
    while index > 0 && !value.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn next_char_boundary(value: &str, mut index: usize) -> usize {
    while index < value.len() && !value.is_char_boundary(index) {
        index += 1;
    }
    index
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{BodyEncoding, HeaderRecord, MessageRecord, TransactionRecord};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use chrono::Utc;

    fn make_record(
        req_headers: Vec<(&str, &str)>,
        res_headers: Vec<(&str, &str)>,
        res_body: &str,
        status: u16,
    ) -> TransactionRecord {
        TransactionRecord::http(
            Utc::now(),
            "GET".into(),
            "https".into(),
            "example.com".into(),
            "/test".into(),
            Some(status),
            10,
            MessageRecord {
                headers: req_headers
                    .into_iter()
                    .map(|(n, v)| HeaderRecord {
                        name: n.into(),
                        value: v.into(),
                    })
                    .collect(),
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            },
            Some(MessageRecord {
                headers: res_headers
                    .into_iter()
                    .map(|(n, v)| HeaderRecord {
                        name: n.into(),
                        value: v.into(),
                    })
                    .collect(),
                body_preview: res_body.into(),
                body_encoding: BodyEncoding::Utf8,
                body_size: res_body.len(),
                decoded_body_size: None,
                preview_truncated: false,
                content_decoded: false,
                content_type: Some("text/html".into()),
            }),
            Vec::new(),
            None,
            None,
        )
    }

    fn finding(title: &str) -> ScannerFinding {
        ScannerFinding {
            id: Uuid::new_v4(),
            record_id: Uuid::new_v4(),
            found_at: Utc::now(),
            rule_id: String::new(),
            severity: Severity::Low,
            category: "test".to_string(),
            title: title.to_string(),
            detail: String::new(),
            evidence: String::new(),
            host: "example.com".to_string(),
            path: "/".to_string(),
            location: None,
        }
    }

    fn custom_rule(id: String) -> CustomRule {
        CustomRule {
            id,
            name: "Custom token".to_string(),
            enabled: true,
            target: "response_body".to_string(),
            header_name: String::new(),
            pattern: "token".to_string(),
            severity: Severity::Medium,
            category: "custom".to_string(),
            description: "custom token rule".to_string(),
        }
    }

    fn jwt_token(header: serde_json::Value, payload: serde_json::Value) -> String {
        format!(
            "{}.{}.signature",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(payload.to_string())
        )
    }

    #[tokio::test]
    async fn scanner_store_from_findings_trims_to_max_entries() {
        let store = ScannerStore::from_findings(
            2,
            vec![finding("first"), finding("second"), finding("third")],
        );

        let findings = store.list(None).await;

        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].title, "first");
        assert_eq!(findings[1].title, "second");
    }

    #[tokio::test]
    async fn scanner_store_trims_restored_custom_rules_to_config_limit() {
        let config = ScannerConfig {
            custom_rules: (0..=MAX_SCANNER_CUSTOM_RULES)
                .map(|index| custom_rule(format!("custom-{index}")))
                .collect(),
            ..ScannerConfig::default()
        };

        let store = ScannerStore::from_findings_with_config(10, Vec::new(), config);

        assert_eq!(
            store.get_config().await.custom_rules.len(),
            MAX_SCANNER_CUSTOM_RULES
        );
    }

    #[tokio::test]
    async fn scanner_store_drops_restored_invalid_custom_rules() {
        let valid = custom_rule("valid".to_string());
        let mut invalid_regex = custom_rule("invalid-regex".to_string());
        invalid_regex.pattern = "(".to_string();
        let mut duplicate = custom_rule("valid".to_string());
        duplicate.name = "Duplicate".to_string();
        let mut oversized = custom_rule("oversized".to_string());
        oversized.description = "x".repeat(MAX_SCANNER_FIELD_BYTES + 1);
        let config = ScannerConfig {
            custom_rules: vec![invalid_regex, valid.clone(), duplicate, oversized],
            ..ScannerConfig::default()
        };

        let store = ScannerStore::from_findings_with_config(10, Vec::new(), config);
        let rules = store.get_config().await.custom_rules;

        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, valid.id);
    }

    #[tokio::test]
    async fn scanner_store_lists_a_host_issue_once_across_paths_and_records() {
        let store = ScannerStore::new(10);
        let mut first = finding("Missing CSP");
        first.path = "/login".to_string();
        let mut second = finding("Missing CSP");
        second.path = "/admin".to_string();
        let mut other_host = finding("Missing CSP");
        other_host.host = "api.example.com".to_string();

        assert!(store.push(first).await);
        assert!(!store.push(second).await);
        assert!(store.push(other_host).await);

        let findings = store.list(None).await;
        assert_eq!(findings.len(), 2);
    }

    #[tokio::test]
    async fn scanner_store_lists_endpoint_issues_per_path_group_and_values_per_value() {
        let store = ScannerStore::new(10);
        let redirect = |path: &str| {
            let mut finding = finding("Possible open redirect");
            finding.category = "auth".to_string();
            finding.path = path.to_string();
            finding
        };
        let secret = |path: &str, evidence: &str| {
            let mut finding = finding("AWS Access Key ID");
            finding.category = "disclosure".to_string();
            finding.path = path.to_string();
            finding.evidence = evidence.to_string();
            finding
        };

        assert!(store.push(redirect("/users/1/go?to=a")).await);
        assert!(!store.push(redirect("/users/2/go?to=b")).await);
        assert!(store.push(redirect("/login")).await);
        assert!(store.push(secret("/a.js", "AKIA-one")).await);
        assert!(!store.push(secret("/b.js", "AKIA-one")).await);
        assert!(store.push(secret("/a.js", "AKIA-two")).await);

        let error = |path: &str| {
            let mut finding = finding("SQL error in error response");
            finding.category = "error".to_string();
            finding.path = path.to_string();
            finding
        };
        assert!(store.push(error("/search?q='")).await);
        assert!(!store.push(error("/search?q=%27")).await);
        assert!(store.push(error("/login")).await);
        let cors = |origin: &str| {
            let mut finding = finding("CORS: another site allowed with credentials");
            finding.category = "cors".to_string();
            finding.evidence = format!("ACAO: {origin}, ACAC: true");
            finding
        };
        assert!(store.push(cors("https://partner.example")).await);
        assert!(store.push(cors("https://evil.example")).await);

        assert_eq!(store.list(None).await.len(), 8);
    }

    #[tokio::test]
    async fn scanner_store_collapses_findings_restored_one_per_request() {
        let newest = finding("Missing CSP");
        let mut older = finding("Missing CSP");
        older.path = "/other".to_string();

        let store = ScannerStore::from_findings_with_config(
            10,
            vec![newest.clone(), older.clone()],
            Default::default(),
        );
        let findings = store.list(None).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, newest.id);

        store.replace_all(vec![older.clone(), newest]).await;
        let findings = store.list(None).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, older.id);
    }

    #[tokio::test]
    async fn scanner_store_removes_dedup_key_when_finding_is_evicted() {
        let store = ScannerStore::new(1);
        let first = finding("Missing CSP");
        let second = finding("Missing HSTS");

        store.push(first.clone()).await;
        store.push(second).await;
        store.push(first).await;

        let findings = store.list(None).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Missing CSP");
    }

    #[tokio::test]
    async fn scanner_store_clear_resets_dedup_state() {
        let store = ScannerStore::new(10);
        let finding = finding("Missing CSP");

        store.push(finding.clone()).await;
        store.clear().await;
        store.push(finding).await;

        let findings = store.list(None).await;
        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn scanner_store_dedup_key_preserves_field_boundaries() {
        let store = ScannerStore::new(10);
        let record_id = Uuid::new_v4();
        let mut first = finding("c");
        first.record_id = record_id;
        first.category = "a:b".to_string();
        let mut second = finding("b:c");
        second.record_id = record_id;
        second.category = "a".to_string();

        assert!(store.push(first).await);
        assert!(store.push(second).await);

        let findings = store.list(None).await;
        assert_eq!(findings.len(), 2);
    }

    #[tokio::test]
    async fn scanner_store_keeps_distinct_custom_rule_ids() {
        let store = ScannerStore::new(10);
        let record_id = Uuid::new_v4();
        let mut first = finding("Custom Secret");
        first.record_id = record_id;
        first.category = "custom".to_string();
        first.rule_id = "custom-rule-a".to_string();
        let mut second = finding("Custom Secret");
        second.record_id = record_id;
        second.category = "custom".to_string();
        second.rule_id = "custom-rule-b".to_string();

        assert!(store.push(first).await);
        assert!(store.push(second).await);

        let findings = store.list(None).await;
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn custom_rules_with_same_display_fields_keep_distinct_findings() {
        let record = make_record(vec![], vec![], "token-one token-two", 200);
        let rules = BUILTIN_RULES
            .iter()
            .map(|(id, _)| ((*id).to_string(), false))
            .collect();
        let config = ScannerConfig {
            enabled: true,
            rules,
            custom_rules: vec![
                CustomRule {
                    id: "custom-token-one".to_string(),
                    name: "Token Leak".to_string(),
                    enabled: true,
                    target: "response_body".to_string(),
                    header_name: String::new(),
                    pattern: "token-one".to_string(),
                    severity: Severity::Medium,
                    category: "custom".to_string(),
                    description: "first custom token".to_string(),
                },
                CustomRule {
                    id: "custom-token-two".to_string(),
                    name: "Token Leak".to_string(),
                    enabled: true,
                    target: "response_body".to_string(),
                    header_name: String::new(),
                    pattern: "token-two".to_string(),
                    severity: Severity::Medium,
                    category: "custom".to_string(),
                    description: "second custom token".to_string(),
                },
            ],
        };

        let findings = scan_transaction(&record, &config);

        assert_eq!(findings.len(), 2);
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "custom-token-one"));
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "custom-token-two"));
    }

    #[test]
    fn custom_request_header_rule_keeps_request_location_when_response_also_matches() {
        let record = make_record(
            vec![("x-api-secret", "shared-custom-secret")],
            vec![],
            "shared-custom-secret",
            200,
        );
        let rules = BUILTIN_RULES
            .iter()
            .map(|(id, _)| ((*id).to_string(), false))
            .collect();
        let config = ScannerConfig {
            enabled: true,
            rules,
            custom_rules: vec![CustomRule {
                id: "request-secret".to_string(),
                name: "Request secret".to_string(),
                enabled: true,
                target: "request_header".to_string(),
                header_name: "x-api-secret".to_string(),
                pattern: "shared-custom-secret".to_string(),
                severity: Severity::Medium,
                category: "custom".to_string(),
                description: "request secret".to_string(),
            }],
        };

        let findings = scan_transaction(&record, &config);
        let finding = findings
            .iter()
            .find(|finding| finding.rule_id == "request-secret")
            .expect("custom request-header finding should be present");

        assert_eq!(
            finding.location,
            Some(FindingLocation {
                side: "request".to_string(),
                section: "header".to_string(),
                line: Some(3),
            })
        );
    }

    #[tokio::test]
    async fn scanner_store_rejects_pre_clear_generation_findings() {
        let store = ScannerStore::new(10);
        let generation = store.clear_generation();
        let finding = finding("Missing CSP");

        store.clear().await;

        assert!(!store.push_if_generation(finding, generation).await);
        assert_eq!(store.count().await, 0);
    }

    #[tokio::test]
    async fn scanner_store_can_restore_clear_generation_after_failed_clear() {
        let store = ScannerStore::new(10);
        let generation = store.clear_generation();

        store.clear().await;
        store.restore_clear_generation(generation);

        assert!(
            store
                .push_if_generation(finding("Missing CSP"), generation)
                .await
        );
        assert_eq!(store.count().await, 1);
    }

    #[test]
    fn truncate_evidence_does_not_split_utf8_codepoints() {
        assert_eq!(truncate_evidence("😀😀", 5), "😀...");
    }

    #[test]
    fn scanner_config_token_is_canonical_session_bound_and_order_sensitive() {
        let session_id = Uuid::new_v4();
        let mut first = ScannerConfig::default();
        first.rules.clear();
        first.rules.insert("header".into(), false);
        first.rules.insert("cookie".into(), true);
        first.custom_rules = vec![custom_rule("one".into()), custom_rule("two".into())];
        let mut reordered_map = first.clone();
        reordered_map.rules.clear();
        reordered_map.rules.insert("cookie".into(), true);
        reordered_map.rules.insert("header".into(), false);
        let token = scanner_config_token(session_id, &first);
        assert_eq!(token, scanner_config_token(session_id, &reordered_map));
        assert_ne!(token, scanner_config_token(Uuid::new_v4(), &first));
        reordered_map.custom_rules.reverse();
        assert_ne!(token, scanner_config_token(session_id, &reordered_map));
        reordered_map = first.clone();
        reordered_map.enabled = false;
        assert_ne!(token, scanner_config_token(session_id, &reordered_map));
        reordered_map = first.clone();
        reordered_map.custom_rules[0].description = "changed".into();
        assert_ne!(token, scanner_config_token(session_id, &reordered_map));
    }

    #[test]
    fn scanner_config_validation_preserves_optional_empty_values_and_false() {
        let mut rule = custom_rule("stable-id".into());
        rule.enabled = false;
        rule.header_name.clear();
        rule.category.clear();
        rule.description.clear();
        for target in ["response_body", "response_header", "request_header"] {
            rule.target = target.into();
            validate_custom_rule(&rule).unwrap();
        }
        let config = ScannerConfig {
            enabled: false,
            custom_rules: vec![rule],
            ..ScannerConfig::default()
        };
        validate_scanner_config(&config).unwrap();
    }

    #[test]
    fn scanner_config_validation_rejects_invalid_rules_without_echoing_pattern() {
        let good = custom_rule("stable-id".into());
        for field in ["id", "name", "pattern"] {
            let mut rule = good.clone();
            match field {
                "id" => rule.id = "  ".into(),
                "name" => rule.name = "  ".into(),
                _ => rule.pattern = "  ".into(),
            }
            assert!(validate_custom_rule(&rule).is_err());
        }
        let mut rule = good.clone();
        rule.target = "url".into();
        assert!(validate_custom_rule(&rule).is_err());
        rule = good.clone();
        rule.pattern = "private-synthetic-value[".into();
        let error = validate_custom_rule(&rule).unwrap_err();
        assert!(error.contains("invalid regex"));
        assert!(!error.contains("private-synthetic-value"));
        for field in [
            "id",
            "name",
            "target",
            "header_name",
            "pattern",
            "category",
            "description",
        ] {
            let mut value = serde_json::to_value(&good).unwrap();
            value[field] = serde_json::json!("x".repeat(MAX_SCANNER_FIELD_BYTES + 1));
            let rule: CustomRule = serde_json::from_value(value).unwrap();
            assert!(validate_custom_rule(&rule)
                .unwrap_err()
                .contains("cannot exceed"));
        }
        let config = ScannerConfig {
            custom_rules: vec![good.clone(), custom_rule(" stable-id ".into())],
            ..ScannerConfig::default()
        };
        assert!(validate_scanner_config(&config)
            .unwrap_err()
            .contains("duplicated"));
    }

    #[test]
    fn scanner_config_validation_checks_total_size_and_count() {
        let rule = custom_rule("one".into());
        let mut config = ScannerConfig {
            custom_rules: vec![rule; MAX_SCANNER_CUSTOM_RULES + 1],
            ..ScannerConfig::default()
        };
        assert!(validate_scanner_config(&config)
            .unwrap_err()
            .contains("custom rules"));
        config.custom_rules = (0..MAX_SCANNER_CUSTOM_RULES)
            .map(|index| {
                let mut rule = custom_rule(format!("rule-{index}"));
                rule.description = "x".repeat(MAX_SCANNER_FIELD_BYTES);
                rule
            })
            .collect();
        assert!(validate_scanner_config(&config)
            .unwrap_err()
            .contains("stored bytes"));
    }

    #[test]
    fn scanner_config_accepts_legacy_empty_object() {
        let config: ScannerConfig =
            serde_json::from_value(serde_json::json!({})).expect("config should deserialize");

        assert!(config.enabled);
        assert!(config.custom_rules.is_empty());
        assert_eq!(config.rules.get("jwt"), Some(&true));
        assert_eq!(config.rules.get("header"), Some(&true));
    }

    #[test]
    fn scanner_config_accepts_partial_legacy_object() {
        let config: ScannerConfig = serde_json::from_value(serde_json::json!({
            "enabled": false
        }))
        .expect("partial config should deserialize");

        assert!(!config.enabled);
        assert!(config.custom_rules.is_empty());
        assert_eq!(config.rules.get("jwt"), Some(&true));
    }

    #[test]
    fn sensitive_scanner_ignores_css_property_that_looks_like_gitlab_token() {
        let record = make_record(
            vec![],
            vec![],
            r#".icon { glyph-orientation-horizontal: 0deg; }"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "GitLab Token detected in response"),
            "CSS glyph-* properties should not be reported as GitLab tokens"
        );
    }

    #[test]
    fn sensitive_scanner_detects_documented_gitlab_token_prefixes() {
        let record = make_record(
            vec![],
            vec![],
            r#"runner_token = "glrt-ABCDEFGHIJKLMNOPQRSTUV123456";"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "GitLab Token detected in response"),
            "documented GitLab token prefixes should still be reported"
        );
    }

    // All token-shaped test values are synthetic, not usable credentials.
    const SYNTHETIC_REPLICATE_TOKEN: &str = "r8_Ab1Cd2Ab1Cd2Ab1Cd2Ab1Cd2Ab1Cd2Ab1Cd2Xy";

    fn replicate_findings_for_body(
        body: &str,
        content_type: &str,
        status: u16,
    ) -> Vec<ScannerFinding> {
        let mut record = make_record(vec![], vec![("Content-Type", content_type)], body, status);
        record.response.as_mut().unwrap().content_type = Some(content_type.into());
        findings_for_rule(&record, "disclosure")
            .into_iter()
            .filter(|finding| finding.title == "Replicate API Token detected in response")
            .collect()
    }

    #[test]
    fn replicate_token_boundary_rejects_opaque_ascii_identifiers() {
        let token = SYNTHETIC_REPLICATE_TOKEN;
        assert_eq!(token.len(), 41);
        let challenge = format!(
            "<!doctype html><script>window.challenge={{mdrd:'prefix.ABCDE{token}WXYZ.suffix'}};</script>"
        );
        assert!(replicate_findings_for_body(&challenge, "text/html", 403).is_empty());
        assert!(replicate_findings_for_body(
            &format!(r#"{{"blob":"ABCDE{token}WXYZ"}}"#),
            "application/json",
            200,
        )
        .is_empty());
        for adjacent in ["A", "z", "0", "_", "-"] {
            for body in [
                format!("{adjacent}{token}"),
                format!("{token}{adjacent}"),
                format!("{adjacent}{token}{adjacent}"),
            ] {
                assert!(
                    replicate_findings_for_body(&body, "text/plain", 200).is_empty(),
                    "{body}"
                );
            }
        }
    }

    #[test]
    fn replicate_token_boundary_preserves_delimiters_and_exact_evidence() {
        let token = SYNTHETIC_REPLICATE_TOKEN;
        for (content_type, body) in [
            ("text/plain", token.to_string()),
            ("text/plain", format!("'{token}'")),
            ("text/plain", format!("\"{token}\"")),
            ("text/plain", format!("\n{token}\n")),
            ("text/plain", format!("({token});")),
            ("application/json", format!(r#"{{"token":"{token}"}}"#)),
            (
                "text/html",
                format!("<!doctype html><script>const replicateToken=\"{token}\";</script>"),
            ),
            ("text/plain", format!("Authorization: Bearer {token}\r\n")),
            (
                "text/plain",
                format!("https://example.com/?token={token}&view=1"),
            ),
        ] {
            // A challenge/error status does not suppress a separately delimited
            // supported token. Header-shaped text is still response body text.
            for status in [200, 403] {
                let findings = replicate_findings_for_body(&body, content_type, status);
                assert_eq!(findings.len(), 1, "{content_type} / {status} / {body}");
                let finding = &findings[0];
                assert_eq!(finding.severity, Severity::High);
                assert_eq!(finding.category, "disclosure");
                assert!(finding.rule_id.is_empty());
                assert_eq!(finding.evidence, token);
                assert_eq!(finding.evidence.len(), 41);
                assert_eq!(finding_scope(finding), token);
                let body_line = body[..body.find(token).unwrap()]
                    .bytes()
                    .filter(|byte| *byte == b'\n')
                    .count();
                assert_eq!(
                    finding.location,
                    Some(FindingLocation {
                        side: "response".into(),
                        section: "body".into(),
                        line: Some(body_line + 4),
                    })
                );
            }
        }
    }

    #[test]
    fn replicate_token_boundary_preserves_unicode_prose_adjacency() {
        let token = SYNTHETIC_REPLICATE_TOKEN;
        for (prefix, suffix) in [
            ("é", ""),
            ("", "é"),
            ("前", "後"),
            ("\u{301}", ""),
            ("", "\u{301}"),
            ("“", "”"),
        ] {
            let body = format!("{prefix}{token}{suffix}");
            let findings = replicate_findings_for_body(&body, "text/plain; charset=utf-8", 200);
            assert_eq!(findings.len(), 1, "{body}");
            assert_eq!(findings[0].evidence, token);
            assert_eq!(findings[0].severity, Severity::High);
            assert_eq!(
                findings[0].location,
                Some(FindingLocation {
                    side: "response".into(),
                    section: "body".into(),
                    line: Some(4),
                })
            );
        }
    }

    #[test]
    fn replicate_token_boundary_continues_after_rejected_candidate() {
        let rejected = SYNTHETIC_REPLICATE_TOKEN;
        for accepted in [rejected.to_string(), format!("r8_{}Xy", "Ef3Gh4".repeat(6))] {
            assert_eq!(accepted.len(), 41);
            let body = format!("前ABCDE{rejected}WXYZ\n中\n後\"{accepted}\"");
            let record = make_record(
                vec![],
                vec![
                    ("Content-Type", "text/plain; charset=utf-8"),
                    ("X-Example-Note", rejected),
                ],
                &body,
                200,
            );
            let findings: Vec<_> = findings_for_rule(&record, "disclosure")
                .into_iter()
                .filter(|finding| finding.title == "Replicate API Token detected in response")
                .collect();
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].evidence, accepted);
            assert_eq!(findings[0].evidence.len(), 41);
            assert_eq!(findings[0].severity, Severity::High);
            assert_eq!(finding_scope(&findings[0]), accepted);
            assert_eq!(
                findings[0].location,
                Some(FindingLocation {
                    side: "response".into(),
                    section: "body".into(),
                    line: Some(7),
                })
            );
            let raw = raw_response_text_for_finding(&record).unwrap();
            assert_eq!(raw.lines().nth(6).unwrap(), format!("後\"{accepted}\""));
        }
    }

    #[test]
    fn replicate_token_boundary_keeps_existing_supported_format() {
        for body in [
            format!("r8_{}", "A".repeat(37)),
            format!("r8_{}", "A".repeat(39)),
            format!("R8_{}", "A".repeat(38)),
            format!("r8_{}-Z", "A".repeat(36)),
            format!("r8_{}_Z", "A".repeat(36)),
        ] {
            assert!(
                replicate_findings_for_body(&body, "text/plain", 200).is_empty(),
                "{body}"
            );
        }
    }

    #[test]
    fn replicate_token_boundary_does_not_suppress_other_provider_findings() {
        let github = format!("ghp_{}", "Ab1Cd2".repeat(6));
        let body = format!(
            "<script>window.challenge={{mdrd:'ABCDE{}WXYZ'}};const credential=\"{github}\";</script>",
            SYNTHETIC_REPLICATE_TOKEN
        );
        let record = make_record(vec![], vec![("Content-Type", "text/html")], &body, 403);
        let findings = findings_for_rule(&record, "disclosure");
        assert!(!findings
            .iter()
            .any(|finding| finding.title == "Replicate API Token detected in response"));
        let github_finding = findings
            .iter()
            .find(|finding| finding.title == "GitHub Personal Access Token detected in response")
            .expect("the Replicate boundary check must not suppress another provider");
        assert_eq!(github_finding.evidence, github);
        assert_eq!(github_finding.severity, Severity::High);
    }

    #[test]
    fn sensitive_scanner_ignores_password_validation_copy() {
        let record = make_record(
            vec![],
            vec![],
            r#"{ "password": "Password is required", "confirmPassword": "Confirm password" }"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "Password in response detected in response"),
            "validation copy should not be reported as a password leak"
        );
    }

    #[test]
    fn sensitive_scanner_ignores_password_policy_copy() {
        let record = make_record(
            vec![],
            vec![],
            r#"{ "password": "At least 8 characters", "password_hint": "Minimum length required" }"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "Password in response detected in response"),
            "password policy text should not be reported as a leaked password value"
        );
    }

    #[test]
    fn sensitive_scanner_ignores_password_failure_copy() {
        let record = make_record(
            vec![],
            vec![],
            r#"{ "password": "Authentication failed", "password_error": "Incorrect password" }"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "Password in response detected in response"),
            "password failure text should not be reported as a leaked password value"
        );
    }

    #[test]
    fn sensitive_scanner_detects_likely_hardcoded_password() {
        let record = make_record(
            vec![],
            vec![],
            r#"{ "password": "CorrectHorseBattery99" }"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "Password in response detected in response"),
            "likely hardcoded passwords should still be reported"
        );
    }

    #[test]
    fn sensitive_scanner_ignores_masked_password_values() {
        let record = make_record(vec![], vec![], r#"{ "password": "************" }"#, 200);
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "Password in response detected in response"),
            "masked password placeholders should not be reported as leaked passwords"
        );
    }

    #[test]
    fn sensitive_scanner_ignores_placeholder_api_key_values() {
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            r#"{"api_key":"your_api_key_here","access_token":"redacted"}"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings.iter().any(|finding| {
                finding.title.contains("API Key/Secret pattern")
                    || finding.title.contains("Secret/Token pattern")
            }),
            "placeholder generic secrets should not create Findings"
        );
    }

    #[test]
    fn sensitive_scanner_ignores_public_identifiers_in_generic_api_key_fields() {
        for body in [
            r#"{"api_key":"AIzaabcdefghijklmnopqrstuvwxyz123456789"}"#,
            r#"{"api_key":"pk_live_1234567890abcdefghijklmnop"}"#,
        ] {
            let record = make_record(
                vec![],
                vec![("content-type", "application/json")],
                body,
                200,
            );
            let findings = scan_transaction(&record, &ScannerConfig::default());

            assert!(
                !findings
                    .iter()
                    .any(|finding| finding.title.contains("API Key/Secret pattern")),
                "{body} should not create generic secret Findings for public client identifiers"
            );
        }
    }

    #[test]
    fn sensitive_scanner_ignores_header_value_copy_as_generic_secret() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/plain")],
            "Required request header: X-Api-Key: HeaderValueForRequests12345",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings.iter().any(|finding| {
                finding.title.contains("API Key/Secret pattern")
                    || finding.title.contains("Secret/Token pattern")
            }),
            "header documentation values should not create generic secret Findings"
        );
    }

    #[test]
    fn sensitive_scanner_ignores_generic_key_prefix_without_mailgun_context() {
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            r#"{"cache_key":"cache-key-1234567890abcdefghijklmnopqrstuv"}"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title.contains("Mailgun API Key")),
            "generic key-* identifiers should not be treated as Mailgun keys without context"
        );
    }

    #[test]
    fn sensitive_scanner_reports_mailgun_key_with_mailgun_context() {
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            r#"{"mailgun_api_key":"key-1234567890abcdefghijklmnopqrstuv"}"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title.contains("Mailgun API Key")),
            "Mailgun key-shaped values with Mailgun context should still be reported"
        );
    }

    #[test]
    fn sensitive_scanner_ignores_google_oauth_client_id() {
        let body = r#"{"client_id":"123456789012-abcdefghijklmnopqrstuvwxyz123456.apps.googleusercontent.com"}"#;
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            body,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title.contains("Google OAuth Client ID")),
            "OAuth client IDs are public identifiers and should not create secret findings"
        );
    }

    #[test]
    fn sensitive_scanner_ignores_public_sentry_dsn() {
        let body = r#"{"dsn":"https://abc123@o123456.ingest.sentry.io/78910"}"#;
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            body,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title.contains("Sentry DSN")),
            "Sentry browser DSNs are public project identifiers and should not create secret findings"
        );
    }

    #[test]
    fn sensitive_scanner_ignores_firebase_app_url() {
        let body = r#"{"authDomain":"demo-project.firebaseapp.com"}"#;
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            body,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title.contains("Firebase app URL")),
            "Firebase app URLs are public auth domains and should not create disclosure findings"
        );
    }

    #[test]
    fn sensitive_scanner_ignores_public_google_api_key() {
        let body = r#"{"googleMapsApiKey":"AIzaabcdefghijklmnopqrstuvwxyz123456789"}"#;
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            body,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title.contains("Google API Key")),
            "browser Google API keys are commonly public identifiers and should not create default Findings"
        );
    }

    #[test]
    fn sensitive_scanner_ignores_standalone_aws_access_key_id() {
        let body = r#"{"aws_access_key_id":"AKIA1234567890ABCDEF"}"#;
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            body,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title.contains("AWS Access Key ID")),
            "an AWS access key id without the secret half is not enough for a high-confidence secret finding"
        );
    }

    #[test]
    fn sensitive_scanner_ignores_twilio_key_sid_without_secret() {
        let key_sid = format!("SK{}", "1".repeat(32));
        let body = format!(r#"{{"twilio_key_sid":"{key_sid}"}}"#);
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            body.as_str(),
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title.contains("Twilio API Key")),
            "Twilio SK identifiers are not enough to prove a leaked secret"
        );
    }

    #[test]
    fn sensitive_scanner_ignores_firebase_database_url_without_secret() {
        let body = r#"{"databaseURL":"https://demo-project.firebaseio.com"}"#;
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            body,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title.contains("Firebase database URL")),
            "Firebase database URLs alone are not high-confidence secret disclosure"
        );
    }

    #[test]
    fn sensitive_scanner_ignores_database_urls_without_credentials() {
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            r#"{"database":"postgres://db.internal:5432/app"}"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title.contains("PostgreSQL connection string")),
            "database endpoints without embedded credentials should not create secret Findings"
        );
    }

    #[test]
    fn sensitive_scanner_ignores_database_urls_with_placeholder_passwords() {
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            r#"{"database":"postgres://user:password@db.internal:5432/app"}"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title.contains("PostgreSQL connection string")),
            "database URI template passwords should not create secret Findings"
        );
    }

    #[test]
    fn sensitive_scanner_detects_database_urls_with_passwords() {
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            r#"{"database":"postgres://app:secretpass@db.internal:5432/app"}"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title.contains("PostgreSQL connection string")),
            "database URLs with embedded passwords should still be reported"
        );
    }

    #[test]
    fn open_redirect_detection_compares_location_host_not_substrings() {
        let mut record = make_record(
            vec![],
            vec![("location", "HTTPS://example.com.evil/landing")],
            "",
            302,
        );
        record.path = "/login?next=https://example.com.evil/landing".to_string();
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "Possible open redirect"),
            "external suffix host should be reported"
        );
    }

    #[test]
    fn open_redirect_detection_allows_same_host_default_port() {
        let mut record = make_record(
            vec![],
            vec![("location", "https://example.com:443/landing")],
            "",
            302,
        );
        record.path = "/login?next=https://example.com/landing".to_string();
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "Possible open redirect"),
            "same host with default port should not be reported"
        );
    }

    #[test]
    fn open_redirect_detection_ignores_unrelated_external_sso_location() {
        let mut record = make_record(
            vec![],
            vec![("location", "https://idp.example/login")],
            "",
            302,
        );
        record.path = "/login?next=/dashboard".to_string();
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "Possible open redirect"),
            "external SSO redirects should not be reported unless the redirect parameter controls the Location"
        );
    }

    #[test]
    fn open_redirect_detection_ignores_external_sso_location_with_nested_return_url() {
        let mut record = make_record(
            vec![],
            vec![(
                "location",
                "https://idp.example/login?return=https://evil.example/landing",
            )],
            "",
            302,
        );
        record.path = "/login?next=https://evil.example/landing".to_string();
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "Possible open redirect"),
            "nested URLs inside an unrelated IdP Location should not count as controlled redirects"
        );
    }

    #[test]
    fn open_redirect_detection_requires_exact_query_parameter_name() {
        let mut record = make_record(
            vec![],
            vec![("location", "https://evil.example/landing")],
            "",
            302,
        );
        record.path = "/login?curl=https://evil.example/landing".to_string();
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "Possible open redirect"),
            "substring matches like curl should not be treated as url parameters"
        );
    }

    #[test]
    fn open_redirect_detection_decodes_query_parameter_names() {
        let mut record = make_record(
            vec![],
            vec![("location", "https://evil.example/landing")],
            "",
            302,
        );
        record.path = "/login?redirect%5Furi=https://evil.example/landing".to_string();
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "Possible open redirect"),
            "percent-encoded redirect parameter names should still be detected"
        );
    }

    #[test]
    fn open_redirect_detection_treats_scheme_downgrade_as_external() {
        let mut record = make_record(
            vec![],
            vec![("location", "http://example.com:8443/callback")],
            "",
            302,
        );
        record.host = "example.com:8443".to_string();
        record.path = "/login?next=http%3A%2F%2Fexample.com%3A8443%2Fcallback".to_string();
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "Possible open redirect"),
            "same host and port with a different scheme is still a cross-origin redirect"
        );
    }

    #[test]
    fn jwt_algorithm_checks_only_use_alg_claim() {
        let token = jwt_token(
            serde_json::json!({ "alg": "RS256", "kid": "none", "hint": "HS256" }),
            serde_json::json!({ "sub": "1234", "exp": 4_102_444_800_i64 }),
        );
        let record = make_record(
            vec![("authorization", &format!("Bearer {token}"))],
            vec![("content-type", "text/html")],
            "",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "JWT with alg:none"),
            "only the alg claim should trigger alg:none"
        );
        assert!(
            !findings
                .iter()
                .any(|finding| finding.title.contains("symmetric algorithm")),
            "symmetric JWT algorithms are not findings by themselves"
        );
    }

    #[test]
    fn jwt_scanner_does_not_report_inventory_only_findings() {
        let token = jwt_token(
            serde_json::json!({ "alg": "RS256", "typ": "JWT" }),
            serde_json::json!({ "sub": "1234", "exp": 4_102_444_800_i64 }),
        );
        let record = make_record(
            vec![("authorization", &format!("Bearer {token}"))],
            vec![("content-type", "text/html")],
            "",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings.iter().any(|finding| finding.category == "jwt"),
            "a normal expiring JWT should not create inventory-only Findings"
        );
    }

    #[test]
    fn jwt_scanner_ignores_expired_token_as_noise() {
        let token = jwt_token(
            serde_json::json!({ "alg": "RS256", "typ": "JWT" }),
            serde_json::json!({ "sub": "1234", "exp": 1_i64 }),
        );
        let record = make_record(
            vec![("authorization", &format!("Bearer {token}"))],
            vec![("content-type", "text/html")],
            "",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "Expired JWT token"),
            "expired tokens alone are not actionable vulnerability findings"
        );
    }

    #[test]
    fn security_header_checks_treat_content_type_case_insensitively() {
        let mut record = make_record(
            vec![],
            vec![("content-type", "TEXT/HTML; Charset=UTF-8")],
            "<html></html>",
            200,
        );
        if let Some(response) = &mut record.response {
            response.content_type = Some("TEXT/HTML; Charset=UTF-8".to_string());
        }
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "Missing Content-Security-Policy"),
            "HTML content-type checks should be case-insensitive"
        );
    }

    #[test]
    fn test_jwt_detection() {
        // JWT with no expiration (header: {"alg":"HS256","typ":"JWT"}, payload: {"sub":"1234"})
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.abc123";
        let record = make_record(
            vec![("authorization", &format!("Bearer {token}"))],
            vec![("content-type", "text/html")],
            "",
            200,
        );
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings
                .iter()
                .any(|f| f.category == "jwt" && f.title.contains("without expiration")),
            "Should detect JWT without expiration"
        );
    }

    #[test]
    fn jwt_detection_accepts_uppercase_bearer_scheme_and_empty_signature() {
        let token = jwt_token(
            serde_json::json!({ "alg": "none", "typ": "JWT" }),
            serde_json::json!({ "sub": "1234", "exp": 4_102_444_800_i64 }),
        );
        let token = token.trim_end_matches("signature").to_string();
        let record = make_record(
            vec![("authorization", &format!("BEARER   {token}"))],
            vec![("content-type", "text/html")],
            "",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "JWT with alg:none"),
            "case-insensitive bearer schemes and empty signatures should be analyzed"
        );
    }

    #[test]
    fn jwt_detection_decodes_url_encoded_cookie_values() {
        let token = jwt_token(
            serde_json::json!({ "alg": "HS256", "typ": "JWT" }),
            serde_json::json!({ "sub": "1234" }),
        );
        let encoded_token = token.replace('.', "%2E");
        let record = make_record(
            vec![("cookie", &format!("session=\"{encoded_token}\""))],
            vec![("content-type", "text/html")],
            "",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "JWT without expiration"),
            "percent-encoded JWT cookie values should still be analyzed"
        );
    }

    #[test]
    fn jwt_detection_decodes_url_encoded_bearer_tokens() {
        let token = jwt_token(
            serde_json::json!({ "alg": "HS256", "typ": "JWT" }),
            serde_json::json!({ "sub": "1234" }),
        );
        let encoded_token = token.replace('.', "%2E");
        let record = make_record(
            vec![("authorization", &format!("Bearer {encoded_token}"))],
            vec![("content-type", "text/html")],
            "",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "JWT without expiration"),
            "percent-encoded bearer JWTs should still be analyzed"
        );
    }

    #[test]
    fn jwt_detection_ignores_three_part_non_json_bearer_tokens() {
        let token = format!(
            "{}.{}.signature",
            URL_SAFE_NO_PAD.encode("not-json"),
            URL_SAFE_NO_PAD.encode("also-not-json")
        );
        let record = make_record(
            vec![("authorization", &format!("Bearer {token}"))],
            vec![("content-type", "text/html")],
            "",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings.iter().any(|finding| finding.category == "jwt"),
            "opaque three-part bearer tokens should not be reported as JWT findings"
        );
    }

    #[test]
    fn jwt_detection_requires_actual_exp_claim() {
        let token = jwt_token(
            serde_json::json!({ "alg": "HS256", "typ": "JWT" }),
            serde_json::json!({ "message": "missing \"exp\" claim" }),
        );
        let record = make_record(
            vec![("authorization", &format!("Bearer {token}"))],
            vec![("content-type", "text/html")],
            "",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "JWT without expiration"),
            "expiration detection should inspect JSON claims, not substring text"
        );
    }

    #[test]
    fn jwt_detection_decodes_url_encoded_body_tokens() {
        let token = jwt_token(
            serde_json::json!({ "alg": "HS256", "typ": "JWT" }),
            serde_json::json!({ "sub": "1234" }),
        );
        let encoded_token = token.replace('.', "%2E");
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            &format!(r#"{{"token":"{encoded_token}"}}"#),
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "JWT without expiration"),
            "percent-encoded JWTs in response bodies should still be analyzed"
        );
    }

    #[test]
    fn jwt_detection_ignores_body_tokens_without_token_context() {
        let token = jwt_token(
            serde_json::json!({ "alg": "HS256", "typ": "JWT" }),
            serde_json::json!({ "sub": "1234" }),
        );
        let record = make_record(
            vec![],
            vec![("content-type", "text/html")],
            &format!(r#"<pre>{token}</pre>"#),
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings.iter().any(|finding| finding.category == "jwt"),
            "body JWT-looking strings need token/auth context before creating Findings"
        );
    }

    #[test]
    fn jwt_detection_accepts_non_object_payload_prefix_in_body_tokens() {
        let token = jwt_token(
            serde_json::json!({ "alg": "none", "typ": "JWT" }),
            serde_json::json!({}),
        );
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            &format!(r#"{{"token":"{token}"}}"#),
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings
            .iter()
            .any(|finding| finding.title == "JWT with alg:none"));
    }

    #[test]
    fn test_missing_security_headers() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/html")],
            "<html></html>",
            200,
        );
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Content-Security-Policy")),
            "Should detect missing CSP"
        );
    }

    #[test]
    fn security_header_checks_reject_invalid_hsts_values() {
        let record = make_record(
            vec![],
            vec![
                ("content-security-policy", "default-src 'self'"),
                ("strict-transport-security", "max-age=0"),
                ("x-content-type-options", "nosniff"),
                ("x-frame-options", "DENY"),
            ],
            "<html></html>",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings
            .iter()
            .any(|finding| finding.title == "Missing Strict-Transport-Security"));
    }

    #[test]
    fn hsts_is_checked_on_navigations_and_their_redirects_only() {
        let mut redirect = make_record(
            vec![("sec-fetch-dest", "document")],
            vec![("location", "https://www.example.com/")],
            "",
            301,
        );
        if let Some(response) = &mut redirect.response {
            response.content_type = None;
        }
        let findings = scan_transaction(&redirect, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "Missing Strict-Transport-Security"),
            "an apex that only redirects still needs HSTS"
        );
        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "Missing Content-Security-Policy"),
            "page-only header checks should still skip non-HTML redirects"
        );

        let mut script = make_record(vec![("sec-fetch-dest", "script")], vec![], "let a;", 200);
        if let Some(response) = &mut script.response {
            response.content_type = Some("application/javascript".into());
        }
        let fragment = make_record(
            vec![("sec-fetch-dest", "empty")],
            vec![],
            "<div>row</div>",
            200,
        );
        for record in [script, fragment] {
            assert!(
                !scan_transaction(&record, &ScannerConfig::default())
                    .iter()
                    .any(|finding| finding.category == "header"),
                "a script or a fragment a page loads is not a document"
            );
        }
    }

    #[test]
    fn security_header_checks_reject_invalid_content_type_options() {
        let record = make_record(
            vec![],
            vec![
                ("content-security-policy", "default-src 'self'"),
                ("strict-transport-security", "max-age=31536000"),
                ("x-content-type-options", "sniff"),
                ("x-frame-options", "DENY"),
            ],
            "<html></html>",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings
            .iter()
            .any(|finding| finding.title == "Missing X-Content-Type-Options"));
    }

    #[test]
    fn security_header_checks_reject_invalid_frame_protection() {
        let record = make_record(
            vec![],
            vec![
                ("content-security-policy", "default-src 'self'"),
                ("strict-transport-security", "max-age=31536000"),
                ("x-content-type-options", "nosniff"),
                ("x-frame-options", "ALLOWALL"),
            ],
            "<html></html>",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings
            .iter()
            .any(|finding| finding.title == "Missing X-Frame-Options"));
    }

    #[test]
    fn security_header_checks_reject_empty_frame_ancestors_directive() {
        let record = make_record(
            vec![],
            vec![
                ("content-security-policy", "frame-ancestors"),
                ("strict-transport-security", "max-age=31536000"),
                ("x-content-type-options", "nosniff"),
            ],
            "<html></html>",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings
            .iter()
            .any(|finding| finding.title == "Missing X-Frame-Options"));
    }

    #[test]
    fn page_header_checks_skip_binary_response_without_content_type() {
        let mut record = make_record(vec![], vec![], "", 200);
        if let Some(response) = &mut record.response {
            response.body_preview = STANDARD.encode([0x89, b'P', b'N', b'G']);
            response.body_encoding = BodyEncoding::Base64;
            response.body_size = 4;
            response.content_type = None;
        }
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "Missing Content-Security-Policy"),
            "binary responses without content-type should not be treated as HTML pages"
        );
        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "Missing Referrer-Policy header"),
            "binary responses without content-type should not get page-only misconfig findings"
        );
    }

    #[test]
    fn security_header_checks_skip_error_html_pages() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/html")],
            "<html><body>Not found</body></html>",
            404,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings.iter().any(|finding| {
                finding.title == "Missing Content-Security-Policy"
                    || finding.title == "Missing Strict-Transport-Security"
                    || finding.title == "Missing X-Content-Type-Options"
                    || finding.title == "Missing X-Frame-Options"
            }),
            "missing security headers on error HTML pages are too noisy for passive findings"
        );
    }

    #[test]
    fn session_token_detection_requires_exact_query_parameter_name() {
        let mut record = make_record(vec![], vec![("content-type", "text/html")], "", 200);
        record.path = "/search?notoken=1&xapi_key=2".to_string();
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title.starts_with("Session/token parameter")),
            "token-like substrings inside unrelated parameter names should not be reported"
        );
    }

    #[test]
    fn session_token_detection_decodes_exact_query_parameter_name() {
        let mut record = make_record(vec![], vec![("content-type", "text/html")], "", 200);
        record.path = "/search?access%5Ftoken=abc123def456".to_string();
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "Session/token parameter in URL: access_token"),
            "percent-encoded token parameter names should be reported"
        );
    }

    #[test]
    fn session_token_detection_ignores_empty_or_placeholder_values() {
        for path in [
            "/search?token=",
            "/search?access_token=your_token_here",
            "/search?api_key=********",
        ] {
            let mut record = make_record(vec![], vec![("content-type", "text/html")], "", 200);
            record.path = path.to_string();
            let findings = scan_transaction(&record, &ScannerConfig::default());

            assert!(
                !findings
                    .iter()
                    .any(|finding| finding.title.starts_with("Session/token parameter")),
                "{path} should not report empty or placeholder token values"
            );
        }
    }

    #[test]
    fn session_token_detection_ignores_public_api_key_identifiers() {
        for key in [
            "AIzaabcdefghijklmnopqrstuvwxyz123456789",
            "pk_live_1234567890abcdefghijklmnop",
        ] {
            let cookie = format!("api_key={key}");
            let mut record = make_record(
                vec![("cookie", cookie.as_str())],
                vec![("content-type", "text/html")],
                "",
                200,
            );
            let path = format!("/maps?api_key={key}");
            record.path = path.clone();
            let findings = scan_transaction(&record, &ScannerConfig::default());

            assert!(
                !findings
                    .iter()
                    .any(|finding| finding.title.starts_with("Session/token parameter")),
                "{path} should not report public client identifiers as session tokens"
            );
        }
    }

    #[test]
    fn session_token_detection_still_reports_random_api_key_parameter() {
        let mut record = make_record(
            vec![("cookie", "api_key=Ab3dEf6hIj9kLm2nOp5qRs8t")],
            vec![("content-type", "text/html")],
            "",
            200,
        );
        record.path = "/api?api_key=Ab3dEf6hIj9kLm2nOp5qRs8t".to_string();
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "Session/token parameter in URL: api_key"),
            "non-public API key-looking query values should still be reported"
        );
    }

    #[test]
    fn session_token_detection_reports_actual_matrix_parameter_name() {
        let mut record = make_record(vec![], vec![("content-type", "text/html")], "", 200);
        record.path = "/app;foo=bar;jsessionid=abc123def456".to_string();
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "Session/token parameter in URL: jsessionid"),
            "matrix path scanning should report the actual session parameter"
        );
        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "Session/token parameter in URL: foo"),
            "unrelated matrix parameters should not be reported as session tokens"
        );
    }

    #[test]
    fn session_token_detection_needs_the_cookie_value_for_generic_names() {
        let reported = |path: &str, cookie: Option<&str>| {
            let headers = cookie.map(|cookie| vec![("cookie", cookie)]);
            let mut record = make_record(
                headers.unwrap_or_default(),
                vec![("content-type", "text/html")],
                "",
                200,
            );
            record.path = path.to_string();
            scan_transaction(&record, &ScannerConfig::default())
                .iter()
                .any(|finding| finding.title.starts_with("Session/token parameter in URL"))
        };

        assert!(!reported("/b?sid=abcdef1234567890", None));
        assert!(!reported(
            "/b?token=abcdef1234567890",
            Some("token=other1234567890")
        ));
        assert!(reported(
            "/b?sid=abcdef1234567890",
            Some("lang=en; sid=abcdef1234567890")
        ));
        assert!(reported(
            "/b?token=Ab3d%2BEf6hIj9kLm2n",
            Some("t=Ab3d+Ef6hIj9kLm2n")
        ));
        assert!(reported("/b?access_token=abcdef1234567890", None));
        assert!(reported("/app;jsessionid=abcdef1234567890", None));
    }

    #[test]
    fn internal_ip_pattern_reports_full_private_ipv4_address() {
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            r#"{"upstream":"10.1.2.3"}"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings.iter().any(|finding| {
                finding.title.contains("Internal IP address")
                    && finding.evidence.contains("10.1.2.3")
            }),
            "10/8 addresses should include all four octets in evidence"
        );
    }

    #[test]
    fn internal_ip_pattern_detects_private_ip_url_endpoint() {
        let record = make_record(
            vec![],
            vec![("content-type", "application/javascript")],
            r#"const apiBase = "http://192.168.10.25:8080/status";"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings.iter().any(|finding| {
                finding.title.contains("Internal IP address")
                    && finding.evidence.contains("192.168.10.25")
            }),
            "private IP URL endpoints should still be reported"
        );
    }

    #[test]
    fn internal_ip_pattern_detects_camel_case_network_field() {
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            r#"{"internalIp":"172.16.4.9"}"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings.iter().any(|finding| {
                finding.title.contains("Internal IP address")
                    && finding.evidence.contains("172.16.4.9")
            }),
            "labeled network fields should still be reported"
        );
    }

    #[test]
    fn internal_ip_pattern_ignores_version_table_values() {
        let record = make_record(
            vec![],
            vec![("content-type", "application/javascript")],
            r#"const TALK_VERSION = {"10.1.0.0":"10.1.0","10.2.0.0":"10.2.0"};"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title.contains("Internal IP address")),
            "version tables in bundled JavaScript should not be reported as internal IP disclosure"
        );
    }

    #[test]
    fn test_cookie_flags() {
        let record = make_record(
            vec![],
            vec![("set-cookie", "session=abc123; Path=/")],
            "",
            200,
        );
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings.iter().any(|f| f.title.contains("HttpOnly")),
            "Should detect missing HttpOnly"
        );
    }

    #[test]
    fn cookie_flags_are_detected_from_attributes_not_cookie_name_or_value() {
        let record = make_record(
            vec![],
            vec![(
                "set-cookie",
                "session_secure_samesite=httponly_value; Path=/",
            )],
            "",
            200,
        );
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);

        assert!(
            findings.iter().any(|f| f.title.contains("HttpOnly")),
            "Should detect missing HttpOnly when only the value contains httponly"
        );
        assert!(
            findings.iter().any(|f| f.title.contains("Secure")),
            "Should detect missing Secure when only the name contains secure"
        );
        assert!(
            findings.iter().any(|f| f.title.contains("SameSite")),
            "Should detect missing SameSite when only the name contains samesite"
        );
    }

    #[test]
    fn cookie_flags_ignore_deletion_cookies() {
        let record = make_record(
            vec![],
            vec![("set-cookie", "session=; Path=/; Max-Age=0")],
            "",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings.iter().any(|finding| finding.category == "cookie"),
            "cookie deletion responses should not be reported as missing cookie flags"
        );
    }

    #[test]
    fn cookie_flags_ignore_non_auth_preference_cookies() {
        let record = make_record(vec![], vec![("set-cookie", "theme=dark; Path=/")], "", 200);
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings.iter().any(|finding| finding.category == "cookie"),
            "non-auth preference cookies should not create cookie flag Findings"
        );
    }

    #[test]
    fn cookie_flags_ignore_auth_substrings_inside_unrelated_names() {
        for cookie in [
            "accessibility=large; Path=/",
            "refreshRate=60; Path=/",
            "assessment_id=abc123; Path=/",
        ] {
            let record = make_record(vec![], vec![("set-cookie", cookie)], "", 200);
            let findings = scan_transaction(&record, &ScannerConfig::default());

            assert!(
                !findings.iter().any(|finding| finding.category == "cookie"),
                "{cookie} should not be treated as an auth/session cookie"
            );
        }
    }

    #[test]
    fn cookie_flags_still_detect_access_token_cookie() {
        let record = make_record(
            vec![],
            vec![("set-cookie", "access_token=abc123; Path=/")],
            "",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings.iter().any(|finding| finding.category == "cookie"),
            "access_token cookies should still require security flags"
        );
    }

    #[test]
    fn cookie_flags_detect_remember_token_cookie() {
        let record = make_record(
            vec![],
            vec![("set-cookie", "remember_token=Ab3dEf6hIj9kLm2nOp5q; Path=/")],
            "",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings.iter().any(|finding| finding.category == "cookie"),
            "persistent-login remember_token cookies should require security flags"
        );
    }

    #[test]
    fn cookie_flags_ignore_malformed_null_cookie() {
        let record = make_record(vec![], vec![("set-cookie", "null")], "", 200);
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings.iter().any(|finding| finding.category == "cookie"),
            "malformed/null Set-Cookie values should not create cookie flag Findings"
        );
    }

    #[test]
    fn cache_context_wording_qualifies_observed_indicators() {
        for (request_headers, session_headers) in [
            (
                vec![],
                vec![(
                    "Set-Cookie",
                    "JSESSIONID=synthetic-session; Path=/; Secure; HttpOnly",
                )],
            ),
            (vec![("Cookie", "JSESSIONID=synthetic-session")], vec![]),
            (
                vec![("Authorization", "Bearer synthetic-credential")],
                vec![],
            ),
        ] {
            for public in [false, true] {
                let mut response_headers = vec![("Content-Type", "text/html")];
                response_headers.extend(session_headers.clone());
                if public {
                    response_headers.push(("Cache-Control", "public, max-age=60"));
                }
                let cache_header_line = response_headers.len() + 1;
                let record = make_record(
                    request_headers.clone(),
                    response_headers,
                    "<html>Example content</html>",
                    200,
                );
                let findings = findings_for_rule(&record, "misconfig");
                assert_eq!(findings.len(), 1);
                let finding = &findings[0];
                let (title, detail, severity, evidence, section, line) = if public {
                    (
                        "Cache-Control: public with session or authorization indicators",
                        "An Authorization header or session-like cookie was observed. This does not establish an authenticated user. Cache-Control: public may allow shared caching of any sensitive content in this response.",
                        Severity::Medium,
                        "Cache-Control: public, max-age=60",
                        "header",
                        Some(cache_header_line),
                    )
                } else {
                    (
                        "Missing Cache-Control with session or authorization indicators",
                        "An Authorization header or session-like cookie was observed. This does not establish an authenticated user. The response lacks Cache-Control, so any sensitive content may be cached by browsers or proxies.",
                        Severity::Low,
                        "",
                        "headers",
                        None,
                    )
                };
                assert_eq!(finding.title, title);
                assert_eq!(finding.detail, detail);
                assert_eq!(finding.severity, severity);
                assert_eq!(finding.category, "misconfig");
                assert!(finding.rule_id.is_empty());
                assert_eq!(finding.evidence, evidence);
                assert_eq!(
                    finding.location,
                    Some(FindingLocation {
                        side: "response".into(),
                        section: section.into(),
                        line,
                    })
                );
            }
        }
    }

    #[test]
    fn cache_context_wording_preserves_no_indicator_controls() {
        for (request_headers, session_headers) in [
            (vec![], vec![]),
            (vec![("Authorization", " ")], vec![]),
            (
                vec![("Cookie", "csrf_token=synthetic-token; theme=dark")],
                vec![],
            ),
            (
                vec![],
                vec![("Set-Cookie", "JSESSIONID=deleted; Max-Age=0; Path=/")],
            ),
            (
                vec![("Cookie", "everest_session_v2=synthetic-session")],
                vec![],
            ),
        ] {
            for public in [false, true] {
                let mut response_headers = vec![("Content-Type", "text/html")];
                response_headers.extend(session_headers.clone());
                if public {
                    response_headers.push(("Cache-Control", "public, max-age=60"));
                }
                let record = make_record(
                    request_headers.clone(),
                    response_headers,
                    "<html>Example content</html>",
                    200,
                );
                assert!(findings_for_rule(&record, "misconfig").is_empty());
            }
        }
    }

    #[tokio::test]
    async fn cache_context_title_change_keeps_endpoint_scope_and_legacy_until_rescan() {
        for (response_headers, legacy_title) in [
            (vec![], "Missing Cache-Control on authenticated response"),
            (
                vec![("Cache-Control", "public, max-age=60")],
                "Cache-Control: public on authenticated response",
            ),
        ] {
            let record = make_record(
                vec![("Authorization", "Bearer synthetic-credential")],
                response_headers,
                "<html>Example content</html>",
                200,
            );
            let current = findings_for_rule(&record, "misconfig").remove(0);
            let mut legacy = current.clone();
            legacy.id = Uuid::new_v4();
            legacy.title = legacy_title.into();
            assert_eq!(finding_scope(&current), "/test");
            assert_eq!(finding_scope(&legacy), finding_scope(&current));
            assert_ne!(finding_dedup_key(&legacy), finding_dedup_key(&current));
            let mut same_endpoint = current.clone();
            same_endpoint.path = "/test?view=next".into();
            assert_eq!(
                finding_dedup_key(&current),
                finding_dedup_key(&same_endpoint)
            );
            let mut different_endpoint = current.clone();
            different_endpoint.path = "/another".into();
            assert_ne!(
                finding_dedup_key(&current),
                finding_dedup_key(&different_endpoint)
            );

            // A title change does not migrate saved findings: live capture can
            // coexist with the legacy title until an explicit successful Rescan.
            let store = ScannerStore::from_findings(10, vec![legacy]);
            assert!(store.push(current.clone()).await);
            assert!(!store.push(same_endpoint).await);
            assert_eq!(store.count().await, 2);
            let restored = ScannerStore::from_findings(10, store.snapshot(None).await);
            assert_eq!(restored.count().await, 2);
        }
    }

    #[test]
    fn cache_control_check_treats_auth_cookies_as_authenticated() {
        let record = make_record(
            vec![("cookie", "session=abc123; theme=dark")],
            vec![("content-type", "application/json")],
            r#"{"private":true}"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings.iter().any(|finding| finding.title
            == "Missing Cache-Control with session or authorization indicators"));
    }

    #[test]
    fn cache_control_check_treats_remember_token_cookie_as_authenticated() {
        let record = make_record(
            vec![("cookie", "remember_me=Ab3dEf6hIj9kLm2nOp5q; theme=dark")],
            vec![("content-type", "application/json")],
            r#"{"private":true}"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings.iter().any(|finding| finding.title
            == "Missing Cache-Control with session or authorization indicators"));
    }

    #[test]
    fn cache_control_check_treats_jwt_cookie_values_as_authenticated() {
        let token = jwt_token(
            serde_json::json!({ "alg": "HS256", "typ": "JWT" }),
            serde_json::json!({ "sub": "1234", "exp": 4_102_444_800_i64 }),
        );
        let record = make_record(
            vec![("cookie", &format!("identity={token}; theme=dark"))],
            vec![("content-type", "application/json")],
            r#"{"private":true}"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "Missing Cache-Control with session or authorization indicators"),
            "JWT-valued cookies should establish authenticated cache-control context even with generic names"
        );
    }

    #[test]
    fn cache_control_check_treats_jwt_set_cookie_values_as_authenticated() {
        let token = jwt_token(
            serde_json::json!({ "alg": "HS256", "typ": "JWT" }),
            serde_json::json!({ "sub": "1234", "exp": 4_102_444_800_i64 }),
        );
        let record = make_record(
            vec![],
            vec![
                ("content-type", "application/json"),
                ("set-cookie", &format!("identity={token}; Path=/")),
            ],
            r#"{"private":true}"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings.iter().any(|finding| finding.title
                == "Missing Cache-Control with session or authorization indicators"),
            "JWT-valued Set-Cookie headers should establish authenticated cache-control context"
        );
    }

    #[test]
    fn cache_control_public_check_treats_auth_cookies_as_authenticated() {
        let record = make_record(
            vec![("cookie", "access_token=abc123")],
            vec![
                ("content-type", "application/json"),
                ("cache-control", "public, max-age=60"),
            ],
            r#"{"private":true}"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings.iter().any(|finding| finding.title
            == "Cache-Control: public with session or authorization indicators"));
    }

    #[test]
    fn cache_control_check_ignores_csrf_only_cookies() {
        let record = make_record(
            vec![("cookie", "csrf_token=abc123; theme=dark")],
            vec![("content-type", "application/json")],
            r#"{"private":false}"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings.iter().any(|finding| finding.title
                == "Missing Cache-Control with session or authorization indicators"),
            "CSRF-only cookies do not establish an authenticated response context"
        );
    }

    #[test]
    fn cache_control_check_ignores_deleted_auth_cookie() {
        let record = make_record(
            vec![],
            vec![
                ("content-type", "application/json"),
                (
                    "set-cookie",
                    "session=deleted; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
                ),
            ],
            r#"{"logged_out":true}"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings.iter().any(|finding| finding.title
                == "Missing Cache-Control with session or authorization indicators"),
            "deleting an auth cookie should not establish an authenticated response context"
        );
    }

    #[test]
    fn cors_wildcard_without_credentials_on_public_response_is_ignored() {
        let record = make_record(vec![], vec![("access-control-allow-origin", "*")], "", 200);
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            !findings.iter().any(|f| f.category == "cors"),
            "public wildcard CORS without credentials should not be noisy"
        );
    }

    #[test]
    fn cors_wildcard_with_credentials_is_not_reported_as_exploitable() {
        let record = make_record(
            vec![],
            vec![
                ("access-control-allow-origin", " * "),
                ("access-control-allow-credentials", " true "),
            ],
            "",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|f| f.title == "CORS: wildcard origin with credentials"),
            "browsers block wildcard ACAO with credentials, so it should not create an exploitable CORS finding"
        );
    }

    #[test]
    fn cors_null_origin_with_credentials_is_reported() {
        let record = make_record(
            vec![("origin", "null")],
            vec![
                ("access-control-allow-origin", "null"),
                ("access-control-allow-credentials", "true"),
            ],
            "",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings
            .iter()
            .any(|finding| finding.title == "CORS: null origin with credentials"));
    }

    fn credentialed_cors_finding(origin: &str) -> Option<ScannerFinding> {
        let record = make_record(
            vec![("origin", origin)],
            vec![
                ("access-control-allow-origin", origin),
                ("access-control-allow-credentials", "true"),
            ],
            "",
            200,
        );
        scan_transaction(&record, &ScannerConfig::default())
            .into_iter()
            .find(|finding| finding.title == "CORS: another site allowed with credentials")
    }

    #[test]
    fn cors_credentials_for_the_same_site_are_ignored() {
        for origin in ["https://example.com", "https://app.example.com"] {
            assert!(
                credentialed_cors_finding(origin).is_none(),
                "a site trusting its own hosts is the usual setup: {origin}"
            );
        }
    }

    #[test]
    fn cors_credentials_for_another_site_or_an_http_page_are_reported() {
        for origin in ["https://evil.example", "http://app.example.com"] {
            let finding = credentialed_cors_finding(origin).expect(origin);
            assert_eq!(finding.severity, Severity::Low);
        }
    }

    #[test]
    fn site_of_keeps_two_level_suffixes_and_addresses_whole() {
        assert_eq!(site_of("victim.herokuapp.com"), "victim.herokuapp.com");
        assert_eq!(site_of("shop.example.com.mx"), "example.com.mx");
        assert_eq!(site_of("a.example.co.za"), "example.co.za");
        assert_eq!(site_of("www.example.com"), "example.com");
        assert_eq!(site_of("example.com."), "example.com");
        assert_eq!(site_of("a.b.example.co.uk"), "example.co.uk");
        assert_eq!(site_of("example.co.kr"), "example.co.kr");
        assert_eq!(site_of("127.0.0.1"), "127.0.0.1");
        assert_eq!(site_of("[::1]"), "[::1]");
        assert_eq!(site_of("localhost"), "localhost");
    }

    #[test]
    fn cors_allowed_methods_match_exact_method_tokens() {
        let record = make_record(
            vec![],
            vec![("access-control-allow-methods", "GET, OPTIONS, COMPUTE")],
            "",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings.iter().any(|f| f.title == "CORS allows PUT"),
            "method names embedded in other tokens should not count as allowed CORS methods"
        );
    }

    #[test]
    fn cors_allowed_methods_without_origin_risk_are_ignored() {
        let record = make_record(
            vec![],
            vec![("access-control-allow-methods", "GET, PATCH")],
            "",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings.iter().any(|f| f.title == "CORS allows PATCH"),
            "allowed method inventory is too noisy without a risky CORS origin/credentials policy"
        );
    }

    #[test]
    fn test_server_disclosure() {
        let record = make_record(vec![], vec![("server", "Apache/2.4.51")], "", 200);
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings
                .iter()
                .any(|f| f.category == "server" && f.title.contains("Server version")),
            "Should detect server version disclosure"
        );
    }

    #[test]
    fn server_disclosure_ignores_asp_substrings_inside_words() {
        let record = make_record(vec![], vec![("server", "Raspbian")], "", 200);
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "Server version disclosure"),
            "ASP detection should use token boundaries instead of matching inside unrelated words"
        );
    }

    #[test]
    fn server_disclosure_needs_a_dotted_version_of_the_targets_own_stack() {
        let disclosed = |name: &str, value: &str| {
            let record = make_record(vec![], vec![(name, value)], "", 200);
            scan_transaction(&record, &ScannerConfig::default())
                .iter()
                .any(|finding| finding.title.ends_with("version disclosure"))
        };

        assert!(disclosed("x-powered-by", "PHP/8.2.12"));
        assert!(disclosed("server", "nginx/1.25.3"));
        assert!(!disclosed("x-powered-by", "PHP"), "a name is no version");
        assert!(!disclosed("server", "BunnyCDN-KR1-1192"), "a CDN node id");
        assert!(
            !disclosed("server", "awselb/2.0"),
            "the load balancer's, not the target's"
        );
    }

    #[test]
    fn scanner_findings_include_response_header_line_location() {
        let record = make_record(vec![], vec![("server", "Apache/2.4.51")], "", 200);
        let findings = scan_transaction(&record, &ScannerConfig::default());
        let finding = findings
            .iter()
            .find(|finding| finding.title == "Server version disclosure")
            .expect("server finding");

        assert_eq!(
            finding.location,
            Some(FindingLocation {
                side: "response".to_string(),
                section: "header".to_string(),
                line: Some(2),
            })
        );
    }

    #[test]
    fn scanner_request_locations_account_for_synthesized_host_header() {
        let token = jwt_token(
            serde_json::json!({ "alg": "HS256", "typ": "JWT" }),
            serde_json::json!({ "sub": "1234" }),
        );
        let record = make_record(
            vec![("Authorization", &format!("Bearer {token}"))],
            vec![("content-type", "text/html")],
            "",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());
        let finding = findings
            .iter()
            .find(|finding| finding.title == "JWT without expiration")
            .expect("jwt finding");

        assert_eq!(
            finding.location,
            Some(FindingLocation {
                side: "request".to_string(),
                section: "header".to_string(),
                line: Some(3),
            }),
            "UI inserts Host before captured headers, so scanner locations must use the same line map"
        );
    }

    #[test]
    fn test_sql_error() {
        let record = make_record(
            vec![],
            vec![],
            "You have an error in your SQL syntax; check the manual",
            500,
        );
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings.iter().any(|f| f.category == "error"),
            "Should detect SQL error message"
        );
    }

    #[test]
    fn scanner_findings_include_response_body_line_location() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/plain")],
            "first line\nsecond line\nSQL syntax error near SELECT",
            500,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());
        let finding = findings
            .iter()
            .find(|finding| finding.category == "error")
            .expect("error finding");

        assert_eq!(
            finding.location,
            Some(FindingLocation {
                side: "response".to_string(),
                section: "body".to_string(),
                line: Some(6),
            })
        );
    }

    #[test]
    fn error_scanner_ignores_json_validation_syntax_error() {
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            r#"{"message":"Syntax error: expected string at line 1"}"#,
            400,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings.iter().any(|finding| finding.category == "error"),
            "client-side JSON validation copy should not be treated as backend error disclosure"
        );
    }

    #[test]
    fn error_scanner_ignores_query_parameter_syntax_error() {
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            r#"{"message":"Syntax error in query parameter 'filter'"}"#,
            400,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings.iter().any(|finding| finding.category == "error"),
            "query-parameter validation copy should not be treated as SQL error disclosure"
        );
    }

    #[test]
    fn error_scanner_ignores_json_unterminated_string_error() {
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            r#"{"message":"Unterminated string in JSON at position 12"}"#,
            400,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings.iter().any(|finding| finding.category == "error"),
            "JSON parser string errors should not be treated as SQL injection indicators"
        );
    }

    #[test]
    fn error_scanner_reports_sql_unterminated_string_error() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/plain")],
            "SQL error: unterminated string literal at or near \"admin\"",
            500,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings.iter().any(|finding| finding.category == "error"),
            "SQL string literal errors should still be reported"
        );
    }

    #[test]
    fn error_scanner_ignores_plain_internal_server_error() {
        let record = make_record(vec![], vec![], "Internal Server Error", 500);
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings.iter().any(|finding| finding.category == "error"),
            "bare 500 title does not reveal backend implementation details"
        );
    }

    #[test]
    fn error_scanner_ignores_generic_json_internal_server_error() {
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            r#"{"error":"Internal Server Error"}"#,
            500,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings.iter().any(|finding| finding.category == "error"),
            "generic JSON 500 messages without stack/file detail should not be reported"
        );
    }

    #[test]
    fn error_scanner_reports_internal_server_error_with_file_detail() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/plain")],
            "Internal Server Error in /srv/app/index.js:10:3",
            500,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings.iter().any(|finding| finding.category == "error"),
            "internal server errors with implementation detail should still be reported"
        );
    }

    #[test]
    fn error_scanner_still_reports_sql_syntax_error() {
        let record = make_record(vec![], vec![], "syntax error near SELECT in SQL query", 500);
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings.iter().any(|finding| finding.category == "error"),
            "database-oriented syntax errors should still be reported"
        );
    }

    #[test]
    fn error_scanner_ignores_database_product_name_without_error_context() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/plain")],
            "This service supports MySQL and PostgreSQL backends.",
            500,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings.iter().any(|finding| finding.category == "error"),
            "database product names without error context should not create error Findings"
        );
    }

    #[test]
    fn error_scanner_reports_database_product_name_with_error_context() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/plain")],
            "MySQL driver error: unknown table users",
            500,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings.iter().any(|finding| finding.category == "error"),
            "database product names with driver/error context should still be reported"
        );
    }

    #[test]
    fn error_scanner_ignores_database_product_substrings() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/plain")],
            "Application error while rediscovering cached settings.",
            500,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings.iter().any(|finding| finding.category == "error"),
            "database product names should require token boundaries"
        );
    }

    #[test]
    fn error_scanner_reports_database_product_with_token_boundary() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/plain")],
            "Redis connection error: failed to connect to cache backend",
            500,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings.iter().any(|finding| finding.category == "error"),
            "database product names with token boundaries and error context should still be reported"
        );
    }

    #[test]
    fn error_scanner_ignores_suppressed_stack_trace_copy() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/plain")],
            "Internal error. Stack trace disabled in production.",
            500,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings.iter().any(|finding| finding.category == "error"),
            "suppressed stack trace copy should not be reported as stack trace disclosure"
        );
    }

    #[test]
    fn error_scanner_reports_actual_stack_trace_copy() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/plain")],
            "Stack trace:\n    at app.render (/srv/app/index.js:10:3)",
            500,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings.iter().any(|finding| finding.category == "error"),
            "actual stack trace text should still be reported"
        );
    }

    #[test]
    fn error_scanner_ignores_framework_names_without_error_context() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/plain")],
            "This integration supports Laravel and Spring Boot services.",
            500,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings.iter().any(|finding| finding.category == "error"),
            "framework names alone should not be treated as backend error disclosure"
        );
    }

    #[test]
    fn error_scanner_reports_laravel_stack_context() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/plain")],
            r#"Whoops! Illuminate\Routing\Exception in /srv/app/vendor/laravel/framework/src/Routing/Router.php on line 42"#,
            500,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings.iter().any(|finding| finding.category == "error"),
            "Laravel stack/debug context should still be reported"
        );
    }

    #[test]
    fn error_scanner_ignores_debug_mode_disabled_copy() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/plain")],
            "Debug mode disabled for production.",
            500,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings.iter().any(|finding| finding.category == "error"),
            "disabled debug-mode copy should not create an error Finding"
        );
    }

    #[test]
    fn error_scanner_ignores_debug_mode_configuration_copy() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/plain")],
            "Debug mode configuration is documented for production deployments.",
            500,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings.iter().any(|finding| finding.category == "error"),
            "debug mode copy should not be reported just because another word contains 'on'"
        );
    }

    #[test]
    fn error_scanner_reports_debug_mode_enabled_context() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/plain")],
            "Debug mode: enabled\nException detail: template rendering failed",
            500,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings.iter().any(|finding| finding.category == "error"),
            "enabled debug mode with exception context should still be reported"
        );
    }

    #[test]
    fn error_scanner_ignores_node_modules_documentation_path() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/plain")],
            "Install dependencies into node_modules/ before build.",
            500,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings.iter().any(|finding| finding.category == "error"),
            "documentation paths should not be treated as Node.js path disclosure"
        );
    }

    #[test]
    fn error_scanner_reports_node_modules_stack_path() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/plain")],
            "Error\n    at render (/srv/app/node_modules/pkg/index.js:10:3)",
            500,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings.iter().any(|finding| finding.category == "error"),
            "node_modules paths in stack frames should still be reported"
        );
    }

    #[test]
    fn sql_error_evidence_window_does_not_split_utf8_padding() {
        let body = format!("a{}sql syntax near select", "語".repeat(7));
        let record = make_record(vec![], vec![], &body, 500);
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);

        assert!(
            findings.iter().any(|f| f.category == "error"),
            "Should detect SQL error without panicking on UTF-8 evidence window"
        );
    }

    #[test]
    fn test_csp_unsafe_inline() {
        let record = make_record(
            vec![],
            vec![
                ("content-type", "text/html"),
                (
                    "content-security-policy",
                    "default-src 'self' 'unsafe-inline'",
                ),
            ],
            "<html></html>",
            200,
        );
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings
                .iter()
                .any(|f| f.category == "misconfig" && f.title.contains("unsafe-inline")),
            "Should detect CSP unsafe-inline"
        );
    }

    #[test]
    fn csp_unsafe_inline_with_nonce_is_ignored() {
        let record = make_record(
            vec![],
            vec![
                ("content-type", "text/html"),
                (
                    "content-security-policy",
                    "default-src 'self'; script-src 'nonce-abc123' 'unsafe-inline'",
                ),
            ],
            "<html></html>",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|f| f.category == "misconfig" && f.title.contains("unsafe-inline")),
            "unsafe-inline alongside script nonce/hash should not create a high-confidence finding"
        );
    }

    #[test]
    fn csp_unsafe_inline_with_hash_is_ignored() {
        let record = make_record(
            vec![],
            vec![
                ("content-type", "text/html"),
                (
                    "content-security-policy",
                    "script-src 'sha256-abc123' 'unsafe-inline'",
                ),
            ],
            "<html></html>",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|f| f.category == "misconfig" && f.title.contains("unsafe-inline")),
            "unsafe-inline alongside script hash should not create a high-confidence finding"
        );
    }

    #[test]
    fn csp_unsafe_inline_in_attr_is_not_suppressed_by_elem_nonce() {
        let record = make_record(
            vec![],
            vec![
                ("content-type", "text/html"),
                (
                    "content-security-policy",
                    "script-src-attr 'unsafe-inline'; script-src-elem 'nonce-abc123'",
                ),
            ],
            "<html></html>",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|f| f.category == "misconfig" && f.title.contains("unsafe-inline")),
            "nonce/hash suppression must be scoped to the directive containing unsafe-inline"
        );
    }

    #[test]
    fn csp_unsafe_inline_in_script_src_is_not_suppressed_by_elem_nonce() {
        let record = make_record(
            vec![],
            vec![
                ("content-type", "text/html"),
                (
                    "content-security-policy",
                    "script-src 'unsafe-inline'; script-src-elem 'nonce-abc123'",
                ),
            ],
            "<html></html>",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|f| f.category == "misconfig" && f.title.contains("unsafe-inline")),
            "a nonce in script-src-elem should not suppress unsafe-inline in script-src"
        );
    }

    #[test]
    fn csp_default_src_unsafe_inline_still_applies_to_attrs_when_elem_has_nonce() {
        let record = make_record(
            vec![],
            vec![
                ("content-type", "text/html"),
                (
                    "content-security-policy",
                    "default-src 'self' 'unsafe-inline'; script-src-elem 'nonce-abc123'",
                ),
            ],
            "<html></html>",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|f| f.category == "misconfig" && f.title.contains("unsafe-inline")),
            "script-src-attr should fall back through script-src to default-src independently of script-src-elem"
        );
    }

    #[test]
    fn csp_unsafe_inline_check_ignores_style_only_directive() {
        let record = make_record(
            vec![],
            vec![
                ("content-type", "text/html"),
                (
                    "content-security-policy",
                    "default-src 'self'; script-src 'self'; style-src 'unsafe-inline' 'unsafe-eval'",
                ),
            ],
            "<html></html>",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings.iter().any(|f| {
                f.category == "misconfig"
                    && (f.title.contains("unsafe-inline") || f.title.contains("unsafe-eval"))
            }),
            "style-only unsafe tokens should not be reported as script CSP risks"
        );
    }

    #[test]
    fn csp_unsafe_inline_uses_default_src_only_without_script_directive() {
        let record = make_record(
            vec![],
            vec![
                ("content-type", "text/html"),
                (
                    "content-security-policy",
                    "default-src 'self' 'unsafe-inline'; style-src 'self'",
                ),
            ],
            "<html></html>",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|f| f.category == "misconfig" && f.title.contains("unsafe-inline")),
            "default-src should be checked when no script directive is present"
        );
    }

    #[test]
    fn test_directory_listing() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/html")],
            "<html><body><h1>Index of /uploads</h1><a href=\"../\">Parent Directory</a><br>Last modified</body></html>",
            200,
        );
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings
                .iter()
                .any(|f| f.category == "info" && f.title.contains("Directory listing")),
            "Should detect directory listing"
        );
    }

    #[test]
    fn directory_listing_evidence_prefix_does_not_split_utf8() {
        let body = format!(
            "a{}<html><body><h1>Index of /uploads</h1>Parent Directory Last modified</body></html>",
            "語".repeat(40)
        );
        let record = make_record(vec![], vec![("content-type", "text/html")], &body, 200);
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);

        assert!(
            findings
                .iter()
                .any(|f| f.category == "info" && f.title.contains("Directory listing")),
            "Should detect directory listing without panicking on UTF-8 prefix"
        );
    }

    #[test]
    fn test_graphql_introspection() {
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            r#"{"data":{"__schema":{"queryType":{"name":"Query"}}}}"#,
            200,
        );
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings
                .iter()
                .any(|f| f.category == "info" && f.title.contains("GraphQL introspection")),
            "Should detect GraphQL introspection"
        );
    }

    #[test]
    fn graphql_introspection_ignores_error_response_that_mentions_schema_querytype() {
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            r#"{"errors":[{"message":"Cannot query field \"__schema\" on type \"queryType\""}]}"#,
            400,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "GraphQL introspection enabled"),
            "GraphQL error text mentioning __schema/queryType is not an introspection response"
        );
    }

    #[test]
    fn test_session_token_in_url() {
        let record = TransactionRecord::http(
            Utc::now(),
            "GET".into(),
            "https".into(),
            "example.com".into(),
            "/app?JSESSIONID=abc123def456".into(),
            Some(200),
            10,
            MessageRecord {
                headers: vec![],
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            },
            Some(MessageRecord {
                headers: vec![],
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: Some("text/html".into()),
                content_decoded: false,
            }),
            Vec::new(),
            None,
            None,
        );
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings
                .iter()
                .any(|f| f.category == "auth" && f.title.contains("Session/token")),
            "Should detect session token in URL"
        );
    }

    #[test]
    fn session_token_url_check_ignores_short_low_signal_values() {
        let mut record = make_record(
            vec![("cookie", "token=1; sid=abc")],
            vec![("content-type", "text/html")],
            "",
            200,
        );
        record.path = "/app?token=1&sid=abc".to_string();
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title.starts_with("Session/token parameter in URL")),
            "short low-signal token parameters should not create auth Findings"
        );
    }

    #[test]
    fn test_basic_auth_over_http() {
        let record = TransactionRecord::http(
            Utc::now(),
            "GET".into(),
            "http".into(),
            "example.com".into(),
            "/admin".into(),
            Some(200),
            10,
            MessageRecord {
                headers: vec![HeaderRecord {
                    name: "Authorization".into(),
                    value: "Basic dXNlcjpwYXNz".into(),
                }],
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            },
            Some(MessageRecord {
                headers: vec![],
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: Some("text/html".into()),
                content_decoded: false,
            }),
            Vec::new(),
            None,
            None,
        );
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings.iter().any(|f| f.category == "auth" && f.title.contains("Basic authentication over HTTP")),
            "Should detect Basic auth over HTTP"
        );
    }

    #[test]
    fn test_stripe_key_detection() {
        // Build test key at runtime to avoid GitHub push protection false positive
        let fake_key = format!("sk_{}_{}a", "live", "TESTKEY000000000000000000");
        let body = format!(r#"<script>var key = "{fake_key}";</script>"#);
        let record = make_record(vec![], vec![("content-type", "text/html")], &body, 200);
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Stripe Secret Key")),
            "Should detect Stripe secret key"
        );
    }

    #[test]
    fn sensitive_scanner_detects_json_api_key() {
        let fake_key = "Ab3dEf6hIj9kLm2nOp5qRs8t";
        let body = format!(r#"{{"api_key":"{fake_key}"}}"#);
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            &body,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings
            .iter()
            .any(|f| f.title.contains("API Key/Secret pattern")));
    }

    #[test]
    fn sensitive_scanner_reports_api_keys_in_browser_code_only_when_named_secret() {
        let key = "Ab3dEf6hIj9kLm2nOp5qRs8t";
        let reported = |content_type: &str, body: String| {
            let record = make_record(vec![], vec![("content-type", content_type)], &body, 200);
            scan_transaction(&record, &ScannerConfig::default())
                .iter()
                .any(|finding| finding.title.contains("API Key/Secret pattern"))
        };

        assert!(!reported(
            "application/javascript",
            format!(r#"analytics.init({{apiKey:"{key}"}})"#)
        ));
        assert!(!reported(
            "text/html; charset=utf-8",
            format!(r#"<script>var api_key = "{key}";</script>"#)
        ));
        assert!(reported(
            "application/javascript",
            format!(r#"var api_secret = "{key}";"#)
        ));
        assert!(reported(
            "application/json",
            format!(r#"{{"apiKey":"{key}"}}"#)
        ));
    }

    #[test]
    fn sensitive_scanner_ignores_stripe_publishable_key() {
        let publishable_key = format!("pk_{}_{}a", "live", "TESTKEY000000000000000000");
        let body = format!(r#"<script>const stripeKey = "{publishable_key}";</script>"#);
        let record = make_record(vec![], vec![("content-type", "text/html")], &body, 200);
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title.contains("Stripe Publishable Key")),
            "Stripe publishable keys are client identifiers and should not create secret findings"
        );
    }

    #[test]
    fn sensitive_scanner_detects_quoted_secret_token_assignment() {
        let fake_token = "z9Yx7-Wv5Ut3Sr1Qp0Nm8Lk6";
        let body = format!(r#"const auth_token = "{fake_token}";"#);
        let record = make_record(vec![], vec![("content-type", "text/html")], &body, 200);
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings
            .iter()
            .any(|f| f.title.contains("Secret/Token pattern")));
    }

    #[test]
    fn sensitive_scanner_detects_json_aws_secret_access_key() {
        let fake_secret = "c".repeat(40);
        let body = format!(r#"{{"aws_secret_access_key":"{fake_secret}"}}"#);
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            &body,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings
            .iter()
            .any(|f| f.title.contains("AWS Secret Access Key")));
    }

    #[test]
    fn sensitive_scanner_detects_huggingface_token_with_digits() {
        let body = format!("token=hf_{}", "a1".repeat(17));
        let record = make_record(vec![], vec![("content-type", "text/html")], &body, 200);
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings
            .iter()
            .any(|f| f.title.contains("HuggingFace Token")));
    }

    #[test]
    fn sensitive_scanner_requires_huggingface_token_boundaries() {
        let token = format!("hf_{}", "a1".repeat(17));
        let record = make_record(
            vec![],
            vec![("content-type", "text/html")],
            &format!("prefix{token} {token}suffix"),
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(!findings
            .iter()
            .any(|f| f.title.contains("HuggingFace Token")));
    }

    #[test]
    fn sensitive_scanner_rejects_invalid_luhn_card_number() {
        let invalid_card = format!("{}{}", "411111111111111", "2");
        let record = make_record(
            vec![],
            vec![("content-type", "text/html")],
            &invalid_card,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(!findings
            .iter()
            .any(|f| f.title.contains("Possible Visa card number")));
    }

    #[test]
    fn sensitive_scanner_detects_luhn_valid_visa_card_number() {
        let valid_card = "4929123456789015";
        let body = format!(r#"{{"card_number":"{valid_card}"}}"#);
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            &body,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings
            .iter()
            .any(|f| f.title.contains("Possible Visa card number")));
    }

    #[test]
    fn sensitive_scanner_ignores_luhn_number_without_payment_context() {
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            r#"{"build":"4929123456789015"}"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title.contains("Possible Visa card number")),
            "Luhn-valid numbers need payment/card context before creating Findings"
        );
    }

    #[test]
    fn sensitive_scanner_ignores_known_test_card_numbers() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/html")],
            "Use 4242 4242 4242 4242 or 5555 5555 5555 4444 in test mode.",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings.iter().any(|finding| {
                finding.title.contains("Possible Visa card number")
                    || finding.title.contains("Possible Mastercard number")
            }),
            "well-known payment test cards should not be reported as leaked card data"
        );
    }

    #[test]
    fn sensitive_scanner_ignores_env_template_file_references() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/html")],
            r#"<a href="/.env.example">environment template</a>"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title.contains("Sensitive file path")),
            ".env.example template references should not be reported as exposed secret files"
        );
    }

    #[test]
    fn sensitive_scanner_still_reports_env_file_reference() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/html")],
            r#"<a href="/.env">environment file</a>"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title.contains("Sensitive file path")),
            "direct .env references should still be reported"
        );
    }

    #[test]
    fn test_html_comment_sensitive() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/html")],
            "<html><!-- TODO: remove admin password check --><body>Hello</body></html>",
            200,
        );
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings
                .iter()
                .any(|f| f.category == "info" && f.title.contains("HTML comment")),
            "Should detect sensitive HTML comment"
        );
    }

    #[test]
    fn html_comment_ignores_plain_todo_copy() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/html")],
            "<html><!-- TODO: update footer copy --><body>Hello</body></html>",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title.starts_with("HTML comment contains")),
            "plain TODO comments without sensitive context should not create Findings"
        );
    }

    #[test]
    fn test_swagger_exposure() {
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            r#"{"swagger":"2.0","info":{"title":"API"},"paths":{"/users":{"get":{}}}}"#,
            200,
        );
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings
                .iter()
                .any(|f| f.category == "info" && f.title.contains("Swagger")),
            "Should detect Swagger/OpenAPI spec exposure"
        );
    }

    #[test]
    fn swagger_words_without_spec_shape_are_ignored() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/html")],
            "<html>Our docs mention swagger, openapi, paths, and info.</html>",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "Swagger/OpenAPI spec exposed"),
            "OpenAPI findings should require a parseable spec shape"
        );
    }

    #[test]
    fn block_comment_source_map_reference_is_reported() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/css")],
            "body{color:#111}/*# sourceMappingURL=app.css.map */",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings
            .iter()
            .any(|finding| finding.title == "JavaScript source map reference"));
    }

    #[test]
    fn source_map_reference_in_html_copy_is_ignored() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/html")],
            "<html><body>//# sourceMappingURL=example.js.map</body></html>",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "JavaScript source map reference"),
            "sourceMappingURL text outside JS/CSS responses should not create source map Findings"
        );
    }

    #[test]
    fn source_map_header_is_reported_even_when_body_is_empty() {
        let record = make_record(
            vec![],
            vec![
                ("content-type", "application/javascript"),
                ("sourcemap", "/static/app.js.map"),
            ],
            "",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings
            .iter()
            .any(|finding| finding.title == "Source map header present"));
    }

    #[test]
    fn source_map_header_on_html_response_is_ignored() {
        let record = make_record(
            vec![],
            vec![
                ("content-type", "text/html"),
                ("sourcemap", "/static/app.js.map"),
            ],
            "<html></html>",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "Source map header present"),
            "SourceMap headers outside JS/CSS responses should not create Findings"
        );
    }

    #[test]
    fn blank_source_map_header_is_ignored() {
        let record = make_record(vec![], vec![("sourcemap", "   ")], "", 200);
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(!findings
            .iter()
            .any(|finding| finding.title == "Source map header present"));
    }

    #[test]
    fn email_disclosure_is_not_reported_for_public_contact_copy() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/html")],
            "<html>Contact ADMIN@EXAMPLE.COM for docs.</html>",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(!findings
            .iter()
            .any(|f| f.title == "Email address in response"));
    }

    #[test]
    fn email_disclosure_is_not_reported_for_non_example_contact_copy() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/html")],
            "<html>Contact security@notexample.com for help.</html>",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(!findings
            .iter()
            .any(|f| f.title == "Email address in response"));
    }

    #[test]
    fn email_disclosure_reports_structured_user_email() {
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            r#"{"user":{"id":12,"email":"alice.smith@corp.test"}}"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings.iter().any(|f| {
                f.title == "Email address in response"
                    && f.evidence.contains("alice.smith@corp.test")
            }),
            "structured user/account email fields should still be reported"
        );
    }

    #[test]
    fn email_disclosure_ignores_role_account_json() {
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            r#"{"support_email":"security@corp.test"}"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|f| f.title == "Email address in response"),
            "role/contact mailbox fields should not create email Findings"
        );
    }

    #[test]
    fn email_disclosure_ignores_example_json_values() {
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            r#"{"user":{"email":"alice@example.com"}}"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|f| f.title == "Email address in response"),
            "example domains should not create email Findings"
        );
    }

    fn titles_for(path: &str, content_type: &str, body: &str) -> Vec<String> {
        let mut record = make_record(vec![], vec![], body, 200);
        record.path = path.to_string();
        if let Some(response) = &mut record.response {
            response.content_type = Some(content_type.into());
        }
        scan_transaction(&record, &ScannerConfig::default())
            .into_iter()
            .map(|finding| finding.title)
            .collect()
    }

    #[test]
    fn password_rule_ignores_code_labels_templates_and_field_names() {
        let password = "Password in response detected in response".to_string();
        let json = |body: &str| titles_for("/api/user", "application/json", body);
        let script = |body: &str| titles_for("/static/app.js", "application/javascript", body);

        assert!(json(r#"{"password":"CorrectHorseBattery99"}"#).contains(&password));
        assert!(script(r#"cfg={password:"Xk29pLm7Qw"}"#).contains(&password));
        for body in [
            r#"{"password":"{{user_pw}}"}"#,
            r#"{"password":"%PW_VALUE%"}"#,
            r#"{"password":"${DB_PASS}"}"#,
            r#"{"pwd":"[name=pw1234]"}"#,
            r#"{"password":"/account/reset"}"#,
            r#"{"pwd":"https://example.com/reset"}"#,
            r#"{"password":"Type it here"}"#,
            r#"{"password":"비밀번호를입력"}"#,
            r#"{"pwd":"user_password"}"#,
            r#"{"password":"new-password"}"#,
        ] {
            assert!(!json(body).contains(&password), "{body}");
        }
        for body in [
            "a={password:e.password,text:t}",
            "if(password=!0){}",
            r#"t.password="ConfirmMsg""#,
            r#"m="Your password: "+user.pin+"!""#,
        ] {
            assert!(!script(body).contains(&password), "{body}");
        }
        let page = titles_for(
            "/",
            "text/html",
            r#"<script>if("password"===e.type||x)</script>"#,
        );
        assert!(!page.contains(&password), "a comparison in a page's script");
    }

    fn password_match_for_test(body: &str, script: bool, corrected: bool) -> Option<String> {
        let legacy = Regex::new(r#"(?i)(?:\b|[_-])(?:password|passwd|pwd)\b\s*["']?\s*[:=]\s*(?:"([^"]{4,})"|'([^']{4,})'|([^\s"'<>{}]{4,}))"#).unwrap();
        if corrected {
            password_response_match(body, script, &legacy).map(|span| body[span].to_string())
        } else {
            legacy.captures_iter(body).find_map(|captures| {
                let m = captures.get(0)?;
                (password_candidate_looks_like_secret(&captures, script)
                    && !is_embedded_in_base64(body, &m))
                .then(|| m.as_str().to_string())
            })
        }
    }

    #[test]
    fn password_quotes_recover_matching_escapes_and_preserve_opposite_quotes() {
        for (body, legacy_found) in [
            (r#"password:"Ab12\"Cd34""#, false),
            (r#"password:'Ab12\'Cd34'"#, false),
            (r#"password:"Ab12'Cd34""#, true),
            (r#"password:'Ab12"Cd34'"#, true),
            (r#"password:"Ab12\\Cd34""#, true),
            (r#"password:"\u0041b12Cd34""#, true),
            (r#"password:"\u5BC6\u78BCAb12Cd34""#, true),
            (r#"password:"Enter\npasscode""#, true),
            (r#"password:"Ab12🔐Cd34""#, true),
        ] {
            assert_eq!(
                password_match_for_test(body, true, false).is_some(),
                legacy_found,
                "{body}"
            );
            assert_eq!(
                password_match_for_test(body, true, true).as_deref(),
                Some(body),
                "{body}"
            );
        }
    }

    #[test]
    fn password_quotes_respect_odd_and_even_backslash_runs() {
        for quote in ['"', '\''] {
            for count in 0..=8 {
                let slashes = "\\".repeat(count);
                let body = format!("password:{quote}Ab12Cd34{slashes}{quote}Ef56Gh78{quote}");
                let expected = if count % 2 == 0 {
                    format!("password:{quote}Ab12Cd34{slashes}{quote}")
                } else {
                    body.clone()
                };
                assert!(password_match_for_test(&body, true, false).is_some());
                assert_eq!(password_match_for_test(&body, true, true), Some(expected));
            }
        }
    }

    #[test]
    fn password_quotes_preserve_legacy_acceptance_when_complete_suffix_is_rejected() {
        for suffix in [
            " human label",
            "password",
            "passwd",
            "://host",
            "密碼",
            "placeholder",
        ] {
            let body = format!(r#"password:"Ab12Cd34\"{suffix}""#);
            assert!(
                password_match_for_test(&body, true, false).is_some(),
                "{body}"
            );
            assert!(
                !password_value_looks_like_secret(&body[10..body.len() - 1], true, true),
                "{body}"
            );
            assert_eq!(password_match_for_test(&body, true, true), Some(body));
        }
        // Extending evidence must not add a new base64 veto to a legacy hit.
        let body = format!(
            r#"{}_password:"Ab12Cd34\"Ef56Gh78"{}"#,
            "A".repeat(21),
            "B".repeat(21)
        );
        assert!(password_match_for_test(&body, true, false).is_some());
        assert_eq!(
            password_match_for_test(&body, true, true).as_deref(),
            Some(r#"_password:"Ab12Cd34\"Ef56Gh78""#)
        );
        // Newly recognized candidates still use the complete-span base64 guard.
        let body = format!(
            r#"{}_password:"Ab12\"Cd34"{};password:"Ef56Gh78""#,
            "A".repeat(21),
            "B".repeat(21)
        );
        assert_eq!(
            password_match_for_test(&body, true, true).as_deref(),
            Some(r#"password:"Ef56Gh78""#)
        );
    }

    #[test]
    fn password_quotes_keep_raw_scalar_and_byte_floors() {
        for (body, accepted) in [
            (r#"password:"Ab12Cd3""#, false),
            (r#"password:"Ab12Cd34""#, true),
            (r#"password:"Ab1\"Cd2""#, true),
            (r#"password:"Ab1\"Cd23""#, true),
            (r#"password:"🔐🌙✨""#, false),
            (r#"password:"🔐🌙✨🗝""#, true),
            (r#"password:"密碼Ab12Cd34""#, false),
        ] {
            assert_eq!(
                password_match_for_test(body, true, true).is_some(),
                accepted,
                "{body}"
            );
        }
    }

    #[test]
    fn password_quotes_find_later_candidates_independently() {
        for rejected in [
            "password:\"Enter passcode\";\n",
            "password:\"unterminated\n",
            "password:'unterminated\\\n",
        ] {
            let body = format!("{rejected}password:\"Ab12\\\"Cd34\";");
            assert_eq!(password_match_for_test(&body, true, false), None, "{body}");
            assert_eq!(
                password_match_for_test(&body, true, true).as_deref(),
                Some(r#"password:"Ab12\"Cd34""#),
                "{body}"
            );
        }
        let body = "password:\"unterminated\npassword:\"Ef56Gh78\";";
        assert_eq!(password_match_for_test(body, true, false), None);
        assert_eq!(
            password_match_for_test(body, true, true).as_deref(),
            Some(r#"password:"Ef56Gh78""#)
        );
        let body = r#"password:"Ab12\"Cd34";password:"Ef56Gh78""#;
        assert_eq!(
            password_match_for_test(body, true, false).as_deref(),
            Some(r#"password:"Ef56Gh78""#)
        );
        assert_eq!(
            password_match_for_test(body, true, true).as_deref(),
            Some(r#"password:"Ab12\"Cd34""#)
        );
    }

    #[test]
    fn password_quotes_do_not_invent_closing_delimiters() {
        for body in [
            "password:\"Ab12Cd34",
            "password:'Ab12Cd34\\",
            r#"password:"Ab1\"Cd2"#,
        ] {
            assert_eq!(password_match_for_test(body, true, false), None);
            assert_eq!(password_match_for_test(body, true, true), None);
        }
        // A legacy accepted prefix in malformed input is retained verbatim.
        let body = r#"password:"Ab12Cd34\""#;
        assert_eq!(password_quoted_end(body, 9), None);
        assert_eq!(
            password_match_for_test(body, true, false).as_deref(),
            Some(body)
        );
        assert_eq!(
            password_match_for_test(body, true, true).as_deref(),
            Some(body)
        );
    }

    #[test]
    fn password_quotes_leave_unquoted_behavior_unchanged() {
        for script in [false, true] {
            for body in [
                "db_password=Rj62Zk91Mn",
                "password=Ab12Cd3",
                "password=state.passcode",
                "password=!0;password=Ab12Cd34",
                "password=f(Ab12Cd34)",
                "password=Enter passcode;pwd=Ef56Gh78",
            ] {
                assert_eq!(
                    password_match_for_test(body, script, true),
                    password_match_for_test(body, script, false),
                    "{body}, script={script}"
                );
            }
        }
    }

    #[test]
    fn password_quotes_keep_ui_shaped_values_and_one_finding() {
        for value in ["#login-pw", "login_form_2", "required|min:8", "string(64)"] {
            for context in ["labels", "credentials"] {
                let body =
                    format!(r#"const {context}={{password:"{value}"}};password:"Ef56Gh78";"#);
                let expected = format!(r#"password:"{value}""#);
                assert_eq!(
                    password_match_for_test(&body, true, false),
                    Some(expected.clone())
                );
                assert_eq!(password_match_for_test(&body, true, true), Some(expected));
            }
        }
    }

    #[test]
    fn password_quotes_handle_many_malformed_heads_and_large_values() {
        let body = format!(
            "{}password:\"Ab12\\\"Cd34\"",
            "password:\"unterminated\n".repeat(10_000)
        );
        assert_eq!(
            password_match_for_test(&body, true, true).as_deref(),
            Some(r#"password:"Ab12\"Cd34""#)
        );
        let body = format!(
            "{}password:'Ab12\\'Cd34'",
            "pwd:\"Enter passcode\npwd:'Enter passcode\n".repeat(10_000)
        );
        assert_eq!(
            password_match_for_test(&body, true, true).as_deref(),
            Some("password:'Ab12\\'Cd34'")
        );
        let body = format!(r#"password:"Ab12\"{}""#, "🔐".repeat(64 * 1024));
        assert_eq!(password_match_for_test(&body, true, false), None);
        assert_eq!(password_match_for_test(&body, true, true), Some(body));
    }

    #[test]
    fn password_quotes_use_exact_raw_evidence_and_accepted_body_location() {
        let evidence = r#"password:"Ab12\"Cd34""#;
        let body =
            format!("🔐 introductory text\nconst cfg={{{evidence}}};\npassword:\"Ef56Gh78\";");
        let mut record = make_record(vec![], vec![("x-copy", evidence)], &body, 200);
        record.response.as_mut().unwrap().content_type = Some("application/javascript".into());
        let findings = scan_transaction(&record, &ScannerConfig::default());
        let passwords: Vec<_> = findings
            .iter()
            .filter(|f| f.title == "Password in response detected in response")
            .collect();
        assert_eq!(passwords.len(), 1);
        assert_eq!(passwords[0].evidence, evidence);
        assert_eq!(passwords[0].severity, Severity::High);
        assert_eq!(passwords[0].category, "disclosure");
        assert_eq!(
            passwords[0].location,
            Some(location_for_line(&record, "response", 5))
        );
    }

    #[test]
    fn password_quotes_preserve_display_truncation_and_provider_findings() {
        let raw = format!(r#"password:"Ab12\"{}""#, "🔐".repeat(30));
        let body = format!("{raw};const token='ghp_{}';", "Ab12".repeat(9));
        let mut record = make_record(vec![], vec![], &body, 200);
        record.response.as_mut().unwrap().content_type = Some("application/javascript".into());
        let findings = scan_transaction(&record, &ScannerConfig::default());
        let passwords: Vec<_> = findings
            .iter()
            .filter(|f| f.title == "Password in response detected in response")
            .collect();
        assert_eq!(passwords.len(), 1);
        assert_eq!(passwords[0].evidence, truncate_evidence(&raw, 80));
        assert!(passwords[0].evidence.ends_with("..."));
        assert_eq!(
            findings
                .iter()
                .filter(
                    |f| f.title == "GitHub Personal Access Token detected in response"
                        && f.severity == Severity::High
                )
                .count(),
            1
        );
    }

    #[test]
    fn card_rule_ignores_uuid_heads_and_scripts() {
        let visa = |path: &str, content_type: &str, body: &str| {
            titles_for(path, content_type, body)
                .iter()
                .any(|title| title.contains("Possible Visa card number"))
        };

        assert!(visa(
            "/pay",
            "application/json",
            r#"{"card_number":"4929123456789015"}"#
        ));
        assert!(!visa(
            "/pay",
            "application/json",
            r#"{"card_id":"49291234-5678-9015-1234-123456789abc"}"#
        ));
        assert!(!visa(
            "/checkout.js",
            "application/javascript",
            r#"var card_number="4929123456789015";"#
        ));
    }

    #[test]
    fn facebook_token_rule_needs_mixed_cases_and_digits() {
        let token = |tail: &str| {
            let body = format!(r#"{{"token":"EAAC{}"}}"#, tail.repeat(13));
            titles_for("/api", "application/json", &body)
                .iter()
                .any(|title| title.contains("Facebook Page Access Token"))
        };

        assert!(token("Ab1cD2eF"));
        assert!(!token("abcdEFGH"), "a run of letters is a minified name");
    }

    #[test]
    fn private_key_rule_needs_key_material_after_the_header() {
        let header = concat!("-----BEGIN RSA ", "PRIVATE KEY-----");
        let key = |body: String| {
            titles_for("/static/app.js", "application/javascript", &body)
                .iter()
                .any(|title| title.starts_with("Private Key"))
        };

        assert!(key(format!("{header}\n{}", "MIIEowIBAAKCAQEA".repeat(4))));
        assert!(
            !key(format!(r#"const H="{header}";"#)),
            "a PEM parser's constant"
        );
    }

    #[test]
    fn session_token_rule_ignores_short_numbers() {
        let reported = |sid: &str| {
            let cookie = format!("sid={sid}");
            let mut record = make_record(
                vec![("cookie", cookie.as_str())],
                vec![("content-type", "text/html")],
                "",
                200,
            );
            record.path = format!("/collect?sid={sid}");
            scan_transaction(&record, &ScannerConfig::default())
                .iter()
                .any(|finding| finding.title.starts_with("Session/token parameter"))
        };

        assert!(!reported("1760000000"), "a session start time");
        assert!(reported("Zm9vYmFyYmF6cXV4MTIz"));
    }

    #[test]
    fn cache_control_check_skips_what_a_page_loads_with_its_cookies() {
        let missing = |dest: &str, content_type: &str| {
            let mut record = make_record(
                vec![("cookie", "session=abc123"), ("sec-fetch-dest", dest)],
                vec![],
                "x",
                200,
            );
            if let Some(response) = &mut record.response {
                response.content_type = Some(content_type.into());
            }
            scan_transaction(&record, &ScannerConfig::default())
                .iter()
                .any(|finding| {
                    finding.title
                        == "Missing Cache-Control with session or authorization indicators"
                })
        };

        assert!(missing("empty", "application/json"));
        assert!(!missing("image", "image/png"));
        assert!(!missing("script", "application/javascript"));
    }

    #[test]
    fn cookie_flags_ignore_an_analytics_service_cookie() {
        let record = make_record(
            vec![],
            vec![("set-cookie", "everest_session_v2=abc123; Path=/")],
            "",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings.iter().any(|finding| finding.category == "cookie"),
            "the map names this cookie as Adobe Advertising's"
        );
    }

    #[test]
    fn exposures_the_map_names_are_findings() {
        let git = "[core]\n\trepositoryformatversion = 0\n\tbare = false\n";
        let found = titles_for("/.git/config", "text/plain", git);
        assert!(found.contains(&"Git repository config exposed".to_string()));
        assert!(
            !titles_for("/docs/setup", "text/html", &format!("<pre>{git}</pre>"))
                .iter()
                .any(|title| title == "Git repository config exposed"),
            "a page quoting the file is not the file"
        );

        let record = make_record(
            vec![],
            vec![
                ("x-upstream", "app-07.internal"),
                (
                    "set-cookie",
                    "BIGipServerpool_web=1677787402.20480.0000; Path=/",
                ),
            ],
            "",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());
        let finding = |title: &str| {
            findings
                .iter()
                .find(|finding| finding.title == title)
                .unwrap_or_else(|| panic!("{title}"))
        };
        assert_eq!(
            finding("Backend host header exposed").evidence,
            "x-upstream"
        );
        assert_eq!(
            finding("Backend address in a BIG-IP cookie").evidence,
            "Set-Cookie: BIGipServerpool_web"
        );
        assert!(
            !findings.iter().any(|finding| finding.category == "cookie"),
            "a load balancer's cookie is not a session token"
        );
    }

    fn findings_for_rule(record: &TransactionRecord, rule_id: &str) -> Vec<ScannerFinding> {
        let mut config = ScannerConfig::default();
        for &(id, _) in BUILTIN_RULES {
            config.rules.insert(id.to_string(), id == rule_id);
        }
        scan_transaction(record, &config)
    }

    #[test]
    fn comment_keywords_require_word_boundaries_in_html() {
        for comment in [
            "tokenization component",
            "secretary contact section",
            "internalization notes",
            "debugger display label",
            "TODO: update product badge",
            "FIXME: repair author biography",
        ] {
            let body = format!("<html><!-- {comment} --></html>");
            let record = make_record(vec![], vec![], &body, 200);
            assert!(findings_for_rule(&record, "info").is_empty(), "{comment}");
        }
        for comment in [
            "TODO: remove admin password check",
            "internal: /admin/recovery",
            "api_key: Ab19Cd28Ef37Gh46Ij55",
            "FIXME: auth bypass remains enabled",
            "token = Ab19Cd28Ef37Gh46Ij55",
            "access_token = Ab19Cd28Ef37Gh46Ij55",
            "client_secret = Ab19Cd28Ef37Gh46Ij55",
            "db_password = Ab19Cd28Ef37Gh46Ij55",
            "credentials for recovery",
            "TODO: verify authorization rules",
            "TODO: remove before production",
        ] {
            let body = format!("<html><!-- {comment} --></html>");
            let record = make_record(vec![], vec![], &body, 200);
            let found = findings_for_rule(&record, "info");
            assert!(
                found
                    .iter()
                    .any(|finding| finding.title.starts_with("HTML comment contains")),
                "{comment}"
            );
        }
    }

    #[test]
    fn html_comment_markers_in_non_html_content_are_not_comments() {
        for content_type in [
            "application/javascript",
            "text/css",
            "application/json",
            "text/plain",
            "application/json; profile=\"text/html\"",
        ] {
            let mut record = make_record(
                vec![],
                vec![("content-type", content_type)],
                r#"const template = "<!-- password field -->";"#,
                200,
            );
            record.response.as_mut().unwrap().content_type = Some(content_type.into());
            assert!(
                findings_for_rule(&record, "info").is_empty(),
                "{content_type}"
            );
        }
    }

    #[test]
    fn html_comments_follow_mime_essence_before_path_or_parameters() {
        for content_type in [
            "text/html",
            "application/xhtml+xml",
            "text/html; note=\"javascript\"",
        ] {
            let mut record = make_record(
                vec![],
                vec![("content-type", content_type)],
                "<html><!-- credentials for recovery --></html>",
                200,
            );
            record.path = "/bundle.js".into();
            let findings = findings_for_rule(&record, "info");
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.title.starts_with("HTML comment contains")),
                "{content_type}"
            );
        }
    }

    #[test]
    fn basic_auth_challenge_requires_an_actual_scheme_not_parameter_copy() {
        for challenge in [
            r#"Digest realm="basic account", nonce="abc123""#,
            r#"Bearer error_description="basic authentication is disabled""#,
            r#"Digest realm="member, Basic account", nonce="abc123""#,
            r#"Digest realm="member\", Basic account", nonce="abc123""#,
            r#"Digest realm="member", basic=enabled"#,
            r#"Digest realm="member", basic = enabled"#,
            "Digest realm=member, basic\t=enabled",
            r#"NotBasic realm="member""#,
        ] {
            let mut record = make_record(vec![], vec![("www-authenticate", challenge)], "", 401);
            record.scheme = "http".into();
            assert!(findings_for_rule(&record, "auth").is_empty(), "{challenge}");
        }
        for challenge in [
            r#"Basic realm="member""#,
            r#"bAsIc realm="member""#,
            "Basic\trealm=member",
            r#"Digest realm="member\\", Basic realm="fallback""#,
            r#"Digest realm="member, account", nonce="abc123", Basic realm="fallback""#,
        ] {
            let mut record = make_record(vec![], vec![("www-authenticate", challenge)], "", 401);
            record.scheme = "http".into();
            assert!(
                findings_for_rule(&record, "auth")
                    .iter()
                    .any(|finding| finding.title == "Server requests Basic auth over HTTP"),
                "{challenge}"
            );
        }
    }

    #[test]
    fn basic_auth_challenge_checks_multiple_fields_and_transport() {
        let mut record = make_record(
            vec![],
            vec![
                ("www-authenticate", r#"Bearer realm="member""#),
                ("www-authenticate", r#"Basic realm="fallback""#),
            ],
            "",
            401,
        );
        assert!(
            findings_for_rule(&record, "auth").is_empty(),
            "HTTPS is not cleartext"
        );
        record.scheme = "http".into();
        let findings = findings_for_rule(&record, "auth");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Server requests Basic auth over HTTP");
        assert!(findings[0].evidence.contains("fallback"));
    }

    #[test]
    fn cache_public_requires_exact_directives_and_honors_restrictions() {
        for cache_control in [
            "x-public-cache=enabled, max-age=60",
            "private=\"x-public-id\", max-age=60",
            "public, no-store",
            "public, private",
            "public=false, max-age=60",
        ] {
            let record = make_record(
                vec![("cookie", "session=Ab19Cd28Ef37Gh46")],
                vec![("cache-control", cache_control)],
                r#"{"private":true}"#,
                200,
            );
            assert!(
                findings_for_rule(&record, "misconfig").is_empty(),
                "{cache_control}"
            );
        }
        for cache_control in [
            "public, max-age=60",
            "PUBLIC, MAX-AGE=60",
            "public, x-no-store=disabled",
            "public, private=\"x-no-store, x-public-id\"",
        ] {
            let record = make_record(
                vec![("cookie", "session=Ab19Cd28Ef37Gh46")],
                vec![("cache-control", cache_control)],
                r#"{"private":true}"#,
                200,
            );
            assert!(
                findings_for_rule(&record, "misconfig")
                    .iter()
                    .any(|finding| finding.title
                        == "Cache-Control: public with session or authorization indicators"),
                "{cache_control}"
            );
        }
        let record = make_record(
            vec![("cookie", "session=Ab19Cd28Ef37Gh46")],
            vec![("cache-control", "public"), ("cache-control", "no-store")],
            r#"{"private":true}"#,
            200,
        );
        assert!(
            findings_for_rule(&record, "misconfig").is_empty(),
            "multiple Cache-Control fields share restrictions"
        );
    }

    #[test]
    fn cache_auth_context_excludes_empty_and_known_analytics_cookies() {
        for cookie in [
            "session=",
            "session=null",
            "session=\"\"",
            "everest_session_v2=Ab19Cd28Ef37Gh46",
        ] {
            let record = make_record(vec![("cookie", cookie)], vec![], r#"{"ok":true}"#, 200);
            assert!(
                findings_for_rule(&record, "misconfig").is_empty(),
                "{cookie}"
            );
            let record = make_record(vec![], vec![("set-cookie", cookie)], r#"{"ok":true}"#, 200);
            assert!(
                findings_for_rule(&record, "misconfig").is_empty(),
                "Set-Cookie: {cookie}"
            );
        }
        for cookie in [
            "session=Ab19Cd28Ef37Gh46",
            "session=Ab19Cd28Ef37Gh46; everest_session_v2=Ab19Cd28Ef37Gh46",
        ] {
            let record = make_record(vec![("cookie", cookie)], vec![], r#"{"private":true}"#, 200);
            assert!(
                findings_for_rule(&record, "misconfig")
                    .iter()
                    .any(|finding| finding.title
                        == "Missing Cache-Control with session or authorization indicators"),
                "{cookie}"
            );
        }
    }
    #[test]
    fn mixed_cookie_and_cache_fields_keep_real_auth_context() {
        let record = make_record(
            vec![],
            vec![
                ("set-cookie", "everest_session_v2=Ab19Cd28Ef37Gh46"),
                ("set-cookie", "session=Ab19Cd28Ef37Gh46"),
            ],
            r#"{"private":true}"#,
            200,
        );
        assert!(findings_for_rule(&record, "misconfig")
            .iter()
            .any(|finding| finding.title
                == "Missing Cache-Control with session or authorization indicators"));
        let record = make_record(
            vec![("cookie", "session=Ab19Cd28Ef37Gh46")],
            vec![("cache-control", "public"), ("cache-control", "private")],
            r#"{"private":true}"#,
            200,
        );
        assert!(findings_for_rule(&record, "misconfig").is_empty());
    }

    fn csp_titles(headers: Vec<(&str, &str)>) -> Vec<String> {
        let record = make_record(vec![], headers, "<html></html>", 200);
        findings_for_rule(&record, "misconfig")
            .into_iter()
            .map(|finding| finding.title)
            .collect()
    }

    #[test]
    fn csp_evidence_selects_unsafe_attribute_after_protected_script_prefix() {
        for protection in [
            "'nonce-Zml4dHVyZQ=='",
            "'sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='",
        ] {
            let policy = format!(
                "default-src 'self' https://example.com/default-source-padding-to-keep-the-operative-script-directive-after-the-truncation-boundary; script-src 'self' 'unsafe-inline' {protection}; script-src-attr 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
            );
            assert!(policy.find("script-src-attr").unwrap() > 120);
            let record = make_record(
                vec![],
                vec![("content-security-policy", &policy)],
                "<html><button onclick=\"void 0\">Example</button></html>",
                200,
            );
            let findings = findings_for_rule(&record, "misconfig");
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].title, "CSP allows unsafe-inline");
            assert_eq!(findings[0].severity, Severity::Medium);
            assert_eq!(findings[0].evidence, "script-src-attr 'unsafe-inline'");
            assert_eq!(
                findings[0].location,
                Some(FindingLocation {
                    side: "response".into(),
                    section: "header".into(),
                    line: Some(2),
                })
            );
            let restricted =
                policy.replace("script-src-attr 'unsafe-inline'", "script-src-attr 'none'");
            assert!(csp_titles(vec![("content-security-policy", &restricted)]).is_empty());
        }
    }

    #[test]
    fn csp_evidence_targets_enforced_header_despite_identical_decoys() {
        let directive = "ScRiPt-SrC-AtTr\t'UNSAFE-INLINE'";
        let record = make_record(
            vec![("x-example-copy", directive)],
            vec![
                ("x-example-copy", directive),
                ("Content-Security-Policy-Report-Only", directive),
                ("Content-Security-Policy", "img-src 'none'"),
                ("Content-Security-Policy", directive),
            ],
            directive,
            200,
        );
        let findings = findings_for_rule(&record, "misconfig");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence, directive);
        let location = findings[0].location.as_ref().unwrap();
        assert_eq!(location.side, "response");
        assert_eq!(location.section, "header");
        assert_eq!(location.line, Some(5));
        assert_eq!(
            raw_response_text_for_finding(&record)
                .unwrap()
                .lines()
                .nth(location.line.unwrap() - 1)
                .unwrap(),
            format!("Content-Security-Policy: {directive}")
        );
    }

    #[test]
    fn csp_evidence_preserves_first_duplicate_and_effective_fallback() {
        for (policy, expected) in [
            (
                "default-src 'unsafe-inline'; default-src 'none'",
                "default-src 'unsafe-inline'",
            ),
            (
                "script-src 'unsafe-inline'; script-src 'none'",
                "script-src 'unsafe-inline'",
            ),
            (
                "script-src-elem 'unsafe-inline'; script-src-elem 'none'",
                "script-src-elem 'unsafe-inline'",
            ),
            (
                "script-src-attr 'unsafe-inline'; script-src-attr 'none'",
                "script-src-attr 'unsafe-inline'",
            ),
            (
                "default-src 'unsafe-inline'; script-src-elem 'none'",
                "default-src 'unsafe-inline'",
            ),
            (
                "script-src 'unsafe-inline'; script-src-elem 'nonce-Zml4dHVyZQ=='",
                "script-src 'unsafe-inline'",
            ),
            (
                "script-src\u{a0}'none'; script-src 'unsafe-inline'",
                "script-src 'unsafe-inline'",
            ),
            (
                "script-src-attr; script-src-attr 'unsafe-inline'; script-src-elem 'unsafe-inline'",
                "script-src-elem 'unsafe-inline'",
            ),
        ] {
            let record = make_record(vec![], vec![("content-security-policy", policy)], "", 200);
            let findings = findings_for_rule(&record, "misconfig");
            assert_eq!(findings.len(), 1, "{policy}");
            assert_eq!(findings[0].evidence, expected, "{policy}");
        }
    }

    #[test]
    fn csp_evidence_uses_context_allowed_across_all_enforced_policies() {
        let element = "script-src-elem 'unsafe-inline'";
        let attribute = "script-src-elem 'none'; script-src-attr 'unsafe-inline'";
        let combined = format!("{element}, {attribute}");
        for (headers, line) in [
            (
                vec![
                    ("content-security-policy", element),
                    ("content-security-policy", attribute),
                ],
                3,
            ),
            (vec![("content-security-policy", combined.as_str())], 2),
        ] {
            let record = make_record(vec![], headers, "", 200);
            let findings = findings_for_rule(&record, "misconfig");
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].evidence, "script-src-attr 'unsafe-inline'");
            assert_eq!(findings[0].location.as_ref().unwrap().line, Some(line));
        }
        let restricted_element = "script-src-elem 'unsafe-inline'; script-src-attr 'none'";
        let blocked = format!("{restricted_element}, {attribute}");
        for headers in [
            vec![
                ("content-security-policy", restricted_element),
                ("content-security-policy", attribute),
            ],
            vec![("content-security-policy", blocked.as_str())],
        ] {
            assert!(csp_titles(headers).is_empty());
        }
    }

    #[test]
    fn csp_eval_evidence_uses_script_or_default_instead_of_element_decoy() {
        for directive in ["script-src", "default-src"] {
            let policy = format!(
                "script-src-elem 'unsafe-eval'; script-src-attr 'none'; {directive} 'nonce-Zml4dHVyZQ==' 'unsafe-eval'"
            );
            let record = make_record(vec![], vec![("content-security-policy", &policy)], "", 200);
            let findings = findings_for_rule(&record, "misconfig");
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].title, "CSP allows unsafe-eval");
            assert_eq!(
                findings[0].evidence,
                format!("{directive} 'nonce-Zml4dHVyZQ==' 'unsafe-eval'")
            );
        }
    }

    #[test]
    fn csp_evidence_bounds_long_directives_without_hiding_unsafe_keyword() {
        let policy = format!(
            "SCRIPT-SRC https://example.com/{} 'UNSAFE-INLINE' 'UNSAFE-EVAL'",
            "x".repeat(160)
        );
        let record = make_record(
            vec![],
            vec![
                ("content-security-policy-report-only", &policy),
                ("content-security-policy", &policy),
            ],
            "",
            200,
        );
        let findings = findings_for_rule(&record, "misconfig");
        assert_eq!(findings.len(), 2);
        for (finding, keyword) in findings.iter().zip(["'UNSAFE-INLINE'", "'UNSAFE-EVAL'"]) {
            assert_eq!(finding.evidence, format!("SCRIPT-SRC ... {keyword}"));
            assert!(finding.evidence.len() <= 120);
            assert_eq!(finding.location.as_ref().unwrap().line, Some(3));
        }
        for length in [120, 121] {
            let prefix = "script-src https://example.com/";
            let suffix = " 'unsafe-inline'";
            let policy = format!(
                "{prefix}{}{suffix}",
                "x".repeat(length - prefix.len() - suffix.len())
            );
            assert_eq!(policy.len(), length);
            let record = make_record(vec![], vec![("content-security-policy", &policy)], "", 200);
            let findings = findings_for_rule(&record, "misconfig");
            assert_eq!(findings.len(), 1);
            let expected = if length == 120 {
                policy.as_str()
            } else {
                "script-src ... 'unsafe-inline'"
            };
            assert_eq!(findings[0].evidence, expected);
            assert!(findings[0].evidence.len() <= 120);
        }
    }

    #[test]
    fn csp_evidence_keeps_host_dedup_and_rescan_first_record() {
        let first = make_record(
            vec![],
            vec![("content-security-policy", "script-src-attr 'unsafe-inline'")],
            "",
            200,
        );
        let mut later = make_record(
            vec![],
            vec![("content-security-policy", "script-src 'unsafe-inline'")],
            "",
            200,
        );
        later.path = "/another".into();
        let first_finding = findings_for_rule(&first, "misconfig").remove(0);
        let later_finding = findings_for_rule(&later, "misconfig").remove(0);
        assert_ne!(first_finding.evidence, later_finding.evidence);
        assert_eq!(
            finding_dedup_key(&first_finding),
            finding_dedup_key(&later_finding)
        );
        let mut legacy_preview = first_finding.clone();
        legacy_preview.evidence = "default-src 'self'; script-src 'nonce-Zml4dHVyZQ=='...".into();
        assert_eq!(
            finding_dedup_key(&legacy_preview),
            finding_dedup_key(&first_finding)
        );
        let mut config = ScannerConfig::default();
        for &(id, _) in BUILTIN_RULES {
            config.rules.insert(id.into(), id == "misconfig");
        }
        let mut rescan = Rescan::new(config);
        rescan.scan(&first);
        rescan.scan(&later);
        let (findings, scanned) = rescan.finish();
        assert_eq!(scanned.len(), 2);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].record_id, first.id);
        assert_eq!(findings[0].evidence, first_finding.evidence);
        assert_eq!(findings[0].location, first_finding.location);
    }

    #[test]
    fn csp_eval_uses_script_default_fallback_not_element_or_attribute() {
        for policy in [
            "script-src 'self'; script-src-elem 'unsafe-eval'",
            "default-src 'self'; script-src-attr 'unsafe-eval'",
            "script-src-elem 'unsafe-eval'",
        ] {
            assert!(
                !csp_titles(vec![("content-security-policy", policy)])
                    .contains(&"CSP allows unsafe-eval".into()),
                "{policy}"
            );
        }
        for policy in [
            "script-src 'unsafe-eval'; script-src-elem 'none'",
            "default-src 'unsafe-eval'; script-src-attr 'none'",
            "script-src 'unsafe-eval'; default-src 'none'",
        ] {
            assert!(
                csp_titles(vec![("content-security-policy", policy)])
                    .contains(&"CSP allows unsafe-eval".into()),
                "{policy}"
            );
        }
    }

    #[test]
    fn csp_inline_uses_only_effective_element_and_attribute_sources() {
        for policy in [
            "script-src 'unsafe-inline'; script-src-elem 'self'; script-src-attr 'none'",
            "default-src 'unsafe-inline'; script-src-elem 'self'; script-src-attr 'none'",
        ] {
            assert!(
                csp_titles(vec![("content-security-policy", policy)]).is_empty(),
                "{policy}"
            );
        }
        for policy in [
            "script-src 'unsafe-inline'; script-src-elem 'self'",
            "default-src 'unsafe-inline'; script-src-attr 'none'",
            "script-src-elem 'unsafe-inline'; script-src-attr 'none'",
            "script-src-elem 'none'; script-src-attr 'unsafe-inline'",
            "script-src 'nonce-abc123'; script-src-attr 'unsafe-inline'",
        ] {
            assert!(
                csp_titles(vec![("content-security-policy", policy)])
                    .contains(&"CSP allows unsafe-inline".into()),
                "{policy}"
            );
        }
    }

    #[test]
    fn csp_first_duplicate_directive_wins_in_both_orders() {
        for directive in [
            "default-src",
            "script-src",
            "script-src-elem",
            "script-src-attr",
        ] {
            let safe_first =
                format!("{directive} 'none'; {directive} 'unsafe-inline' 'unsafe-eval'");
            assert!(
                csp_titles(vec![("content-security-policy", &safe_first)]).is_empty(),
                "{safe_first}"
            );
            let empty_first = format!("{directive}; {directive} 'unsafe-inline' 'unsafe-eval'");
            assert!(
                csp_titles(vec![("content-security-policy", &empty_first)]).is_empty(),
                "{empty_first}"
            );
            let unsafe_first =
                format!("{directive} 'unsafe-inline' 'unsafe-eval'; {directive} 'none'");
            assert!(
                csp_titles(vec![("content-security-policy", &unsafe_first)])
                    .contains(&"CSP allows unsafe-inline".into()),
                "{unsafe_first}"
            );
        }
    }

    #[test]
    fn csp_intersects_multiple_enforced_headers_and_comma_policies() {
        let permissive = "script-src 'unsafe-inline' 'unsafe-eval'";
        let restrictive = "script-src 'none'";
        for headers in [
            vec![
                ("content-security-policy", permissive),
                ("content-security-policy", restrictive),
            ],
            vec![
                ("content-security-policy", restrictive),
                ("content-security-policy", permissive),
            ],
            vec![(
                "content-security-policy",
                "script-src 'unsafe-inline' 'unsafe-eval', script-src 'none'",
            )],
            vec![
                (
                    "content-security-policy",
                    "script-src-elem 'unsafe-inline'; script-src-attr 'none'",
                ),
                (
                    "content-security-policy",
                    "script-src-elem 'none'; script-src-attr 'unsafe-inline'",
                ),
            ],
        ] {
            assert!(csp_titles(headers.clone()).is_empty(), "{headers:?}");
        }
        for headers in [
            vec![
                ("content-security-policy", permissive),
                ("content-security-policy", permissive),
            ],
            vec![
                ("content-security-policy", permissive),
                ("content-security-policy", "img-src 'none'"),
            ],
            vec![
                ("content-security-policy", permissive),
                ("content-security-policy-report-only", restrictive),
            ],
        ] {
            let titles = csp_titles(headers.clone());
            assert!(
                titles.contains(&"CSP allows unsafe-inline".into()),
                "{headers:?}"
            );
            assert!(
                titles.contains(&"CSP allows unsafe-eval".into()),
                "{headers:?}"
            );
        }
        assert!(csp_titles(vec![("content-security-policy-report-only", permissive)]).is_empty());
    }

    #[test]
    fn csp_inline_overrides_require_valid_source_syntax() {
        for source in ["'nonce-abc123'", "'sha256-abc123'", "'strict-dynamic'"] {
            let policy = format!("script-src 'unsafe-inline' {source}");
            assert!(
                csp_titles(vec![("content-security-policy", &policy)]).is_empty(),
                "{policy}"
            );
        }
        for source in [
            "nonce-abc123",
            "'nonce-'",
            "'sha256-'",
            "'nonce-???'",
            "'nonce-abc==='",
            "'sha256-ab=c'",
        ] {
            let policy = format!("script-src 'unsafe-inline' {source}");
            assert!(
                csp_titles(vec![("content-security-policy", &policy)])
                    .contains(&"CSP allows unsafe-inline".into()),
                "{policy}"
            );
        }
        let policy = "script-src 'unsafe-inline'; script-src 'none'";
        assert!(csp_titles(vec![("content-security-policy", policy)])
            .contains(&"CSP allows unsafe-inline".into()));
    }

    #[test]
    fn comment_context_preserves_sniffed_html_and_metadata_xhtml() {
        let mut record = make_record(
            vec![],
            vec![],
            "<html><!-- internal route /admin --></html>",
            200,
        );
        record.response.as_mut().unwrap().content_type = None;
        assert!(findings_for_rule(&record, "info")
            .iter()
            .any(|finding| finding.title.starts_with("HTML comment contains")));
        record.response.as_mut().unwrap().content_type = Some("application/xhtml+xml".into());
        assert!(findings_for_rule(&record, "info")
            .iter()
            .any(|finding| finding.title.starts_with("HTML comment contains")));
        let record = make_record(
            vec![(
                "cookie",
                "everest_session_v2=Ab19Cd28Ef37Gh46; session=Ab19Cd28Ef37Gh46",
            )],
            vec![],
            r#"{"private":true}"#,
            200,
        );
        assert!(findings_for_rule(&record, "misconfig")
            .iter()
            .any(|finding| finding.title
                == "Missing Cache-Control with session or authorization indicators"));
    }

    #[test]
    fn refined_rules_keep_rescan_filtering_and_issue_deduplication() {
        let mut config = ScannerConfig::default();
        for &(id, _) in BUILTIN_RULES {
            config.rules.insert(id.to_string(), id == "auth");
        }
        let mut benign = make_record(
            vec![],
            vec![("www-authenticate", r#"Digest realm="basic account""#)],
            "",
            401,
        );
        benign.scheme = "http".into();
        let mut positive = make_record(
            vec![],
            vec![("www-authenticate", r#"Basic realm="member""#)],
            "",
            401,
        );
        positive.scheme = "http".into();
        let mut repeated = positive.clone();
        repeated.id = Uuid::new_v4();
        repeated.path = "/another".into();
        let mut rescan = Rescan::new(config);
        rescan.scan(&benign);
        rescan.scan(&positive);
        rescan.scan(&repeated);
        let (findings, scanned) = rescan.finish();
        assert_eq!(scanned.len(), 3);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].record_id, positive.id);
        assert_eq!(findings[0].title, "Server requests Basic auth over HTTP");
    }

    #[test]
    fn csp_empty_or_non_ascii_first_directives_follow_browser_parsing() {
        for directive in [
            "default-src",
            "script-src",
            "script-src-elem",
            "script-src-attr",
        ] {
            let policy = format!("{directive}; {directive} 'unsafe-inline' 'unsafe-eval'");
            assert!(
                csp_titles(vec![("content-security-policy", &policy)]).is_empty(),
                "{policy}"
            );
        }
        for directive in ["default-src", "script-src"] {
            for policy in [
                format!("{directive} 'unsafe-inline' 'unsafe-eval'; {directive} 'none'"),
                format!("{directive} 'none'; {directive} 'unsafe-inline' 'unsafe-eval'"),
            ] {
                let titles = csp_titles(vec![("content-security-policy", &policy)]);
                assert!(
                    titles.contains(&"CSP allows unsafe-inline".into()),
                    "{policy}"
                );
                assert!(
                    titles.contains(&"CSP allows unsafe-eval".into()),
                    "{policy}"
                );
            }
        }
    }

    fn cors_value_fixture(origin: &str, credentials: &str) -> TransactionRecord {
        let mut record = make_record(
            vec![("origin", origin)],
            vec![
                ("access-control-allow-origin", origin),
                ("access-control-allow-credentials", credentials),
            ],
            r#"{"private":true}"#,
            200,
        );
        // Synthetic distinct-site target; no network request is made.
        record.host = "127.0.0.1".into();
        record
    }

    #[test]
    fn cors_credentials_value_is_case_sensitive() {
        for origin in ["null", "https://example.com"] {
            for credentials in [
                "True",
                "TRUE",
                "false",
                "true, true",
                "true\u{a0}",
                "\u{a0}true",
            ] {
                let record = cors_value_fixture(origin, credentials);
                assert!(
                    findings_for_rule(&record, "cors").is_empty(),
                    "{origin} / {credentials:?}"
                );
            }
            for credentials in ["true", " \ttrue\t "] {
                let record = cors_value_fixture(origin, credentials);
                assert_eq!(
                    findings_for_rule(&record, "cors").len(),
                    1,
                    "{origin} / {credentials:?}"
                );
            }
        }
    }

    #[test]
    fn cors_origin_requires_exact_null_or_serialized_tuple_origin() {
        for origin in [
            "Null",
            "NULL",
            "*",
            "https://example.com/",
            "https://example.com/path",
            "https://example.com?query=1",
            "https://example.com#fragment",
            "https://user:pass@example.com",
            "https://example.com:443",
            "http://example.com:80",
            "https://192.000.002.001",
            "https://[2001:db8:0:0:0:0:0:1]",
            "file:///example",
            "data:text/plain,example",
            "blob:https://example.com/id",
            "HTTPS://EXAMPLE.COM",
            "https://example.com, https://example.com",
            "not-an-origin",
            "null\u{a0}",
        ] {
            let record = cors_value_fixture(origin, "true");
            assert!(findings_for_rule(&record, "cors").is_empty(), "{origin:?}");
        }
        for origin in [
            "null",
            "https://example.com",
            "https://example.com:8443",
            "http://example.com",
            "ftp://example.com",
            "ws://example.com",
            "wss://example.com",
            "https://192.0.2.1",
            "https://[2001:db8::1]",
            "https://xn--bcher-kva.example.com",
            "https://example.com.",
            "https://example.com:0",
        ] {
            let record = cors_value_fixture(origin, "true");
            let found = findings_for_rule(&record, "cors");
            assert_eq!(found.len(), 1, "{origin}");
            if origin == "null" {
                assert_eq!(found[0].title, "CORS: null origin with credentials");
                assert_eq!(found[0].severity, Severity::Medium);
            } else {
                assert_eq!(
                    found[0].title,
                    "CORS: another site allowed with credentials"
                );
                assert_eq!(found[0].severity, Severity::Low);
            }
        }
        for origin in ["null", "https://example.com"] {
            for (request, response) in [
                (format!(" \t{origin}\t "), origin.to_string()),
                (origin.to_string(), format!(" \t{origin}\t ")),
            ] {
                let mut record = cors_value_fixture(origin, "true");
                record.request.headers[0].value = request;
                record.response.as_mut().unwrap().headers[0].value = response;
                assert_eq!(findings_for_rule(&record, "cors").len(), 1);
            }
        }
        // This is a policy observation, not proof the captured request passed CORS.
        for request_origin in [None, Some("https://example.com")] {
            let mut record = cors_value_fixture("null", "true");
            record.request.headers.clear();
            if let Some(value) = request_origin {
                record.request.headers.push(HeaderRecord {
                    name: "origin".into(),
                    value: value.into(),
                });
            }
            let found = findings_for_rule(&record, "cors");
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].severity, Severity::Medium);
        }
    }

    #[test]
    fn cors_duplicate_response_fields_do_not_imply_browser_access() {
        for origin in ["null", "https://example.com"] {
            for (name, value) in [
                ("Access-Control-Allow-Origin", origin),
                ("Access-Control-Allow-Origin", ""),
                ("Access-Control-Allow-Credentials", "true"),
                ("Access-Control-Allow-Credentials", "false"),
            ] {
                let mut record = cors_value_fixture(origin, "true");
                record
                    .response
                    .as_mut()
                    .unwrap()
                    .headers
                    .push(HeaderRecord {
                        name: name.into(),
                        value: value.into(),
                    });
                assert!(
                    findings_for_rule(&record, "cors").is_empty(),
                    "{origin} / {name}: {value}"
                );
            }
        }
        let mut record = cors_value_fixture("https://example.com", "true");
        record.request.headers.push(HeaderRecord {
            name: "Origin".into(),
            value: "https://example.com".into(),
        });
        assert!(findings_for_rule(&record, "cors").is_empty());
        let mut record = cors_value_fixture("https://example.com", "true");
        record
            .response
            .as_mut()
            .unwrap()
            .headers
            .push(HeaderRecord {
                name: "Vary".into(),
                value: "Origin".into(),
            });
        assert_eq!(findings_for_rule(&record, "cors").len(), 1);
    }
    #[test]
    fn oracle_errors_require_a_complete_numeric_code_token() {
        for body in [
            "The flora-guide page was not found.",
            "flora-00942 guide unavailable",
            "ORA-",
            "ORA-code",
            "ORA-0094",
            "ORA-942: abbreviated code",
            "ORA-009420",
            "ORA-00942x",
            "error_ORA-00942",
            "ORA-00942_suffix",
            "éORA-00942",
            "ORA-00942é",
            "ORA-１２３４５",
        ] {
            let record = make_record(vec![], vec![], body, 404);
            assert!(findings_for_rule(&record, "error").is_empty(), "{body}");
        }
        for body in [
            "ORA-00942: table or view does not exist",
            "ora-01017: invalid username/password; logon denied",
            "[ORA-00600] internal error code",
            "ORA-06502: PL/SQL: numeric or value error\nORA-06512: at line 1",
            "ORA-00942",
        ] {
            let record = make_record(vec![], vec![], body, 500);
            let found = findings_for_rule(&record, "error");
            assert_eq!(found.len(), 1, "{body}");
            assert_eq!(
                found[0].title,
                "Oracle DB error disclosure in error response"
            );
            assert_eq!(found[0].severity, Severity::Medium);
        }
        let record = make_record(vec![], vec![], "ORA-00942", 200);
        assert!(findings_for_rule(&record, "error").is_empty());
    }

    #[test]
    fn oracle_error_evidence_uses_the_qualifying_occurrence() {
        let body = format!(
            "flora-guide ORA-short {}\nORA-00942: table or view does not exist",
            "가".repeat(80)
        );
        let record = make_record(vec![], vec![], &body, 500);
        let found = findings_for_rule(&record, "error");
        assert_eq!(found.len(), 1);
        assert!(found[0].evidence.contains("ORA-00942"));
        assert!(!found[0].evidence.contains("flora-guide"));
        assert!(!found[0].evidence.contains("ORA-short"));
        assert_eq!(found[0].location.as_ref().unwrap().line, Some(4));

        let body = format!(
            "flora-00942: table or view does not exist\n{}\nORA-00942: table or view does not exist",
            "가".repeat(80)
        );
        let record = make_record(vec![], vec![], &body, 500);
        let found = findings_for_rule(&record, "error");
        assert_eq!(found.len(), 1);
        assert!(found[0].evidence.contains("ORA-00942"));
        let location = found[0].location.as_ref().unwrap();
        assert_eq!(location.side, "response");
        assert_eq!(location.section, "body");
        assert_eq!(location.line, Some(5), "skip the identical code in a word");
    }

    #[test]
    fn coldfusion_heading_needs_local_diagnostic_context() {
        const HEADING: &str = "Error Occurred While Processing Request";
        for body in [
            HEADING.to_string(),
            format!(r#"{{"message":"{HEADING}","retry":true}}"#),
            format!("{HEADING}. ColdFusion guide is unavailable."),
            format!("{HEADING}. notcoldfusion.runtime.Example"),
            format!(
                "{HEADING} {} coldfusion.runtime.TemplateNotFoundException",
                "x".repeat(1100)
            ),
        ] {
            let record = make_record(vec![], vec![], &body, 500);
            assert!(findings_for_rule(&record, "error").is_empty(), "{body}");
        }
        let embedded_marker = "coldfusion.runtime.Example";
        let body = format!(
            "not{embedded_marker}{}{HEADING}",
            " ".repeat(512 - embedded_marker.len())
        );
        let record = make_record(vec![], vec![], &body, 500);
        assert!(findings_for_rule(&record, "error").is_empty());
        for marker in [
            "coldfusion.runtime.TemplateNotFoundException",
            "coldfusion.tagext.sql.QueryTag",
            "coldfusion.filter.FormValidationException",
            "coldfusion.sql.QueryTable",
            "coldfusion.compiler.ParseException",
            "Check the ColdFusion documentation to verify the syntax.",
            "Enable Robust Exception Information to provide greater detail.",
        ] {
            let body = format!("{HEADING}\n{marker}");
            let record = make_record(vec![], vec![], &body, 500);
            let found = findings_for_rule(&record, "error");
            assert_eq!(found.len(), 1, "{marker}");
            assert_eq!(found[0].title, "ColdFusion error in error response");
            assert_eq!(found[0].severity, Severity::Medium);
        }
        let body = format!("{HEADING}\ncoldfusion.filter.FormValidationException");
        let record = make_record(vec![], vec![], &body, 200);
        assert!(findings_for_rule(&record, "error").is_empty());
    }

    #[test]
    fn coldfusion_error_evidence_uses_the_corroborated_occurrence() {
        let body = format!(
            "FIRST Error Occurred While Processing Request {}\nError Occurred While Processing Request\ncoldfusion.runtime.TemplateNotFoundException",
            "가".repeat(400)
        );
        let record = make_record(vec![], vec![], &body, 500);
        let found = findings_for_rule(&record, "error");
        assert_eq!(found.len(), 1);
        assert!(found[0].evidence.contains("coldfusion.runtime."));
        assert!(!found[0].evidence.contains("FIRST"));
        let location = found[0].location.as_ref().unwrap();
        assert_eq!(location.side, "response");
        assert_eq!(location.section, "body");
        assert_eq!(location.line, Some(5), "locate the later vendor diagnostic");
        let duplicate_marker = "coldfusion.runtime.TemplateNotFoundException";
        let body = format!(
            "{duplicate_marker}\n{}\nError Occurred While Processing Request\n{duplicate_marker}",
            "가".repeat(400)
        );
        let record = make_record(vec![], vec![], &body, 500);
        let found = findings_for_rule(&record, "error");
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].location.as_ref().unwrap().line,
            Some(6),
            "skip an identical unassociated marker"
        );
        for body in [
            format!("Error Occurred While Processing Request {} coldfusion.runtime.TemplateNotFoundException", "가".repeat(66)),
            format!("coldfusion.runtime.TemplateNotFoundException {} Error Occurred While Processing Request", "가".repeat(66)),
        ] {
            let record = make_record(vec![], vec![], &body, 500);
            let found = findings_for_rule(&record, "error");
            assert_eq!(found.len(), 1);
            assert!(found[0].evidence.contains("Error Occurred While Processing Request"));
            assert!(found[0].evidence.contains("coldfusion.runtime."));
            assert!(found[0].evidence.len() <= 123);
            assert!(found[0].evidence.lines().next().unwrap().contains("coldfusion.runtime."));
            let location = found[0].location.as_ref().unwrap();
            assert_eq!(location.side, "response");
            assert_eq!(location.section, "body");
            assert_eq!(location.line, Some(3));
        }
    }

    #[test]
    fn hsts_missing_header_excludes_only_parsed_ip_literals() {
        for host in [
            "192.0.2.1",
            "127.0.0.1",
            "2001:db8::1",
            "[2001:db8::1]",
            "[::1]",
            "192.0.2.1:443",
            "192.0.2.1:8443",
            "[2001:db8::1]:8443",
            "[::1]:443",
        ] {
            let mut record = make_record(
                vec![("sec-fetch-dest", "document")],
                vec![],
                "<html></html>",
                200,
            );
            record.host = host.into();
            let found = findings_for_rule(&record, "header");
            assert!(
                !found
                    .iter()
                    .any(|f| f.title == "Missing Strict-Transport-Security"),
                "{host}"
            );
            assert!(
                found
                    .iter()
                    .any(|f| f.title == "Missing Content-Security-Policy"),
                "other header rules remain active for {host}"
            );
        }
        for host in [
            "example.com",
            "localhost",
            "192.0.2.1.example.com",
            "[example.com]",
            "[192.0.2.1]",
            "example.com:443",
            "192.0.2.1.example.com:8443",
            "192.0.2.1:",
            "192.0.2.1:invalid",
            "192.0.2.1:65536",
            "[2001:db8::1]:invalid",
            "[2001:db8::1]:65536",
            "[192.0.2.1]:443",
            "[2001:db8::1]suffix:443",
        ] {
            let mut record = make_record(
                vec![("sec-fetch-dest", "document")],
                vec![],
                "<html></html>",
                200,
            );
            record.host = host.into();
            let found = findings_for_rule(&record, "header");
            assert!(
                found
                    .iter()
                    .any(|f| f.title == "Missing Strict-Transport-Security"),
                "{host}"
            );
        }
        for (host, expected) in [
            ("example.com", true),
            ("example.com:8443", true),
            ("192.0.2.1", false),
            ("192.0.2.1:443", false),
            ("[2001:db8::1]:8443", false),
        ] {
            let mut record = make_record(
                vec![("sec-fetch-dest", "document")],
                vec![("location", "https://example.com/")],
                "",
                301,
            );
            record.host = host.into();
            assert_eq!(
                findings_for_rule(&record, "header")
                    .iter()
                    .any(|f| f.title == "Missing Strict-Transport-Security"),
                expected
            );
        }
    }

    #[test]
    fn jwt_and_cors_details_distinguish_observation_from_proven_impact() {
        let token = jwt_token(
            serde_json::json!({"alg": "HS256", "typ": "JWT"}),
            serde_json::json!({"sub": "synthetic"}),
        );
        let authorization = format!("Bearer {token}");
        let record = make_record(vec![("authorization", &authorization)], vec![], "", 200);
        let found = findings_for_rule(&record, "jwt");
        let jwt = found
            .iter()
            .find(|f| f.title == "JWT without expiration")
            .unwrap();
        assert_eq!(jwt.severity, Severity::Medium);
        assert!(jwt.detail.contains("Server-side session expiry"));
        assert!(jwt.detail.contains("does not establish indefinite reuse"));
        assert!(!jwt.detail.contains("never expire"));

        let record = cors_value_fixture("https://example.com", "true");
        let found = findings_for_rule(&record, "cors");
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].title,
            "CORS: another site allowed with credentials"
        );
        assert_eq!(found[0].severity, Severity::Low);
        assert!(found[0]
            .detail
            .contains("does not establish that credentials were sent"));
        assert!(found[0].detail.contains("intentional allowlist"));
        assert!(!found[0].detail.contains("read it with credentials"));
    }
}
