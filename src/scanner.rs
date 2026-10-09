use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::atomic::{AtomicU64, Ordering},
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
        }
    }

    /// Push a finding, deduplicating by transaction+host+path+category+title.
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
        for finding in findings.into_iter().take(self.max_entries) {
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
        let findings: Vec<_> = findings.into_iter().take(max_entries).collect();
        let seen = findings.iter().map(finding_dedup_key).collect();
        Self {
            max_entries,
            entries: RwLock::new(VecDeque::from(findings)),
            events,
            config: RwLock::new(sanitize_scanner_config(config)),
            seen: RwLock::new(seen),
            clear_generation: AtomicU64::new(0),
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
    record_id: Uuid,
    host: String,
    path: String,
    rule_id: String,
    category: String,
    title: String,
}

fn finding_dedup_key(finding: &ScannerFinding) -> FindingDedupKey {
    FindingDedupKey {
        record_id: finding.record_id,
        host: finding.host.clone(),
        path: finding.path.clone(),
        rule_id: finding.rule_id.clone(),
        category: finding.category.clone(),
        title: finding.title.clone(),
    }
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
    let bytes = body.as_bytes();
    let start = m.start();
    let end = m.end();

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

fn infer_finding_location(
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
    // Each part should be valid base64url
    parts[0..2].iter().all(|part| is_non_empty_base64url(part))
        && parts[2]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=')
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
            format!("JWT token in {source} has no 'exp' claim. Tokens without expiration never expire and can be reused indefinitely if stolen."),
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

    if should_check_hsts(record)
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

    // Only check successful HTML document responses. Error pages and fallback
    // HTML snippets create noisy checklist findings in passive capture.
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

fn should_check_hsts(record: &TransactionRecord) -> bool {
    record.scheme.eq_ignore_ascii_case("https") && matches!(record.status, Some(200..=399))
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
    if is_auth_cookie_name(name) {
        return true;
    }
    looks_like_jwt(&normalize_jwt_token_candidate(value))
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
        (
            r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
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
            for captures in re.captures_iter(body) {
                let Some(m) = captures.get(0) else {
                    continue;
                };
                if label == "Password in response"
                    && !password_candidate_looks_like_secret(&captures)
                {
                    continue;
                }
                if is_generic_secret_label(label)
                    && !generic_secret_candidate_looks_like_secret(&captures)
                {
                    continue;
                }
                if is_card_number_label(label)
                    && (!luhn_valid(m.as_str())
                        || card_number_is_known_test(m.as_str())
                        || !card_number_match_has_payment_context(body, &m))
                {
                    continue;
                }
                if is_database_connection_label(label)
                    && !database_connection_string_has_credentials(m.as_str())
                {
                    continue;
                }
                if label == "Mailgun API Key" && !mailgun_key_match_has_context(body, &m) {
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
                findings.push(make_finding(
                    record,
                    severity.clone(),
                    "disclosure",
                    format!("{label} detected in response"),
                    format!("{label} found in response body. This may expose sensitive information to clients."),
                    truncate_evidence(m.as_str(), 80),
                ));
                break;
            }
        }
    }

    check_internal_ip_disclosure(record, body, findings);
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

fn password_candidate_looks_like_secret(captures: &regex::Captures<'_>) -> bool {
    let Some(value) = captured_secret_value(captures) else {
        return false;
    };
    if value.len() < 8 {
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

    let acao = response
        .header_value("access-control-allow-origin")
        .map(str::trim);
    let acac = response
        .header_value("access-control-allow-credentials")
        .map(str::trim);

    if let Some(origin) = acao {
        if origin == "*" {
            // Browsers block wildcard ACAO when credentials are enabled, so this
            // is a policy smell rather than a browser-exploitable passive finding.
        } else if origin.eq_ignore_ascii_case("null")
            && acac.is_some_and(|v| v.eq_ignore_ascii_case("true"))
        {
            findings.push(make_finding(
                record,
                Severity::Medium,
                "cors",
                "CORS: null origin with credentials",
                "Access-Control-Allow-Origin: null with Access-Control-Allow-Credentials: true can expose credentialed responses to sandboxed or file-origin contexts.",
                "ACAO: null, ACAC: true",
            ));
        } else if acac.is_some_and(|v| v.eq_ignore_ascii_case("true")) {
            // Reflect origin with credentials — potentially dangerous
            let req_origin = record.request.header_value("origin").unwrap_or("").trim();
            if !req_origin.is_empty()
                && origin == req_origin
                && !origin_matches_request_origin(origin, &record.scheme, &record.host)
            {
                findings.push(make_finding(
                    record,
                    Severity::Medium,
                    "cors",
                    "CORS: reflected origin with credentials",
                    format!("Server reflects the request Origin ({origin}) with credentials allowed. If there is no whitelist, any site can read authenticated responses."),
                    format!("ACAO: {origin}, ACAC: true"),
                ));
            }
        }
    }
}

fn origin_matches_request_origin(origin: &str, request_scheme: &str, request_host: &str) -> bool {
    let Ok(base) = url::Url::parse(&format!("{request_scheme}://{request_host}")) else {
        return false;
    };
    let Ok(origin) = url::Url::parse(origin) else {
        return false;
    };
    let Some(base_host) = base.host_str() else {
        return false;
    };
    let Some(origin_host) = origin.host_str() else {
        return false;
    };
    base.scheme().eq_ignore_ascii_case(origin.scheme())
        && base_host.eq_ignore_ascii_case(origin_host)
        && base.port_or_known_default() == origin.port_or_known_default()
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
            // Only flag if it contains version-like info
            if server_header_value_reveals_stack(value) {
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

fn server_header_value_reveals_stack(value: &str) -> bool {
    if value.chars().any(|c| c.is_ascii_digit()) {
        return true;
    }
    value
        .to_ascii_lowercase()
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|token| matches!(token, "php" | "asp" | "aspnet"))
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
        if body_lower.contains(pattern) {
            if error_pattern_is_too_generic(pattern, &body_lower) {
                continue;
            }
            let evidence_start = body_lower.find(pattern).unwrap_or(0);
            let evidence = evidence_window(body, evidence_start, pattern.len(), 20, 60);
            findings.push(make_finding(
                record,
                severity.clone(),
                "error",
                format!("{label} in error response"),
                format!("HTTP {status} response contains {label}. Detailed error messages help attackers understand the backend stack."),
                truncate_evidence(evidence, 120),
            ));
            break; // One finding per response is enough
        }
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

    let header_value = |name: &str| -> Option<String> {
        response
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.clone())
    };

    // CSP with unsafe-inline or unsafe-eval
    if let Some(csp) = header_value("content-security-policy") {
        if csp_script_sources_have_actionable_unsafe_inline(&csp) {
            findings.push(make_finding(
                record,
                Severity::Medium,
                "misconfig",
                "CSP allows unsafe-inline",
                "Content-Security-Policy contains 'unsafe-inline', which undermines XSS protection by allowing inline scripts.",
                truncate_evidence(&csp, 120),
            ));
        }
        if csp_script_sources_contain(&csp, "'unsafe-eval'") {
            findings.push(make_finding(
                record,
                Severity::Medium,
                "misconfig",
                "CSP allows unsafe-eval",
                "Content-Security-Policy contains 'unsafe-eval', which allows eval() and similar dynamic code execution.",
                truncate_evidence(&csp, 120),
            ));
        }
    }

    // Cache-Control missing on authenticated responses
    let has_auth = has_authenticated_cache_context(record, response);
    if has_auth && !has_header("cache-control") {
        findings.push(make_finding(
            record,
            Severity::Low,
            "misconfig",
            "Missing Cache-Control on authenticated response",
            "Response to an authenticated request lacks Cache-Control header. Sensitive data may be cached by browsers or proxies.",
            "",
        ));
    }

    // Sensitive data in Cache-Control: public
    if has_auth {
        if let Some(cc) = header_value("cache-control") {
            let cc_lower = cc.to_ascii_lowercase();
            if cc_lower.contains("public") && !cc_lower.contains("no-store") {
                findings.push(make_finding(
                    record,
                    Severity::Medium,
                    "misconfig",
                    "Cache-Control: public on authenticated response",
                    "Authenticated response has Cache-Control: public, allowing caching of potentially sensitive data.",
                    format!("Cache-Control: {cc}"),
                ));
            }
        }
    }
}

fn csp_script_sources_contain(csp: &str, token: &str) -> bool {
    let token = token.to_ascii_lowercase();
    let mut default_sources: Option<Vec<String>> = None;
    let mut has_script_directive = false;
    let mut matched_script_directive = false;

    for directive in csp.split(';') {
        let mut parts = directive.split_whitespace();
        let Some(name) = parts.next() else {
            continue;
        };
        let name = name.to_ascii_lowercase();
        let sources = parts.map(str::to_ascii_lowercase).collect::<Vec<String>>();
        if name == "default-src" {
            default_sources = Some(sources);
            continue;
        }
        if matches!(
            name.as_str(),
            "script-src" | "script-src-elem" | "script-src-attr"
        ) {
            has_script_directive = true;
            matched_script_directive |= sources.iter().any(|source| source == &token);
        }
    }

    if has_script_directive {
        matched_script_directive
    } else {
        default_sources
            .as_deref()
            .is_some_and(|sources| sources.iter().any(|source| source == &token))
    }
}

fn csp_script_sources_have_actionable_unsafe_inline(csp: &str) -> bool {
    let mut default_sources: Option<Vec<String>> = None;
    let mut script_sources: Option<Vec<String>> = None;
    let mut script_elem_sources: Option<Vec<String>> = None;
    let mut script_attr_sources: Option<Vec<String>> = None;

    for directive in csp.split(';') {
        let mut parts = directive.split_whitespace();
        let Some(name) = parts.next() else {
            continue;
        };
        let name = name.to_ascii_lowercase();
        let sources = parts.map(str::to_ascii_lowercase).collect::<Vec<String>>();
        if name == "default-src" {
            default_sources = Some(sources);
            continue;
        }
        match name.as_str() {
            "script-src" => script_sources = Some(sources),
            "script-src-elem" => script_elem_sources = Some(sources),
            "script-src-attr" => script_attr_sources = Some(sources),
            _ => {}
        }
    }

    let effective_script = script_sources.as_deref().or(default_sources.as_deref());
    let effective_elem = script_elem_sources
        .as_deref()
        .or(script_sources.as_deref())
        .or(default_sources.as_deref());
    let effective_attr = script_attr_sources
        .as_deref()
        .or(script_sources.as_deref())
        .or(default_sources.as_deref());

    for sources in [effective_script, effective_elem, effective_attr]
        .into_iter()
        .flatten()
    {
        if csp_sources_contain(sources, "'unsafe-inline'")
            && !csp_sources_have_nonce_or_hash(sources)
        {
            return true;
        }
    }
    false
}

fn csp_sources_contain(sources: &[String], token: &str) -> bool {
    sources.iter().any(|source| source == token)
}

fn csp_sources_have_nonce_or_hash(sources: &[String]) -> bool {
    sources.iter().any(|source| {
        let source = source.trim_matches('\'');
        source.starts_with("nonce-")
            || source.starts_with("sha256-")
            || source.starts_with("sha384-")
            || source.starts_with("sha512-")
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
    if let Ok(comment_re) = Regex::new(r"<!--[\s\S]{0,500}?-->") {
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
        if comment_lower.contains(keyword) {
            return Some(*keyword);
        }
    }

    const DEV_NOTE_KEYWORDS: &[&str] =
        &["todo", "fixme", "hack", "bug", "temporary", "remove before"];
    DEV_NOTE_KEYWORDS
        .iter()
        .find(|keyword| comment_lower.contains(**keyword))
        .copied()
        .filter(|_| {
            ["auth", "login", "session", "role", "permission", "prod"]
                .iter()
                .any(|context| comment_lower.contains(context))
        })
}

// ── Rule 10: Authentication Issues ──

fn check_auth_issues(record: &TransactionRecord, findings: &mut Vec<ScannerFinding>) {
    // Session token in URL
    if let Some(param) = session_token_parameter_in_url(&record.path) {
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

    // WWW-Authenticate header reveals auth scheme
    if let Some(response) = &record.response {
        if let Some(www_auth) = response.header_value("www-authenticate") {
            let wa_lower = www_auth.to_ascii_lowercase();
            if wa_lower.contains("basic") && record.scheme == "http" {
                findings.push(make_finding(
                    record,
                    Severity::Medium,
                    "auth",
                    "Server requests Basic auth over HTTP",
                    "WWW-Authenticate header requests Basic authentication over unencrypted HTTP.",
                    format!("WWW-Authenticate: {www_auth}"),
                ));
            }
        }
    }
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

fn session_token_parameter_in_url(path: &str) -> Option<String> {
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
            && session_token_value_looks_sensitive(&decoded, value))
        .then_some(decoded)
    })
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
    async fn scanner_store_deduplicates_by_path_too() {
        let store = ScannerStore::new(10);
        let mut first = finding("Missing CSP");
        first.path = "/login".to_string();
        let mut second = finding("Missing CSP");
        second.path = "/admin".to_string();

        store.push(first).await;
        store.push(second).await;

        let findings = store.list(None).await;
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|finding| finding.path == "/login"));
        assert!(findings.iter().any(|finding| finding.path == "/admin"));
    }

    #[tokio::test]
    async fn scanner_store_keeps_same_path_findings_for_distinct_records() {
        let store = ScannerStore::new(10);
        let first = finding("Missing CSP");
        let mut second = first.clone();
        second.id = Uuid::new_v4();
        second.record_id = Uuid::new_v4();

        store.push(first).await;
        store.push(second).await;

        let findings = store.list(None).await;
        assert_eq!(findings.len(), 2);
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
    fn hsts_check_runs_for_non_html_https_redirects() {
        let mut record = make_record(
            vec![],
            vec![("location", "https://example.com/login")],
            "",
            302,
        );
        if let Some(response) = &mut record.response {
            response.content_type = None;
        }
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "Missing Strict-Transport-Security"),
            "HSTS is a host-level HTTPS policy and should be checked on redirects"
        );
        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "Missing Content-Security-Policy"),
            "page-only header checks should still skip non-HTML redirects"
        );
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
        for path in [
            "/maps?api_key=AIzaabcdefghijklmnopqrstuvwxyz123456789",
            "/checkout?api_key=pk_live_1234567890abcdefghijklmnop",
        ] {
            let mut record = make_record(vec![], vec![("content-type", "text/html")], "", 200);
            record.path = path.to_string();
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
        let mut record = make_record(vec![], vec![("content-type", "text/html")], "", 200);
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
    fn cache_control_check_treats_auth_cookies_as_authenticated() {
        let record = make_record(
            vec![("cookie", "session=abc123; theme=dark")],
            vec![("content-type", "application/json")],
            r#"{"private":true}"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings
            .iter()
            .any(|finding| finding.title == "Missing Cache-Control on authenticated response"));
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

        assert!(findings
            .iter()
            .any(|finding| finding.title == "Missing Cache-Control on authenticated response"));
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
                .any(|finding| finding.title == "Missing Cache-Control on authenticated response"),
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
            findings
                .iter()
                .any(|finding| finding.title == "Missing Cache-Control on authenticated response"),
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

        assert!(findings
            .iter()
            .any(|finding| finding.title == "Cache-Control: public on authenticated response"));
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
            !findings
                .iter()
                .any(|finding| finding.title == "Missing Cache-Control on authenticated response"),
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
            !findings
                .iter()
                .any(|finding| finding.title == "Missing Cache-Control on authenticated response"),
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

    #[test]
    fn cors_reflected_same_origin_with_credentials_is_ignored() {
        let record = make_record(
            vec![("origin", "https://example.com")],
            vec![
                ("access-control-allow-origin", "https://example.com"),
                ("access-control-allow-credentials", "true"),
            ],
            "",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "CORS: reflected origin with credentials"),
            "same-origin reflection should not be reported as arbitrary reflected CORS"
        );
    }

    #[test]
    fn cors_reflected_cross_origin_with_credentials_is_reported() {
        let record = make_record(
            vec![("origin", "https://evil.example")],
            vec![
                ("access-control-allow-origin", "https://evil.example"),
                ("access-control-allow-credentials", "true"),
            ],
            "",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings
            .iter()
            .any(|finding| finding.title == "CORS: reflected origin with credentials"));
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
    fn server_disclosure_still_reports_php_token_without_version() {
        let record = make_record(vec![], vec![("x-powered-by", "PHP")], "", 200);
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "X-Powered-By version disclosure"),
            "explicit PHP stack tokens should still be reported even without a version number"
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
        let mut record = make_record(vec![], vec![("content-type", "text/html")], "", 200);
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
}
