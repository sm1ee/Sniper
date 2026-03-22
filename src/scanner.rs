use std::collections::{HashSet, VecDeque};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

use crate::model::{BodyEncoding, MessageRecord, TransactionRecord};

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
    pub enabled: bool,
    /// Per-rule toggle. Key = rule id (e.g. "jwt", "header"), value = enabled.
    pub rules: std::collections::HashMap<String, bool>,
    pub custom_rules: Vec<CustomRule>,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        let mut rules = std::collections::HashMap::new();
        for &(id, _) in BUILTIN_RULES {
            rules.insert(id.to_string(), true);
        }
        Self {
            enabled: true,
            rules,
            custom_rules: Vec::new(),
        }
    }
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
    pub severity: Severity,
    pub category: String,
    pub title: String,
    pub detail: String,
    pub evidence: String,
    pub host: String,
    pub path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FindingSummary {
    pub id: Uuid,
    pub record_id: Uuid,
    pub found_at: DateTime<Utc>,
    pub severity: Severity,
    pub category: String,
    pub title: String,
    pub host: String,
    pub path: String,
}

impl ScannerFinding {
    pub fn summary(&self) -> FindingSummary {
        FindingSummary {
            id: self.id,
            record_id: self.record_id,
            found_at: self.found_at,
            severity: self.severity.clone(),
            category: self.category.clone(),
            title: self.title.clone(),
            host: self.host.clone(),
            path: self.path.clone(),
        }
    }
}

// ── Finding store ──

pub struct ScannerStore {
    max_entries: usize,
    entries: RwLock<VecDeque<ScannerFinding>>,
    events: broadcast::Sender<FindingSummary>,
    config: RwLock<ScannerConfig>,
    /// Dedup set: key = "host:path:category:title"
    seen: RwLock<HashSet<String>>,
}

impl ScannerStore {
    pub fn new(max_entries: usize) -> Self {
        let (events, _) = broadcast::channel(max_entries.max(64));
        Self {
            max_entries,
            entries: RwLock::new(VecDeque::new()),
            events,
            config: RwLock::new(ScannerConfig::default()),
            seen: RwLock::new(HashSet::new()),
        }
    }

    /// Push a finding, deduplicating by host+category+title.
    pub async fn push(&self, finding: ScannerFinding) {
        let dedup_key = format!(
            "{}:{}:{}",
            finding.host, finding.category, finding.title
        );
        {
            let mut seen = self.seen.write().await;
            if !seen.insert(dedup_key) {
                return; // duplicate — skip
            }
        }
        let summary = finding.summary();
        let mut entries = self.entries.write().await;
        entries.push_front(finding);
        while entries.len() > self.max_entries {
            entries.pop_back();
        }
        let _ = self.events.send(summary);
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
        self.entries.write().await.clear();
        // Keep `seen` intact so cleared findings are not re-detected from new traffic.
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
        *self.config.write().await = new_config;
    }

    /// Create a store pre-populated with persisted findings.
    pub fn from_findings(max_entries: usize, findings: Vec<ScannerFinding>) -> Self {
        let (events, _) = broadcast::channel(max_entries.max(64));
        let mut seen = HashSet::new();
        for f in &findings {
            seen.insert(format!("{}:{}:{}", f.host, f.category, f.title));
        }
        Self {
            max_entries,
            entries: RwLock::new(VecDeque::from(findings)),
            events,
            config: RwLock::new(ScannerConfig::default()),
            seen: RwLock::new(seen),
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

    findings
}

/// Execute a single custom regex rule against the transaction.
fn check_custom_rule(record: &TransactionRecord, rule: &CustomRule, findings: &mut Vec<ScannerFinding>) {
    let re = match Regex::new(&rule.pattern) {
        Ok(re) => re,
        Err(_) => return, // invalid pattern — skip silently
    };

    let targets: Vec<(&str, String)> = match rule.target.as_str() {
        "response_body" => {
            if let Some(response) = &record.response {
                if is_binary_body(response) {
                    vec![]
                } else {
                    vec![("response body", response.body_preview.clone())]
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
                    .filter(|h| {
                        rule.header_name.is_empty()
                            || h.name.eq_ignore_ascii_case(&rule.header_name)
                    })
                    .map(|h| (h.name.as_str(), h.value.clone()))
                    .collect::<Vec<_>>()
                    .into_iter()
                    .map(|(n, v)| {
                        // Need to own the name for the tuple
                        (n as &str, v)
                    })
                    .collect::<Vec<_>>()
            } else {
                vec![]
            }
        }
        "request_header" => {
            record
                .request
                .headers
                .iter()
                .filter(|h| {
                    rule.header_name.is_empty()
                        || h.name.eq_ignore_ascii_case(&rule.header_name)
                })
                .map(|h| ("request header", h.value.clone()))
                .collect()
        }
        _ => vec![],
    };

    for (_source, text) in targets {
        if let Some(m) = re.find(&text) {
            findings.push(make_finding(
                record,
                rule.severity.clone(),
                &rule.category,
                &rule.name,
                &rule.description,
                truncate_evidence(m.as_str(), 120),
            ));
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
        severity,
        category: category.to_string(),
        title: title.into(),
        detail: detail.into(),
        evidence: evidence.into(),
        host: record.host.clone(),
        path: record.path.clone(),
    }
}

// ── Rule 1: JWT Analysis ──

fn check_jwt(record: &TransactionRecord, findings: &mut Vec<ScannerFinding>) {
    let mut jwt_sources: Vec<(&str, String)> = Vec::new();

    // Check Authorization header in request
    if let Some(auth) = record.request.header_value("authorization") {
        let token = auth.strip_prefix("Bearer ").or_else(|| auth.strip_prefix("bearer "));
        if let Some(token) = token {
            if looks_like_jwt(token) {
                jwt_sources.push(("Authorization header", token.to_string()));
            }
        }
    }

    // Check cookies for JWTs
    for header in &record.request.headers {
        if header.name.eq_ignore_ascii_case("cookie") {
            for part in header.value.split(';') {
                let part = part.trim();
                if let Some((_name, value)) = part.split_once('=') {
                    if looks_like_jwt(value.trim()) {
                        jwt_sources.push(("Cookie", value.trim().to_string()));
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
                        if looks_like_jwt(val.trim()) {
                            jwt_sources.push(("Set-Cookie", val.trim().to_string()));
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
    parts.iter().all(|part| {
        !part.is_empty()
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=')
    })
}

fn extract_jwt_from_text(text: &str) -> Vec<String> {
    // Simple pattern: eyJ followed by base64url.base64url.base64url
    let re = Regex::new(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").unwrap();
    re.find_iter(text)
        .map(|m| m.as_str().to_string())
        .collect()
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
    let payload_json = decode_jwt_part(parts[1]).unwrap_or_default();

    // Check alg:none
    let header_lower = header_json.to_ascii_lowercase();
    if header_lower.contains("\"alg\"") && header_lower.contains("\"none\"") {
        findings.push(make_finding(
            record,
            Severity::High,
            "jwt",
            "JWT with alg:none",
            format!("JWT token in {source} uses algorithm \"none\", which means no signature verification. This is a critical vulnerability if the server accepts this token."),
            truncate_evidence(token, 120),
        ));
    }

    // Check weak algorithms
    for weak_alg in &["hs256", "hs384", "hs512"] {
        if header_lower.contains(&format!("\"{weak_alg}\"")) {
            findings.push(make_finding(
                record,
                Severity::Low,
                "jwt",
                format!("JWT uses symmetric algorithm ({})", weak_alg.to_uppercase()),
                format!("JWT token in {source} uses symmetric signing ({0}). If the secret is weak or shared, tokens can be forged.", weak_alg.to_uppercase()),
                truncate_evidence(token, 120),
            ));
        }
    }

    // Check expiration
    if payload_json.contains("\"exp\"") {
        // Try to extract exp value
        if let Some(exp) = extract_json_number(&payload_json, "exp") {
            let now = Utc::now().timestamp();
            if exp < now {
                findings.push(make_finding(
                    record,
                    Severity::Info,
                    "jwt",
                    "Expired JWT token",
                    format!("JWT token in {source} has expired (exp: {exp}, now: {now})."),
                    truncate_evidence(token, 120),
                ));
            }
        }
    } else {
        findings.push(make_finding(
            record,
            Severity::Medium,
            "jwt",
            "JWT without expiration",
            format!("JWT token in {source} has no 'exp' claim. Tokens without expiration never expire and can be reused indefinitely if stolen."),
            truncate_evidence(token, 120),
        ));
    }

    // Always report JWT detection as info (so user knows JWTs are in use)
    findings.push(make_finding(
        record,
        Severity::Info,
        "jwt",
        format!("JWT detected in {source}"),
        format!("JWT token found in {source}. Header: {header_json}"),
        truncate_evidence(token, 120),
    ));
}

// ── Rule 2: Security Headers ──

fn check_security_headers(record: &TransactionRecord, findings: &mut Vec<ScannerFinding>) {
    let response = match &record.response {
        Some(r) => r,
        None => return,
    };

    // Only check HTML responses
    let ct = response.content_type.as_deref().unwrap_or("");
    if !ct.contains("text/html") && !ct.is_empty() {
        return;
    }

    let has_header = |name: &str| -> bool {
        response
            .headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case(name))
    };

    if !has_header("content-security-policy") {
        findings.push(make_finding(
            record,
            Severity::Low,
            "header",
            "Missing Content-Security-Policy",
            "No CSP header found. CSP helps prevent XSS and data injection attacks.",
            "",
        ));
    }

    if !has_header("strict-transport-security") && record.scheme == "https" {
        findings.push(make_finding(
            record,
            Severity::Low,
            "header",
            "Missing Strict-Transport-Security",
            "HTTPS response lacks HSTS header. Browsers may allow HTTP downgrade attacks.",
            "",
        ));
    }

    if !has_header("x-content-type-options") {
        findings.push(make_finding(
            record,
            Severity::Info,
            "header",
            "Missing X-Content-Type-Options",
            "No X-Content-Type-Options: nosniff header. Browsers may MIME-sniff the response.",
            "",
        ));
    }

    if !has_header("x-frame-options") && !has_csp_frame_ancestors(response) {
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

fn has_csp_frame_ancestors(response: &crate::model::MessageRecord) -> bool {
    response
        .headers
        .iter()
        .any(|h| {
            h.name.eq_ignore_ascii_case("content-security-policy")
                && h.value.to_ascii_lowercase().contains("frame-ancestors")
        })
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

        let cookie_name = header
            .value
            .split('=')
            .next()
            .unwrap_or("unknown")
            .trim();
        let lower = header.value.to_ascii_lowercase();

        if !lower.contains("httponly") {
            findings.push(make_finding(
                record,
                Severity::Medium,
                "cookie",
                format!("Cookie '{cookie_name}' missing HttpOnly flag"),
                "Cookie accessible via JavaScript. If XSS exists, attacker can steal this cookie.",
                &header.value,
            ));
        }

        if !lower.contains("secure") && record.scheme == "https" {
            findings.push(make_finding(
                record,
                Severity::Medium,
                "cookie",
                format!("Cookie '{cookie_name}' missing Secure flag"),
                "Cookie may be sent over unencrypted HTTP connections, exposing it to interception.",
                &header.value,
            ));
        }

        if !lower.contains("samesite") {
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
        // ── Cloud provider keys ──
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", Severity::High),
        (
            r"(?i)(aws_secret_access_key|aws_secret)\s*[=:]\s*[A-Za-z0-9/+=]{40}",
            "AWS Secret Access Key",
            Severity::High,
        ),
        (r"AIza[0-9A-Za-z_-]{35}", "Google API Key", Severity::High),
        (
            r"(?i)\b[0-9]+-[a-z0-9_]+\.apps\.googleusercontent\.com\b",
            "Google OAuth Client ID",
            Severity::Medium,
        ),
        // ── AI / ML tokens ──
        (r"sk-proj-[A-Za-z0-9_-]{74,}", "OpenAI Project API Key", Severity::Critical),
        (r"sk-svcacct-[A-Za-z0-9_-]{74,}", "OpenAI Service Account Key", Severity::Critical),
        (r"sk-ant-api03-[a-zA-Z0-9_\-]{93}", "Anthropic API Key", Severity::Critical),
        (r"sk-ant-admin01-[a-zA-Z0-9_\-]{80,}", "Anthropic Admin Key", Severity::Critical),
        (r"hf_[a-zA-Z]{34}", "HuggingFace Token", Severity::High),
        (r"gsk_[a-zA-Z0-9]{48}", "Groq API Key", Severity::Critical),
        (r"pplx-[a-zA-Z0-9]{48}", "Perplexity API Key", Severity::Critical),
        (r"xai-[a-zA-Z0-9]{20,}", "xAI (Grok) API Key", Severity::Critical),
        (r"r8_[a-zA-Z0-9]{38}", "Replicate API Token", Severity::High),
        // ── VCS / DevOps tokens ──
        (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token", Severity::High),
        (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth Token", Severity::High),
        (r"ghs_[A-Za-z0-9]{36}", "GitHub App Token", Severity::High),
        (r"ghr_[A-Za-z0-9]{36}", "GitHub Refresh Token", Severity::High),
        (r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}", "GitHub Fine-Grained PAT", Severity::High),
        (r"glpat-[A-Za-z0-9\-]{20,}", "GitLab Personal Access Token", Severity::High),
        (r"gl[a-z]{2,4}-[A-Za-z0-9\-]{20,}", "GitLab Token", Severity::High),
        (r"ATATT3[A-Za-z0-9_\-=]{100,}", "Atlassian/Jira API Token", Severity::High),
        (r"dop_v1_[a-f0-9]{64}", "DigitalOcean PAT", Severity::High),
        (r"dapi[a-f0-9]{32}", "Databricks API Token", Severity::High),
        (r"LTAI[a-z0-9]{20}", "Alibaba Cloud Access Key", Severity::High),
        (r"dckr_pat_[a-zA-Z0-9_-]{20,}", "Docker Hub PAT", Severity::High),
        (r"pscale_tkn_[a-zA-Z0-9_=-]{32,}", "PlanetScale Token", Severity::High),
        (r"sbp_[a-f0-9]{40,}", "Supabase PAT", Severity::High),
        (r"dt0c01\.[a-z0-9]{24}\.[a-z0-9]{64}", "Dynatrace API Token", Severity::High),
        (r"pul-[a-f0-9]{40}", "Pulumi API Token", Severity::High),
        (r"AKCp[A-Za-z0-9]{69}", "JFrog Artifactory Token", Severity::High),
        (r"ntn_[a-zA-Z0-9]{40,}", "Notion API Token", Severity::High),
        (r"figd_[a-zA-Z0-9_-]{40,}", "Figma PAT", Severity::High),
        (r"EAA[MC][a-zA-Z0-9]{100,}", "Facebook Page Access Token", Severity::High),
        // ── Chat / SaaS tokens ──
        (r"xox[bpras]-[A-Za-z0-9\-]{10,}", "Slack Token", Severity::High),
        (
            r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+",
            "Slack Webhook URL",
            Severity::High,
        ),
        // ── Generic secrets ──
        (
            r#"(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:"']\s*[A-Za-z0-9_\-]{20,}"#,
            "API Key/Secret pattern",
            Severity::Medium,
        ),
        (
            r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            "Private Key",
            Severity::High,
        ),
        (
            r#"(?i)(password|passwd|pwd)\s*[=:"']\s*[^\s"']{4,}"#,
            "Password in response",
            Severity::High,
        ),
        (
            r#"(?i)(secret[_-]?key|client[_-]?secret|auth[_-]?token|access[_-]?token)\s*[=:"']\s*[A-Za-z0-9_\-/+=]{16,}"#,
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
            r"pk_live_[0-9a-zA-Z]{24,}",
            "Stripe Publishable Key",
            Severity::Low,
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
            r"SK[0-9a-fA-F]{32}",
            "Twilio API Key",
            Severity::High,
        ),
        (
            r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
            "SendGrid API Key",
            Severity::High,
        ),
        (
            r"key-[0-9a-zA-Z]{32}",
            "Mailgun API Key",
            Severity::High,
        ),
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
        (
            r"dp\.pt\.[a-z0-9]{43}",
            "Doppler API Token",
            Severity::High,
        ),
        (
            r"lin_api_[a-zA-Z0-9]{40}",
            "Linear API Key",
            Severity::High,
        ),
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
        (
            r"https://[a-zA-Z0-9]+@[a-z]+\.ingest\.sentry\.io/\d+",
            "Sentry DSN",
            Severity::Medium,
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
        (
            r"npm_[A-Za-z0-9]{36}",
            "npm Access Token",
            Severity::High,
        ),
        (
            r"pypi-[A-Za-z0-9_-]{50,}",
            "PyPI API Token",
            Severity::High,
        ),
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
        // ── Firebase ──
        (
            r"(?i)[a-z0-9-]+\.firebaseio\.com",
            "Firebase database URL",
            Severity::Low,
        ),
        (
            r"(?i)[a-z0-9-]+\.firebaseapp\.com",
            "Firebase app URL",
            Severity::Info,
        ),
        // ── Network / Infrastructure ──
        (
            r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
            "Internal IP address",
            Severity::Low,
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
            if let Some(m) = re.find(body) {
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
            }
        }
    }
}

// ── Rule 5: CORS ──

fn check_cors(record: &TransactionRecord, findings: &mut Vec<ScannerFinding>) {
    let response = match &record.response {
        Some(r) => r,
        None => return,
    };

    let acao = response.header_value("access-control-allow-origin");
    let acac = response.header_value("access-control-allow-credentials");

    if let Some(origin) = acao {
        if origin == "*" {
            if acac.is_some_and(|v| v.eq_ignore_ascii_case("true")) {
                findings.push(make_finding(
                    record,
                    Severity::High,
                    "cors",
                    "CORS: wildcard origin with credentials",
                    "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. Browsers block this, but the misconfiguration indicates sloppy CORS policy.",
                    "ACAO: * + ACAC: true",
                ));
            } else {
                findings.push(make_finding(
                    record,
                    Severity::Low,
                    "cors",
                    "CORS: wildcard origin",
                    "Access-Control-Allow-Origin: *. Any site can read responses from this endpoint.",
                    "ACAO: *",
                ));
            }
        } else if origin != "null" && acac.is_some_and(|v| v.eq_ignore_ascii_case("true")) {
            // Reflect origin with credentials — potentially dangerous
            let req_origin = record.request.header_value("origin").unwrap_or("");
            if !req_origin.is_empty() && origin == req_origin {
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
            let has_version = value.chars().any(|c| c.is_ascii_digit())
                || value.to_ascii_lowercase().contains("php")
                || value.to_ascii_lowercase().contains("asp");
            if has_version {
                findings.push(make_finding(
                    record,
                    Severity::Info,
                    "disclosure",
                    format!("{label} version disclosure"),
                    format!("{label} header reveals server technology/version. This helps attackers fingerprint the stack."),
                    format!("{header_name}: {value}"),
                ));
            }
        }
    }

    // Debug / infrastructure headers that should not be in production
    for (header_name, label, severity) in &[
        ("x-backend-server", "X-Backend-Server header", Severity::Medium),
        ("x-chromelogger-data", "ChromeLogger debug data", Severity::Medium),
        ("x-chromephp-data", "ChromePHP debug data", Severity::Medium),
        ("x-debug-token-link", "Symfony debug profiler link", Severity::Medium),
    ] {
        if let Some(value) = response.header_value(header_name) {
            findings.push(make_finding(
                record,
                severity.clone(),
                "disclosure",
                format!("{label} exposed"),
                format!("{label} found in response. This debug/infrastructure header should not be present in production."),
                format!("{header_name}: {}", truncate_evidence(&value, 80)),
            ));
        }
    }
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
        ("postgresql", "PostgreSQL error disclosure", Severity::Medium),
        ("ora-", "Oracle DB error disclosure", Severity::Medium),
        ("sqlite", "SQLite error disclosure", Severity::Medium),
        ("mongodb", "MongoDB error disclosure", Severity::Medium),
        ("mongoose", "Mongoose (MongoDB) error", Severity::Medium),
        ("redis", "Redis error disclosure", Severity::Low),
        ("mariadb", "MariaDB error disclosure", Severity::Medium),
        ("microsoft sql server", "MSSQL error disclosure", Severity::Medium),
        ("unclosed quotation mark", "SQL injection indicator", Severity::High),
        ("unterminated string", "SQL injection indicator", Severity::High),
        ("column count doesn't match", "SQL column mismatch error", Severity::Medium),
        ("incorrect column name", "SQL column error", Severity::Medium),
        ("unknown table", "SQL unknown table error", Severity::Medium),
        // ── DB2 / Informix / Access / JDBC (ZAP) ──
        ("db2 driver", "DB2 error disclosure", Severity::Medium),
        ("db2 error", "DB2 error disclosure", Severity::Medium),
        ("odbc db2", "DB2 ODBC error", Severity::Medium),
        ("[cli driver][db2", "DB2 CLI error", Severity::Medium),
        ("[informix]", "Informix DB error", Severity::Medium),
        ("odbc microsoft access", "MS Access ODBC error", Severity::Medium),
        ("jdbc driver", "JDBC driver error", Severity::Medium),
        ("jdbc error", "JDBC error disclosure", Severity::Medium),
        ("ole db provider", "OLE DB error", Severity::Medium),
        // ── Generic errors ──
        ("syntax error", "Syntax error in response", Severity::Low),
        ("stack trace", "Stack trace disclosure", Severity::Medium),
        ("internal server error", "Internal server error detail", Severity::Low),
        // ── Language-specific stack traces ──
        ("traceback (most recent", "Python traceback", Severity::Medium),
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
        ("warning: mysql_query()", "PHP MySQL warning", Severity::Medium),
        ("warning: pg_connect()", "PHP PostgreSQL warning", Severity::Medium),
        ("warning: cannot modify header information", "PHP header warning", Severity::Low),
        // ── Node.js / JavaScript ──
        ("syntaxerror:", "JavaScript SyntaxError", Severity::Medium),
        ("referenceerror:", "JavaScript ReferenceError", Severity::Medium),
        ("typeerror:", "JavaScript TypeError", Severity::Low),
        ("node_modules/", "Node.js path disclosure", Severity::Low),
        // ── ASP / VBScript / ColdFusion ──
        ("microsoft vbscript", "VBScript error", Severity::Medium),
        ("active server pages error", "Classic ASP error", Severity::Medium),
        ("adodb.field error", "ASP ADODB error", Severity::Medium),
        ("server error in '/' application", "ASP.NET application error", Severity::Medium),
        ("error occurred while processing request", "ColdFusion error", Severity::Medium),
        ("jrun servlet error", "JRun servlet error", Severity::Medium),
        ("disallowed parent path", "IIS path error", Severity::Medium),
        // ── Framework debug ──
        ("debug mode", "Debug mode enabled", Severity::Medium),
        ("django.core", "Django debug info", Severity::Medium),
        ("laravel", "Laravel framework error", Severity::Medium),
        ("spring boot", "Spring Boot error page", Severity::Low),
        ("whitelabel error page", "Spring Boot default error page", Severity::Low),
        ("werkzeug debugger", "Flask/Werkzeug debugger exposed", Severity::High),
        ("x-debug-token", "Symfony debug token", Severity::Medium),
    ];

    for &(pattern, label, ref severity) in ERROR_PATTERNS {
        if body_lower.contains(pattern) {
            let evidence_start = body_lower.find(pattern).unwrap_or(0);
            let start = evidence_start.saturating_sub(20);
            let end = (evidence_start + pattern.len() + 60).min(body.len());
            let evidence = &body[start..end];
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

// ── Rule 8: Security Misconfiguration ──

fn check_security_misconfig(record: &TransactionRecord, findings: &mut Vec<ScannerFinding>) {
    let response = match &record.response {
        Some(r) => r,
        None => return,
    };

    let ct = response.content_type.as_deref().unwrap_or("");

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

    // Referrer-Policy missing (HTML responses)
    if (ct.contains("text/html") || ct.is_empty()) && !has_header("referrer-policy") {
        findings.push(make_finding(
            record,
            Severity::Info,
            "misconfig",
            "Missing Referrer-Policy header",
            "No Referrer-Policy header. The browser may send full URL as referer to external sites, potentially leaking sensitive path/query info.",
            "",
        ));
    }

    // Permissions-Policy / Feature-Policy missing (HTML responses)
    if (ct.contains("text/html") || ct.is_empty())
        && !has_header("permissions-policy")
        && !has_header("feature-policy")
    {
        findings.push(make_finding(
            record,
            Severity::Info,
            "misconfig",
            "Missing Permissions-Policy header",
            "No Permissions-Policy (or Feature-Policy) header. Browser features like camera, microphone, geolocation are not restricted.",
            "",
        ));
    }

    // CSP with unsafe-inline or unsafe-eval
    if let Some(csp) = header_value("content-security-policy") {
        let csp_lower = csp.to_ascii_lowercase();
        if csp_lower.contains("'unsafe-inline'") {
            findings.push(make_finding(
                record,
                Severity::Medium,
                "misconfig",
                "CSP allows unsafe-inline",
                "Content-Security-Policy contains 'unsafe-inline', which undermines XSS protection by allowing inline scripts.",
                truncate_evidence(&csp, 120),
            ));
        }
        if csp_lower.contains("'unsafe-eval'") {
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

    // X-XSS-Protection set (deprecated — can cause issues in modern browsers)
    if let Some(xxp) = header_value("x-xss-protection") {
        if xxp.contains("1") {
            findings.push(make_finding(
                record,
                Severity::Info,
                "misconfig",
                "Deprecated X-XSS-Protection header",
                "X-XSS-Protection is deprecated and can introduce XSS vulnerabilities in older browsers. Use CSP instead.",
                format!("X-XSS-Protection: {xxp}"),
            ));
        }
    }

    // Cache-Control missing on authenticated responses
    let has_auth = record
        .request
        .headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case("authorization"));
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

    // Access-Control-Allow-Methods with dangerous methods
    if let Some(methods) = header_value("access-control-allow-methods") {
        let m_lower = methods.to_ascii_lowercase();
        for dangerous in &["put", "delete", "patch"] {
            if m_lower.contains(dangerous) {
                findings.push(make_finding(
                    record,
                    Severity::Info,
                    "misconfig",
                    format!("CORS allows {}", dangerous.to_uppercase()),
                    format!("Access-Control-Allow-Methods includes {}. Verify these methods are intentionally exposed.", dangerous.to_uppercase()),
                    format!("ACAM: {methods}"),
                ));
                break;
            }
        }
    }
}

// ── Rule 9: Information Disclosure ──

fn check_info_disclosure(record: &TransactionRecord, findings: &mut Vec<ScannerFinding>) {
    let response = match &record.response {
        Some(r) => r,
        None => return,
    };

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
            truncate_evidence(
                &body[..body.len().min(120)],
                120,
            ),
        ));
    }

    // Source map references
    let sourcemap_re = Regex::new(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+\.map)").unwrap();
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

    // Also check SourceMap header
    if let Some(sm) = response.header_value("sourcemap").or_else(|| response.header_value("x-sourcemap")) {
        findings.push(make_finding(
            record,
            Severity::Low,
            "info",
            "Source map header present",
            "SourceMap HTTP header found. Source maps can expose original source code.",
            format!("SourceMap: {sm}"),
        ));
    }

    // GraphQL Introspection enabled
    if body.contains("__schema") && body.contains("queryType") {
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
            let sensitive_keywords = [
                "todo", "fixme", "hack", "bug", "password", "secret",
                "credential", "token", "api_key", "apikey", "admin",
                "internal", "debug", "temporary", "remove before",
            ];
            for keyword in &sensitive_keywords {
                if comment.contains(keyword) {
                    findings.push(make_finding(
                        record,
                        Severity::Info,
                        "info",
                        format!("HTML comment contains '{keyword}'"),
                        "HTML comments may reveal developer notes, internal paths, or sensitive information to users.",
                        truncate_evidence(m.as_str(), 120),
                    ));
                    break;
                }
            }
        }
    }

    // Email addresses in response body
    if let Ok(email_re) = Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}") {
        let ct = response.content_type.as_deref().unwrap_or("");
        // Only flag in non-email contexts (HTML/JSON)
        if ct.contains("html") || ct.contains("json") {
            if let Some(m) = email_re.find(body) {
                // Skip obvious false positives
                let email = m.as_str();
                if !email.ends_with("example.com")
                    && !email.ends_with("example.org")
                    && !email.contains("schema.org")
                    && !email.contains("w3.org")
                {
                    findings.push(make_finding(
                        record,
                        Severity::Info,
                        "info",
                        "Email address in response",
                        "Email addresses found in response body. These could be used for phishing or social engineering.",
                        truncate_evidence(email, 80),
                    ));
                }
            }
        }
    }

    // Version control metadata exposure
    if body.contains("\"sha\"") && body.contains("\"commit\"") && body.contains("\"author\"") {
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
    if (body_lower.contains("\"swagger\"") || body_lower.contains("\"openapi\""))
        && (body_lower.contains("\"paths\"") || body_lower.contains("\"info\""))
    {
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
    if body_lower.contains("<wsdl:") || body_lower.contains("xmlns:wsdl") {
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

// ── Rule 10: Authentication Issues ──

fn check_auth_issues(record: &TransactionRecord, findings: &mut Vec<ScannerFinding>) {
    // Session token in URL
    let path_lower = record.path.to_ascii_lowercase();
    let session_params = [
        "jsessionid", "phpsessid", "sessionid", "session_id",
        "sid=", "aspsessionid", "token=", "access_token=",
        "auth_token=", "api_key=",
    ];
    for param in &session_params {
        if path_lower.contains(param) {
            findings.push(make_finding(
                record,
                Severity::Medium,
                "auth",
                format!("Session/token parameter in URL: {param}"),
                "Session token or credentials found in URL. URLs are logged in browser history, server logs, and referer headers, exposing the token.",
                truncate_evidence(&record.path, 120),
            ));
            break;
        }
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
                    let query = path_params[1].to_ascii_lowercase();
                    let redirect_params = [
                        "redirect", "url", "next", "return", "goto",
                        "redir", "redirect_uri", "return_url", "continue",
                        "dest", "destination",
                    ];
                    for param in &redirect_params {
                        if query.contains(param) {
                            // Check if Location points to external domain
                            if loc.starts_with("http") && !loc.contains(&record.host) {
                                findings.push(make_finding(
                                    record,
                                    Severity::Medium,
                                    "auth",
                                    "Possible open redirect",
                                    format!("Redirect to external URL based on user-controlled parameter. Query contains '{param}' and Location points to a different host."),
                                    format!("Location: {}", truncate_evidence(&loc, 80)),
                                ));
                                break;
                            }
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

// ── Utilities ──

fn extract_json_number(json: &str, key: &str) -> Option<i64> {
    let pattern = format!("\"{key}\"");
    let idx = json.find(&pattern)?;
    let rest = &json[idx + pattern.len()..];
    // Skip whitespace and colon
    let rest = rest.trim_start().strip_prefix(':')?;
    let rest = rest.trim_start();
    // Parse number
    let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit() || *c == '-').collect();
    num_str.parse().ok()
}

fn truncate_evidence(value: &str, max: usize) -> String {
    if value.len() <= max {
        value.to_string()
    } else {
        format!("{}...", &value[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{BodyEncoding, HeaderRecord, MessageRecord, TransactionRecord};
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
                    .map(|(n, v)| HeaderRecord { name: n.into(), value: v.into() })
                    .collect(),
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                preview_truncated: false,
                content_type: None,
            },
            Some(MessageRecord {
                headers: res_headers
                    .into_iter()
                    .map(|(n, v)| HeaderRecord { name: n.into(), value: v.into() })
                    .collect(),
                body_preview: res_body.into(),
                body_encoding: BodyEncoding::Utf8,
                body_size: res_body.len(),
                preview_truncated: false,
                content_type: Some("text/html".into()),
            }),
            Vec::new(),
            None,
            None,
        )
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
            findings.iter().any(|f| f.category == "jwt" && f.title.contains("without expiration")),
            "Should detect JWT without expiration"
        );
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
            findings.iter().any(|f| f.title.contains("Content-Security-Policy")),
            "Should detect missing CSP"
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
    fn test_cors_wildcard() {
        let record = make_record(
            vec![],
            vec![("access-control-allow-origin", "*")],
            "",
            200,
        );
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings.iter().any(|f| f.category == "cors"),
            "Should detect wildcard CORS"
        );
    }

    #[test]
    fn test_server_disclosure() {
        let record = make_record(
            vec![],
            vec![("server", "Apache/2.4.51")],
            "",
            200,
        );
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings.iter().any(|f| f.title.contains("Server version")),
            "Should detect server version disclosure"
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
    fn test_csp_unsafe_inline() {
        let record = make_record(
            vec![],
            vec![
                ("content-type", "text/html"),
                ("content-security-policy", "default-src 'self' 'unsafe-inline'"),
            ],
            "<html></html>",
            200,
        );
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings.iter().any(|f| f.category == "misconfig" && f.title.contains("unsafe-inline")),
            "Should detect CSP unsafe-inline"
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
            findings.iter().any(|f| f.category == "info" && f.title.contains("Directory listing")),
            "Should detect directory listing"
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
            findings.iter().any(|f| f.category == "info" && f.title.contains("GraphQL introspection")),
            "Should detect GraphQL introspection"
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
                preview_truncated: false,
                content_type: None,
            },
            Some(MessageRecord {
                headers: vec![],
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                preview_truncated: false,
                content_type: Some("text/html".into()),
            }),
            Vec::new(),
            None,
            None,
        );
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings.iter().any(|f| f.category == "auth" && f.title.contains("Session/token")),
            "Should detect session token in URL"
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
                preview_truncated: false,
                content_type: None,
            },
            Some(MessageRecord {
                headers: vec![],
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                preview_truncated: false,
                content_type: Some("text/html".into()),
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
        let record = make_record(
            vec![],
            vec![("content-type", "text/html")],
            &body,
            200,
        );
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings.iter().any(|f| f.title.contains("Stripe Secret Key")),
            "Should detect Stripe secret key"
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
            findings.iter().any(|f| f.category == "info" && f.title.contains("HTML comment")),
            "Should detect sensitive HTML comment"
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
            findings.iter().any(|f| f.category == "info" && f.title.contains("Swagger")),
            "Should detect Swagger/OpenAPI spec exposure"
        );
    }
}
