//! Nuclei templates: the community's detection templates, and the subset of
//! their HTTP language Sniper can run.
//!
//! Templates are data, not code. Sniper never runs the protocols that execute
//! on this machine or open sockets it cannot scope (code, javascript,
//! headless, network, dns and the rest), and a template that needs anything
//! outside the supported subset is listed as unsupported rather than run in
//! part.

pub mod active;
pub mod dsl;
pub mod engine;
pub mod flow;
pub mod jq;
pub mod library;
pub mod model;
pub mod scan;
pub mod version;

use chrono::Utc;
use uuid::Uuid;

use crate::model::{TrafficKind, TransactionRecord};
use crate::scanner::{ScannerFinding, Severity};
use engine::{CompiledTemplate, PassiveSet, ResponseView, TemplateMatch, UrlVars};

/// Bumped whenever classification or compilation changes, so an index built
/// by an older engine is rebuilt instead of trusted.
pub const ENGINE_VERSION: u32 = 10;

/// Rule ids of findings from passive templates; the rest of the id is the
/// template id and, for a named matcher, `:<matcher>`.
pub const PASSIVE_RULE_PREFIX: &str = "nuclei-passive:";

/// Rule ids of findings from Template Scan. A rescan cannot make them again,
/// since it sends nothing, so it keeps them.
pub const ACTIVE_RULE_PREFIX: &str = "nuclei:";

/// The category template findings are filed under.
pub const FINDING_CATEGORY: &str = "nuclei";

/// The most evidence a finding keeps, as the built-in rules do.
const MAX_EVIDENCE_CHARS: usize = 120;

/// Whether passive templates judge this record: a response to an HTTP
/// request whose host is in a scope the operator has set. An empty include
/// list means everything to the rest of Sniper; for templates nobody chose
/// to point anywhere, it means nothing. Media is never a template's target.
pub fn passive_applies(record: &TransactionRecord, include: &[String], exclude: &[String]) -> bool {
    if !matches!(record.kind, TrafficKind::Http) || include.is_empty() || record.response.is_none()
    {
        return false;
    }
    if !crate::scope::is_host_in_scope(&record.host, include, exclude) {
        return false;
    }
    let content_type = record
        .original_response
        .as_ref()
        .or(record.response.as_ref())
        .and_then(|response| response.content_type.as_deref())
        .unwrap_or("")
        .trim_start()
        .to_ascii_lowercase();
    !["image/", "font/", "audio/", "video/"]
        .iter()
        .any(|media| content_type.starts_with(media))
}

/// The findings the enabled passive templates report on one record.
pub fn passive_findings(set: &PassiveSet, record: &TransactionRecord) -> Vec<ScannerFinding> {
    let Some(url) = UrlVars::of_record(record) else {
        return Vec::new();
    };
    let Some(view) = ResponseView::from_record(record, url, engine::MAX_PASSIVE_BODY_BYTES) else {
        return Vec::new();
    };
    set.scan(&view)
        .into_iter()
        .map(|(template, result)| finding(&template, &result, record, PASSIVE_RULE_PREFIX))
        .collect()
}

/// An Active Scan finding: the record is the exchange the template matched.
pub fn active_finding(
    template: &CompiledTemplate,
    result: &TemplateMatch,
    record: &TransactionRecord,
    job: Uuid,
    library: &str,
) -> ScannerFinding {
    let mut finding = finding(template, result, record, ACTIVE_RULE_PREFIX);
    finding.detail.push_str(&format!(
        "\nSent by Active Scan job {job}, template library {library}.\nRequest: {} {}://{}{}",
        record.method, record.scheme, record.host, record.path
    ));
    finding
}

fn severity(text: &str) -> Severity {
    match text {
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        // `unknown` too: Sniper has no such level, and the detail says so.
        _ => Severity::Info,
    }
}

fn truncate_chars(text: &str, limit: usize) -> String {
    match text.char_indices().nth(limit) {
        Some((end, _)) => format!("{}…", &text[..end]),
        None => text.to_string(),
    }
}

fn finding(
    template: &CompiledTemplate,
    result: &TemplateMatch,
    record: &TransactionRecord,
    prefix: &str,
) -> ScannerFinding {
    let info = &template.info;
    let suffix = result
        .matcher
        .as_ref()
        .map(|name| format!(":{name}"))
        .unwrap_or_default();
    let name = if info.name.is_empty() {
        info.id.as_str()
    } else {
        info.name.as_str()
    };
    let title = match &result.matcher {
        Some(matcher) => format!("{name} [{matcher}]"),
        None => name.to_string(),
    };
    let evidence = if result.extracted.is_empty() {
        result.snippets.first().cloned().unwrap_or_default()
    } else {
        result.extracted.join(", ")
    };
    let mut detail = Vec::new();
    if !info.description.is_empty() {
        detail.push(info.description.clone());
    }
    detail.push(format!("Nuclei template: {}", info.id));
    if info.severity == "unknown" {
        detail.push("The template gives no severity; listed as Info.".into());
    }
    if !info.cve.is_empty() {
        detail.push(format!("CVE: {}", info.cve.join(", ")));
    }
    if !info.cwe.is_empty() {
        detail.push(format!("CWE: {}", info.cwe.join(", ")));
    }
    if let Some(score) = info.cvss_score {
        detail.push(format!("CVSS: {score}"));
    }
    if !info.tags.is_empty() {
        detail.push(format!("Tags: {}", info.tags.join(", ")));
    }
    if !result.extracted.is_empty() {
        detail.push(format!("Extracted: {}", result.extracted.join(", ")));
    }
    for reference in info.references.iter().take(5) {
        detail.push(format!("Reference: {reference}"));
    }
    let mut finding = ScannerFinding {
        id: Uuid::new_v4(),
        record_id: record.id,
        found_at: Utc::now(),
        rule_id: format!("{prefix}{}{suffix}", info.id),
        severity: severity(&info.severity),
        category: FINDING_CATEGORY.into(),
        title,
        detail: detail.join("\n"),
        evidence: truncate_chars(&evidence, MAX_EVIDENCE_CHARS),
        host: record.host.clone(),
        path: record.path.clone(),
        location: None,
    };
    finding.location = crate::scanner::infer_finding_location(record, &finding);
    finding
}
