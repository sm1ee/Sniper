use std::collections::HashSet;

use anyhow::Result;
use bytes::Bytes;
use http::HeaderMap;
use regex::{Regex, RegexBuilder};
use serde::{ser::SerializeStruct, Deserialize, Serialize, Serializer};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::model::{decode_content_encoding, BodyEncoding, EditableRequest, HeaderRecord};

pub const MAX_MATCH_REPLACE_RULES: usize = 500;
pub const MAX_MATCH_REPLACE_FIELD_BYTES: usize = 256 * 1024;
pub const MAX_MATCH_REPLACE_RULES_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_RULE_ANNOTATION_NOTE_BYTES: usize = 1024;
pub const MAX_RULE_ANNOTATION_NOTES_BYTES: usize = 32 * 1024;
pub const RULE_ANNOTATION_COLORS: &[&str] = &["red", "orange", "yellow", "green", "blue", "purple"];
const BODY_ANNOTATION_UNAVAILABLE: &str =
    "Rule body annotation skipped: complete text unavailable.";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchReplaceScope {
    Request,
    Response,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchReplaceTarget {
    Any,
    Path,
    HeaderName,
    HeaderValue,
    Body,
}

#[derive(Clone, Debug, Deserialize)]
pub struct MatchReplaceRule {
    pub id: Uuid,
    pub enabled: bool,
    #[serde(default)]
    pub annotation_only_enabled: Option<bool>,
    #[serde(default)]
    pub annotation_note: Option<String>,
    #[serde(default)]
    pub annotation_color: Option<String>,
    pub description: String,
    pub scope: MatchReplaceScope,
    pub target: MatchReplaceTarget,
    pub search: String,
    pub replace: String,
    pub regex: bool,
    pub case_sensitive: bool,
}

// An old binary ignores the new fields. Every typed output must therefore
// leave annotation-only rules disabled for the legacy replacement engine.
impl Serialize for MatchReplaceRule {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut out = serializer.serialize_struct(
            "MatchReplaceRule",
            9 + usize::from(self.annotation_only_enabled.is_some())
                + usize::from(self.annotation_note.is_some())
                + usize::from(self.annotation_color.is_some()),
        )?;
        out.serialize_field("id", &self.id)?;
        out.serialize_field("enabled", &self.replacement_enabled())?;
        out.serialize_field("description", &self.description)?;
        out.serialize_field("scope", &self.scope)?;
        out.serialize_field("target", &self.target)?;
        out.serialize_field("search", &self.search)?;
        out.serialize_field("replace", &self.replace)?;
        out.serialize_field("regex", &self.regex)?;
        out.serialize_field("case_sensitive", &self.case_sensitive)?;
        if let Some(enabled) = self.annotation_only_enabled {
            out.serialize_field("annotation_only_enabled", &enabled)?;
        }
        if let Some(note) = &self.annotation_note {
            out.serialize_field("annotation_note", note)?;
        }
        if let Some(color) = &self.annotation_color {
            out.serialize_field("annotation_color", color)?;
        }
        out.end()
    }
}

impl MatchReplaceRule {
    pub fn is_enabled(&self) -> bool {
        self.annotation_only_enabled.unwrap_or(self.enabled)
    }

    pub fn replacement_enabled(&self) -> bool {
        self.annotation_only_enabled.is_none() && self.enabled
    }

    fn has_annotation(&self) -> bool {
        self.annotation_note
            .as_ref()
            .is_some_and(|note| !note.is_empty())
            || self.annotation_color.is_some()
    }

    pub(crate) fn normalize_restored_activation(&mut self) {
        if self.enabled && self.annotation_only_enabled.is_some() {
            self.enabled = false;
            self.annotation_only_enabled = Some(false);
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct RuleAnnotations {
    pub notes: Vec<String>,
    pub color: Option<String>,
}

#[derive(Default)]
struct AnnotationCollector {
    effects: RuleAnnotations,
    seen: HashSet<Uuid>,
    body_unavailable: bool,
}

impl AnnotationCollector {
    fn observe(&mut self, rule: &MatchReplaceRule, matched: bool, body_unavailable: bool) {
        if !rule.is_enabled() || !rule.has_annotation() || rule.search.is_empty() {
            return;
        }
        if self.seen.contains(&rule.id) {
            return;
        }
        if !matched {
            self.body_unavailable |= body_unavailable;
            return;
        }
        if !self.seen.insert(rule.id) {
            return;
        }
        if let Some(note) = rule
            .annotation_note
            .as_ref()
            .filter(|note| !note.is_empty())
        {
            let stage = match rule.scope {
                MatchReplaceScope::Request => "request",
                MatchReplaceScope::Response => "response",
            };
            self.effects.notes.push(format!("Rule ({stage}): {note}"));
        }
        if let Some(color) = &rule.annotation_color {
            self.effects.color = Some(color.clone());
        }
    }

    fn finish(mut self) -> RuleAnnotations {
        if self.body_unavailable {
            self.effects
                .notes
                .push(BODY_ANNOTATION_UNAVAILABLE.to_string());
        }
        self.effects
    }
}

fn condition_matches(rule: &MatchReplaceRule, value: &str) -> bool {
    if rule.search.is_empty() {
        return false;
    }
    if rule.regex || !rule.case_sensitive {
        let pattern = if rule.regex {
            rule.search.clone()
        } else {
            regex::escape(&rule.search)
        };
        RegexBuilder::new(&pattern)
            .case_insensitive(!rule.case_sensitive)
            .build()
            .is_ok_and(|regex| regex.is_match(value))
    } else {
        value.contains(&rule.search)
    }
}

fn annotation_match(
    rule: &MatchReplaceRule,
    headers: &[HeaderRecord],
    path: Option<&str>,
    host: Option<&str>,
    body: Option<&str>,
) -> (bool, bool) {
    if !rule.is_enabled() || !rule.has_annotation() || rule.search.is_empty() {
        return (false, false);
    }
    let any = matches!(rule.target, MatchReplaceTarget::Any);
    let matched = ((any || matches!(rule.target, MatchReplaceTarget::Path))
        && path.is_some_and(|value| condition_matches(rule, value)))
        || ((any || matches!(rule.target, MatchReplaceTarget::HeaderName))
            && headers
                .iter()
                .any(|header| condition_matches(rule, &header.name)))
        || ((any || matches!(rule.target, MatchReplaceTarget::HeaderValue))
            && (host.is_some_and(|value| condition_matches(rule, value))
                || headers
                    .iter()
                    .any(|header| condition_matches(rule, &header.value))))
        || ((any || matches!(rule.target, MatchReplaceTarget::Body))
            && body.is_some_and(|value| condition_matches(rule, value)));
    (
        matched,
        !matched && (any || matches!(rule.target, MatchReplaceTarget::Body)) && body.is_none(),
    )
}

fn has_content_encoding(headers: &[HeaderRecord]) -> bool {
    headers
        .iter()
        .any(|header| header.name.eq_ignore_ascii_case("content-encoding"))
}

/// Only complete retained streaming text is eligible. This never changes the
/// decoder's policy or treats its opaque/raw fallback as decoded annotation text.
pub(crate) fn annotate_streamed_response(
    rules: &[MatchReplaceRule],
    headers: &HeaderMap,
    retained: &[u8],
    complete: bool,
    body_size: usize,
    max_preview: usize,
    known_bodyless: bool,
) -> RuleAnnotations {
    let headers = header_records(headers.clone());
    let needs_body = rules.iter().any(|rule| {
        rule.is_enabled()
            && rule.has_annotation()
            && !rule.search.is_empty()
            && matches!(rule.scope, MatchReplaceScope::Response)
            && matches!(
                rule.target,
                MatchReplaceTarget::Any | MatchReplaceTarget::Body
            )
    });
    let complete = needs_body && complete && body_size == retained.len();
    let decoded = complete
        .then(|| decode_content_encoding_records(&headers, retained))
        .flatten();
    let bytes = if !complete {
        None
    } else if known_bodyless && retained.is_empty() {
        Some(retained)
    } else if has_content_encoding(&headers) {
        decoded.as_deref()
    } else {
        Some(retained)
    };
    let body = bytes
        .filter(|body| body.len() <= max_preview)
        .and_then(|body| std::str::from_utf8(body).ok());
    let mut collector = AnnotationCollector::default();
    for rule in rules
        .iter()
        .filter(|rule| matches!(rule.scope, MatchReplaceScope::Response))
    {
        let (matched, unavailable) = annotation_match(rule, &headers, None, None, body);
        collector.observe(rule, matched, unavailable);
    }
    collector.finish()
}

pub(crate) fn response_replacement_enabled(rules: &[MatchReplaceRule]) -> bool {
    rules
        .iter()
        .any(|rule| rule.replacement_enabled() && matches!(rule.scope, MatchReplaceScope::Response))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MatchReplaceRulesPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<Uuid>,
    pub rules: Vec<MatchReplaceRule>,
}

#[derive(Clone, Debug)]
pub struct AppliedRequest {
    pub request: EditableRequest,
    pub notes: Vec<String>,
    pub traffic_changed: bool,
    pub annotations: RuleAnnotations,
}

#[derive(Clone, Debug)]
pub struct AppliedResponse {
    pub headers: HeaderMap,
    pub body: Bytes,
    pub notes: Vec<String>,
    pub traffic_changed: bool,
    pub annotations: RuleAnnotations,
}

pub struct MatchReplaceStore {
    rules: RwLock<Vec<MatchReplaceRule>>,
}

impl MatchReplaceStore {
    pub fn new() -> Self {
        Self::from_rules(Vec::new())
    }

    pub fn from_rules(rules: Vec<MatchReplaceRule>) -> Self {
        Self {
            rules: RwLock::new(sanitize_match_replace_rules(rules)),
        }
    }

    pub async fn snapshot(&self) -> Vec<MatchReplaceRule> {
        self.rules.read().await.clone()
    }

    pub async fn len(&self) -> usize {
        self.rules.read().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.rules.read().await.is_empty()
    }

    pub async fn replace_all(&self, rules: Vec<MatchReplaceRule>) -> Vec<MatchReplaceRule> {
        let mut current = self.rules.write().await;
        *current = sanitize_match_replace_rules(rules);
        current.clone()
    }

    pub async fn apply_request(&self, request: EditableRequest) -> AppliedRequest {
        let rules = self.rules.read().await.clone();
        apply_request_rules(request, rules)
    }

    pub async fn apply_response(&self, headers: HeaderMap, body: Bytes) -> AppliedResponse {
        let rules = self.rules.read().await.clone();
        apply_response_rules(headers, body, rules)
    }

    pub async fn has_enabled_response_rules(&self) -> bool {
        let rules = self.rules.read().await;
        response_replacement_enabled(rules.as_slice())
    }
}

impl Default for MatchReplaceStore {
    fn default() -> Self {
        Self::new()
    }
}

pub fn sanitize_match_replace_rules(rules: Vec<MatchReplaceRule>) -> Vec<MatchReplaceRule> {
    let mut note_bytes = 0usize;
    let mut sanitized = rules
        .into_iter()
        .map(|mut rule| {
            rule.normalize_restored_activation();
            rule
        })
        .filter(valid_restored_match_replace_rule)
        .filter(|rule| {
            let bytes = rule.annotation_note.as_ref().map_or(0, String::len);
            if note_bytes.saturating_add(bytes) > MAX_RULE_ANNOTATION_NOTES_BYTES {
                return false;
            }
            note_bytes += bytes;
            true
        })
        .take(MAX_MATCH_REPLACE_RULES)
        .collect::<Vec<_>>();
    while serde_json::to_vec(&sanitized)
        .map(|bytes| bytes.len() > MAX_MATCH_REPLACE_RULES_BYTES)
        .unwrap_or(true)
    {
        if sanitized.pop().is_none() {
            break;
        }
    }
    sanitized
}

fn valid_restored_match_replace_rule(rule: &MatchReplaceRule) -> bool {
    if rule.description.len() > MAX_MATCH_REPLACE_FIELD_BYTES
        || rule.search.len() > MAX_MATCH_REPLACE_FIELD_BYTES
        || rule.replace.len() > MAX_MATCH_REPLACE_FIELD_BYTES
    {
        return false;
    }
    if rule.annotation_note.as_ref().is_some_and(|note| {
        note.len() > MAX_RULE_ANNOTATION_NOTE_BYTES || (!note.is_empty() && note.trim().is_empty())
    }) || rule
        .annotation_color
        .as_ref()
        .is_some_and(|color| !RULE_ANNOTATION_COLORS.contains(&color.as_str()))
    {
        return false;
    }
    !rule.regex || RegexBuilder::new(&rule.search).build().is_ok()
}

fn apply_request_rules(request: EditableRequest, rules: Vec<MatchReplaceRule>) -> AppliedRequest {
    let mut request = request;
    let mut notes = Vec::new();
    let mut body_changed = false;
    let mut headers_changed = false;
    let needs_request_body = rules.iter().any(|rule| {
        rule.is_enabled()
            && (rule.replacement_enabled() || (rule.has_annotation() && !rule.search.is_empty()))
            && matches!(rule.scope, MatchReplaceScope::Request)
            && matches!(
                rule.target,
                MatchReplaceTarget::Any | MatchReplaceTarget::Body
            )
    });
    let decoded_body_for_rules = needs_request_body
        .then(|| {
            request
                .try_body_bytes()
                .ok()
                .and_then(|body| decode_content_encoding_records(&request.headers, body.as_ref()))
        })
        .flatten();
    let mut decoded_body_text_for_rules = decoded_body_for_rules
        .as_ref()
        .and_then(|decoded| std::str::from_utf8(decoded).ok())
        .map(ToOwned::to_owned);
    let mut decoded_body_changed = false;
    let mut body_annotation_eligible = !request.preview_truncated
        && (!has_content_encoding(&request.headers) || decoded_body_for_rules.is_some());
    let mut annotations = AnnotationCollector::default();

    for rule in rules
        .into_iter()
        .filter(|rule| rule.is_enabled() && matches!(rule.scope, MatchReplaceScope::Request))
    {
        let body = if body_annotation_eligible {
            decoded_body_text_for_rules.as_deref().or_else(|| {
                (!has_content_encoding(&request.headers)
                    && matches!(request.body_encoding, BodyEncoding::Utf8))
                .then_some(request.body.as_str())
            })
        } else {
            None
        };
        let (annotation_matched, unavailable) = annotation_match(
            &rule,
            &request.headers,
            Some(&request.path),
            Some(&request.host),
            body,
        );
        annotations.observe(&rule, annotation_matched, unavailable);
        if !rule.replacement_enabled() {
            continue;
        }
        let mut matched = false;

        match rule.target {
            MatchReplaceTarget::Any | MatchReplaceTarget::Path => {
                if let Ok((value, changed)) = replace_text(&request.path, &rule) {
                    if changed {
                        request.path = value;
                        matched = true;
                    }
                }
            }
            _ => {}
        }

        if matches!(
            rule.target,
            MatchReplaceTarget::Any | MatchReplaceTarget::HeaderName
        ) {
            for header in &mut request.headers {
                if let Ok((value, changed)) = replace_text(&header.name, &rule) {
                    if changed && valid_header_name(&value) {
                        // Legacy replacement keeps its frozen body representation.
                        // Do not annotate later bodies under changed encoding metadata.
                        if header.name.eq_ignore_ascii_case("content-encoding")
                            || value.eq_ignore_ascii_case("content-encoding")
                        {
                            body_annotation_eligible = false;
                        }
                        header.name = value;
                        headers_changed = true;
                        matched = true;
                    }
                }
            }
        }

        if matches!(
            rule.target,
            MatchReplaceTarget::Any | MatchReplaceTarget::HeaderValue
        ) {
            if let Ok((value, changed)) = replace_text(&request.host, &rule) {
                if changed {
                    request.host = value;
                    matched = true;
                }
            }

            for header in &mut request.headers {
                if let Ok((value, changed)) = replace_text(&header.value, &rule) {
                    if changed && valid_header_value(&value) {
                        if header.name.eq_ignore_ascii_case("content-encoding") {
                            body_annotation_eligible = false;
                        }
                        header.value = value;
                        if header.name.eq_ignore_ascii_case("host") {
                            request.host = header.value.clone();
                        }
                        headers_changed = true;
                        matched = true;
                    }
                }
            }
        }

        if matches!(
            rule.target,
            MatchReplaceTarget::Any | MatchReplaceTarget::Body
        ) {
            if let Some(body_text) = decoded_body_text_for_rules.as_mut() {
                if let Ok((value, changed)) = replace_text(body_text, &rule) {
                    if changed {
                        *body_text = value;
                        matched = true;
                        body_changed = true;
                        decoded_body_changed = true;
                    }
                }
            } else if matches!(request.body_encoding, BodyEncoding::Utf8) {
                if let Ok((value, changed)) = replace_text(&request.body, &rule) {
                    if changed {
                        request.body = value;
                        matched = true;
                        body_changed = true;
                    }
                }
            }
        }

        if matched {
            notes.push(format!(
                "Match and replace applied request rule: {}",
                rule.description
            ));
        }
    }

    if decoded_body_changed {
        if let Some(body_text) = decoded_body_text_for_rules {
            request.body = body_text;
            request.body_encoding = BodyEncoding::Utf8;
            strip_content_encoding_records(&mut request.headers);
        }
    }

    if body_changed || headers_changed {
        if let Ok(body) = request.try_body_bytes() {
            normalize_content_length_records(&mut request.headers, body.len());
        }
    }

    AppliedRequest {
        request,
        traffic_changed: !notes.is_empty(),
        notes,
        annotations: annotations.finish(),
    }
}

pub(crate) fn apply_response_rules(
    headers: HeaderMap,
    body: Bytes,
    rules: Vec<MatchReplaceRule>,
) -> AppliedResponse {
    apply_response_rules_with_bodyless(headers, body, rules, false)
}

pub(crate) fn apply_response_rules_with_bodyless(
    headers: HeaderMap,
    body: Bytes,
    rules: Vec<MatchReplaceRule>,
    known_bodyless: bool,
) -> AppliedResponse {
    let mut headers = header_records(headers);
    let mut body = body;
    let needs_response_body = rules.iter().any(|rule| {
        rule.is_enabled()
            && (rule.replacement_enabled() || (rule.has_annotation() && !rule.search.is_empty()))
            && matches!(rule.scope, MatchReplaceScope::Response)
            && matches!(
                rule.target,
                MatchReplaceTarget::Any | MatchReplaceTarget::Body
            )
    });
    let decoded_body_for_rules = needs_response_body
        .then(|| decode_content_encoding_records(&headers, body.as_ref()))
        .flatten();
    let mut body_for_rules = decoded_body_for_rules
        .as_ref()
        .map(|decoded| Bytes::from(decoded.clone()))
        .unwrap_or_else(|| body.clone());
    let mut notes = Vec::new();
    let mut body_changed = false;
    let mut headers_changed = false;
    let mut body_annotation_eligible = !has_content_encoding(&headers)
        || decoded_body_for_rules.is_some()
        || (known_bodyless && body.is_empty());
    let mut annotations = AnnotationCollector::default();

    for rule in rules
        .into_iter()
        .filter(|rule| rule.is_enabled() && matches!(rule.scope, MatchReplaceScope::Response))
    {
        let text = body_annotation_eligible
            .then(|| std::str::from_utf8(body_for_rules.as_ref()).ok())
            .flatten();
        let (annotation_matched, unavailable) = annotation_match(&rule, &headers, None, None, text);
        annotations.observe(&rule, annotation_matched, unavailable);
        if !rule.replacement_enabled() {
            continue;
        }
        let mut matched = false;

        if matches!(
            rule.target,
            MatchReplaceTarget::Any | MatchReplaceTarget::HeaderName
        ) {
            for header in &mut headers {
                if let Ok((value, changed)) = replace_text(&header.name, &rule) {
                    if changed && valid_header_name(&value) {
                        // Legacy replacement keeps its frozen body representation.
                        // Do not annotate later bodies under changed encoding metadata.
                        if header.name.eq_ignore_ascii_case("content-encoding")
                            || value.eq_ignore_ascii_case("content-encoding")
                        {
                            body_annotation_eligible = false;
                        }
                        header.name = value;
                        headers_changed = true;
                        matched = true;
                    }
                }
            }
        }

        if matches!(
            rule.target,
            MatchReplaceTarget::Any | MatchReplaceTarget::HeaderValue
        ) {
            for header in &mut headers {
                if let Ok((value, changed)) = replace_text(&header.value, &rule) {
                    if changed && valid_header_value(&value) {
                        if header.name.eq_ignore_ascii_case("content-encoding") {
                            body_annotation_eligible = false;
                        }
                        header.value = value;
                        headers_changed = true;
                        matched = true;
                    }
                }
            }
        }

        if matches!(
            rule.target,
            MatchReplaceTarget::Any | MatchReplaceTarget::Body
        ) {
            if let Ok(text) = std::str::from_utf8(body_for_rules.as_ref()) {
                if let Ok((value, changed)) = replace_text(text, &rule) {
                    if changed {
                        body_for_rules = Bytes::from(value);
                        matched = true;
                        body_changed = true;
                    }
                }
            }
        }

        if matched {
            notes.push(format!(
                "Match and replace applied response rule: {}",
                rule.description
            ));
        }
    }

    if body_changed {
        body = body_for_rules;
        if decoded_body_for_rules.is_some() {
            strip_content_encoding_records(&mut headers);
        }
    }

    if body_changed || headers_changed {
        normalize_content_length_records(&mut headers, body.len());
    }

    AppliedResponse {
        headers: header_map(headers),
        body,
        traffic_changed: !notes.is_empty(),
        notes,
        annotations: annotations.finish(),
    }
}

fn decode_content_encoding_records(headers: &[HeaderRecord], body: &[u8]) -> Option<Vec<u8>> {
    decode_content_encoding(&header_map(headers.to_vec()), body)
}

fn strip_content_encoding_records(headers: &mut Vec<HeaderRecord>) {
    headers.retain(|header| !header.name.eq_ignore_ascii_case("content-encoding"));
}

fn normalize_content_length_records(headers: &mut Vec<HeaderRecord>, body_len: usize) {
    let mut had_content_length = false;
    headers.retain(|header| {
        if header.name.eq_ignore_ascii_case("content-length") {
            had_content_length = true;
            false
        } else {
            true
        }
    });
    if had_content_length {
        headers.push(HeaderRecord {
            name: "Content-Length".to_string(),
            value: body_len.to_string(),
        });
    }
}

fn valid_header_name(value: &str) -> bool {
    http::HeaderName::from_bytes(value.as_bytes()).is_ok()
}

fn valid_header_value(value: &str) -> bool {
    http::HeaderValue::from_str(value).is_ok()
}

fn replace_text(value: &str, rule: &MatchReplaceRule) -> Result<(String, bool)> {
    if rule.search.is_empty() {
        return Ok((value.to_string(), false));
    }

    if rule.regex {
        let regex = build_regex(rule)?;
        let replaced = regex.replace_all(value, rule.replace.as_str()).into_owned();
        let changed = replaced != value;
        Ok((replaced, changed))
    } else if rule.case_sensitive {
        let replaced = value.replace(&rule.search, &rule.replace);
        let changed = replaced != value;
        Ok((replaced, changed))
    } else {
        replace_case_insensitive(value, &rule.search, &rule.replace)
    }
}

fn replace_case_insensitive(value: &str, search: &str, replace: &str) -> Result<(String, bool)> {
    let escaped = regex::escape(search);
    let regex = RegexBuilder::new(&escaped).case_insensitive(true).build()?;
    let replaced = regex
        .replace_all(value, regex::NoExpand(replace))
        .into_owned();
    let changed = replaced != value;
    Ok((replaced, changed))
}

fn build_regex(rule: &MatchReplaceRule) -> Result<Regex> {
    Ok(RegexBuilder::new(&rule.search)
        .case_insensitive(!rule.case_sensitive)
        .build()?)
}

fn header_records(headers: HeaderMap) -> Vec<HeaderRecord> {
    headers
        .iter()
        .map(|(name, value)| HeaderRecord {
            name: name.as_str().to_string(),
            value: String::from_utf8_lossy(value.as_bytes()).into_owned(),
        })
        .collect()
}

fn header_map(headers: Vec<HeaderRecord>) -> HeaderMap {
    let mut map = HeaderMap::new();
    for header in headers {
        if let (Ok(name), Ok(value)) = (
            http::HeaderName::from_bytes(header.name.as_bytes()),
            http::HeaderValue::from_str(&header.value),
        ) {
            map.append(name, value);
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use flate2::{
        write::{GzEncoder, ZlibEncoder},
        Compression,
    };
    use std::io::Write;

    fn annotation_rule(scope: MatchReplaceScope, target: MatchReplaceTarget) -> MatchReplaceRule {
        MatchReplaceRule {
            id: Uuid::new_v4(),
            enabled: false,
            annotation_only_enabled: Some(true),
            annotation_note: Some("flag 탐지".into()),
            annotation_color: Some("yellow".into()),
            description: "must not leak this description".into(),
            scope,
            target,
            search: "flag".into(),
            replace: "changed".into(),
            regex: false,
            case_sensitive: true,
        }
    }

    // Exact pre-feature fields: unknown action fields are discarded by old typed clients.
    #[derive(Serialize, Deserialize)]
    struct LegacyRule {
        id: Uuid,
        enabled: bool,
        description: String,
        scope: MatchReplaceScope,
        target: MatchReplaceTarget,
        search: String,
        replace: String,
        regex: bool,
        case_sensitive: bool,
    }

    #[test]
    fn annotation_only_serialization_is_safe_through_legacy_typed_clients() {
        for active in [false, true] {
            let mut rule = annotation_rule(MatchReplaceScope::Response, MatchReplaceTarget::Body);
            rule.annotation_only_enabled = Some(active);
            for contradictory in [false, true] {
                rule.enabled = contradictory;
                let wire = serde_json::to_value(&rule).unwrap();
                assert_eq!(wire["enabled"], false);
                assert_eq!(wire["annotation_only_enabled"], active);
                let legacy: LegacyRule = serde_json::from_value(wire).unwrap();
                assert!(!legacy.enabled);
                let restored: MatchReplaceRule =
                    serde_json::from_value(serde_json::to_value(legacy).unwrap()).unwrap();
                assert!(!restored.is_enabled());
                assert_eq!(restored.annotation_only_enabled, None);
            }
        }
        let mut rule = annotation_rule(MatchReplaceScope::Request, MatchReplaceTarget::Body);
        rule.annotation_only_enabled = None;
        rule.enabled = true;
        let wire = serde_json::to_value(&rule).unwrap();
        assert!(wire.get("annotation_only_enabled").is_none());
        let legacy: LegacyRule = serde_json::from_value(wire).unwrap();
        assert!(legacy.enabled);
    }

    #[test]
    fn restored_annotation_activation_disables_only_raw_contradictions() {
        for active in [false, true] {
            let mut canonical =
                annotation_rule(MatchReplaceScope::Response, MatchReplaceTarget::Body);
            canonical.annotation_only_enabled = Some(active);
            let mut raw = serde_json::to_value(&canonical).unwrap();
            raw["enabled"] = true.into();
            let contradiction: MatchReplaceRule = serde_json::from_value(raw).unwrap();
            assert!(contradiction.enabled);
            let restored = sanitize_match_replace_rules(vec![contradiction]);
            assert_eq!(restored[0].annotation_only_enabled, Some(false));
            assert!(!restored[0].enabled);
            let valid = sanitize_match_replace_rules(vec![canonical]);
            assert_eq!(valid[0].is_enabled(), active);
        }
    }

    #[test]
    fn annotation_only_and_noop_matches_do_not_modify_traffic() {
        let rule = annotation_rule(MatchReplaceScope::Response, MatchReplaceTarget::Any);
        let mut headers = HeaderMap::new();
        headers.insert("x-flag", "flag".parse().unwrap());
        headers.insert("content-length", "4".parse().unwrap());
        let applied = apply_response_rules(
            headers.clone(),
            Bytes::from_static(b"flag"),
            vec![rule.clone()],
        );
        assert_eq!(applied.headers, headers);
        assert_eq!(applied.body, Bytes::from_static(b"flag"));
        assert!(!applied.traffic_changed);
        assert!(applied.notes.is_empty());
        assert_eq!(applied.annotations.notes, ["Rule (response): flag 탐지"]);
        assert_eq!(applied.annotations.color.as_deref(), Some("yellow"));
        assert!(!response_replacement_enabled(&[rule.clone()]));
        let mut noop = rule;
        noop.annotation_only_enabled = None;
        noop.enabled = true;
        noop.replace = noop.search.clone();
        let applied = apply_response_rules(headers, Bytes::from_static(b"flag"), vec![noop]);
        assert!(!applied.traffic_changed);
        assert_eq!(applied.annotations.notes.len(), 1);
    }

    #[test]
    fn annotation_match_is_independent_of_invalid_replacement_and_inert_actions() {
        let mut rule = annotation_rule(MatchReplaceScope::Response, MatchReplaceTarget::HeaderName);
        rule.annotation_only_enabled = None;
        rule.enabled = true;
        rule.replace = "invalid header name".into();
        let mut headers = HeaderMap::new();
        headers.insert("flag", "value".parse().unwrap());
        let applied = apply_response_rules(headers.clone(), Bytes::new(), vec![rule.clone()]);
        assert!(!applied.traffic_changed);
        assert_eq!(applied.headers, headers);
        assert_eq!(applied.annotations.color.as_deref(), Some("yellow"));
        rule.annotation_only_enabled = Some(true);
        rule.enabled = false;
        rule.target = MatchReplaceTarget::Body;
        rule.annotation_note = None;
        rule.annotation_color = None;
        let inert = annotate_streamed_response(&[rule.clone()], &headers, b"", false, 0, 1, false);
        assert!(inert.notes.is_empty() && inert.color.is_none());
        rule.annotation_note = Some("literal".into());
        rule.search.clear();
        let empty_search = annotate_streamed_response(&[rule], &headers, b"", false, 0, 1, false);
        assert!(empty_search.notes.is_empty() && empty_search.color.is_none());
    }

    #[test]
    fn annotation_effects_resolve_snapshot_order_and_first_matching_duplicate() {
        let body = annotation_rule(MatchReplaceScope::Response, MatchReplaceTarget::Body);
        let mut header =
            annotation_rule(MatchReplaceScope::Response, MatchReplaceTarget::HeaderValue);
        header.annotation_color = Some("blue".into());
        let mut headers = HeaderMap::new();
        headers.insert("x-test", "flag".parse().unwrap());
        for (rules, color) in [
            (vec![body.clone(), header.clone()], "blue"),
            (vec![header.clone(), body.clone()], "yellow"),
        ] {
            let buffered =
                apply_response_rules(headers.clone(), Bytes::from_static(b"flag"), rules.clone());
            let streamed =
                annotate_streamed_response(&rules, &headers, b"flag", true, 4, 16, false);
            assert_eq!(buffered.annotations.color.as_deref(), Some(color));
            assert_eq!(streamed.color, buffered.annotations.color);
            assert_eq!(streamed.notes, buffered.annotations.notes);
        }
        header.id = body.id;
        let effects =
            annotate_streamed_response(&[body, header], &headers, b"flag", true, 4, 16, false);
        assert_eq!(effects.notes.len(), 1);
        assert_eq!(effects.color.as_deref(), Some("yellow"));
    }

    #[test]
    fn incomplete_streams_and_opaque_encoding_do_not_match_body_prefix() {
        let mut rule = annotation_rule(MatchReplaceScope::Response, MatchReplaceTarget::Body);
        rule.regex = true;
        rule.search = "flag$".into();
        let headers = HeaderMap::new();
        for (complete, size, limit) in [(false, 4, 16), (true, 5, 16), (true, 4, 3)] {
            let effects = annotate_streamed_response(
                &[rule.clone()],
                &headers,
                b"flag",
                complete,
                size,
                limit,
                false,
            );
            assert_eq!(effects.color, None);
            assert_eq!(effects.notes, [BODY_ANNOTATION_UNAVAILABLE]);
        }
        let mut opaque = HeaderMap::new();
        opaque.insert("content-encoding", "unsupported".parse().unwrap());
        let effects = apply_response_rules(
            opaque.clone(),
            Bytes::from_static(b"flag"),
            vec![rule.clone()],
        );
        assert_eq!(effects.annotations.color, None);
        assert_eq!(effects.headers, opaque);
        assert_eq!(effects.body, Bytes::from_static(b"flag"));
        assert!(!effects.traffic_changed);
        let complete = annotate_streamed_response(&[rule], &headers, b"flag", true, 4, 16, false);
        assert_eq!(complete.color.as_deref(), Some("yellow"));
    }

    #[test]
    fn invalid_utf8_body_annotations_are_unavailable_but_any_header_matches_remain_valid() {
        let body = annotation_rule(MatchReplaceScope::Response, MatchReplaceTarget::Body);
        let mut any = annotation_rule(MatchReplaceScope::Response, MatchReplaceTarget::Any);
        any.annotation_note = Some("header match".into());
        any.annotation_color = Some("blue".into());
        let mut headers = HeaderMap::new();
        headers.insert("x-test", "flag".parse().unwrap());
        for (rules, expected_notes, expected_color) in [
            (vec![body.clone()], vec![BODY_ANNOTATION_UNAVAILABLE], None),
            (
                vec![any.clone()],
                vec!["Rule (response): header match"],
                Some("blue"),
            ),
            (
                vec![body, any],
                vec!["Rule (response): header match", BODY_ANNOTATION_UNAVAILABLE],
                Some("blue"),
            ),
        ] {
            let streamed =
                annotate_streamed_response(&rules, &headers, b"flag\xff", true, 5, 16, false);
            let buffered =
                apply_response_rules(headers.clone(), Bytes::from_static(b"flag\xff"), rules);
            assert_eq!(streamed.notes, expected_notes);
            assert_eq!(streamed.color.as_deref(), expected_color);
            assert_eq!(buffered.annotations.notes, streamed.notes);
            assert_eq!(buffered.annotations.color, streamed.color);
            assert_eq!(buffered.headers, headers);
            assert_eq!(buffered.body, Bytes::from_static(b"flag\xff"));
            assert!(!buffered.traffic_changed);
            assert!(buffered.notes.is_empty());
        }
    }

    #[test]
    fn known_bodyless_is_distinct_from_failed_empty_encoded_body() {
        let mut rule = annotation_rule(MatchReplaceScope::Response, MatchReplaceTarget::Body);
        rule.search = "^$".into();
        rule.regex = true;
        let mut headers = HeaderMap::new();
        headers.insert("content-encoding", "gzip".parse().unwrap());
        for bodyless in [false, true] {
            let streamed =
                annotate_streamed_response(&[rule.clone()], &headers, b"", true, 0, 16, bodyless);
            let buffered = apply_response_rules_with_bodyless(
                headers.clone(),
                Bytes::new(),
                vec![rule.clone()],
                bodyless,
            );
            assert_eq!(streamed.color.is_some(), bodyless);
            assert_eq!(buffered.annotations.color, streamed.color);
            assert!(!buffered.traffic_changed);
            assert_eq!(buffered.headers, headers);
        }
    }

    #[test]
    fn duplicate_after_known_match_does_not_add_irrelevant_coverage_note() {
        let header = annotation_rule(MatchReplaceScope::Response, MatchReplaceTarget::HeaderValue);
        let mut body = header.clone();
        body.target = MatchReplaceTarget::Body;
        let mut headers = HeaderMap::new();
        headers.insert("x-test", "flag".parse().unwrap());
        let effects = annotate_streamed_response(
            &[header.clone(), body.clone()],
            &headers,
            b"",
            false,
            0,
            16,
            false,
        );
        assert_eq!(effects.notes, ["Rule (response): flag 탐지"]);
        let uncertain_first =
            annotate_streamed_response(&[body, header], &headers, b"", false, 0, 16, false);
        assert_eq!(uncertain_first.notes.len(), 2);
        assert_eq!(uncertain_first.notes[1], BODY_ANNOTATION_UNAVAILABLE);
    }

    #[test]
    fn accepted_encoding_metadata_edits_retire_only_later_body_annotations() {
        for (name, value, target, search, replacement, expected_match) in [
            (
                "x-encoding",
                "opaque",
                MatchReplaceTarget::HeaderName,
                "x-encoding",
                "content-encoding",
                false,
            ),
            (
                "content-encoding",
                "opaque",
                MatchReplaceTarget::HeaderName,
                "content-encoding",
                "x-encoding",
                false,
            ),
            (
                "content-encoding",
                "opaque",
                MatchReplaceTarget::HeaderValue,
                "opaque",
                "gzip",
                false,
            ),
            (
                "x-encoding",
                "opaque",
                MatchReplaceTarget::HeaderName,
                "x-encoding",
                "x-encoding",
                true,
            ),
            (
                "x-encoding",
                "opaque",
                MatchReplaceTarget::HeaderName,
                "x-encoding",
                "invalid name",
                true,
            ),
        ] {
            let mut replacement_rule = annotation_rule(MatchReplaceScope::Response, target);
            replacement_rule.annotation_only_enabled = None;
            replacement_rule.enabled = true;
            replacement_rule.annotation_note = None;
            replacement_rule.annotation_color = None;
            replacement_rule.search = search.into();
            replacement_rule.replace = replacement.into();
            let annotation = annotation_rule(MatchReplaceScope::Response, MatchReplaceTarget::Body);
            let mut headers = HeaderMap::new();
            headers.insert(name, value.parse().unwrap());
            let applied = apply_response_rules(
                headers.clone(),
                Bytes::from_static(b"flag"),
                vec![replacement_rule.clone(), annotation.clone()],
            );
            assert_eq!(applied.annotations.color.is_some(), expected_match);
            assert_eq!(applied.body, Bytes::from_static(b"flag"));
            assert_eq!(
                applied
                    .annotations
                    .notes
                    .iter()
                    .any(|note| note == BODY_ANNOTATION_UNAVAILABLE),
                !expected_match
            );
            let request = EditableRequest {
                scheme: "https".into(),
                host: "example.com".into(),
                method: "POST".into(),
                path: "/".into(),
                headers: header_records(headers),
                body: "flag".into(),
                body_encoding: BodyEncoding::Utf8,
                preview_truncated: false,
            };
            replacement_rule.scope = MatchReplaceScope::Request;
            let mut annotation = annotation;
            annotation.scope = MatchReplaceScope::Request;
            let applied = apply_request_rules(request, vec![replacement_rule, annotation]);
            assert_eq!(applied.annotations.color.is_some(), expected_match);
            assert_eq!(applied.request.body, "flag");
        }
    }

    #[test]
    fn annotation_note_restore_limits_are_bytes_and_include_inactive_rows() {
        let mut rule = annotation_rule(MatchReplaceScope::Response, MatchReplaceTarget::Body);
        rule.annotation_only_enabled = Some(false);
        rule.annotation_note = Some("x".repeat(MAX_RULE_ANNOTATION_NOTE_BYTES));
        assert_eq!(
            sanitize_match_replace_rules(vec![rule.clone(); 32]).len(),
            32
        );
        assert_eq!(
            sanitize_match_replace_rules(vec![rule.clone(); 33]).len(),
            32
        );
        rule.annotation_note.as_mut().unwrap().push('x');
        assert!(sanitize_match_replace_rules(vec![rule.clone()]).is_empty());
        rule.annotation_note = Some("  ".into());
        assert!(sanitize_match_replace_rules(vec![rule]).is_empty());
    }

    fn gzip(body: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(body).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn gzip_members_body_rule_matches_later_member_in_both_directions() {
        let compressed = [gzip(b"alpha=one;"), gzip(b"beta=two;")].concat();
        let rule = MatchReplaceRule {
            annotation_only_enabled: None,
            annotation_note: None,
            annotation_color: None,
            id: Uuid::new_v4(),
            enabled: true,
            description: "later gzip member".to_string(),
            scope: MatchReplaceScope::Response,
            target: MatchReplaceTarget::Body,
            search: "two".to_string(),
            replace: "changed".to_string(),
            regex: false,
            case_sensitive: true,
        };
        let mut headers = HeaderMap::new();
        headers.insert("content-encoding", "gzip".parse().unwrap());
        headers.insert(
            "content-length",
            compressed.len().to_string().parse().unwrap(),
        );
        let request = EditableRequest {
            scheme: "http".to_string(),
            host: "example.com".to_string(),
            method: "POST".to_string(),
            path: "/fixture".to_string(),
            headers: vec![
                HeaderRecord {
                    name: "content-encoding".to_string(),
                    value: "gzip".to_string(),
                },
                HeaderRecord {
                    name: "content-length".to_string(),
                    value: compressed.len().to_string(),
                },
            ],
            body: STANDARD.encode(&compressed),
            body_encoding: BodyEncoding::Base64,
            preview_truncated: false,
        };
        let response = apply_response_rules(headers, Bytes::from(compressed), vec![rule.clone()]);
        assert_eq!(response.body.as_ref(), b"alpha=one;beta=changed;");
        assert!(!response.headers.contains_key("content-encoding"));
        assert_eq!(response.headers["content-length"], "23");
        let request = apply_request_rules(
            request,
            vec![MatchReplaceRule {
                annotation_only_enabled: None,
                annotation_note: None,
                annotation_color: None,
                scope: MatchReplaceScope::Request,
                ..rule
            }],
        );
        assert_eq!(request.request.body_bytes(), b"alpha=one;beta=changed;");
        assert!(!request
            .request
            .headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("content-encoding")));
        assert!(request
            .request
            .headers
            .iter()
            .any(
                |header| header.name.eq_ignore_ascii_case("content-length") && header.value == "23"
            ));
    }

    fn zlib_deflate(body: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(body).unwrap();
        encoder.finish().unwrap()
    }

    fn test_rule(description: String) -> MatchReplaceRule {
        MatchReplaceRule {
            annotation_only_enabled: None,
            annotation_note: None,
            annotation_color: None,
            id: Uuid::new_v4(),
            enabled: true,
            description,
            scope: MatchReplaceScope::Request,
            target: MatchReplaceTarget::Path,
            search: "/old".to_string(),
            replace: "/new".to_string(),
            regex: false,
            case_sensitive: false,
        }
    }

    #[tokio::test]
    async fn store_trims_restored_rules_to_rule_limit() {
        let rules = (0..=MAX_MATCH_REPLACE_RULES)
            .map(|index| test_rule(format!("restored rule {index}")))
            .collect::<Vec<_>>();

        let store = MatchReplaceStore::from_rules(rules);

        assert_eq!(store.len().await, MAX_MATCH_REPLACE_RULES);
    }

    #[tokio::test]
    async fn store_drops_restored_invalid_rules() {
        let valid = test_rule("valid".to_string());
        let mut invalid_regex = test_rule("invalid regex".to_string());
        invalid_regex.regex = true;
        invalid_regex.search = "(".to_string();
        let mut oversized = test_rule("oversized".to_string());
        oversized.description = "x".repeat(MAX_MATCH_REPLACE_FIELD_BYTES + 1);

        let store = MatchReplaceStore::from_rules(vec![invalid_regex, valid.clone(), oversized]);
        let rules = store.snapshot().await;

        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, valid.id);
    }

    #[tokio::test]
    async fn applies_request_rule_to_path_and_header_values() {
        let store = MatchReplaceStore::new();
        store
            .replace_all(vec![MatchReplaceRule {
                annotation_only_enabled: None,
                annotation_note: None,
                annotation_color: None,
                id: Uuid::new_v4(),
                enabled: true,
                description: "rewrite host".to_string(),
                scope: MatchReplaceScope::Request,
                target: MatchReplaceTarget::Any,
                search: "example.com".to_string(),
                replace: "internal.local".to_string(),
                regex: false,
                case_sensitive: false,
            }])
            .await;

        let applied = store
            .apply_request(EditableRequest {
                scheme: "https".to_string(),
                host: "example.com".to_string(),
                method: "GET".to_string(),
                path: "/api/example.com".to_string(),
                headers: vec![HeaderRecord {
                    name: "host".to_string(),
                    value: "example.com".to_string(),
                }],
                body: "hello example.com".to_string(),
                body_encoding: BodyEncoding::Utf8,
                preview_truncated: false,
            })
            .await;

        assert_eq!(applied.request.host, "internal.local");
        assert_eq!(applied.request.path, "/api/internal.local");
        assert!(applied.request.body.contains("internal.local"));
        assert_eq!(applied.notes.len(), 1);
    }

    #[tokio::test]
    async fn request_body_rule_refreshes_existing_content_length() {
        let store = MatchReplaceStore::new();
        store
            .replace_all(vec![MatchReplaceRule {
                annotation_only_enabled: None,
                annotation_note: None,
                annotation_color: None,
                id: Uuid::new_v4(),
                enabled: true,
                description: "grow body".to_string(),
                scope: MatchReplaceScope::Request,
                target: MatchReplaceTarget::Body,
                search: "tiny".to_string(),
                replace: "larger-body".to_string(),
                regex: false,
                case_sensitive: true,
            }])
            .await;

        let applied = store
            .apply_request(EditableRequest {
                scheme: "https".to_string(),
                host: "example.com".to_string(),
                method: "POST".to_string(),
                path: "/".to_string(),
                headers: vec![HeaderRecord {
                    name: "Content-Length".to_string(),
                    value: "4".to_string(),
                }],
                body: "tiny".to_string(),
                body_encoding: BodyEncoding::Utf8,
                preview_truncated: false,
            })
            .await;

        assert_eq!(applied.request.body, "larger-body");
        assert_eq!(
            applied
                .request
                .headers
                .iter()
                .find(|header| header.name.eq_ignore_ascii_case("content-length"))
                .map(|header| header.value.as_str()),
            Some("11")
        );
    }

    #[tokio::test]
    async fn request_body_rule_applies_to_gzip_body_and_strips_encoding() {
        let store = MatchReplaceStore::new();
        store
            .replace_all(vec![MatchReplaceRule {
                annotation_only_enabled: None,
                annotation_note: None,
                annotation_color: None,
                id: Uuid::new_v4(),
                enabled: true,
                description: "rewrite compressed request".to_string(),
                scope: MatchReplaceScope::Request,
                target: MatchReplaceTarget::Body,
                search: "tiny".to_string(),
                replace: "larger-body".to_string(),
                regex: false,
                case_sensitive: true,
            }])
            .await;

        let compressed = gzip(b"tiny");
        let applied = store
            .apply_request(EditableRequest {
                scheme: "https".to_string(),
                host: "example.com".to_string(),
                method: "POST".to_string(),
                path: "/".to_string(),
                headers: vec![
                    HeaderRecord {
                        name: "Content-Encoding".to_string(),
                        value: "gzip".to_string(),
                    },
                    HeaderRecord {
                        name: "Content-Length".to_string(),
                        value: compressed.len().to_string(),
                    },
                ],
                body: STANDARD.encode(&compressed),
                body_encoding: BodyEncoding::Base64,
                preview_truncated: false,
            })
            .await;

        assert_eq!(applied.request.body, "larger-body");
        assert_eq!(applied.request.body_encoding, BodyEncoding::Utf8);
        assert!(applied
            .request
            .headers
            .iter()
            .all(|header| !header.name.eq_ignore_ascii_case("content-encoding")));
        assert_eq!(
            applied
                .request
                .headers
                .iter()
                .find(|header| header.name.eq_ignore_ascii_case("content-length"))
                .map(|header| header.value.as_str()),
            Some("11")
        );
        assert_eq!(applied.notes.len(), 1);
    }

    #[tokio::test]
    async fn request_body_rule_leaves_unmatched_gzip_body_untouched() {
        let store = MatchReplaceStore::new();
        store
            .replace_all(vec![MatchReplaceRule {
                annotation_only_enabled: None,
                annotation_note: None,
                annotation_color: None,
                id: Uuid::new_v4(),
                enabled: true,
                description: "no match".to_string(),
                scope: MatchReplaceScope::Request,
                target: MatchReplaceTarget::Body,
                search: "absent".to_string(),
                replace: "larger-body".to_string(),
                regex: false,
                case_sensitive: true,
            }])
            .await;

        let compressed = gzip(b"tiny");
        let applied = store
            .apply_request(EditableRequest {
                scheme: "https".to_string(),
                host: "example.com".to_string(),
                method: "POST".to_string(),
                path: "/".to_string(),
                headers: vec![
                    HeaderRecord {
                        name: "Content-Encoding".to_string(),
                        value: "gzip".to_string(),
                    },
                    HeaderRecord {
                        name: "Content-Length".to_string(),
                        value: compressed.len().to_string(),
                    },
                ],
                body: STANDARD.encode(&compressed),
                body_encoding: BodyEncoding::Base64,
                preview_truncated: false,
            })
            .await;

        assert_eq!(applied.request.body_encoding, BodyEncoding::Base64);
        assert_eq!(applied.request.try_body_bytes().unwrap(), compressed);
        assert_eq!(
            applied
                .request
                .headers
                .iter()
                .find(|header| header.name.eq_ignore_ascii_case("content-encoding"))
                .map(|header| header.value.as_str()),
            Some("gzip")
        );
        assert!(applied.notes.is_empty());
    }

    #[tokio::test]
    async fn request_header_value_rule_normalizes_existing_content_length() {
        let store = MatchReplaceStore::new();
        store
            .replace_all(vec![MatchReplaceRule {
                annotation_only_enabled: None,
                annotation_note: None,
                annotation_color: None,
                id: Uuid::new_v4(),
                enabled: true,
                description: "bad content length edit".to_string(),
                scope: MatchReplaceScope::Request,
                target: MatchReplaceTarget::HeaderValue,
                search: "4".to_string(),
                replace: "999".to_string(),
                regex: false,
                case_sensitive: true,
            }])
            .await;

        let applied = store
            .apply_request(EditableRequest {
                scheme: "https".to_string(),
                host: "example.com".to_string(),
                method: "POST".to_string(),
                path: "/".to_string(),
                headers: vec![HeaderRecord {
                    name: "Content-Length".to_string(),
                    value: "4".to_string(),
                }],
                body: "body".to_string(),
                body_encoding: BodyEncoding::Utf8,
                preview_truncated: false,
            })
            .await;

        assert_eq!(
            applied
                .request
                .headers
                .iter()
                .find(|header| header.name.eq_ignore_ascii_case("content-length"))
                .map(|header| header.value.as_str()),
            Some("4")
        );
        assert_eq!(applied.notes.len(), 1);
    }

    #[tokio::test]
    async fn invalid_header_name_replacement_is_ignored() {
        let store = MatchReplaceStore::new();
        store
            .replace_all(vec![MatchReplaceRule {
                annotation_only_enabled: None,
                annotation_note: None,
                annotation_color: None,
                id: Uuid::new_v4(),
                enabled: true,
                description: "invalid header".to_string(),
                scope: MatchReplaceScope::Request,
                target: MatchReplaceTarget::HeaderName,
                search: "X-Test".to_string(),
                replace: "Bad Header".to_string(),
                regex: false,
                case_sensitive: true,
            }])
            .await;

        let applied = store
            .apply_request(EditableRequest {
                scheme: "https".to_string(),
                host: "example.com".to_string(),
                method: "GET".to_string(),
                path: "/".to_string(),
                headers: vec![HeaderRecord {
                    name: "X-Test".to_string(),
                    value: "kept".to_string(),
                }],
                body: String::new(),
                body_encoding: BodyEncoding::Utf8,
                preview_truncated: false,
            })
            .await;

        assert_eq!(applied.request.headers[0].name, "X-Test");
        assert!(applied.notes.is_empty());
    }

    #[tokio::test]
    async fn response_body_rule_refreshes_existing_content_length() {
        let store = MatchReplaceStore::new();
        store
            .replace_all(vec![MatchReplaceRule {
                annotation_only_enabled: None,
                annotation_note: None,
                annotation_color: None,
                id: Uuid::new_v4(),
                enabled: true,
                description: "grow response".to_string(),
                scope: MatchReplaceScope::Response,
                target: MatchReplaceTarget::Body,
                search: "tiny".to_string(),
                replace: "larger-body".to_string(),
                regex: false,
                case_sensitive: true,
            }])
            .await;

        let mut headers = HeaderMap::new();
        headers.insert("content-length", "4".parse().unwrap());
        let applied = store
            .apply_response(headers, Bytes::from_static(b"tiny"))
            .await;

        assert_eq!(applied.body.as_ref(), b"larger-body");
        assert_eq!(applied.headers.get("content-length").unwrap(), "11");
    }

    #[tokio::test]
    async fn response_header_value_rule_normalizes_existing_content_length() {
        let store = MatchReplaceStore::new();
        store
            .replace_all(vec![MatchReplaceRule {
                annotation_only_enabled: None,
                annotation_note: None,
                annotation_color: None,
                id: Uuid::new_v4(),
                enabled: true,
                description: "bad content length edit".to_string(),
                scope: MatchReplaceScope::Response,
                target: MatchReplaceTarget::HeaderValue,
                search: "4".to_string(),
                replace: "999".to_string(),
                regex: false,
                case_sensitive: true,
            }])
            .await;

        let mut headers = HeaderMap::new();
        headers.insert("content-length", "4".parse().unwrap());
        let applied = store
            .apply_response(headers, Bytes::from_static(b"body"))
            .await;

        assert_eq!(applied.body.as_ref(), b"body");
        assert_eq!(applied.headers.get("content-length").unwrap(), "4");
        assert_eq!(applied.notes.len(), 1);
    }

    #[tokio::test]
    async fn response_body_rule_applies_to_gzip_body_and_strips_encoding() {
        let store = MatchReplaceStore::new();
        store
            .replace_all(vec![MatchReplaceRule {
                annotation_only_enabled: None,
                annotation_note: None,
                annotation_color: None,
                id: Uuid::new_v4(),
                enabled: true,
                description: "rewrite compressed response".to_string(),
                scope: MatchReplaceScope::Response,
                target: MatchReplaceTarget::Body,
                search: "tiny".to_string(),
                replace: "larger-body".to_string(),
                regex: false,
                case_sensitive: true,
            }])
            .await;

        let compressed = gzip(b"tiny");
        let mut headers = HeaderMap::new();
        headers.insert("content-encoding", "gzip".parse().unwrap());
        headers.insert(
            "content-length",
            compressed.len().to_string().parse().unwrap(),
        );
        let applied = store.apply_response(headers, Bytes::from(compressed)).await;

        assert_eq!(applied.body.as_ref(), b"larger-body");
        assert!(applied.headers.get("content-encoding").is_none());
        assert_eq!(applied.headers.get("content-length").unwrap(), "11");
        assert_eq!(applied.notes.len(), 1);
    }

    #[tokio::test]
    async fn response_body_rule_applies_to_zlib_deflate_body_and_strips_encoding() {
        let store = MatchReplaceStore::new();
        store
            .replace_all(vec![MatchReplaceRule {
                annotation_only_enabled: None,
                annotation_note: None,
                annotation_color: None,
                id: Uuid::new_v4(),
                enabled: true,
                description: "rewrite deflate response".to_string(),
                scope: MatchReplaceScope::Response,
                target: MatchReplaceTarget::Body,
                search: "tiny".to_string(),
                replace: "larger-body".to_string(),
                regex: false,
                case_sensitive: true,
            }])
            .await;

        let compressed = zlib_deflate(b"tiny");
        let mut headers = HeaderMap::new();
        headers.insert("content-encoding", "deflate".parse().unwrap());
        headers.insert(
            "content-length",
            compressed.len().to_string().parse().unwrap(),
        );
        let applied = store.apply_response(headers, Bytes::from(compressed)).await;

        assert_eq!(applied.body.as_ref(), b"larger-body");
        assert!(applied.headers.get("content-encoding").is_none());
        assert_eq!(applied.headers.get("content-length").unwrap(), "11");
        assert_eq!(applied.notes.len(), 1);
    }

    #[tokio::test]
    async fn response_body_rule_leaves_unmatched_gzip_body_untouched() {
        let store = MatchReplaceStore::new();
        store
            .replace_all(vec![MatchReplaceRule {
                annotation_only_enabled: None,
                annotation_note: None,
                annotation_color: None,
                id: Uuid::new_v4(),
                enabled: true,
                description: "no match".to_string(),
                scope: MatchReplaceScope::Response,
                target: MatchReplaceTarget::Body,
                search: "absent".to_string(),
                replace: "larger-body".to_string(),
                regex: false,
                case_sensitive: true,
            }])
            .await;

        let compressed = gzip(b"tiny");
        let mut headers = HeaderMap::new();
        headers.insert("content-encoding", "gzip".parse().unwrap());
        headers.insert(
            "content-length",
            compressed.len().to_string().parse().unwrap(),
        );
        let applied = store
            .apply_response(headers, Bytes::from(compressed.clone()))
            .await;

        assert_eq!(applied.body.as_ref(), compressed.as_slice());
        assert_eq!(applied.headers.get("content-encoding").unwrap(), "gzip");
        assert_eq!(
            applied.headers.get("content-length").unwrap(),
            compressed.len().to_string().as_str()
        );
        assert!(applied.notes.is_empty());
    }
}
