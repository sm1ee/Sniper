use anyhow::Result;
use bytes::Bytes;
use http::HeaderMap;
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::model::{decode_content_encoding, BodyEncoding, EditableRequest, HeaderRecord};

pub const MAX_MATCH_REPLACE_RULES: usize = 500;
pub const MAX_MATCH_REPLACE_FIELD_BYTES: usize = 256 * 1024;
pub const MAX_MATCH_REPLACE_RULES_BYTES: usize = 8 * 1024 * 1024;

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MatchReplaceRule {
    pub id: Uuid,
    pub enabled: bool,
    pub description: String,
    pub scope: MatchReplaceScope,
    pub target: MatchReplaceTarget,
    pub search: String,
    pub replace: String,
    pub regex: bool,
    pub case_sensitive: bool,
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
}

#[derive(Clone, Debug)]
pub struct AppliedResponse {
    pub headers: HeaderMap,
    pub body: Bytes,
    pub notes: Vec<String>,
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
        self.rules
            .read()
            .await
            .iter()
            .any(|rule| rule.enabled && matches!(rule.scope, MatchReplaceScope::Response))
    }
}

impl Default for MatchReplaceStore {
    fn default() -> Self {
        Self::new()
    }
}

pub fn sanitize_match_replace_rules(rules: Vec<MatchReplaceRule>) -> Vec<MatchReplaceRule> {
    let mut sanitized = rules
        .into_iter()
        .filter(valid_restored_match_replace_rule)
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
    !rule.regex || RegexBuilder::new(&rule.search).build().is_ok()
}

fn apply_request_rules(request: EditableRequest, rules: Vec<MatchReplaceRule>) -> AppliedRequest {
    let mut request = request;
    let mut notes = Vec::new();
    let mut body_changed = false;
    let mut headers_changed = false;
    let needs_request_body = rules.iter().any(|rule| {
        rule.enabled
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

    for rule in rules
        .into_iter()
        .filter(|rule| rule.enabled && matches!(rule.scope, MatchReplaceScope::Request))
    {
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

    AppliedRequest { request, notes }
}

fn apply_response_rules(
    headers: HeaderMap,
    body: Bytes,
    rules: Vec<MatchReplaceRule>,
) -> AppliedResponse {
    let mut headers = header_records(headers);
    let mut body = body;
    let needs_response_body = rules.iter().any(|rule| {
        rule.enabled
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

    for rule in rules
        .into_iter()
        .filter(|rule| rule.enabled && matches!(rule.scope, MatchReplaceScope::Response))
    {
        let mut matched = false;

        if matches!(
            rule.target,
            MatchReplaceTarget::Any | MatchReplaceTarget::HeaderName
        ) {
            for header in &mut headers {
                if let Ok((value, changed)) = replace_text(&header.name, &rule) {
                    if changed && valid_header_name(&value) {
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
        notes,
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

    fn gzip(body: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(body).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn gzip_members_body_rule_matches_later_member_in_both_directions() {
        let compressed = [gzip(b"alpha=one;"), gzip(b"beta=two;")].concat();
        let rule = MatchReplaceRule {
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
