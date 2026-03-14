use anyhow::Result;
use bytes::Bytes;
use http::HeaderMap;
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::model::{BodyEncoding, EditableRequest, HeaderRecord};

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
            rules: RwLock::new(rules),
        }
    }

    pub async fn snapshot(&self) -> Vec<MatchReplaceRule> {
        self.rules.read().await.clone()
    }

    pub async fn replace_all(&self, rules: Vec<MatchReplaceRule>) -> Vec<MatchReplaceRule> {
        let mut current = self.rules.write().await;
        *current = rules;
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
}

fn apply_request_rules(request: EditableRequest, rules: Vec<MatchReplaceRule>) -> AppliedRequest {
    let mut request = request;
    let mut notes = Vec::new();

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
                    if changed {
                        header.name = value;
                        matched = true;
                    }
                }
            }
        }

        if matches!(
            rule.target,
            MatchReplaceTarget::Any | MatchReplaceTarget::HeaderValue
        ) {
            for header in &mut request.headers {
                if let Ok((value, changed)) = replace_text(&header.value, &rule) {
                    if changed {
                        header.value = value;
                        matched = true;
                    }
                }
            }
        }

        if matches!(
            rule.target,
            MatchReplaceTarget::Any | MatchReplaceTarget::Body
        ) && matches!(request.body_encoding, BodyEncoding::Utf8)
        {
            if let Ok((value, changed)) = replace_text(&request.body, &rule) {
                if changed {
                    request.body = value;
                    matched = true;
                }
            }
        }

        if let Some(host) = request
            .headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case("host"))
            .map(|header| header.value.clone())
        {
            request.host = host;
        }

        if matched {
            notes.push(format!(
                "Match and replace applied request rule: {}",
                rule.description
            ));
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
    let mut notes = Vec::new();

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
                    if changed {
                        header.name = value;
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
                    if changed {
                        header.value = value;
                        matched = true;
                    }
                }
            }
        }

        if matches!(
            rule.target,
            MatchReplaceTarget::Any | MatchReplaceTarget::Body
        ) {
            if let Ok(text) = std::str::from_utf8(body.as_ref()) {
                if let Ok((value, changed)) = replace_text(text, &rule) {
                    if changed {
                        body = Bytes::from(value);
                        matched = true;
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

    AppliedResponse {
        headers: header_map(headers),
        body,
        notes,
    }
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
    let replaced = regex.replace_all(value, replace).into_owned();
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
}
